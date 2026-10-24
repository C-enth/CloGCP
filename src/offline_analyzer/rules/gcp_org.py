"""Organization-wide (cross-project) GCP IAM rules over Cloud Asset IAM search results.

Each search result is the allow policy attached to one resource anywhere in the scanned
organization or folder. Rules evaluate observed bindings only: inherited policies, deny
policies, principal access boundaries and conditions are not resolved, so findings are
POTENTIAL_EXPOSURE with effective access unresolved. Collection completeness (pagination)
is unverified, so an absence of matches is never a PASS.
"""

import re
from collections import defaultdict
from dataclasses import replace
from datetime import datetime

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Result, stable_id
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.methodology_links import LINKS, mapping_fields

VERSION = "1.0.0"
PUBLIC = {"allUsers", "allAuthenticatedUsers"}
BASIC = {"roles/owner", "roles/editor"}
IMPERSONATE = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
}
PRIVILEGED = (
    BASIC
    | {
        "roles/resourcemanager.projectIamAdmin",
        "roles/resourcemanager.organizationAdmin",
        "roles/resourcemanager.folderAdmin",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
    }
    | IMPERSONATE
)
SERVERLESS = {
    "run.googleapis.com/Service",
    "run.googleapis.com/Job",
    "cloudfunctions.googleapis.com/Function",
    "cloudfunctions.googleapis.com/CloudFunction",
}
DATA = {
    "storage.googleapis.com/Bucket",
    "bigquery.googleapis.com/Dataset",
    "bigquery.googleapis.com/Table",
    "secretmanager.googleapis.com/Secret",
    "pubsub.googleapis.com/Topic",
    "pubsub.googleapis.com/Subscription",
    "artifactregistry.googleapis.com/Repository",
}
DATA_PERMISSIONS = {
    "storage.googleapis.com/Bucket": {
        "roles/storage.objectViewer",
        "roles/storage.objectAdmin",
        "roles/storage.admin",
    },
    "bigquery.googleapis.com/Dataset": {
        "roles/bigquery.dataViewer",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.admin",
    },
    "bigquery.googleapis.com/Table": {
        "roles/bigquery.dataViewer",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.admin",
    },
    "secretmanager.googleapis.com/Secret": {"roles/secretmanager.secretAccessor"},
    "pubsub.googleapis.com/Topic": {"roles/pubsub.publisher", "roles/pubsub.admin"},
    "pubsub.googleapis.com/Subscription": {"roles/pubsub.subscriber", "roles/pubsub.admin"},
    "artifactregistry.googleapis.com/Repository": {
        "roles/artifactregistry.reader",
        "roles/artifactregistry.writer",
        "roles/artifactregistry.repoAdmin",
    },
}
HIERARCHY = {
    "cloudresourcemanager.googleapis.com/Project",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Organization",
}
# Google-managed service agents hold default roles; their bindings are not customer choices.
AGENT = re.compile(
    r"@(gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com|cloudservices\.gserviceaccount\.com"
    r"|system\.gserviceaccount\.com|cloudbuild\.gserviceaccount\.com"
    r"|container-engine-robot\.iam\.gserviceaccount\.com"
    r"|compute-system\.iam\.gserviceaccount\.com|serverless-robot-prod\.iam\.gserviceaccount\.com"
    r"|firebase-sa-management\.iam\.gserviceaccount\.com)$"
)
UNRESOLVED = (
    "Inherited and deny policies, principal access boundaries and IAM conditions",
    "Organization IAM search completeness (pagination unverified)",
)
EXPOSURE = "OBSERVED_ALLOW_BINDING_EFFECTIVE_ACCESS_UNRESOLVED"


def _rule(
    rid,
    title,
    domain,
    risk,
    remediation,
    severity,
    finding_class="POTENTIAL_EXPOSURE",
    version=VERSION,
):
    return Rule(
        rid,
        version,
        "GCP::AssetIAMSearchResult",
        "gcp:cloudasset.organizationIamSearch",
        title,
        domain,
        ("organization or folder Cloud Asset IAM search",),
        lambda _obs: Verdict(Outcome.UNKNOWN, "Evaluated by the organization pass"),
        risk,
        remediation,
        severity,
        "Severity reflects observed binding scope and exposure; effective access, asset "
        "criticality and business context are not established by evidence.",
        follow_up=(
            "Confirm the binding is intended, its business owner and any compensating "
            "deny policy or condition",
        ),
        methodology=LINKS[rid],
        scope="GLOBAL",
        provider="GCP",
        finding_class=finding_class,
    )


ORG_RULES = (
    _rule(
        "GCP-ORG-PUBLIC-SERVERLESS",
        "Serverless service allows unauthenticated invocation",
        "Network and Exposure",
        "Anyone on the internet can invoke the service; impact depends on what the service "
        "does with requests and its runtime identity.",
        "Remove allUsers/allAuthenticatedUsers invoker bindings unless the service is an "
        "approved public endpoint; front public endpoints with a load balancer and Cloud "
        "Armor, and restrict ingress.",
        "MEDIUM",
    ),
    _rule(
        "GCP-ORG-PUBLIC-DATA",
        "Data resource grants access to public principals",
        "Data Protection",
        "Public principals can read or modify data in the resource; data classification is "
        "not established by evidence.",
        "Remove allUsers/allAuthenticatedUsers bindings and enforce public access prevention "
        "or domain-restricted sharing org policies after dependency testing.",
        "HIGH",
    ),
    _rule(
        "GCP-ORG-PUBLIC-OTHER",
        "Resource policy grants a role to public principals",
        "Identity and Access",
        "A role is granted to anyone on the internet or any Google account.",
        "Remove public principal bindings and enforce iam.allowedPolicyMemberDomains.",
        "HIGH",
    ),
    _rule(
        "GCP-ORG-BASIC-ROLE",
        "Human principal holds Owner or Editor in the resource hierarchy",
        "Identity and Access",
        "Basic roles grant broad permissions across nearly all services in scope; a "
        "compromised account gains wide control.",
        "Replace Owner/Editor with task-specific predefined roles granted to groups; keep "
        "break-glass Owner accounts few, monitored and MFA-enforced.",
        "HIGH",
    ),
    _rule(
        "GCP-ORG-SA-PRIVILEGED",
        "Service account holds Owner or Editor in the resource hierarchy",
        "Identity and Access",
        "Any workload or principal able to act as this service account inherits broad "
        "project control; default compute service accounts are a common escalation path.",
        "Grant least-privilege predefined roles to dedicated service accounts; remove Editor "
        "from default service accounts (iam.automaticIamGrantsForDefaultServiceAccounts).",
        "HIGH",
        # 1.2.0: account ownership classes (PLATFORM_AGENT / DEFAULT_SA / USER_MANAGED).
        version="1.2.0",
    ),
    _rule(
        "GCP-ORG-IMPERSONATION",
        "Service-account impersonation granted on a project, folder or organization",
        "Identity and Access",
        "Granting Token Creator / Service Account User at a hierarchy level lets the "
        "principal impersonate every service account beneath it, including privileged ones.",
        "Grant impersonation roles on specific service accounts only, to named principals, "
        "with conditions where possible.",
        "HIGH",
    ),
    _rule(
        "GCP-ORG-CROSSPROJECT-SA",
        "Service account from another project holds a privileged role",
        "Identity and Access",
        "Compromise of the source project (its workloads or keys) extends to this project; "
        "the trust crosses a project boundary.",
        "Document approved cross-project dependencies; replace privileged roles with "
        "narrowly scoped roles or move the workload identity into the target project.",
        "MEDIUM",
        # 1.2.0: account ownership classes (PLATFORM_AGENT / DEFAULT_SA / USER_MANAGED).
        version="1.2.0",
    ),
    _rule(
        "GCP-ORG-DELETED-PRINCIPAL",
        "Deleted principal still holds a role binding",
        "Identity and Access",
        "Stale bindings obscure access reviews; a recovered principal (undelete window) "
        "regains the access.",
        "Remove bindings for deleted principals and include IAM cleanup in leaver processing.",
        "LOW",
        finding_class="BASELINE_DEVIATION",
    ),
    _rule(
        "GCP-ORG-EXTERNAL-DOMAIN",
        "Principals from an email domain have access (third-party validation)",
        "Identity and Access",
        "Access by identities outside the organization's own domains is third-party access "
        "and needs ownership and recertification.",
        "Confirm which domains are organization-owned; restrict others with "
        "iam.allowedPolicyMemberDomains and time-bound vendor access.",
        "MEDIUM",
    ),
    _rule(
        "GCP-ORG-FEDERATION",
        "External workload identity can act as a service account",
        "Identity and Access",
        "Identities from another cloud or CI system obtain Google credentials; the trust is "
        "only as strong as the pool's provider and attribute conditions.",
        "Restrict pool providers with attribute conditions bound to specific accounts, "
        "roles or repositories, and grant impersonation only on dedicated service accounts.",
        "MEDIUM",
    ),
)
# Organization-scope rows (scope_rows): PASS needs a complete organization-scope search; no
# search gives explicit UNKNOWN rows. Logic changed for these rules only.
# GCP-ORG-FEDERATION 1.1.0: provider evidence decides FAIL/PASS where it can (manual_reviews).
ORG_RULES = tuple(
    replace(r, version="1.1.0") if r.rule_id == "GCP-ORG-FEDERATION" else r for r in ORG_RULES
)
SCOPE_ROW_RULES = frozenset(
    r.rule_id
    for r in ORG_RULES
    if r.rule_id not in {"GCP-ORG-EXTERNAL-DOMAIN", "GCP-ORG-FEDERATION"}
)
ORG_RULES = tuple(
    replace(r, version={"1.0.0": "1.1.0", "1.2.0": "1.3.0"}[r.version])
    if r.rule_id in SCOPE_ROW_RULES
    else r
    for r in ORG_RULES
)
ORG_CORRECTED = {
    "GCP-ORG-SA-PRIVILEGED",
    "GCP-ORG-CROSSPROJECT-SA",
    "GCP-ORG-IMPERSONATION",
    "GCP-ORG-PUBLIC-SERVERLESS",
    "GCP-ORG-PUBLIC-DATA",
    "GCP-ORG-BASIC-ROLE",
    "GCP-ORG-PUBLIC-OTHER",
    "GCP-ORG-FEDERATION",
}
ORG_RULES = tuple(
    replace(
        r,
        version="clogcp-1.0.0",
        risk=(
            "A public invoker allow binding is observed; ingress, endpoint "
            "reachability, application authorization and intended audience "
            "remain unresolved."
        )
        if r.rule_id == "GCP-ORG-PUBLIC-SERVERLESS"
        else r.risk,
    )
    if r.rule_id in ORG_CORRECTED
    else r
    for r in ORG_RULES
)
BY_ID = {r.rule_id: r for r in ORG_RULES}


def email_domain(member: str) -> str | None:
    if member.startswith(("user:", "group:")) and "@" in member:
        return member.rsplit("@", 1)[1].split("?", 1)[0].lower()
    if member.startswith("domain:"):
        return member.split(":", 1)[1].lower()
    return None


def sa_project(member: str) -> str | None:
    match = re.fullmatch(
        r"serviceAccount:[^@]+@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com", member
    )
    return match[1] if match else None


FIREBASE_DEFAULT = re.compile(r"^serviceAccount:firebase-adminsdk-[a-z0-9]+@")


def is_agent(member: str) -> bool:
    # service-<project number>@... accounts are Google-managed service agents.
    return bool(AGENT.search(member) or re.match(r"serviceAccount:service-\d+@", member))


def federation(member: str) -> dict | None:
    """Parse a workload identity pool principal set; None for other principals."""
    match = re.match(
        r"principal(?:Set)?://iam\.googleapis\.com/projects/(\d+)/locations/global/"
        r"workloadIdentityPools/([^/]+)/(.*)$",
        member,
    )
    if not match:
        return None
    pool_project, pool, tail = match.groups()
    attribute = tail.split("/", 1)
    aws = re.search(r"arn:aws:(?:iam|sts)::(\d{12}):(?:role|assumed-role)/([^/\s]+)", tail)
    return {
        "pool_project_number": pool_project,
        "pool": pool,
        "attribute": attribute[0],
        "value": attribute[1] if len(attribute) > 1 else "",
        "aws_account": aws[1] if aws else None,
        "aws_role": aws[2] if aws else None,
        "kind": "AWS"
        if aws or "aws" in pool.lower()
        else "GITHUB"
        if "github" in pool.lower() or "repository" in tail
        else "OTHER",
    }


def project_index(records) -> dict[str, str]:
    """Project number -> project ID from search results for Project resources."""
    index = {}
    for obs in records:
        config = obs.configuration
        if config.get("assetType") != "cloudresourcemanager.googleapis.com/Project":
            continue
        match = re.search(r"/projects/([a-z][a-z0-9-]{4,28}[a-z0-9])$", config.get("resource", ""))
        number = str(config.get("project", "")).removeprefix("projects/")
        if match and number.isdigit():
            index[number] = match[1]
    return index


def resource_project(config: dict, index: dict[str, str]) -> tuple[str | None, str | None]:
    """(project_id, project_number) owning the resource, when determinable."""
    number = str(config.get("project", "")).removeprefix("projects/") or None
    match = re.search(
        r"/projects/([a-z][a-z0-9-]{4,28}[a-z0-9])(?:/|$)", config.get("resource", "")
    )
    project = match[1] if match else None
    if number and number.isdigit():
        project = project or index.get(number)
    else:
        number = None
    return project, number


def org_records(observations) -> list:
    seen, unique = set(), []
    for obs in observations:
        if obs.resource_type != "GCP::AssetIAMSearchResult":
            continue
        resource = obs.configuration.get("resource")
        if not isinstance(resource, str) or resource in seen:
            continue
        seen.add(resource)
        unique.append(obs)
    return unique


def bindings(config: dict):
    policy = config.get("policy") or {}
    for binding in policy.get("bindings", []) if isinstance(policy, dict) else []:
        if isinstance(binding, dict):
            for member in binding.get("members", []) or []:
                if isinstance(member, str):
                    yield binding.get("role", ""), member, bool(binding.get("condition"))


def matches(rule_id: str, config: dict, project: str | None, scope=None, notes=None) -> list[str]:
    """Bindings (role -> member) on this resource that meet the rule. ``scope`` (a
    gcp_identity.Scope) is given only to identity-aware rules; their non-reported members
    are recorded in ``notes`` (platform / linked / unknown) with the evidence used."""
    from offline_analyzer.rules.gcp_identity import (
        IN_SCOPE_OTHER_PROJECT,
        OUT_OF_SCOPE,
        PLATFORM_MANAGED,
        UNKNOWN,
        account_class,
    )

    kind = config.get("assetType", "")
    hits = []
    notes = {} if notes is None else notes
    policy = config.get("policy")
    if not isinstance(policy, dict) or not isinstance(policy.get("bindings", []), list):
        notes.setdefault("policy_unknown", []).append("Malformed or absent allow policy")
    elif any(
        not isinstance(b, dict)
        or not isinstance(b.get("role"), str)
        or not isinstance(b.get("members"), list)
        or any(not isinstance(m, str) for m in b.get("members", []))
        for b in policy.get("bindings", [])
    ):
        notes.setdefault("policy_unknown", []).append("Malformed role/member metadata")
    for role, member, conditional in bindings(config):
        if conditional and rule_id not in {"GCP-ORG-DELETED-PRINCIPAL"}:
            category = (
                "GCP-ORG-PUBLIC-SERVERLESS"
                if kind in SERVERLESS
                else "GCP-ORG-PUBLIC-DATA"
                if kind in DATA
                else "GCP-ORG-PUBLIC-OTHER"
            )
            relevant = (
                (rule_id == category and member in PUBLIC)
                or (
                    rule_id == "GCP-ORG-BASIC-ROLE"
                    and kind in HIERARCHY
                    and role in BASIC
                    and member.startswith(("user:", "group:", "domain:"))
                )
                or (
                    rule_id == "GCP-ORG-SA-PRIVILEGED"
                    and kind in HIERARCHY
                    and role in BASIC
                    and member.startswith("serviceAccount:")
                )
                or (
                    rule_id == "GCP-ORG-CROSSPROJECT-SA"
                    and role in PRIVILEGED
                    and member.startswith("serviceAccount:")
                )
                or (
                    rule_id == "GCP-ORG-IMPERSONATION" and kind in HIERARCHY and role in IMPERSONATE
                )
            )
            if relevant:
                notes.setdefault("condition_unknown", []).append(
                    f"{role} -> {member}; IAM Condition unresolved"
                )
            continue  # conditional grants need analyst review of the condition
        if rule_id.startswith("GCP-ORG-PUBLIC-") and member in PUBLIC:
            bucket = (
                "GCP-ORG-PUBLIC-SERVERLESS"
                if kind in SERVERLESS
                else "GCP-ORG-PUBLIC-DATA"
                if kind in DATA
                else "GCP-ORG-PUBLIC-OTHER"
            )
            if bucket == rule_id:
                if bucket == "GCP-ORG-PUBLIC-SERVERLESS" and role not in {
                    "roles/run.invoker",
                    "roles/cloudfunctions.invoker",
                }:
                    notes.setdefault("permission_unknown", []).append(
                        f"{role} -> {member}; invoker permission not established"
                    )
                elif bucket == "GCP-ORG-PUBLIC-DATA" and role == "roles/bigquery.metadataViewer":
                    notes.setdefault("non_data", []).append(
                        f"{role} -> {member}; metadata role does not establish table-data "
                        f"read access"
                    )
                elif bucket == "GCP-ORG-PUBLIC-DATA" and role not in DATA_PERMISSIONS.get(
                    kind, set()
                ):
                    notes.setdefault("permission_unknown", []).append(
                        f"{role} -> {member}; resource-specific sensitive permissions unresolved"
                    )
                elif bucket == "GCP-ORG-PUBLIC-OTHER" and role not in {
                    "roles/owner",
                    "roles/editor",
                    "roles/compute.admin",
                    "roles/iam.serviceAccountTokenCreator",
                    "roles/resourcemanager.projectIamAdmin",
                }:
                    notes.setdefault("permission_unknown", []).append(
                        f"{role} -> {member}; resource-specific sensitive permissions unresolved"
                    )
                else:
                    hits.append(f"{role} -> {member}")
        elif rule_id == "GCP-ORG-BASIC-ROLE":
            if (
                kind in HIERARCHY
                and role in BASIC
                and member.startswith(("user:", "group:", "domain:"))
            ):
                hits.append(f"{role} -> {member}")
        elif rule_id == "GCP-ORG-SA-PRIVILEGED" and scope is not None:
            if kind in HIERARCHY and role in BASIC and member.startswith("serviceAccount:"):
                identity = account_class(member, scope)
                from offline_analyzer.rules.gcp_context import canonical
                from offline_analyzer.rules.gcp_identity import expected_agent_grant

                if identity.relation == PLATFORM_MANAGED and expected_agent_grant(
                    member, role, scope, canonical(config.get("resource"))
                ):
                    notes.setdefault("platform", []).append(f"{role} -> {identity.text}")
                else:
                    hits.append(f"{role} -> {identity.text}")
        elif rule_id == "GCP-ORG-SA-PRIVILEGED":
            if (
                kind in HIERARCHY
                and role in BASIC
                and member.startswith("serviceAccount:")
                and not is_agent(member)
            ):
                hits.append(f"{role} -> {member}")
        elif rule_id == "GCP-ORG-IMPERSONATION":
            if kind in HIERARCHY and role in IMPERSONATE:
                qualifier = (
                    ("attachment authorization; workload creation and effective access unresolved")
                    if role == "roles/iam.serviceAccountUser"
                    else "credential authorization; effective access unresolved"
                )
                hits.append(f"{role} -> {member} ({qualifier})")
        elif rule_id == "GCP-ORG-CROSSPROJECT-SA" and scope is not None:
            if (
                role in PRIVILEGED
                and kind in HIERARCHY | {"iam.googleapis.com/ServiceAccount"}
                and (identity := account_class(member, scope))
            ):
                from offline_analyzer.rules.gcp_context import canonical
                from offline_analyzer.rules.gcp_identity import expected_agent_grant

                if identity.relation == PLATFORM_MANAGED and expected_agent_grant(
                    member, role, scope, canonical(config.get("resource"))
                ):
                    notes.setdefault("platform", []).append(f"{role} -> {identity.text}")
                elif identity.relation == PLATFORM_MANAGED:
                    notes.setdefault("same_project_agent", []).append(
                        f"{role} -> {identity.text}; unusual grant is assessed by basic-role rules"
                    )
                elif identity.relation in OUT_OF_SCOPE:
                    hits.append(f"{role} -> {identity.text}")
                elif identity.relation == IN_SCOPE_OTHER_PROJECT:
                    notes.setdefault("linked", []).append(f"{role} -> {identity.text}")
                elif identity.relation == UNKNOWN:
                    notes.setdefault("unknown", []).append(f"{role} -> {identity.text}")
        elif rule_id == "GCP-ORG-CROSSPROJECT-SA":
            source = sa_project(member)
            if (
                project
                and source
                and source != project
                and role in PRIVILEGED
                and kind in HIERARCHY | {"iam.googleapis.com/ServiceAccount"}
                and not is_agent(member)
            ):
                hits.append(f"{role} -> {member} (from project {source})")
        elif rule_id == "GCP-ORG-DELETED-PRINCIPAL":
            if member.startswith("deleted:"):
                hits.append(f"{role} -> {member.split('?', 1)[0]}")
    return hits


def scope_of(config: dict, index, fallback: str) -> dict:
    project, number = resource_project(config, index)
    resource = config.get("resource", "")
    org = re.search(r"organizations/(\d+)", resource) or re.search(
        r"organizations/(\d+)", str(config.get("organization", ""))
    )
    folder = re.search(r"/folders/(\d+)$", resource)
    return {
        "project_id": project or fallback,
        "project_number": number,
        "organization_id": org[1] if org else None,
        "folder_id": folder[1] if folder else None,
    }


def assess_org(store, run: str, observations, sources, assessed_at: datetime) -> list[dict]:
    """Persist org-wide results; return parsed federation edges for correlation."""
    from offline_analyzer.rules.engine import persist_result

    records = org_records(observations)
    if not records:
        # No IAM search results (not collected, denied or empty): organization-wide results
        # are unknown, never a PASS and never silently absent.
        projects = sorted({s["project_id"] for s in sources if s.get("project_id")})
        if projects:
            scope_rows(store, run, projects[0], assessed_at, [], {}, organization=False)
        return []
    index = project_index(records)
    fallback = records[0].project_id
    complete_artifacts = complete_searches(observations, sources)
    complete = all(o.evidence.artifact_id in complete_artifacts for o in records)
    # Only an organization-scope search can establish an organization-wide "no match";
    # project and folder searches cover their own scope only.
    organization = any(
        source_family(s) == "organization_iam_search" and s["artifact_id"] in complete_artifacts
        for s in sources
    )
    # Projects with directly collected project IAM are evaluated by the project rules.
    direct = {
        o.project_id
        for o in observations
        if o.resource_type == "GCP::IAMBinding" and o.operation == "gcp:projects.getIamPolicy"
    }
    from offline_analyzer.rules.gcp_identity import scope_from
    from offline_analyzer.rules.registry import IDENTITY_ENRICHED

    known = scope_from(sources, index)
    from offline_analyzer.rules.gcp_context import GCPContext
    from offline_analyzer.rules.gcp_public_context import public_context

    indexed = GCPContext(observations, sources)
    native_findings = {
        (rid, resource): finding
        for rid, resource, finding in store.db.execute(
            "SELECT json_extract_string(data,'$.rule_id'), "
            "json_extract_string(data,'$.resource_id'), finding_id "
            "FROM findings WHERE run_id=? AND json_extract_string(data,'$.rule_id') "
            "IN ('GCP-RUN-PUBLIC','GCP-FUNCTION-PUBLIC')",
            [run],
        ).fetchall()
    }
    fired, uncertain = defaultdict(int), defaultdict(int)
    for obs in records:
        config = obs.configuration
        scope = scope_of(config, index, fallback)
        identity_scope = known.for_project(scope["project_id"], scope["project_number"])
        if config.get("assetType") == "cloudresourcemanager.googleapis.com/Project" and (
            scope["project_id"] in direct
        ):
            skip = {"GCP-ORG-BASIC-ROLE", "GCP-ORG-SA-PRIVILEGED", "GCP-ORG-CROSSPROJECT-SA"}
        else:
            skip = set()
        for rule in ORG_RULES:
            if rule.rule_id in skip or rule.rule_id in {
                "GCP-ORG-EXTERNAL-DOMAIN",
                "GCP-ORG-FEDERATION",
            }:
                continue
            notes: dict[str, list[str]] = {}
            hits = matches(
                rule.rule_id,
                config,
                scope["project_id"],
                identity_scope if rule.rule_id in IDENTITY_ENRICHED else None,
                notes,
            )
            resource_id = (
                "gcp://"
                + scope["project_id"]
                + "/global/GCP::IAMPolicy/"
                + config["resource"].lstrip("/")
            )
            evidence = identity_notes(notes)
            if not hits:
                if notes:
                    # Reclassified members are recorded with the evidence used, never dropped.
                    uncertain[rule.rule_id] += bool(
                        notes.get("unknown")
                        or notes.get("permission_unknown")
                        or notes.get("condition_unknown")
                        or notes.get("policy_unknown")
                    )
                    persist_result(
                        store,
                        run,
                        identity_result(
                            store, run, rule, obs, scope, resource_id, notes, evidence, assessed_at
                        ),
                    )
                continue
            fired[rule.rule_id] += 1
            contextual = public_context(
                rule.rule_id, obs, indexed.for_project(scope["project_id"]), native_findings
            )
            related_ids = tuple(
                dict.fromkeys((obs.observation_id,) + (contextual.related if contextual else ()))
            )
            # Firebase provisions Token Creator for its Admin SDK account by default: the
            # impersonation reach is real, but it is a platform default, not a custom grant.
            platform_default = rule.rule_id == "GCP-ORG-IMPERSONATION" and all(
                FIREBASE_DEFAULT.search(hit.split(" -> ", 1)[1]) for hit in hits
            )
            persist_result(
                store,
                run,
                Result(
                    **mapping_fields(rule),
                    provider="GCP",
                    **scope,
                    evaluation_id=stable_id(
                        "evaluation", [rule.rule_id, rule.version, resource_id]
                    ),
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    account_id=None,
                    region="global",
                    resource_id=resource_id,
                    native_id=config["resource"],
                    outcome=contextual.outcome if contextual else Outcome.FAIL,
                    reasoning=contextual.reasoning
                    if contextual
                    else f"{config.get('assetType')} {config['resource']}: "
                    + "; ".join(hits[:20])
                    + (f"; +{len(hits) - 20} more" if len(hits) > 20 else "")
                    + (
                        " (Firebase-provisioned default grant; any holder of this account's "
                        "keys can impersonate every service account in the project)"
                        if platform_default
                        else ""
                    )
                    + evidence,
                    suggested_severity=contextual.severity
                    if contextual
                    else "MEDIUM"
                    if platform_default
                    else None,
                    evidence=store.refs(run, related_ids),
                    supporting_observations=related_ids,
                    missing_dependencies=UNRESOLVED + (contextual.missing if contextual else ()),
                    evidence_needed=contextual.evidence_needed if contextual else (),
                    confidence="UNASSESSED"
                    if contextual and contextual.outcome == Outcome.UNKNOWN
                    else "HIGH"
                    if rule.finding_class == "BASELINE_DEVIATION"
                    else "MEDIUM",
                    limitations=(
                        "Direct allow bindings on the resource only; effective access unresolved",
                        "Proposed checklist mapping (check area); no control-level PASS",
                    ),
                    assessed_at=assessed_at,
                    exposure_status=EXPOSURE
                    if rule.finding_class == "POTENTIAL_EXPOSURE"
                    else None,
                    finding_class=rule.finding_class,
                ),
            )
    scope_rows(
        store,
        run,
        fallback,
        assessed_at,
        records,
        fired,
        organization=organization and complete,
        unresolved=uncertain,
    )
    return manual_reviews(
        store, run, records, index, fallback, assessed_at, providers(observations, sources)
    )


PARENT_SCOPE = "GCP_PARENT_SCOPE_SUMMARY_NOT_EFFECTIVE_PERMISSIONS"


def complete_searches(observations, sources) -> set[str]:
    """Artifacts of complete IAM searches. Folder/organization records always carry the
    ADR-010 qualifier PARENT_SCOPE (reduced to the collected project; allow bindings, not
    effective permissions), which makes the importer report them PARTIAL. That qualifier
    states what a record means, not that collection was incomplete: a search whose records
    carry only that tag counts as complete when its declared coverage is COMPLETE. Any other
    unresolved tag, or any incomplete declaration, keeps it incomplete."""
    tags: dict[str, set[str]] = {}
    for obs in observations:
        if obs.resource_type == "GCP::AssetIAMSearchResult":
            tags.setdefault(obs.evidence.artifact_id, set()).update(obs.unresolved)
    found = set()
    for source in sources:
        artifact = source.get("artifact_id")
        if source["effective_coverage"] == "COMPLETE":
            found.add(artifact)
        elif (
            source.get("coverage") == "COMPLETE"
            and not source.get("errors")
            and artifact in tags
            and tags[artifact] <= {PARENT_SCOPE}
        ):
            found.add(artifact)
    return found


def source_family(source: dict) -> str | None:
    """Collector dataset family of a GCP source (expanded contracts), or None."""
    contract = (source.get("gcp_metadata") or {}).get("dataset_contract") or {}
    if contract.get("family"):
        return contract["family"]
    if source.get("operation") == "gcp:cloudasset.organizationIamSearch":
        return "organization_iam_search"
    return None


def scope_rows(store, run, project, assessed_at, records, fired, *, organization, unresolved=None):
    """One collection-scope row per organization rule without a matching binding.

    PASS only when a complete organization-scope IAM search was evaluated, every search
    record came from complete evidence and no member stayed unresolved. Without an
    organization search (none, denied, partial, or only project/folder searches) the
    organization-wide result is UNKNOWN."""
    from offline_analyzer.rules.engine import persist_result

    unresolved = unresolved or {}
    for rule in ORG_RULES:
        if fired.get(rule.rule_id) or rule.rule_id in {
            "GCP-ORG-EXTERNAL-DOMAIN",
            "GCP-ORG-FEDERATION",
        }:
            continue
        open_members = unresolved.get(rule.rule_id, 0)
        passed = organization and bool(records) and not open_members
        if not records:
            reason = (
                "No Cloud Asset IAM search results were collected (not run, denied or empty); "
                "organization-wide bindings are unknown, never a PASS"
            )
        elif passed:
            reason = (
                f"No matching binding in {len(records)} IAM search results of a complete "
                "organization-scope search (reduced to the collected project, ADR-010); "
                "direct allow bindings only"
            )
        else:
            reason = f"No matching binding in {len(records)} IAM search results; " + (
                f"{open_members} resource(s) with an unresolved service-account home "
                "project, so not a PASS"
                if open_members
                else "no complete organization-scope search, so not an organization-wide PASS"
            )
        missing = (
            ()
            if passed
            else ("Complete organization-scope Cloud Asset IAM search",)
            + (
                ("Service-account home project (project ID and number metadata)",)
                if open_members
                else ()
            )
        )
        persist_result(
            store,
            run,
            Result(
                **mapping_fields(rule),
                provider="GCP",
                project_id=project,
                evaluation_id=stable_id("gcp-org-scope", [rule.rule_id, project]),
                rule_id=rule.rule_id,
                rule_version=rule.version,
                account_id=None,
                region="global",
                resource_id=None,
                native_id=None,
                evaluation_scope="COLLECTION_SCOPE",
                outcome=Outcome.PASS if passed else Outcome.UNKNOWN,
                reasoning=reason,
                # A PASS cites every search record it evaluated.
                evidence=store.refs(run, [o.observation_id for o in records]) if passed else (),
                missing_dependencies=missing,
                limitations=(UNRESOLVED[0],),
                confidence="UNASSESSED",
                assessed_at=assessed_at,
            ),
        )


def identity_notes(notes: dict[str, list[str]]) -> str:
    labels = {
        "platform": "Google-managed service agent (platform-managed), not reported",
        "permission_unknown": "Public role permissions require review",
        "non_data": "No table-data read grant established",
        "same_project_agent": "Same-project agent; no cross-project trust inferred",
        "condition_unknown": "IAM Condition applicability unresolved",
        "policy_unknown": "Allow policy shape unresolved",
        "linked": "informational link(s) to collected projects",
        "unknown": "members with an unresolved home project",
    }
    return "".join(
        f"; {labels[key]}: "
        + "; ".join(values[:10])
        + (f"; +{len(values) - 10} more" if len(values) > 10 else "")
        for key, values in notes.items()
        if values
    )


def identity_result(store, run, rule, obs, scope, resource_id, notes, evidence, assessed_at):
    """Non-finding result recording identity reclassification evidence (E1/E2)."""
    unresolved = bool(
        notes.get("unknown")
        or notes.get("permission_unknown")
        or notes.get("condition_unknown")
        or notes.get("policy_unknown")
    )
    return Result(
        **mapping_fields(rule),
        provider="GCP",
        **scope,
        evaluation_id=stable_id("evaluation", [rule.rule_id, rule.version, resource_id]),
        rule_id=rule.rule_id,
        rule_version=rule.version,
        account_id=None,
        region="global",
        resource_id=resource_id,
        native_id=obs.configuration["resource"],
        outcome=Outcome.UNKNOWN if unresolved else Outcome.NOT_APPLICABLE,
        reasoning=f"{obs.configuration.get('assetType')} {obs.configuration['resource']}: "
        + (
            "Google-managed service agent (platform-managed)"
            if set(notes) == {"platform"}
            else "no reportable member"
        )
        + evidence,
        evidence=store.refs(run, [obs.observation_id]),
        supporting_observations=(obs.observation_id,),
        missing_dependencies=(
            (("Conditional/invalid policy applicability and public role permissions"),)
            if notes.get("permission_unknown")
            or notes.get("condition_unknown")
            or notes.get("policy_unknown")
            else ("Service-account home project (project ID and number metadata)",)
        )
        if unresolved
        else (),
        confidence="UNASSESSED" if unresolved else "MEDIUM",
        limitations=("Direct allow bindings on the resource only; effective access unresolved",),
        assessed_at=assessed_at,
    )


POOL = re.compile(r"projects/([^/]+)/locations/global/workloadIdentityPools/([^/]+)/providers/")
POOL_ROOT = re.compile(r"projects/([^/]+)/locations/global/workloadIdentityPools/([^/]+)$")


def providers(observations, sources) -> dict[tuple[str, str], dict]:
    """Index provider and parent-pool snapshots by observed project ID/number aliases.

    Provider and parent-pool source completeness are retained independently.
    """
    complete = {s["artifact_id"] for s in sources if s["effective_coverage"] == "COMPLETE"}
    found: dict[tuple[str, str], dict] = {}
    for obs in observations:
        if obs.resource_type not in {"GCP::WorkloadIdentityProvider", "GCP::WorkloadIdentityPool"}:
            continue
        parent = obs.resource_type == "GCP::WorkloadIdentityPool"
        pattern = POOL_ROOT if parent else POOL
        match = pattern.search(str(obs.configuration.get("name") or obs.native_id or ""))
        if not match:
            continue
        aliases = {match[1]}
        if match[1] in {obs.project_id, obs.project_number}:
            aliases |= {obs.project_id, obs.project_number} - {None}
        entry = next(
            (found[(p, match[2])] for p in aliases if (p, match[2]) in found),
            {"items": [], "complete": True, "pools": [], "pools_complete": True},
        )
        for p in aliases:
            found[(p, match[2])] = entry
        entry["pools" if parent else "items"].append(obs)
        key = "pools_complete" if parent else "complete"
        entry[key] &= obs.evidence.artifact_id in complete and not obs.unresolved
    return found


def provider_state(items: list[dict], provider_info: dict | None) -> tuple:
    """(outcome, detail, related observation IDs) for one pool's trust (see manual_reviews)."""
    if any(i.get("conditional") for i in items):
        return Outcome.UNKNOWN, "IAM Conditions on federation grants require evaluation.", ()
    from offline_analyzer.rules.gcp_context import pool_guard

    pools = (provider_info or {}).get("pools", [])
    guard = pool_guard(pools, (provider_info or {}).get("pools_complete", False))
    if guard:
        return guard.outcome, guard.reasoning, guard.related
    if not provider_info or not provider_info["complete"] or not provider_info["items"]:
        return Outcome.MANUAL_VALIDATION_REQUIRED, "Validate provider attribute conditions.", ()
    related = tuple(o.observation_id for o in [*provider_info["items"], *pools])
    enabled = [
        o
        for o in provider_info["items"]
        if o.configuration.get("disabled") is not True
        and o.configuration.get("state") not in {"DELETED"}
    ]
    if not enabled:
        return (
            Outcome.PASS,
            "Every provider of the pool is disabled or deleted in complete provider evidence: "
            "no external identity can obtain credentials through it.",
            related,
        )
    open_ = [o for o in enabled if not str(o.configuration.get("attributeCondition") or "").strip()]
    whole_pool = any(e["attribute"] == "*" for e in items)
    if open_ and whole_pool:
        names = ", ".join(sorted(str(o.native_id or "").rsplit("/", 1)[-1] for o in open_))
        return (
            Outcome.FAIL,
            f"The whole pool is granted and enabled provider(s) {names} have no attribute "
            "condition. This is a potential trust gap; parent pool state, claim mapping, "
            "audience and effective resource authorization require validation.",
            related,
        )
    conditions = "; ".join(
        sorted(
            f"{str(o.native_id or '').rsplit('/', 1)[-1]}: "
            + (str(o.configuration.get("attributeCondition") or "no condition")[:160])
            for o in enabled
        )
    )
    return (
        Outcome.MANUAL_VALIDATION_REQUIRED,
        f"Validate that the provider conditions restrict to intended identities ({conditions}).",
        related,
    )


def manual_reviews(
    store, run, records, index, fallback, assessed_at, pool_providers=None
) -> list[dict]:
    """Per-domain third-party review items and per-pool federation trust items."""
    from offline_analyzer.rules.engine import persist_result

    domains: dict[str, dict] = {}
    edges: list[dict] = []
    for obs in records:
        config = obs.configuration
        project = scope_of(config, index, fallback)["project_id"]
        for role, member, _conditional in bindings(config):
            domain = email_domain(member)
            if domain:
                entry = domains.setdefault(
                    domain, {"principals": set(), "projects": set(), "roles": set(), "obs": []}
                )
                entry["principals"].add(member.split("?", 1)[0])
                entry["projects"].add(project)
                entry["roles"].add(role)
                if len(entry["obs"]) < 200:
                    entry["obs"].append(obs.observation_id)
            parsed = federation(member)
            if parsed:
                edges.append(
                    {
                        **parsed,
                        "role": role,
                        "conditional": _conditional,
                        "target": config.get("resource", ""),
                        "target_type": config.get("assetType", ""),
                        "project_id": project,
                        "observation_id": obs.observation_id,
                    }
                )
    rule = BY_ID["GCP-ORG-EXTERNAL-DOMAIN"]
    for domain, entry in sorted(domains.items()):
        persist_result(
            store,
            run,
            Result(
                **mapping_fields(rule),
                provider="GCP",
                project_id=fallback,
                evaluation_id=stable_id("gcp-org-domain", [rule.rule_id, domain]),
                rule_id=rule.rule_id,
                rule_version=rule.version,
                account_id=None,
                region="global",
                resource_id="gcp://" + fallback + "/global/GCP::PrincipalDomain/" + domain,
                native_id="domain:" + domain,
                outcome=Outcome.MANUAL_VALIDATION_REQUIRED,
                reasoning=f"{len(entry['principals'])} principals from {domain} hold "
                f"{len(entry['roles'])} distinct roles across {len(entry['projects'])} projects; "
                "confirm whether the domain is organization-owned or third-party.",
                evidence=store.refs(run, entry["obs"]),
                supporting_observations=tuple(entry["obs"]),
                evidence_needed=("Approved organization domain list",),
                confidence="UNASSESSED",
                assessed_at=assessed_at,
            ),
        )
    rule = BY_ID["GCP-ORG-FEDERATION"]
    pools: dict[tuple, list[dict]] = defaultdict(list)
    for edge in edges:
        pools[(edge["pool_project_number"], edge["pool"], edge["target"])].append(edge)
    for (number, pool, target), items in sorted(pools.items()):
        native = f"projects/{number}/workloadIdentityPools/{pool}"
        detail = "; ".join(
            sorted({f"{e['role']} via {e['attribute']}={e['value'][:120]}" for e in items})
        )
        # Providers are named by the pool's project number, as the principal set is.
        info = (pool_providers or {}).get((number, pool))
        outcome, verdict, related = provider_state(items, info)
        persist_result(
            store,
            run,
            Result(
                **mapping_fields(rule),
                provider="GCP",
                project_id=items[0]["project_id"],
                evaluation_id=stable_id("gcp-org-federation", [rule.rule_id, native, target]),
                rule_id=rule.rule_id,
                rule_version=rule.version,
                account_id=None,
                region="global",
                resource_id="gcp://"
                + items[0]["project_id"]
                + "/global/GCP::WorkloadIdentityTrust/"
                + native
                + "/"
                + target.lstrip("/"),
                native_id=native,
                outcome=outcome,
                reasoning=f"Observed {items[0]['kind']} workload-identity allow grant "
                f"from pool {pool} towards "
                f"{target}: {detail}. {verdict}",
                evidence=store.refs(run, [e["observation_id"] for e in items] + list(related)),
                supporting_observations=tuple({e["observation_id"] for e in items}) + related,
                evidence_needed=()
                if outcome != Outcome.MANUAL_VALIDATION_REQUIRED
                else ("Workload identity pool provider configuration",)
                if not related
                else ("Analyst review of provider attribute conditions",),
                confidence="UNASSESSED"
                if outcome == Outcome.MANUAL_VALIDATION_REQUIRED
                else "MEDIUM",
                assessed_at=assessed_at,
            ),
        )
    return edges
