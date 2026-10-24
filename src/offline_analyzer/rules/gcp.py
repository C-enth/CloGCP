"GCP configuration rules; never an effective IAM permission or exploitation engine."

import json
import re
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from functools import partial
from urllib.parse import unquote

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized, Result, stable_id
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.gcp_context import GCPContext
from offline_analyzer.rules.gcp_identity import (
    AGENT_REASON,
    IN_SCOPE_OTHER_PROJECT,
    OUT_OF_SCOPE,
    PLATFORM_MANAGED,
    UNKNOWN,
    Scope,
    account_class,
)
from offline_analyzer.rules.methodology_links import LINKS, mapping_fields

VERSION = "1.2.0"
# Preserve the existing narrow disabled-service handling. Compute, SQL, KMS and GKE
# disabled-API collection errors do not establish resource absence.
# Rules that read a documented omitted field, only from COMPLETE datasets (phase 3).
OMITTED_FIELD_RULES = {"GCP-API-APP", "GCP-API-API", "GCP-API-BOTH", "GCP-KMS-ROTATION"}
# Rules given iam_hierarchy() completeness (PASS needs complete project and parent IAM).
HIERARCHY_RULES = {"GCP-KEY-PRIVILEGED", "GCP-LOG-AUDIT"}
# Scope evidence for rules whose resources come from more than one dataset: exclusions are
# listed directly and embedded in sinks. Zero derived resources in complete evidence is N/A.
SCOPE_OPERATIONS = {"GCP-LOG-EXCLUSION": {"gcp:logging.exclusions.list", "gcp:logging.sinks.list"}}
DERIVED_RESOURCES = {"GCP-LOG-EXCLUSION"}
RESOURCE_APIS = {"apikeys.googleapis.com", "storage.googleapis.com", "storage-api.googleapis.com"}
BASIC = {"roles/owner", "roles/editor"}
IMPERSONATION = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.workloadIdentityUser",
    "roles/iam.serviceAccountUser",
}
SENSITIVE = (
    BASIC
    | IMPERSONATION
    | {
        "roles/iam.securityAdmin",
        "roles/resourcemanager.projectIamAdmin",
        "roles/storage.objectViewer",
        "roles/storage.objectAdmin",
        "roles/storage.admin",
        "roles/secretmanager.secretAccessor",
        "roles/cloudkms.cryptoKeyDecrypter",
    }
)
IAM_UNCERTAINTY = (
    "Inherited IAM allow and deny policies",
    "Principal access boundaries",
    "IAM Conditions and resource applicability",
    "Credential possession or workload compromise",
)


PARENT_IAM = {"gcp:organizations.getIamPolicy", "gcp:folders.getIamPolicy"}


def iam_hierarchy(sources: list[dict], project: str) -> tuple[bool, str]:
    """(complete, reason): the project IAM policy and every collected organization/folder IAM
    policy of the project were collected completely. No parent policy collected, or any denied
    or partial policy, is incomplete: inherited grants and exemptions stay unknown."""
    own = [s for s in sources if s.get("project_id") == project]
    project_iam = [s for s in own if s["operation"] == "gcp:projects.getIamPolicy"]
    parents = [s for s in own if s["operation"] in PARENT_IAM]
    if not project_iam or any(s["effective_coverage"] != "COMPLETE" for s in project_iam):
        return False, "Complete project IAM policy"
    if not parents:
        return False, "Organization/folder IAM policies of the project (not collected)"
    if any(s["effective_coverage"] != "COMPLETE" for s in parents):
        return False, "Complete organization/folder IAM policies (denied, failed or partial)"
    return True, ""


def unknown(*fields: str) -> Verdict:
    return Verdict(
        Outcome.UNKNOWN, "Required GCP configuration or policy context is unresolved.", fields
    )


def answer(failed: bool, positive: str, negative: str) -> Verdict:
    return Verdict(Outcome.FAIL if failed else Outcome.PASS, positive if failed else negative)


def restrictions(obs: Normalized, mode: str, complete: bool = False) -> Verdict:
    """`complete`: the key came from a COMPLETE dataset. Only then is an omitted
    `restrictions` field read, as documented by Google: "API keys without application
    restrictions can be used from anywhere"; "API keys without API restrictions can be used
    with all APIs that accept keys" (docs/RULE_SPECIFICATIONS.md, omitted fields)."""
    c = obs.configuration
    if c.get("deleteTime"):
        return Verdict(Outcome.NOT_APPLICABLE, "API key is deleted in this snapshot.")
    if "restrictions" not in c:
        # Omitted default fields in native responses need complete collection evidence.
        meta = c.get("_collection", {})
        declared = meta.get("provenance") == "collector-declared" and meta.get("status") in {
            "SUCCESS",
            "EMPTY",
        }
        if not (declared or complete):
            return unknown("Complete API key restrictions metadata")
    r = c.get("restrictions", {})
    if not isinstance(r, dict):
        return unknown("restrictions object")
    apps = {
        "browserKeyRestrictions": "allowedReferrers",
        "serverKeyRestrictions": "allowedIps",
        "androidKeyRestrictions": "allowedApplications",
        "iosKeyRestrictions": "allowedBundleIds",
    }
    if set(r) - {*apps, "apiTargets"}:
        return unknown("Supported API key restriction fields")
    present = [(k, r[k]) for k in apps if k in r]
    if len(present) > 1 or any(not isinstance(v, dict) for _, v in present):
        return unknown("Supported application restriction configuration")
    app = any(isinstance(v.get(apps[k]), list) and v[apps[k]] for k, v in present)
    if any(apps[k] in v and not isinstance(v[apps[k]], list) for k, v in present):
        return unknown("Application restriction list")
    for key, value in present:
        entries = value.get(apps[key], [])
        if key == "androidKeyRestrictions":
            if any(
                not isinstance(entry, dict)
                or not entry.get("packageName")
                or not entry.get("sha1Fingerprint")
                for entry in entries
            ):
                return unknown("Android application identity and certificate fingerprint")
        elif any(not isinstance(entry, str) or not entry for entry in entries):
            return unknown("Application restriction values")
    targets = r.get("apiTargets", [])
    if not isinstance(targets, list) or any(
        not isinstance(t, dict) or not isinstance(t.get("service"), str) or not t["service"]
        for t in targets
    ):
        return unknown("API target service metadata")
    api = bool(targets)
    if mode != "both" and not app and not api:
        return Verdict(
            Outcome.NOT_APPLICABLE, "Both restrictions missing; represented by the combined rule."
        )
    failed = not app and not api if mode == "both" else not (app if mode == "app" else api)
    return answer(
        failed,
        f"API key lacks {mode} restrictions; possession and misuse are not established.",
        f"The {mode} restriction criterion is satisfied by observed metadata.",
    )


def key_rule(
    obs: Normalized, mode: str, context: list[Normalized], hierarchy: tuple | None = None
) -> Verdict:
    c = obs.configuration
    if "disabled" in c and type(c["disabled"]) is not bool:
        return unknown("Boolean key disabled metadata")
    if c.get("keyType") == "SYSTEM_MANAGED" or c.get("disabled") is True:
        return Verdict(Outcome.NOT_APPLICABLE, "Key is system managed or explicitly disabled.")
    if c.get("keyType") != "USER_MANAGED":
        return unknown("keyType")
    if mode == "persistent":
        return answer(
            True,
            (
                "An enabled user-managed service-account key is present; compromise is "
                "not established."
            ),
            "",
        )
    if mode == "age":
        try:
            start = datetime.fromisoformat(c["validAfterTime"].replace("Z", "+00:00"))
            now = obs.collected_at
            if not now or start.tzinfo is None or now < start:
                return unknown("UTC key creation and collection timestamps")
            threshold = c.get("_collection", {}).get("max_key_age_days", 90)
            days = (now - start).total_seconds() / 86400
        except (ValueError, KeyError, TypeError):
            return unknown("validAfterTime")
        return answer(
            days > threshold,
            f"User-managed key age exceeds policy threshold of {threshold} days.",
            "Observed key age is within the configured threshold.",
        )
    name = obs.native_id or ""
    if "/serviceAccounts/" not in name or "/keys/" not in name:
        return unknown("Service-account key subject")
    subject = name.split("/serviceAccounts/", 1)[1].split("/keys/", 1)[0]
    accounts = [
        o
        for o in context
        if o.project_id == obs.project_id
        and o.resource_type == "GCP::ServiceAccount"
        and (o.configuration.get("uniqueId") == subject or o.configuration.get("email") == subject)
    ]
    principals = {
        "serviceAccount:" + str(o.configuration.get("email"))
        for o in accounts
        if o.configuration.get("email")
    }
    if "@" in subject:
        principals.add("serviceAccount:" + subject)
    related = [
        o
        for o in context
        if o.resource_type == "GCP::IAMBinding"
        and o.project_id == obs.project_id
        and o.configuration.get("role") in BASIC
        and principals.intersection(o.configuration.get("members", []))
    ]
    if not related:
        complete, missing = hierarchy or (False, "Complete project and parent IAM policies")
        if not principals:
            return unknown("Service-account identity of the key")
        if not complete:
            return unknown(missing)
        # Complete project and inherited organization/folder policies show no Owner/Editor
        # binding of this account (conditional ones included): the criterion does not hold.
        return Verdict(
            Outcome.PASS,
            "No Owner/Editor binding of the key's service account in the complete project "
            "and organization/folder IAM policies; effective permissions are not asserted.",
            related=tuple(o.observation_id for o in accounts),
        )
    if any(o.configuration.get("condition") for o in related):
        return unknown("Evaluate privileged binding IAM Conditions")
    return Verdict(
        Outcome.FAIL,
        (
            "A persistent user-managed key belongs to a service account with an "
            "observed Owner/Editor binding; effective permissions remain unresolved."
        ),
        related=tuple(o.observation_id for o in related + accounts),
        evidence_needed=IAM_UNCERTAINTY,
    )


def identities_text(identities) -> str:
    return "; ".join(i.text for i in identities[:10]) + (
        f"; +{len(identities) - 10} more" if len(identities) > 10 else ""
    )


def binding_rule(obs: Normalized, mode: str, scope: Scope | None = None) -> Verdict:
    """Project IAM binding rules. ``scope`` is given only to identity-aware rules
    (registry.IDENTITY_ENRICHED); without it the evaluation is unchanged."""
    c = obs.configuration
    role, members = c.get("role"), c.get("members")
    if not isinstance(role, str) or not isinstance(members, list):
        return unknown("IAM role and members")
    if not members or any(
        not isinstance(m, str)
        or (m.startswith("serviceAccount:") and "@" not in m)
        or not (
            m in {"allUsers", "allAuthenticatedUsers"}
            or m.startswith(
                (
                    "user:",
                    "group:",
                    "domain:",
                    "serviceAccount:",
                    "principal://",
                    "principalSet://",
                    "deleted:",
                )
            )
        )
        for m in members
    ):
        return unknown("Nonempty supported IAM principals")
    if "condition" in c and not isinstance(c["condition"], dict):
        return unknown("Supported IAM Conditions object")
    if c.get("condition"):
        return unknown("Evaluate IAM Conditions for the assessment context")
    if mode == "basic":
        active = [m for m in members if not m.startswith("deleted:")]
        if not active:
            return Verdict(
                Outcome.MANUAL_VALIDATION_REQUIRED,
                (
                    "Only deleted principals in this binding; review stale grants and "
                    "the undelete window, not active administrator exposure."
                ),
                evidence_needed=(("Principal deletion/undelete state and approved IAM cleanup"),),
            )
        members = active
    identities = [i for m in members if (i := account_class(m, scope))] if scope is not None else []
    from offline_analyzer.rules.gcp_identity import expected_agent_grant

    platform = [
        i
        for i in identities
        if i.relation == PLATFORM_MANAGED
        and expected_agent_grant(i.member, role, scope, c.get("subject", ""))
    ]
    if platform and mode in {"basic", "impersonation"}:
        # Google-managed service agents are never a finding; their classification is
        # recorded and the other members are evaluated as before.
        managed = {i.member for i in platform}
        members = [m for m in members if m not in managed]
        applies = (
            role in BASIC
            if mode == "basic"
            else role in IMPERSONATION and c.get("subject", "").startswith("projects/")
        )
        if not members and applies:
            return Verdict(
                Outcome.NOT_APPLICABLE,
                f"{AGENT_REASON}: " + identities_text(platform),
            )
    if mode == "basic":
        if (
            scope
            and not scope.project_number
            and role == "roles/editor"
            and members
            and all(
                re.fullmatch(r"serviceAccount:\d+@cloudservices\.gserviceaccount\.com", m)
                for m in members
            )
        ):
            return unknown(
                "Project number needed to distinguish the expected Google APIs Service Agent grant"
            )
        failed = role in BASIC and bool(members)
    elif mode == "public":
        if c.get("subject", "").startswith("buckets/"):
            return Verdict(
                Outcome.NOT_APPLICABLE,
                "Bucket sharing is evaluated with public-access prevention context.",
            )
        if role not in SENSITIVE and {"allUsers", "allAuthenticatedUsers"}.intersection(members):
            return unknown("Role permissions for public principal")
        failed = role in SENSITIVE and bool(
            {"allUsers", "allAuthenticatedUsers"}.intersection(members)
        )
    elif mode == "impersonation":
        if role not in IMPERSONATION:
            return Verdict(
                Outcome.NOT_APPLICABLE, "Binding is outside the supported impersonation roles."
            )
        if not c.get("subject", "").startswith("projects/"):
            return unknown("Supported project or service-account policy scope")
        failed = "/serviceAccounts/" not in c["subject"] or any(
            m in {"allUsers", "allAuthenticatedUsers"}
            or m.startswith(("domain:", "group:", "principalSet:"))
            for m in members
        )
    elif scope is not None:
        if role not in BASIC:
            return Verdict(
                Outcome.NOT_APPLICABLE,
                "Cross-project rule evaluates Owner/Editor service-account bindings only.",
            )
        if identities and len(platform) == len(identities):
            return Verdict(Outcome.NOT_APPLICABLE, f"{AGENT_REASON}: " + identities_text(platform))
        outside = [i for i in identities if i.relation in OUT_OF_SCOPE]
        unresolved = [i for i in identities if i.relation == UNKNOWN]
        linked = [i for i in identities if i.relation == IN_SCOPE_OTHER_PROJECT]
        note = (
            "; informational link(s) to collected project(s): " + identities_text(linked)
            if linked
            else ""
        )
        if outside:
            return Verdict(
                Outcome.FAIL,
                f"Service account(s) from outside the assessed projects hold {role}: "
                + identities_text(outside)
                + note
                + ". Allow metadata does not establish effective access.",
                evidence_needed=IAM_UNCERTAINTY,
            )
        if unresolved:
            return Verdict(
                Outcome.UNKNOWN,
                f"Home project of service-account member(s) holding {role} is unresolved: "
                + identities_text(unresolved)
                + note,
                ("Service-account home project (project ID and number metadata)",),
            )
        if linked:
            return Verdict(
                Outcome.NOT_APPLICABLE,
                f"Informational cross-project link: service account(s) of another collected "
                f"project hold {role}: "
                + identities_text(linked)
                + ". Not reported as cross-project; review it within the collected scope.",
            )
        return Verdict(
            Outcome.PASS,
            "No service account from another project in this observed binding"
            + (": " + identities_text(identities) if identities else "")
            + "; no project-wide IAM assurance is asserted.",
        )
    else:
        if role not in BASIC:
            return Verdict(
                Outcome.NOT_APPLICABLE,
                "Cross-project rule evaluates Owner/Editor service-account bindings only.",
            )
        foreign = [
            m
            for m in members
            if m.startswith("serviceAccount:")
            and ".iam.gserviceaccount.com" in m
            and m.split("@")[-1].split(".iam.gserviceaccount.com")[0] != obs.project_id
        ]
        failed = bool(foreign)
    v = answer(
        failed,
        f"Observed {mode} IAM binding requires least-privilege review; "
        "allow metadata does not establish effective access.",
        f"No {mode} condition in this observed binding; no project-wide IAM assurance is asserted.",
    )
    if failed:
        listed = [i for i in identities if i.member in members]
        reasoning = v.reasoning + (
            " Service-account members: " + identities_text(listed) if listed else ""
        )
        if platform:
            reasoning += f" Not counted ({AGENT_REASON}): " + identities_text(platform)
        return Verdict(v.outcome, reasoning, evidence_needed=IAM_UNCERTAINTY)
    return v


def public_storage(obs: Normalized, context: list[Normalized]) -> Verdict:
    c = obs.configuration
    subject = c.get("subject", "")
    if not subject.startswith("buckets/"):
        return Verdict(Outcome.NOT_APPLICABLE, "Binding is not a Cloud Storage bucket policy.")
    role = c.get("role")
    members = c.get("members")
    if not isinstance(members, list) or c.get("condition"):
        return unknown("Unconditional bucket IAM bindings and principals")
    public = bool({"allUsers", "allAuthenticatedUsers"}.intersection(members))
    if not public:
        return Verdict(
            Outcome.PASS,
            "No public principal in this observed binding; bucket-wide sharing is not established.",
        )
    if role not in {
        "roles/storage.objectViewer",
        "roles/storage.objectAdmin",
        "roles/storage.admin",
    }:
        return unknown("Supported bucket-role permissions")
    bucket_name = subject.removeprefix("buckets/")
    buckets = [
        o
        for o in context
        if o.project_id == obs.project_id
        and o.resource_type == "GCP::Bucket"
        and o.native_id == bucket_name
        and not o.unresolved
        and o.source_status in {"SUCCESS", "COMPLETE", "PARTIAL", "TRUNCATED"}
    ]
    pap_values = {
        o.configuration.get("public_access_prevention")
        or (o.configuration.get("iamConfiguration") or {}).get("publicAccessPrevention")
        for o in buckets
    }
    pap_values.discard(None)
    if len(pap_values) != 1:
        return unknown("Consistent bucket public-access prevention metadata")
    pap = next(iter(pap_values))
    related = list(buckets)
    if pap == "enforced":
        return Verdict(
            Outcome.PASS,
            "Bucket public-access prevention blocks the observed public IAM binding.",
            related=tuple(o.observation_id for o in buckets),
        )
    if pap != "inherited":
        return unknown("Supported bucket public-access prevention setting")
    policies = [
        o
        for o in context
        if o.project_id == obs.project_id
        and o.resource_type == "GCP::OrgPolicy"
        and not o.unresolved
        and o.source_status in {"SUCCESS", "COMPLETE"}
        and constraint_name(o.configuration) == "storage.publicAccessPrevention"
        and o.configuration.get("_parameters", {}).get("effective") in (True, "true")
    ]
    values = [boolean_enforcement(o.configuration)[0] for o in policies]
    if any(type(value) is not bool for value in values):
        return unknown("Boolean inherited public-access prevention enforcement")
    enforcement = set(values)
    if not policies or enforcement not in ({True}, {False}):
        return unknown("Consistent effective inherited storage.publicAccessPrevention policy")
    related.extend(policies)
    if enforcement == {True}:
        return Verdict(
            Outcome.PASS,
            "Effective inherited public-access prevention blocks the observed binding.",
            related=tuple(o.observation_id for o in related),
        )
    return Verdict(
        Outcome.FAIL,
        (
            "Public bucket IAM grants object permissions while bucket and effective"
            " inherited public-access prevention do not block them; effective "
            "access and intended sharing require validation."
        ),
        related=tuple(o.observation_id for o in related),
        evidence_needed=(
            "IAM deny, object ACLs, intended sharing and anonymous access validation",
        ),
    )


KEY_CONSTRAINTS = {"iam.disableServiceAccountKeyCreation", "iam.disableServiceAccountKeyUpload"}


def constraint_name(c: dict) -> str:
    """Bare constraint name from `constraint` (bare or constraints/x), the v2 policy `name`
    (.../policies/x) or the collector's command parameter."""
    for value in (c.get("constraint"), c.get("name"), c.get("_parameters", {}).get("constraint")):
        if isinstance(value, str) and value:
            match = re.search(r"(?:^|/)(?:constraints|policies)/([A-Za-z][\w.]*)$", value)
            if match:
                return match[1]
            if re.fullmatch(r"[A-Za-z]\w*\.[\w.]+", value):
                return value
    return ""


def boolean_enforcement(c: dict) -> tuple[bool | None, str]:
    """Unconditional effective enforcement of a boolean constraint, or (None, reason).

    Shapes: Resource Manager v1 `booleanPolicy.enforced`; Org Policy v2 (`gcloud
    org-policies describe --effective`) `spec.rules[].enforce`, with optional
    `inheritFromParent`, `reset` and `dryRunSpec` (dry run never counts as enforcement).
    Conditional, list-shaped, contradictory, unset or unparseable policies are not decided.
    """
    if isinstance(c.get("booleanPolicy"), dict):
        value = c["booleanPolicy"].get("enforced")
        return (value, "") if type(value) is bool else (None, "booleanPolicy without enforced")
    spec = c.get("spec")
    if spec is None:
        if c.get("dryRunSpec") is not None:
            return None, "dry-run specification only; not enforced live"
        return None, "no effective specification (unset)"
    if not isinstance(spec, dict):
        return None, "unparseable specification"
    if spec.get("reset") is True:
        return None, "reset to the constraint default"
    rules = spec.get("rules")
    if not isinstance(rules, list) or not rules:
        return None, "no rules (unset)"
    if not all(isinstance(r, dict) for r in rules):
        return None, "unparseable rules"
    if any(r.get("condition") for r in rules):
        return None, "conditional rules"
    values = [r.get("enforce") for r in rules]
    if not all(type(v) is bool for v in values):
        if any(k in r for r in rules for k in ("values", "allowAll", "denyAll")):
            return None, "list rules on a boolean constraint"
        return None, "rule without a boolean enforce value"
    if len(set(values)) != 1:
        return None, "contradictory rules"
    return values[0], ""


def observed_policy(c: dict) -> str:
    """The effective value as observed in the record, for finding text and detail."""
    if isinstance(c.get("booleanPolicy"), dict):
        return f"booleanPolicy.enforced: {json_value(c['booleanPolicy'].get('enforced'))}"
    spec = c.get("spec")
    if spec is None:
        return "dryRunSpec only (no live spec)" if c.get("dryRunSpec") is not None else "no spec"
    if not isinstance(spec, dict):
        return "unparseable spec"
    if spec.get("reset") is True:
        return "spec.reset: true"
    rules = spec.get("rules")
    if not isinstance(rules, list) or not rules:
        return "no rules"
    parts = []
    for rule in rules[:5]:
        if not isinstance(rule, dict):
            parts.append("unparseable rule")
        elif rule.get("condition"):
            parts.append(f"conditional rule (enforce: {json_value(rule.get('enforce'))})")
        else:
            parts.append(f"enforce: {json_value(rule.get('enforce'))}")
    return "rules: " + "; ".join(parts)


def json_value(value) -> str:
    return json.dumps(value) if value is not None else "absent"


def governance(obs: Normalized, context: list[Normalized] | None = None) -> Verdict:
    c = obs.configuration
    name = constraint_name(c)
    if name not in KEY_CONSTRAINTS:
        return Verdict(
            Outcome.NOT_APPLICABLE, "Constraint is outside the implemented key-governance rules."
        )
    observed = observed_policy(c)
    # Expanded packages record the --effective flag as a boolean, pilot packages as "true".
    if c.get("_parameters", {}).get("effective") not in (True, "true"):
        return unknown("Effective organization-policy and inherited hierarchy context")
    enforce, reason = boolean_enforcement(c)
    if enforce is None:
        return unknown(
            f"Unconditional effective enforcement of {name} ({reason}; observed {observed})"
        )
    if enforce:
        return Verdict(Outcome.PASS, f"Effective {name} is enforced (observed {observed}).")
    # The managed successor constraint, enforced unconditionally, blocks the same action.
    managed_name = "iam.managed." + name.removeprefix("iam.")
    managed = [
        o
        for o in context or []
        if o.resource_type == obs.resource_type
        and o.project_id == obs.project_id
        and constraint_name(o.configuration) == managed_name
        and o.configuration.get("_parameters", {}).get("effective") in (True, "true")
    ]
    if any(boolean_enforcement(o.configuration)[0] is True for o in managed):
        return Verdict(
            Outcome.PASS,
            f"Effective {name} is unenforced (observed {observed}), but the managed constraint "
            f"{managed_name} is enforced unconditionally, which blocks the same action.",
            related=tuple(o.observation_id for o in managed),
        )
    return Verdict(
        Outcome.FAIL,
        f"Effective {name} is explicitly unenforced (observed {observed}).",
        related=tuple(o.observation_id for o in managed),
        limitations=() if managed else (f"Managed constraint not observed ({managed_name})",),
    )


def exemptions_of(config: dict) -> list[dict] | None:
    """Data Access exemptions of one IAM policy; None when the audit configuration is
    malformed. A policy without auditConfigs has no exemption."""
    configs = config.get("auditConfigs", [])
    if not isinstance(configs, list):
        return None
    found = []
    for cfg in configs:
        if not isinstance(cfg, dict) or not isinstance(cfg.get("auditLogConfigs", []), list):
            return None
        found.extend(
            x
            for x in cfg.get("auditLogConfigs", [])
            if isinstance(x, dict)
            and x.get("logType") in {"DATA_READ", "DATA_WRITE"}
            and x.get("exemptedMembers")
        )
    return found


def audit(
    obs: Normalized, context: Sequence[Normalized] | None = None, hierarchy: tuple | None = None
) -> Verdict:
    c = obs.configuration
    subject = str(c.get("subject") or obs.native_id or "")
    if not re.fullmatch(r"projects/[^/]+|organizations/[0-9]+|folders/[0-9]+", subject):
        # Audit configuration exists only on project, folder and organization policies.
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Resource-level IAM policy; audit configuration applies to project, folder and "
            "organization policies only.",
        )
    if not subject.startswith("projects/"):
        own = exemptions_of(c)
        if own is None:
            return unknown("Supported audit configuration")
        if own:
            return answer(
                True,
                "Explicit Data Access audit-log principal exemptions are "
                "configured on this organization/folder policy.",
                "",
            )
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Organization/folder policy without exemptions; it is evaluated as part of the "
            "effective configuration of each collected project.",
        )
    own = exemptions_of(c)
    if own is None:
        return unknown("Supported audit configuration")
    parents = [
        o
        for o in context or []
        if o.resource_type == "GCP::IAMPolicy"
        and o.project_id == obs.project_id
        and re.fullmatch(
            r"organizations/[0-9]+|folders/[0-9]+",
            str(o.configuration.get("subject") or o.native_id or ""),
        )
    ]
    inherited = []
    for parent in parents:
        found = exemptions_of(parent.configuration)
        if found is None:
            return unknown("Supported inherited audit configuration")
        if found:
            inherited.append(str(parent.configuration.get("subject") or parent.native_id))
    if own or inherited:
        where = (["this project"] if own else []) + inherited
        return Verdict(
            Outcome.FAIL,
            "Explicit Data Access audit-log principal exemptions are configured or inherited ("
            + ", ".join(where)
            + "); exempted principals' data access is not logged.",
            related=tuple(o.observation_id for o in parents),
        )
    complete, missing = hierarchy or (False, "Complete project and parent IAM policies")
    if not complete:
        return unknown(missing + " for inherited Data Access exemptions")
    return Verdict(
        Outcome.PASS,
        f"No Data Access audit-log exemption in the project policy or the {len(parents)} "
        "collected organization/folder policies; whether Data Access logs are enabled for each "
        "service is a separate question.",
        related=tuple(o.observation_id for o in parents),
    )


AUDIT_LOG = re.compile(r"cloudaudit\.googleapis\.com", re.IGNORECASE)
LOG_SELECTOR = re.compile(r'^(?:log_id\(\s*"([^"]+)"\s*\)|logName\s*=\s*"[^"]*/logs/([^"]+)")$')


def log_selectors(text: str) -> list[str] | None:
    """Positive log selectors of a plain conjunction (`a AND b AND ...`); None when the filter
    uses OR, NOT, negation or grouping, or has no positive log selector (unsupported)."""
    bare = re.sub(r'log_id\(\s*"[^"]*"\s*\)', "LOG", text)
    if re.search(r"\bOR\b|\bNOT\b|[()]|(?:^|\s)-", bare):
        return None
    terms = [term.strip() for term in re.split(r"\s+AND\s+", text.strip()) if term.strip()]
    selectors = []
    for term in terms:
        match = LOG_SELECTOR.fullmatch(term)
        if match:
            selectors.append(unquote(match[1] or match[2]))
    return selectors or None


def exclusion(obs: Normalized) -> Verdict:
    c = obs.configuration
    if c.get("disabled") is True:
        return Verdict(Outcome.NOT_APPLICABLE, "Logging exclusion is explicitly disabled.")
    if not isinstance(c.get("filter"), str):
        return unknown("Logging exclusion filter")
    selectors = log_selectors(c["filter"])
    audit_logs = [s for s in selectors or [] if AUDIT_LOG.search(s)]
    if c["filter"].strip() == 'log_id("cloudaudit.googleapis.com/data_access")' or (
        selectors and audit_logs
    ):
        return Verdict(
            Outcome.FAIL,
            (
                "An enabled logging exclusion selects audit logs ("
                + ", ".join(audit_logs or ["cloudaudit.googleapis.com/data_access"])
                + "); evaluate it against required security events and other sinks."
            ),
            evidence_needed=(
                "Effective routing, filter matching, inherited sinks and retention requirements",
            ),
        )
    if selectors:
        # Every entry it drops must be in one of these non-audit logs (a conjunction with a
        # positive log selector cannot match any other log).
        return Verdict(
            Outcome.PASS,
            "The exclusion only selects non-audit logs (" + ", ".join(selectors) + "); it cannot "
            "drop Cloud Audit Logs entries.",
        )
    return unknown("Exclusion filter event matching and effective logging destinations")


def scc(obs: Normalized) -> Verdict:
    c = obs.configuration
    if c.get("state") == "INACTIVE":
        return Verdict(Outcome.NOT_APPLICABLE, "SCC observation is inactive in this snapshot.")
    if c.get("state") != "ACTIVE" or not c.get("category") or not c.get("resourceName"):
        return unknown("SCC category, state and resource identity")
    return Verdict(
        Outcome.FAIL,
        (
            "Active SCC observation requires native configuration and timestamp "
            "validation; detector severity is retained separately."
        ),
        evidence_needed=("Native configuration confirmation and SCC event-time reconciliation",),
    )


def _evaluate(
    rule_id: str,
    obs: Normalized,
    context: Sequence[Normalized] | None = None,
    scope: Scope | None = None,
    hierarchy: tuple | None = None,
    complete: bool = False,
) -> Verdict:
    """`hierarchy` (iam_hierarchy) is given to GCP-KEY-PRIVILEGED and GCP-LOG-AUDIT only;
    `complete` (the observation's dataset is COMPLETE) to the OMITTED_FIELD_RULES only."""
    context = context or []
    from offline_analyzer.rules.gcp_config import bounded_check
    from offline_analyzer.rules.gcp_domains import SPECS

    if rule_id in SPECS:
        return bounded_check(SPECS[rule_id].check)(obs, context)
    if rule_id in CONFIG_EVALUATORS:
        if rule_id in OMITTED_FIELD_RULES:
            return CONFIG_EVALUATORS[rule_id](obs, context, complete=complete)
        return CONFIG_EVALUATORS[rule_id](obs, context)
    if rule_id == "GCP-STORAGE-PUBLIC":
        return public_storage(obs, context)
    if rule_id.startswith("GCP-API-"):
        return restrictions(
            obs, {"APP": "app", "API": "api", "BOTH": "both"}[rule_id.split("-")[-1]], complete
        )
    if rule_id.startswith("GCP-KEY-"):
        return key_rule(
            obs,
            {"PERSISTENT": "persistent", "AGE": "age", "PRIVILEGED": "privileged"}[
                rule_id.split("-")[-1]
            ],
            context,
            hierarchy,
        )
    if rule_id.startswith("GCP-IAM-"):
        return binding_rule(
            obs,
            {
                "BASIC": "basic",
                "PUBLIC": "public",
                "IMPERSONATION": "impersonation",
                "CROSSPROJECT": "crossproject",
            }[rule_id.split("-")[-1]],
            scope,
        )
    if rule_id == "GCP-GOV-KEYS":
        return governance(obs, context)
    if rule_id == "GCP-LOG-AUDIT":
        return audit(obs, context, hierarchy)
    return {
        "GCP-LOG-EXCLUSION": exclusion,
        "GCP-SCC-OBSERVATION": scc,
    }[rule_id](obs)


def evaluate(
    rule_id: str,
    obs: Normalized,
    context: Sequence[Normalized] | None = None,
    scope: Scope | None = None,
    hierarchy: tuple | None = None,
    complete: bool = False,
) -> Verdict:
    """Malformed imported field types are an explicit limitation, never PASS or FAIL."""
    try:
        return _evaluate(rule_id, obs, context, scope, hierarchy, complete)
    except (TypeError, ValueError, AttributeError, KeyError):
        return unknown("Valid GCP configuration field types and supported source shape")


def rule(
    rid: str,
    kind: str,
    operation: str,
    title: str,
    domain: str,
    remediation: str,
    severity: str = "MEDIUM",
    version: str = VERSION,
) -> Rule:
    return Rule(
        rid,
        version,
        kind,
        operation,
        title,
        domain,
        (operation,),
        partial(evaluate, rid),
        (
            "The observed configuration may increase unauthorized access, credential "
            "misuse or detection risk. Actual access, compromise and business impact "
            "require analyst validation."
        ),
        remediation,
        severity,
        (
            "Severity reflects the observed configuration and supported risk, "
            "independent of source detector severity and analyst approval."
        ),
        scope="GLOBAL",
        contextual=True,
        provider="GCP",
        context_operations=("gcp:iam.serviceAccounts.list", "gcp:projects.getIamPolicy")
        if rid == "GCP-KEY-PRIVILEGED"
        else ("gcp:storage.buckets.list", "gcp:orgpolicy.getEffectivePolicy")
        if rid == "GCP-STORAGE-PUBLIC"
        else (),
        follow_up=(
            "Validate scope, configuration ownership, workload dependencies and business impact",
        ),
        methodology=LINKS[rid],
    )


GCP_RULES = (
    rule(
        "GCP-STORAGE-PUBLIC",
        "GCP::IAMBinding",
        "gcp:storage.buckets.getIamPolicy",
        "Potential public Cloud Storage object access",
        "Data Protection",
        (
            "Validate intended sharing and remove public object-role bindings, or "
            "enforce public-access prevention after workload dependency testing."
        ),
        "HIGH",
    ),
    rule(
        "GCP-API-APP",
        "GCP::APIKey",
        "gcp:apikeys.keys.list",
        "API key lacks application restrictions",
        "Credentials and API Security",
        "Apply application restrictions validated against the consuming clients.",
    ),
    rule(
        "GCP-API-API",
        "GCP::APIKey",
        "gcp:apikeys.keys.list",
        "API key lacks API restrictions",
        "Credentials and API Security",
        "Limit allowed APIs to the application's required services.",
    ),
    rule(
        "GCP-API-BOTH",
        "GCP::APIKey",
        "gcp:apikeys.keys.list",
        "API key lacks application and API restrictions",
        "Credentials and API Security",
        ("Inventory key consumers and apply both restriction categories after canary testing."),
        "HIGH",
    ),
    rule(
        "GCP-KEY-PERSISTENT",
        "GCP::ServiceAccountKey",
        "gcp:iam.serviceAccountKeys.list",
        "User-managed service-account key present",
        "Credentials and API Security",
        "Migrate key consumers to attached identities or workload identity federation.",
    ),
    rule(
        "GCP-KEY-AGE",
        "GCP::ServiceAccountKey",
        "gcp:iam.serviceAccountKeys.list",
        "Service-account key exceeds age policy",
        "Credentials and API Security",
        ("Replace aged keys through a rollback-capable migration; prefer keyless credentials."),
    ),
    rule(
        "GCP-KEY-PRIVILEGED",
        "GCP::ServiceAccountKey",
        "gcp:iam.serviceAccountKeys.list",
        "Persistent key on an observed privileged service account",
        "Identity and Access",
        (
            "Reduce observed Owner/Editor bindings and migrate the workload to "
            "keyless authentication."
        ),
        "HIGH",
    ),
    rule(
        "GCP-IAM-BASIC",
        "GCP::IAMBinding",
        "gcp:projects.getIamPolicy",
        "Broad Owner or Editor binding",
        "Identity and Access",
        "Replace basic roles with task-specific predefined or reviewed custom roles.",
        "HIGH",
        # 1.4.0: account ownership classes (PLATFORM_AGENT / DEFAULT_SA / USER_MANAGED).
        version="1.4.0",
    ),
    rule(
        "GCP-IAM-PUBLIC",
        "GCP::IAMBinding",
        "gcp:projects.getIamPolicy",
        "Public principal has a sensitive role binding",
        "Network and Exposure",
        "Validate intended sharing and remove unnecessary public sensitive bindings.",
        "HIGH",
    ),
    rule(
        "GCP-IAM-IMPERSONATION",
        "GCP::IAMBinding",
        "gcp:projects.getIamPolicy",
        "Broad service-account impersonation binding",
        "Identity and Access",
        "Bind specific authorized principals to specific target service accounts.",
        "HIGH",
        # 1.4.0: account ownership classes (PLATFORM_AGENT / DEFAULT_SA / USER_MANAGED).
        version="1.4.0",
    ),
    rule(
        "GCP-IAM-CROSSPROJECT",
        "GCP::IAMBinding",
        "gcp:projects.getIamPolicy",
        "Cross-project service account has an Owner or Editor binding",
        "Identity and Access",
        "Review approved cross-project dependencies and narrow target-project roles.",
        "HIGH",
        # 1.4.0: account ownership classes (PLATFORM_AGENT / DEFAULT_SA / USER_MANAGED).
        version="1.4.0",
    ),
    rule(
        "GCP-GOV-KEYS",
        "GCP::OrgPolicy",
        "gcp:orgpolicy.getEffectivePolicy",
        "Service-account key governance is unenforced",
        "Governance",
        ("Validate keyless readiness and enforce the effective key creation/upload constraint."),
        # 1.3.0: Org Policy v2 effective shapes and bare constraint names are evaluated.
        # 1.4.0: observed value and constraint in the text; managed successor suppresses.
        version="1.4.0",
    ),
    rule(
        "GCP-LOG-AUDIT",
        "GCP::IAMPolicy",
        "gcp:projects.getIamPolicy",
        "Data Access audit-log exemption configured",
        "Monitoring and Detection",
        (
            "Review exempted principals and remove exemptions that conflict with "
            "required detection coverage."
        ),
    ),
    rule(
        "GCP-LOG-EXCLUSION",
        "GCP::LoggingExclusion",
        "gcp:logging.sinks.list",
        "Logging exclusion requires security-event review",
        "Monitoring and Detection",
        (
            "Evaluate the filter against security telemetry and retain required "
            "events in an appropriate sink."
        ),
    ),
    rule(
        "GCP-SCC-OBSERVATION",
        "GCP::SCCFinding",
        "gcp:securitycenter.findings.list",
        "Active Security Command Center observation",
        "Vulnerability and Risk",
        (
            "Validate the detector condition using fresh native configuration and "
            "apply category-specific corrective action."
        ),
    ),
)

# Network, Compute Engine, storage, Cloud SQL, KMS and logging configuration rules.
from offline_analyzer.rules.gcp_config import EVALUATORS as CONFIG_EVALUATORS  # noqa: E402
from offline_analyzer.rules.gcp_config import config_rules  # noqa: E402

GCP_RULES = GCP_RULES + config_rules()
from offline_analyzer.rules.gcp_domains import domain_rules  # noqa: E402

GCP_RULES = GCP_RULES + domain_rules()
# GCP correctness RC phase 2: PASS from complete evidence (KEY-PRIVILEGED and LOG-AUDIT with
# complete project and parent IAM; LOG-EXCLUSION for non-audit log selectors and N/A when
# complete evidence has no exclusion). Other rules keep their versions.
PHASE2_VERSIONS = {
    # Phase 3: documented omitted fields from complete evidence.
    "GCP-API-APP": "1.3.0",
    "GCP-API-API": "1.3.0",
    "GCP-API-BOTH": "1.3.0",
    "GCP-KEY-PRIVILEGED": "1.3.0",
    "GCP-LOG-AUDIT": "1.3.0",
    "GCP-LOG-EXCLUSION": "1.3.0",
}
GCP_RULES = tuple(
    replace(r, version=PHASE2_VERSIONS[r.rule_id]) if r.rule_id in PHASE2_VERSIONS else r
    for r in GCP_RULES
)
# CloGCP context/identity corrections have changed semantics and require revalidation.
CORRECTED_RULES = {
    "GCP-IAM-BASIC",
    "GCP-IAM-IMPERSONATION",
    "GCP-IAM-CROSSPROJECT",
    "GCP-VM-SERIAL-PORT",
    "GCP-VM-OSLOGIN",
    "GCP-VM-PROJECT-SSH-KEYS",
    "GCP-NET-FW-ADMIN-INTERNET",
    "GCP-NET-FW-DB-INTERNET",
    "GCP-NET-FW-ANY-INTERNET",
    "GCP-STORAGE-PUBLIC",
    "GCP-STORAGE-PAP",
    "GCP-STORAGE-VERSIONING",
}
GCP_RULES = tuple(
    replace(r, version="clogcp-1.0.0") if r.rule_id in CORRECTED_RULES else r for r in GCP_RULES
)
BY_ID = {r.rule_id: r for r in GCP_RULES}


def assess_gcp(store, run: str, assessed_at: datetime) -> None:
    from offline_analyzer.provenance.execution import checkpoint

    "Called inside the shared assessment transaction; findings use the shared lifecycle."
    from offline_analyzer.ingestion.json_input import InputError
    from offline_analyzer.rules.engine import persist_result

    observations, context_bytes = [], 0
    for observation in store.observations(run, provider="GCP"):
        checkpoint()
        if observation.provider != "GCP":
            continue
        context_bytes += len(observation.model_dump_json().encode())
        if len(observations) >= 100000 or context_bytes > 128 * 1024 * 1024:
            raise InputError("GCP_ASSESSMENT_RECORD_LIMIT")
        observations.append(observation)
    sources = [s for s in store.source_data(run) if s["format"] == "gcp-json-v1"]
    by_artifact = {s["artifact_id"]: s for s in sources}
    observation_sources = {
        o.observation_id: by_artifact.get(o.evidence.artifact_id, {}) for o in observations
    }
    from offline_analyzer.rules.gcp_identity import scope_from
    from offline_analyzer.rules.gcp_org import org_records, project_index
    from offline_analyzer.rules.registry import IDENTITY_ENRICHED

    known = scope_from(sources, project_index(org_records(observations)))
    indexed_context = GCPContext(observations, sources)
    from offline_analyzer.rules.registry import PRINCIPAL_CONTEXT_RULES

    principal_index = []  # built once, on first use, over this run only (E5)

    def principals():
        if not principal_index:
            from offline_analyzer.iam.gcp_principals import build

            principal_index.append(build(store, [run]))
        return principal_index[0]

    hierarchies: dict[str, tuple] = {}
    service_accounts, principal_bindings, project_context = {}, {}, {}
    for obs in observations:
        project_context.setdefault(obs.project_id, []).append(obs)
        if obs.resource_type == "GCP::ServiceAccount":
            for subject in (obs.configuration.get("uniqueId"), obs.configuration.get("email")):
                if subject:
                    service_accounts.setdefault((obs.project_id, subject), []).append(obs)
        elif obs.resource_type == "GCP::IAMBinding" and obs.configuration.get("role") in BASIC:
            for principal in obs.configuration.get("members", []):
                principal_bindings.setdefault((obs.project_id, principal), []).append(obs)

    def key_context(obs: Normalized) -> list[Normalized]:
        if not obs.native_id or "/serviceAccounts/" not in obs.native_id:
            return []
        subject = obs.native_id.split("/serviceAccounts/", 1)[1].split("/keys/", 1)[0]
        accounts = service_accounts.get((obs.project_id, subject), [])
        emails = {a.configuration.get("email") for a in accounts} - {None}
        if "@" in subject:
            emails.add(subject)
        related = [
            o
            for email in emails
            for o in principal_bindings.get((obs.project_id, "serviceAccount:" + email), [])
        ]
        return accounts + related

    grouped = {}
    for obs in observations:
        grouped.setdefault(
            (obs.project_id, obs.resource_id or obs.observation_id, obs.resource_type), []
        ).append(obs)
    for (_project, _rid, _kind), group in grouped.items():
        checkpoint()
        identity = group[0]
        for r in GCP_RULES:
            if identity.resource_type != r.resource_type:
                continue
            if r.rule_id == "GCP-STORAGE-PUBLIC" and not any(
                o.operation == r.operation for o in group
            ):
                continue
            verdicts = []
            for obs in group:
                source = by_artifact[obs.evidence.artifact_id]
                if source["effective_coverage"] in {"ERROR", "NOT_COLLECTED"} or obs.unresolved:
                    verdicts.append(unknown("Successful collection and native resource identity"))
                else:
                    context = (
                        key_context(obs)
                        if r.rule_id == "GCP-KEY-PRIVILEGED"
                        else indexed_context.for_project(obs.project_id)
                    )
                    scope = (
                        known.for_project(obs.project_id, obs.project_number)
                        if r.rule_id in IDENTITY_ENRICHED
                        else None
                    )
                    hierarchy = (
                        hierarchies.setdefault(
                            obs.project_id, iam_hierarchy(sources, obs.project_id)
                        )
                        if r.rule_id in HIERARCHY_RULES
                        else None
                    )
                    verdict = evaluate(
                        r.rule_id,
                        obs,
                        context,
                        scope,
                        hierarchy,
                        complete=r.rule_id in OMITTED_FIELD_RULES
                        and source["effective_coverage"] == "COMPLETE",
                    )
                    if r.rule_id in PRINCIPAL_CONTEXT_RULES and verdict.outcome == Outcome.FAIL:
                        from offline_analyzer.rules.gcp_principal_context import enrich

                        instances = (
                            [obs]
                            if obs.resource_type == "GCP::ComputeInstance"
                            else [
                                o
                                for o in context
                                if o.resource_type == "GCP::ComputeInstance"
                                and o.observation_id in verdict.related
                            ]
                        )
                        verdict = enrich(r.rule_id, verdict, instances, principals())
                    if (
                        source["effective_coverage"] != "COMPLETE"
                        and verdict.outcome == Outcome.PASS
                    ):
                        verdict = unknown(
                            "Complete, non-truncated collection for a positive conclusion"
                        )
                    if verdict.outcome == Outcome.PASS and any(
                        observation_sources.get(oid, {}).get("effective_coverage") != "COMPLETE"
                        for oid in verdict.related
                    ):
                        verdict = unknown(
                            "Complete supporting policy/resource evidence for a positive conclusion"
                        )
                    verdicts.append(verdict)
            # A documented insecure value can stand despite a second incomplete summary.
            # Positive assurance cannot ignore an unknown or contradictory snapshot.
            failures = [v for v in verdicts if v.outcome == Outcome.FAIL]
            first = failures[0] if failures else verdicts[0]
            outcomes = {v.outcome for v in verdicts}
            conflict = len(outcomes) > 1 and not outcomes <= {Outcome.FAIL, Outcome.UNKNOWN}
            v = unknown("Consistent configuration snapshots and timestamps") if conflict else first
            if failures and Outcome.UNKNOWN in outcomes:
                v = replace(
                    v,
                    limitations=v.limitations
                    + (
                        (
                            "An alternate source snapshot lacks required metadata; the finding "
                            "cites the observed insecure configuration only."
                        ),
                    ),
                )
            refs = store.refs(run, [o.observation_id for o in group] + list(v.related))
            result = Result(
                **mapping_fields(r),
                provider="GCP",
                project_id=identity.project_id,
                project_number=identity.project_number,
                organization_id=identity.organization_id,
                folder_id=identity.folder_id,
                evaluation_id=stable_id("evaluation", [r.rule_id, r.version, _rid]),
                rule_id=r.rule_id,
                rule_version=r.version,
                account_id=None,
                region=identity.region,
                resource_id=identity.resource_id,
                native_id=identity.native_id,
                outcome=v.outcome,
                reasoning=v.reasoning,
                evidence=refs,
                supporting_observations=tuple(o.observation_id for o in group) + v.related,
                contradictory_observations=tuple(o.observation_id for o in group)
                if conflict
                else (),
                missing_dependencies=v.missing,
                evidence_needed=v.evidence_needed,
                suggested_severity=v.severity,
                compensating_controls=v.compensating,
                confidence="UNASSESSED"
                if v.outcome == Outcome.UNKNOWN
                else "MEDIUM"
                if r.rule_id == "GCP-SCC-OBSERVATION"
                else "HIGH",
                limitations=(
                    (
                        "Configuration observation only; no verified exploitation or effective "
                        "IAM authorization"
                    ),
                    "Proposed checklist mapping (check area); no control-level PASS",
                    (
                        "Result applies only to observed metadata; partial collection does not "
                        "establish project coverage"
                    ),
                )
                + v.limitations,
                assessed_at=assessed_at,
                exposure_status="OBSERVED_ALLOW_BINDING_EFFECTIVE_ACCESS_UNRESOLVED"
                if r.rule_id.startswith("GCP-IAM-") or r.rule_id == "GCP-STORAGE-PUBLIC"
                else v.exposure,
                finding_class="POTENTIAL_EXPOSURE"
                if r.rule_id.startswith("GCP-IAM-") or r.rule_id == "GCP-STORAGE-PUBLIC"
                else v.finding_class or r.finding_class,
            )
            persist_result(store, run, result)
    from offline_analyzer.correlation.gcp import deduplicate
    from offline_analyzer.rules.gcp_org import assess_org

    assess_org(store, run, observations, sources, assessed_at)
    deduplicate(store, run)
    projects = {
        p
        for s in sources
        for p in s.get("gcp_metadata", {}).get("expected_projects", [s["project_id"]])
    }
    for project in sorted(projects):
        for r in GCP_RULES:
            operations = SCOPE_OPERATIONS.get(r.rule_id, {r.operation})
            matching = [
                s for s in sources if s["project_id"] == project and s["operation"] in operations
            ]
            observed = any(
                o.project_id == project and o.resource_type == r.resource_type for o in observations
            )
            if (
                matching
                and all(s["effective_coverage"] == "COMPLETE" for s in matching)
                and observed
            ):
                continue
            # GCP-GOV-KEYS is decided per key constraint below once any effective policy was
            # observed: a denied dataset for an unrelated constraint does not make it UNKNOWN.
            if r.rule_id == "GCP-GOV-KEYS" and observed:
                continue
            empty = bool(matching) and all(
                s["effective_coverage"] == "COMPLETE"
                and (s["record_count"] == 0 or r.rule_id in DERIVED_RESOURCES)
                for s in matching
            )
            # The collector observed the required API disabled in the project: the service
            # holds no resources there, so its rules do not apply (not a clean PASS).
            # Only for services whose resources cannot exist without the API (API keys,
            # storage). IAM-backed accounts/keys and SCC are not proven absent by a disabled
            # API, and SCC off is itself a detection-coverage question.
            disabled = bool(matching) and all(
                (s.get("gcp_metadata") or {}).get("status") == "API_DISABLED"
                and (s.get("gcp_metadata") or {}).get("required_api") in RESOURCE_APIS
                for s in matching
            )
            persist_result(
                store,
                run,
                Result(
                    **mapping_fields(r),
                    provider="GCP",
                    project_id=project,
                    evaluation_id=stable_id("gcp-scope", [r.rule_id, project]),
                    rule_id=r.rule_id,
                    rule_version=r.version,
                    account_id=None,
                    region="global",
                    resource_id=None,
                    native_id=None,
                    evaluation_scope="COLLECTION_SCOPE",
                    outcome=Outcome.NOT_APPLICABLE if empty or disabled else Outcome.UNKNOWN,
                    reasoning="Complete collection returned zero resources; no project PASS"
                    if empty
                    else "Required API is disabled in the project; the service is not in use."
                    if disabled
                    else "Missing or incomplete project evidence blocks scope assessment.",
                    missing_dependencies=() if empty or disabled else (r.operation,),
                    confidence="UNASSESSED",
                    assessed_at=assessed_at,
                ),
            )
        # GCP-GOV-KEYS: a key constraint without its own effective record stays UNKNOWN.
        policies = [
            o
            for o in observations
            if o.project_id == project and o.resource_type == "GCP::OrgPolicy"
        ]
        if policies:
            keys = next(r for r in GCP_RULES if r.rule_id == "GCP-GOV-KEYS")
            seen = {constraint_name(o.configuration) for o in policies}
            for name in sorted(KEY_CONSTRAINTS - seen):
                persist_result(
                    store,
                    run,
                    Result(
                        **mapping_fields(keys),
                        provider="GCP",
                        project_id=project,
                        evaluation_id=stable_id("gcp-scope", [keys.rule_id, project, name]),
                        rule_id=keys.rule_id,
                        rule_version=keys.version,
                        account_id=None,
                        region="global",
                        resource_id=None,
                        native_id=None,
                        evaluation_scope="COLLECTION_SCOPE",
                        outcome=Outcome.UNKNOWN,
                        reasoning=f"No effective {name} record was collected; key governance "
                        "for this constraint is unknown, never a PASS.",
                        missing_dependencies=(f"Effective organization policy {name}",),
                        confidence="UNASSESSED",
                        assessed_at=assessed_at,
                    ),
                )
