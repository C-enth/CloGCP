"""Cross-project (GCP) and cross-cloud (AWS <-> GCP) attack-path correlation.

Paths are built only from observed bindings and trust documents:
- XP-01 principal -> impersonation grant -> privileged service account -> target scope
- XP-02 service account of project A -> privileged role in project B
- XP-03 public principal -> serverless/data resource (no credential required)
- XC-01 AWS IAM role -> GCP workload identity pool -> GCP service account -> GCP roles
- XC-02 Google identity -> AWS role trusting accounts.google.com

A step is "observed" when an allow binding or trust statement is in evidence. Deny
policies, principal access boundaries and pool provider conditions are separate
prerequisites: unless their absence is verified, a path is INSUFFICIENT_EVIDENCE, never
FEASIBLE. Credential possession and workload compromise are attacker-side prerequisites
and are never verified from configuration.
"""

import json
import re
from collections import Counter, defaultdict
from types import SimpleNamespace

from offline_analyzer.attack_paths.model import BLOCKED, HYPOTHESIS, PROVEN, hop, summarize
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.iam.gcp_permissions import ACCESS_TOKEN, PermissionIndex
from offline_analyzer.rules.gcp_org import (
    BASIC,
    DATA,
    HIERARCHY,
    IMPERSONATE,
    PUBLIC,
    SERVERLESS,
    bindings,
    federation,
    is_agent,
    org_records,
    project_index,
    scope_of,
)

FEASIBLE, INSUFFICIENT = "FEASIBLE", "INSUFFICIENT_EVIDENCE"
ADMIN = BASIC | {
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
}
QUALIFICATION = "Observed allow bindings and trust only; exploitation not performed."
SA_RESOURCE = re.compile(r"//iam\.googleapis\.com/projects/([^/]+)/serviceAccounts/([^/]+)$")


def org_resource_id(project: str, resource: str) -> str:
    return "gcp://" + project + "/global/GCP::IAMPolicy/" + resource.lstrip("/")


def sa_home(email: str, numbers: dict[str, str]) -> str | None:
    """Project that owns a service account, from its email form."""
    if match := re.fullmatch(
        r"[^@]+@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com", email
    ):
        return match[1]
    if match := re.fullmatch(
        r"([a-z][a-z0-9-]{4,28}[a-z0-9])@appspot\.gserviceaccount\.com", email
    ):
        return match[1]
    if match := re.fullmatch(r"(\d+)-compute@developer\.gserviceaccount\.com", email):
        return numbers.get(match[1])
    return None


def deny_status(store, run_id: str) -> dict[str, bool]:
    """Project -> True when deny policies and PABs were collected and found empty."""
    seen: dict[str, list[bool]] = defaultdict(list)
    for (data,) in store.rows("SELECT data FROM sources WHERE run_id=?", [run_id]):
        source = json.loads(data)
        if source.get("operation") in {
            "gcp:expanded.deny_policies_project",
            "gcp:expanded.principal_access_boundaries_project",
        }:
            seen[source.get("project_id")].append(
                source.get("effective_coverage") == "COMPLETE" and source.get("record_count") == 0
            )
    return {project: len(flags) == 2 and all(flags) for project, flags in seen.items()}


def item(
    kind,
    title,
    scope,
    steps,
    unresolved,
    findings,
    *,
    provider="GCP",
    aws=None,
    paths=(),
    attacker=(),
    hops=(),
    entry="",
    objective="",
    impact="",
    assumptions=None,
):
    hops = list(hops)
    unresolved = list(unresolved)
    if "GCP" in provider:
        # These legacy projections are observed relationships, not the v2 evaluator.
        # Never let an observed role/empty project deny export imply end-to-end proof.
        unresolved.append("effective IAM and service-specific restrictions require v2 evaluation")
        if hops and all(h["status"] == PROVEN for h in hops):
            hops[-1] = {
                **hops[-1],
                "status": HYPOTHESIS,
                "missing_evidence": [*hops[-1]["missing_evidence"], unresolved[-1]],
            }
    verdict = INSUFFICIENT if unresolved else FEASIBLE
    record = {
        "path_id": stable_id("cross-path", [kind, *steps]),
        "attack_path": kind,
        "provider": provider,
        "project_id": scope,
        "account_id": aws,
        "title": title,
        "anchor": steps[0],
        "steps": steps,
        "feasibility": verdict,
        "feasibility_reason": (
            "Every evidence-checkable step is observed"
            if verdict == FEASIBLE
            else "All allow steps observed; unverified: " + "; ".join(unresolved)
        )
        + (f"; attacker-side prerequisites remain: {'; '.join(attacker)}." if attacker else "."),
        "unresolved": unresolved,
        "finding_ids": sorted(findings),
        "methodology_paths": list(paths),
        "confidence": "MEDIUM" if verdict == FEASIBLE else "LOW",
        "qualification": QUALIFICATION,
        "scope": "cross-cloud" if kind.startswith("XC") else "cross-project",
        "evidence_classification": "BLOCKED"
        if any(h["status"] == BLOCKED and h["observation_ids"] for h in hops)
        else "INSUFFICIENT_EVIDENCE",
        "exploitation_verification": "UNVERIFIED",
        "evaluation_version": "2.0.0",
    }
    return summarize(
        record,
        list(hops),
        entry or steps[0],
        objective or steps[-1],
        impact,
        attacker if assumptions is None else assumptions,
    )


INGRESS_OPEN = {"INGRESS_TRAFFIC_ALL", "all", "ALLOW_ALL"}
INGRESS_CLOSED = {"INGRESS_TRAFFIC_INTERNAL_ONLY", "internal", "ALLOW_INTERNAL_ONLY"}


def serverless_ingress(observations, numbers: dict[str, str]) -> dict[tuple, tuple]:
    """(project, location, name) -> (ingress setting, observation ID) for services/functions."""
    found = {}
    for obs in observations:
        if obs.resource_type not in {"GCP::RunService", "GCP::Function"}:
            continue
        config = obs.configuration or {}
        meta = config.get("metadata") or {}
        name = config.get("name") or ""
        setting = (
            config.get("ingress")
            or config.get("ingressSettings")
            or (config.get("serviceConfig") or {}).get("ingressSettings")
            or (meta.get("annotations") or {}).get("run.googleapis.com/ingress")
        )
        match = re.match(
            r"projects/([^/]+)/locations/([^/]+)/(?:services|functions)/([^/]+)$", name
        )
        if match:
            key = match.groups()
        elif meta.get("name"):
            location = (meta.get("labels") or {}).get("cloud.googleapis.com/location", "")
            key = (str(meta.get("namespace", "")), location, meta["name"])
        else:
            continue
        project = numbers.get(key[0], key[0])
        found[(project, key[1], key[2])] = (setting, obs.observation_id)
    return found


def reachability(resource: str, kind: str, ingress: dict, numbers: dict[str, str]):
    """Internet -> serverless endpoint hop from the collected ingress setting."""
    match = re.search(
        r"/projects/([^/]+)/locations/([^/]+)/(?:services|functions)/([^/]+)$", resource
    )
    key = (numbers.get(match[1], match[1]), match[2], match[3]) if match else None
    setting, observation = ingress.get(key, (None, None)) if key else (None, None)
    if setting in INGRESS_OPEN:
        return PROVEN, f"ingress setting {setting} admits internet traffic", [observation], []
    if setting in INGRESS_CLOSED:
        return BLOCKED, f"ingress setting {setting} admits internal traffic only", [observation], []
    if setting:
        return (
            HYPOTHESIS,
            f"ingress setting {setting} admits traffic only through a load balancer",
            [observation],
            ["external load balancer fronting the service (not correlated)"],
        )
    return HYPOTHESIS, "ingress setting not collected", [], [f"ingress setting of {resource}"]


def classify(records, numbers: dict[str, str], fallback) -> SimpleNamespace:
    """Sort unconditional allow bindings into the inputs of every cross-project path kind."""
    found = SimpleNamespace(
        impersonators=defaultdict(list),  # SA email -> impersonation grants on that SA
        scope_grants=[],  # hierarchy-level impersonation grants
        privileged=defaultdict(list),  # SA email -> admin grants
        agent_privileged=defaultdict(list),  # Google-managed agent email -> admin grants
        public=[],
        grant_obs={},  # (member, role, resource) -> observation ID
        counts=Counter(),
    )
    for obs in records:
        config = obs.configuration
        resource, kind = config.get("resource", ""), config.get("assetType", "")
        project = scope_of(config, numbers, fallback)["project_id"]
        target_sa = SA_RESOURCE.search(resource)
        for role, member, conditional in bindings(config):
            found.counts["bindings"] += 1
            if conditional:
                found.counts["conditional"] += 1
                continue
            found.grant_obs.setdefault((member, role, resource), obs.observation_id)
            if member in PUBLIC and kind in SERVERLESS | DATA:
                found.public.append((project, resource, kind, role, member))
            if role in IMPERSONATE | {"roles/iam.workloadIdentityUser"} and not is_agent(member):
                if target_sa:
                    found.impersonators[target_sa[2]].append((member, role, project, resource))
                elif kind in HIERARCHY:
                    found.scope_grants.append((member, role, project, resource, kind))
            # Management class is context, never proof that IAM impersonation is impossible.
            if member.startswith("serviceAccount:") and role in ADMIN and kind in HIERARCHY:
                if is_agent(member):
                    found.counts["agent_admin"] += 1
                    found.agent_privileged[member.split(":", 1)[1]].append(
                        (role, project, resource, kind)
                    )
                else:
                    found.privileged[member.split(":", 1)[1]].append(
                        (role, project, resource, kind)
                    )
            if edge := federation(member):
                found.counts["federated_" + edge["kind"]] += 1
    return found


def cross_paths(store, run_id: str, limit: int | None = 300) -> list[dict]:
    observations = list(store.observations(run_id, provider="GCP"))
    records = org_records(observations)
    if not records:
        return []
    numbers = project_index(records)
    fallback = records[0].project_id
    stored = {f for (f,) in store.rows("SELECT finding_id FROM findings WHERE run_id=?", [run_id])}
    deny_clear = deny_status(store, run_id)

    def unverified(*projects: str) -> list[str]:
        missing = sorted({p for p in projects if p and not deny_clear.get(p)})
        return (
            [f"deny policies / access boundaries for {', '.join(missing[:5])}"] if missing else []
        )

    def finding(rule: str, project: str, resource: str) -> set[str]:
        fid = stable_id("finding", [rule, org_resource_id(project, resource)])
        return {fid} & stored

    found = classify(records, numbers, fallback)
    from offline_analyzer.rules.gcp_identity import (
        IN_SCOPE_OTHER_PROJECT,
        OUT_OF_SCOPE,
        classify_member,
        scope_from,
    )

    known = scope_from(
        [s for s in store.source_data(run_id) if s.get("format") == "gcp-json-v1"], numbers
    )

    def identity(email: str, project: str):
        return classify_member("serviceAccount:" + email, known.for_project(project, None))

    impersonators, scope_grants = found.impersonators, found.scope_grants
    privileged, public, grant_obs = found.privileged, found.public, found.grant_obs

    items: list[dict] = []
    permissions = PermissionIndex(observations, store.source_data(run_id))
    # XP-01: impersonation of privileged service accounts, one path per source grant.
    reach: dict[tuple, dict] = {}
    for email, grants in privileged.items():
        home = sa_home(email, numbers)
        sources = [(*grant, False) for grant in impersonators.get(email, [])]
        sources += [
            (m, r, p, res, kind == "cloudresourcemanager.googleapis.com/Folder")
            for m, r, p, res, kind in scope_grants
            if (kind == "cloudresourcemanager.googleapis.com/Project" and p == home)
            or kind != "cloudresourcemanager.googleapis.com/Project"
        ]
        for member, role, project, resource, via_folder in sources:
            if member == "serviceAccount:" + email:
                continue
            entry = reach.setdefault(
                (member, role, project, resource),
                {
                    "accounts": set(),
                    "targets": set(),
                    "projects": set(),
                    "folder": via_folder,
                    "findings": finding("GCP-ORG-IMPERSONATION", project, resource),
                },
            )
            entry["accounts"].add(email)
            for target_role, target_project, target_resource, _kind in grants:
                entry["targets"].add(f"{target_role} on {target_resource}")
                entry["projects"].add(target_project)
                entry["findings"] |= finding(
                    "GCP-ORG-SA-PRIVILEGED", target_project, target_resource
                )
    for (member, role, project, resource), entry in reach.items():
        accounts, targets = sorted(entry["accounts"]), sorted(entry["targets"])
        source_gap = unverified(project) + (
            ["folder ancestry of the impersonated accounts"] if entry["folder"] else []
        )
        for email in accounts:
            home = sa_home(email, numbers)
            result = permissions.evaluate(
                member,
                ACCESS_TOKEN,
                f"projects/{home or project}/serviceAccounts/{email}",
                home or project,
            )
            if result.state != "AVAILABLE":
                source_gap.append(f"{email}: getAccessToken {result.state}: {result.reason}")
        source_gap.append("control of source principal credentials and token request not verified")
        target_gap = unverified(*entry["projects"])
        account_label = f"{len(accounts)} privileged service account(s): " + ", ".join(accounts[:5])
        hops = [
            hop(
                1,
                member,
                account_label,
                "can-impersonate",
                f"{member} holds {role} on {resource}; direct access-token generation requires "
                "iam.serviceAccounts.getAccessToken. actAs alone permits workload attachment, "
                "whose deployment and execution permissions require separate evidence.",
                HYPOTHESIS if source_gap else PROVEN,
                rule_ids=["GCP-ORG-IMPERSONATION"],
                finding_ids=finding("GCP-ORG-IMPERSONATION", project, resource),
                observation_ids=[grant_obs.get((member, role, resource))]
                if grant_obs.get((member, role, resource))
                else [],
                missing=source_gap,
            ),
            hop(
                2,
                account_label,
                f"{len(targets)} privileged grant(s) in {len(entry['projects'])} scope(s)",
                "holds-role",
                "The impersonated service account(s) are members of administrative bindings ("
                + "; ".join(targets[:5])
                + "), so access flows service account → those scopes. Identities: "
                + "; ".join(
                    identity(email, next(iter(entry["projects"]), project)).text
                    for email in accounts[:5]
                )
                + ".",
                HYPOTHESIS if target_gap else PROVEN,
                rule_ids=["GCP-ORG-SA-PRIVILEGED"],
                finding_ids=entry["findings"] - finding("GCP-ORG-IMPERSONATION", project, resource),
                observation_ids=[
                    o
                    for email in accounts
                    for target_role, _p, target_resource, _k in privileged.get(email, [])
                    if (
                        o := grant_obs.get(
                            ("serviceAccount:" + email, target_role, target_resource)
                        )
                    )
                ],
                missing=target_gap,
            ),
        ]
        items.append(
            item(
                "XP-01",
                "Impersonation of privileged service accounts",
                project,
                [
                    f"{member} holds {role} on {resource}",
                    f"delegation requires verification for {len(accounts)} service account(s): "
                    + ", ".join(accounts[:5])
                    + (f" +{len(accounts) - 5} more" if len(accounts) > 5 else ""),
                    f"reaching {len(targets)} privileged grant(s) in "
                    f"{len(entry['projects'])} scope(s): "
                    + "; ".join(targets[:5])
                    + (f" +{len(targets) - 5} more" if len(targets) > 5 else ""),
                ],
                source_gap
                + unverified(project, *entry["projects"])
                + (["folder ancestry of the impersonated accounts"] if entry["folder"] else []),
                entry["findings"],
                paths=("AP-06",),
                attacker=("control of the source principal's credentials",),
                hops=hops,
                entry=member,
                objective=f"administrative roles in {len(entry['projects'])} scope(s)",
                impact="Administrative control of the reached project, folder or organization "
                "scopes.",
            )
        )
    # XP-02: service account of another project privileged here. Home and trust class come
    # from the same identity resolution as the rules (E1/E2): same-project, platform-managed
    # and unresolved identities never form an edge.
    for email, grants in [*privileged.items(), *found.agent_privileged.items()]:
        for role, project, resource, _kind in grants:
            who = identity(email, project) if project else None
            if who and who.trust in OUT_OF_SCOPE | {IN_SCOPE_OTHER_PROJECT}:
                home = who.home
                member = "serviceAccount:" + email
                xp02 = [
                    hop(
                        1,
                        f"workloads or keys of project {home}",
                        member,
                        "authenticates-as",
                        f"The service account belongs to project {home} (trust "
                        f"{who.trust}: {who.evidence}); workloads and keys there run as it, "
                        "so access flows those identities → the service account.",
                        HYPOTHESIS,
                        missing=[f"workload or key bound to {member} in {home} (not correlated)"],
                    ),
                    hop(
                        2,
                        member,
                        resource,
                        "holds-role",
                        f"{member} is a member of {role} on {resource}, so access flows "
                        f"the service account → {resource}.",
                        HYPOTHESIS if unverified(project) else PROVEN,
                        rule_ids=["GCP-ORG-CROSSPROJECT-SA"],
                        finding_ids=finding("GCP-ORG-CROSSPROJECT-SA", project, resource),
                        observation_ids=[o]
                        if (o := grant_obs.get((member, role, resource)))
                        else [],
                        missing=unverified(project),
                    ),
                ]
                items.append(
                    item(
                        "XP-02",
                        "Cross-project trust through a privileged service account",
                        project,
                        [
                            f"workloads or keys of project {home}",
                            f"run as serviceAccount:{email}",
                            f"which holds {role} on {resource}",
                        ],
                        unverified(project),
                        finding("GCP-ORG-CROSSPROJECT-SA", project, resource),
                        paths=("AP-02", "AP-06"),
                        attacker=(f"compromise of a workload or key in {home}",),
                        hops=xp02,
                        entry=f"workloads or keys of project {home}",
                        objective=f"{role} on {resource}",
                        impact="Privileged access to another project through a foreign service "
                        "account.",
                    )
                )
    # XP-03: public principal on serverless or data resources.
    ingress = serverless_ingress(observations, numbers)
    for project, resource, kind, role, member in public:
        rule = "GCP-ORG-PUBLIC-SERVERLESS" if kind in SERVERLESS else "GCP-ORG-PUBLIC-DATA"
        found = finding(rule, project, resource)
        binding_obs = [o] if (o := grant_obs.get((member, role, resource))) else []
        xp03 = []
        reached = False
        if kind in SERVERLESS and not kind.endswith("/Job"):
            state, why, observed, gap = reachability(resource, kind, ingress, numbers)
            reached = state == PROVEN
            xp03.append(
                hop(
                    1,
                    "Internet",
                    resource,
                    "network-reachable",
                    f"Internet clients connect to the service endpoint because its {why}.",
                    state,
                    rule_ids=[rule],
                    observation_ids=[x for x in observed if x],
                    missing=gap,
                )
            )
        xp03.append(
            hop(
                len(xp03) + 1,
                resource if xp03 else f"any internet client ({member})",
                f"{role} on {resource}" if xp03 else resource,
                "can-invoke-anonymously" if kind in SERVERLESS else "can-read-anonymously",
                f"{member} is granted {role} on {resource}, so requests without credentials are "
                "authorized: access flows anonymous caller → "
                + (f"{role} on the resource." if xp03 else "resource.")
                + " VPC Service Controls and organization policies are not evaluated.",
                PROVEN,
                rule_ids=[rule],
                finding_ids=found,
                observation_ids=binding_obs,
            )
        )
        items.append(
            item(
                "XP-03",
                "Unauthenticated internet access to a cloud resource",
                project,
                [f"any internet client ({member})", f"is granted {role}", f"on {resource}"],
                [],
                found,
                paths=("AP-08",) if kind in SERVERLESS else ("AP-05",),
                attacker=("network reachability of the endpoint (ingress settings not verified)",)
                if kind in SERVERLESS
                else (),
                hops=xp03,
                # The collected ingress setting replaces the reachability assumption.
                assumptions=() if reached or kind not in SERVERLESS else None,
                entry=f"Internet ({member})",
                objective=f"{role} on {resource}",
                impact="Unauthenticated invocation of the service."
                if kind in SERVERLESS
                else "Unauthenticated access to the data resource.",
            )
        )
    items += cross_cloud(
        store, records, numbers, fallback, privileged, run_id, deny_clear, grant_obs
    )
    items.sort(
        key=lambda p: (p["feasibility"] != FEASIBLE, p["attack_path"], p["project_id"] or "")
    )
    return items[:limit]


def aws_roles(store) -> dict[str, list[dict]]:
    """Role name -> [{account, arn, trust}] across every imported AWS run in the workspace."""
    found: dict[str, list[dict]] = defaultdict(list)
    for observation_id, data in store.rows(
        "SELECT observation_id,data FROM observations WHERE kind='AWS::IAM::Role'"
    ):
        obs = json.loads(data)
        config = obs.get("configuration") or {}
        name = config.get("RoleName") or str(obs.get("native_id", "")).rsplit("/", 1)[-1]
        if name:
            found[name].append(
                {
                    "account": obs.get("account_id"),
                    "arn": config.get("Arn") or obs.get("native_id"),
                    "trust": config.get("AssumeRolePolicyDocument"),
                    "observation_id": observation_id,
                }
            )
    return found


def trust_statements(document) -> list[dict]:
    from offline_analyzer.rules.iam_trust import statement_list

    return statement_list(document) or []


def unverified_projects(grants, deny_clear) -> list[str]:
    missing = sorted({p for _r, p, _res, _k in grants if p and not deny_clear.get(p)})
    return [f"deny policies / access boundaries for {', '.join(missing[:5])}"] if missing else []


def cross_cloud(
    store, records, numbers, fallback, privileged, run_id, deny_clear=None, grant_obs=None
) -> list[dict]:
    deny_clear, grant_obs = deny_clear or {}, grant_obs or {}
    roles = aws_roles(store)
    imported = {
        a
        for (a,) in store.rows("SELECT DISTINCT account_id FROM observations WHERE tool<>'gcp'")
        if a
    }
    items = []
    # XC-01: AWS role -> GCP workload identity pool -> service account.
    for obs in records:
        config = obs.configuration
        target = SA_RESOURCE.search(config.get("resource", ""))
        if not target:
            continue
        email, project = target[2], scope_of(config, numbers, fallback)["project_id"]
        for role, member, _conditional in bindings(config):
            edge = federation(member)
            if not edge or edge["kind"] != "AWS":
                continue
            name = edge["aws_role"] or edge["value"].rsplit("/", 1)[-1]
            matches = [
                r
                for r in roles.get(name, [])
                if not edge["aws_account"] or r["account"] == edge["aws_account"]
            ]
            unresolved = ["workload identity pool provider attribute conditions"]
            if edge["aws_account"] and edge["aws_account"] not in imported:
                unresolved.append(f"AWS account {edge['aws_account']} evidence not imported")
            elif not matches:
                unresolved.append(f"AWS role {name} not found in imported AWS evidence")
            reach = [f"{r} on {res}" for r, _p, res, _k in privileged.get(email, [])][:5]
            steps = [
                f"AWS principals able to assume role {name}"
                + (f" in account {edge['aws_account']}" if edge["aws_account"] else ""),
                f"federate through pool {edge['pool']} ({edge['attribute']})",
                f"obtain {role} on serviceAccount:{email}",
                "which holds " + (", ".join(reach) if reach else "no observed admin role"),
            ]
            xc01 = [
                hop(
                    1,
                    steps[0],
                    f"AWS role {name}",
                    "can-assume",
                    f"The trust policy of AWS role {name} admits these principals, so access "
                    "flows trusted AWS principal → role.",
                    PROVEN if matches else HYPOTHESIS,
                    observation_ids=[m["observation_id"] for m in matches],
                    missing=[] if matches else unresolved[1:],
                ),
                hop(
                    2,
                    f"AWS role {name}",
                    f"serviceAccount:{email}",
                    "federates-as",
                    f"Pool {edge['pool']} maps the AWS role ({edge['attribute']}) to a principal "
                    f"granted {role} on the service account, so access flows AWS role → GCP "
                    "service account.",
                    HYPOTHESIS,
                    rule_ids=["GCP-ORG-FEDERATION"],
                    observation_ids=[obs.observation_id],
                    missing=["workload identity pool provider attribute conditions"],
                ),
            ]
            if reach:
                xc01.append(
                    hop(
                        3,
                        f"serviceAccount:{email}",
                        "; ".join(reach),
                        "holds-role",
                        "The service account is a member of administrative bindings, so access "
                        "flows service account → those scopes.",
                        HYPOTHESIS
                        if unverified_projects(privileged.get(email, []), deny_clear)
                        else PROVEN,
                        rule_ids=["GCP-ORG-SA-PRIVILEGED"],
                        observation_ids=[
                            grant_obs.get(("serviceAccount:" + email, r, res))
                            for r, _p, res, _k in privileged.get(email, [])
                        ],
                        missing=unverified_projects(privileged.get(email, []), deny_clear),
                    )
                )
            if matches:
                trusted = sorted(
                    {
                        json.dumps(s.get("Principal"), sort_keys=True)[:160]
                        for m in matches
                        for s in trust_statements(m["trust"])
                        if s.get("Effect") == "Allow"
                    }
                )
                steps.insert(
                    1, "AWS role trust principals: " + ("; ".join(trusted) or "none parsed")
                )
            items.append(
                item(
                    "XC-01",
                    "AWS identity can act as a GCP service account",
                    project,
                    steps,
                    unresolved,
                    set(),
                    provider="AWS→GCP",
                    aws=edge["aws_account"] or (matches[0]["account"] if matches else None),
                    paths=("AP-06", "AP-27"),
                    attacker=("control of a principal trusted by the AWS role",),
                    hops=xc01,
                    entry=steps[0],
                    objective=f"serviceAccount:{email}",
                    impact="A cloud identity in AWS acts in GCP as the service account.",
                )
            )
    # XC-02: AWS roles that trust Google identities (accounts.google.com).
    for entries in roles.values():
        for entry in entries:
            for statement in trust_statements(entry["trust"]):
                principal = json.dumps(statement.get("Principal", ""))
                if statement.get("Effect") != "Allow" or "accounts.google.com" not in principal:
                    continue
                condition = statement.get("Condition") or {}
                bound = "accounts.google.com:sub" in json.dumps(condition) or (
                    "accounts.google.com:oaud" in json.dumps(condition)
                )
                if bound:
                    continue  # trust bound to a specific Google identity is the intended edge
                items.append(
                    item(
                        "XC-02",
                        "Google identity can assume an AWS role",
                        fallback,
                        [
                            "Google-issued identity token",
                            f"assumes AWS role {entry['arn']}",
                            "conditions: " + (json.dumps(condition)[:200] or "none"),
                        ],
                        [],
                        set(),
                        provider="GCP→AWS",
                        aws=entry["account"],
                        paths=("AP-06", "AP-27"),
                        attacker=("any Google-issued identity token (no sub/oaud binding)",),
                        hops=[
                            hop(
                                1,
                                "Google-issued identity token",
                                f"AWS role {entry['arn']}",
                                "can-assume",
                                "The role trusts accounts.google.com without a sub or oaud "
                                "condition, so any Google identity token flows into the role.",
                                PROVEN,
                                observation_ids=[entry["observation_id"]],
                            )
                        ],
                        entry="Google-issued identity token",
                        objective=f"AWS role {entry['arn']}",
                        impact="Any Google identity assumes the AWS role.",
                    )
                )
    return items
