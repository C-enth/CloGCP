"""Evidence-driven GCP discovery, independent of finding generation and UI state."""

import re
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import islice
from time import perf_counter

from offline_analyzer.contracts.gcp_attack_path import (
    Condition,
    DiscoveryLimits,
    GCPAttackPathRegister,
    GCPPathEvaluation,
    classify,
)
from offline_analyzer.contracts.r0 import Candidate, Normalized, stable_id
from offline_analyzer.iam.gcp_permissions import (
    ACCESS_TOKEN,
    ACT_AS,
    AUTH_MECHANISMS,
    WORKLOAD_MECHANISMS,
    PermissionIndex,
    canonical,
)
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.gcp_identity import account_class

VERSION = "2.0.1"
LIMITATIONS = [
    "Configuration support is not successful exploitation. Execution "
    "is never verified automatically.",
    "No comprehensive network reachability, group expansion, CEL, "
    "PAB, federation or service-agent simulation.",
    "Unknown predefined permissions require collected role details or "
    "a reviewed permission projection.",
    "Project-only deny/PAB exports do not establish absence of inherited restrictions.",
    "Workload creation requires image, network, service-agent and "
    "organization-policy context not fully collected.",
    "Legacy statuses are retained as history; PROVEN is never a basis for SUPPORTED.",
]


def condition(name: str, state: str, reason: str, *ids: str) -> Condition:
    return Condition(
        name=name, state=state, reason=reason, observation_ids=sorted({i for i in ids if i})
    )


def _discover_identities(
    observations: list[Normalized],
    index: PermissionIndex,
    limits: DiscoveryLimits,
    truncated: list[str],
    paths: dict[str, GCPPathEvaluation],
    emit: Callable[..., None],
) -> None:
    # Exact service-account resource references; never infer an account is immune because
    # Google manages it. Actual permissions and service-specific restrictions decide.
    accounts = {}
    account_observations = defaultdict(list)
    credentials_services = defaultdict(list)
    for o in observations:
        if (
            o.resource_type == "GCP::Service"
            and (o.configuration.get("config") or {}).get("name") == "iamcredentials.googleapis.com"
        ):
            credentials_services[o.project_id].append(o)
        if o.resource_type == "GCP::ServiceAccount":
            email = (
                o.configuration.get("email") or (o.native_id or "").split("/serviceAccounts/")[-1]
            )
            if "@" in email:
                accounts[email] = (o.project_id, f"projects/{o.project_id}/serviceAccounts/{email}")
                account_observations[email].append(o)
    for g in index.grants:
        member_identity = account_class(g.member, index.identity_scope.for_project(g.project, None))
        if member_identity and member_identity.owner_project_id in index.identity_scope.collected:
            email = g.member.split(":", 1)[1]
            home = member_identity.owner_project_id
            accounts.setdefault(email, (home, f"projects/{home}/serviceAccounts/{email}"))
        if "/serviceAccounts/" in g.resource:
            email = g.resource.split("/serviceAccounts/", 1)[1]
            project = g.resource.split("/")[1]
            if project != "-":
                accounts.setdefault(email, (project, g.resource))
    # Bound fan-out before joins. Queue entries carry individual technical chains.
    combinations = 0
    for principal in sorted(index.by_member):
        if combinations >= limits.max_bindings:
            break
        queue = deque([(principal, [], [], {principal}, "")])
        expanded = 0
        while queue and len(paths) < limits.max_candidates:
            actor, preceding, relations, visited, originating_root = queue.popleft()
            expanded += 1
            if expanded > limits.max_candidates:
                truncated.append("identity traversal limit reached")
                break
            for email, (project, resource) in sorted(accounts.items()):
                combinations += 1
                if combinations > limits.max_bindings:
                    truncated.append("identity comparison limit reached (max_bindings)")
                    queue.clear()
                    break
                if actor == "serviceAccount:" + email:
                    continue
                for mechanism, permission in AUTH_MECHANISMS.items():
                    result = index.evaluate(actor, permission, resource, project)
                    if result.allow_state not in {"AVAILABLE", "CONDITIONAL"}:
                        continue
                    conditions = [
                        *preceding,
                        Condition.model_validate(
                            result.model_dump(include=set(Condition.model_fields))
                        ),
                    ]
                    if permission != ACT_AS:
                        targets = account_observations.get(email, [])
                        states = {a.configuration.get("disabled") for a in targets}
                        disabled = next(iter(states)) if len(states) == 1 else None
                        conditions.append(
                            condition(
                                "active target service account",
                                "CONTRADICTED"
                                if disabled is True
                                else "AVAILABLE"
                                if disabled is False
                                else "UNCOLLECTED",
                                "account disabled"
                                if disabled is True
                                else "enabled account observed"
                                if disabled is False
                                else "account enabled state not collected",
                                *(a.observation_id for a in targets),
                            )
                        )
                        observed_services = credentials_services.get(project, [])
                        api = (
                            observed_services
                            if observed_services
                            and all(
                                o.configuration.get("state") == "ENABLED" for o in observed_services
                            )
                            else []
                        )
                        conditions.append(
                            condition(
                                "IAM Credentials service availability",
                                "AVAILABLE" if api else "UNCOLLECTED",
                                "enabled IAM Credentials service observed"
                                if api
                                else "API enablement and service usage context not collected",
                                *(o.observation_id for o in api),
                            )
                        )
                    relation = f"{actor} has an observed allow for {permission} on {resource}"
                    grant_scopes = sorted(
                        {
                            g.resource
                            for g in index.by_member.get(actor, [])
                            if index.scope(g, resource, project)
                            and index.role_permission(g.role, permission)[0] == "AVAILABLE"
                        }
                    )
                    root = originating_root or (
                        f"Delegation grant to {principal} at {', '.join(grant_scopes)}"
                    )
                    if permission == ACT_AS:
                        for workload, permissions in WORKLOAD_MECHANISMS.items():
                            checks = [
                                index.evaluate(actor, p, f"projects/{project}", project)
                                for p in permissions
                            ]
                            # Keep attachment and execution as one typed prerequisite each;
                            # the reasons preserve every individual required permission.
                            workload_state = classify(
                                [
                                    Condition.model_validate(
                                        p.model_dump(include=set(Condition.model_fields))
                                    )
                                    for p in checks
                                ]
                            )
                            mapping = {
                                "SUPPORTED": "AVAILABLE",
                                "CONDITIONAL": "CONDITIONAL",
                                "BLOCKED": "CONTRADICTED",
                                "UNSUPPORTED": "UNSUPPORTED",
                                "INSUFFICIENT_EVIDENCE": "UNCOLLECTED",
                            }
                            cfg = condition(
                                workload,
                                mapping[workload_state],
                                "; ".join(p.name + ": " + p.reason for p in checks),
                                *(oid for p in checks for oid in p.observation_ids),
                            )
                            emit(
                                "workload-identity",
                                project,
                                principal,
                                resource,
                                email,
                                workload,
                                root,
                                [
                                    *conditions,
                                    cfg,
                                    condition(
                                        "workload service prerequisites",
                                        "UNCOLLECTED",
                                        "image access, resource scopes, service "
                                        "agents, org policies "
                                        "and workload execution configuration require verification",
                                    ),
                                ],
                                [*relations, relation],
                                "Code execution under the attached identity.",
                                "Remove unnecessary actAs and workload deployment permissions.",
                                [
                                    "Control of source principal credentials",
                                    "Attacker-controlled workload execution",
                                ],
                            )
                        # Explicitly retain the unsupported direct-token interpretation.
                        emit(
                            "service-account-identity",
                            project,
                            principal,
                            resource,
                            email,
                            "actAs-only-direct-token",
                            root,
                            [
                                *conditions,
                                condition(
                                    "direct access-token generation",
                                    "UNSUPPORTED",
                                    "actAs does not grant getAccessToken; workload execution is a "
                                    "separate mechanism",
                                ),
                            ],
                            [*relations, relation],
                            "Workload delegation only; direct token access is not established.",
                            "Review actAs with the specific workload execution permissions.",
                        )
                        continue
                    emit(
                        "service-account-identity",
                        project,
                        principal,
                        resource,
                        email,
                        mechanism if not preceding else "identity-chain/" + mechanism,
                        root,
                        conditions,
                        [*relations, relation],
                        "Use of this identity's separately authorized permissions or "
                        "signed assertions.",
                        "Restrict delegation to required principals and target service accounts.",
                        [
                            "Control of source principal credentials",
                            "Successful token/signing request not verified",
                        ],
                    )
                    next_actor = "serviceAccount:" + email
                    if permission == ACCESS_TOKEN:
                        for grant in index.by_member.get(next_actor, []):
                            emit(
                                "cross-project-identity"
                                if grant.project != project
                                else "identity-privilege",
                                project,
                                principal,
                                grant.resource,
                                email,
                                "access-token/role-scope",
                                root,
                                [
                                    *conditions,
                                    condition(
                                        "target role binding",
                                        "CONDITIONAL" if grant.conditional else "AVAILABLE",
                                        f"observed {grant.role} on {grant.resource}",
                                        grant.observation_id,
                                    ),
                                    condition(
                                        "target effective permissions",
                                        "UNCOLLECTED",
                                        "role permissions, resource restrictions and "
                                        "target deny/PAB "
                                        "context require separate evaluation",
                                    ),
                                ],
                                [
                                    *relations,
                                    relation,
                                    f"{next_actor} holds {grant.role} on {grant.resource}",
                                ],
                                "Potential permissions in the target binding scope.",
                                "Restrict source delegation and minimize target identity grants.",
                                ["Control of source credentials", "Successful token request"],
                            )
                    if permission == ACCESS_TOKEN and next_actor not in visited:
                        if len(conditions) < limits.max_depth:
                            queue.append(
                                (
                                    next_actor,
                                    conditions,
                                    [*relations, relation],
                                    visited | {next_actor},
                                    root,
                                )
                            )
                        elif "depth limit reached; chains omitted" not in truncated:
                            truncated.append("depth limit reached; chains omitted")


def _discover_data(
    observations: list[Normalized], index: PermissionIndex, emit: Callable[..., None]
) -> None:
    public_access_blockers = defaultdict(list)
    for o in observations:
        if (
            o.resource_type == "GCP::Bucket"
            and (o.configuration.get("iamConfiguration") or {}).get("publicAccessPrevention")
            == "enforced"
        ):
            public_access_blockers[
                (o.project_id, canonical(o.native_id or "", index.numbers))
            ].append(o)
    # Public data and invocation are actual role-permission questions, not role-name
    # 'Admin' heuristics. allAuthenticatedUsers always requires an authenticated identity.
    for g in index.grants:
        permissions = (
            "run.routes.invoke",
            "cloudfunctions.functions.invoke",
            "storage.objects.get",
            "bigquery.tables.getData",
        )
        for permission in permissions:
            supported, _ = index.role_permission(g.role, permission)
            if supported != "AVAILABLE":
                continue
            public = g.member in {"allUsers", "allAuthenticatedUsers"}
            result = index.evaluate(g.member, permission, g.resource, g.project)
            checks = [
                Condition.model_validate(result.model_dump(include=set(Condition.model_fields)))
            ]
            if g.member == "allAuthenticatedUsers":
                checks.append(
                    condition(
                        "authenticated Google identity",
                        "UNCOLLECTED",
                        "allAuthenticatedUsers is not anonymous access",
                    )
                )
            blockers = public_access_blockers.get((g.project, g.resource), []) if public else []
            checks.append(
                condition(
                    "service-specific access controls",
                    "CONTRADICTED" if blockers else "UNCOLLECTED",
                    "public access prevention enforced"
                    if blockers
                    else "resource configuration, service perimeter and organization "
                    "restrictions unresolved",
                    *(o.observation_id for o in blockers),
                )
            )
            emit(
                "public-data" if public else "identity-data",
                g.project,
                g.member,
                g.resource,
                g.member,
                permission,
                f"Access grant {permission} on {g.resource}",
                checks,
                [f"{g.member} is bound to {g.role} on {g.resource}"],
                "Potential resource invocation or data read within the granted scope.",
                "Remove unnecessary public or broad data/invocation grants.",
                [] if g.member == "allUsers" else ["Control of the authorized identity"],
            )


def _discover_workloads(
    observations: list[Normalized], index: PermissionIndex, emit: Callable[..., None]
) -> None:
    network_denies = defaultdict(list)
    for firewall in observations:
        config = firewall.configuration
        if firewall.resource_type == "GCP::Firewall" and config.get("denied"):
            if (
                config.get("direction") == "INGRESS"
                and not config.get("disabled")
                and "0.0.0.0/0" in (config.get("sourceRanges") or [])
            ):
                network_denies[
                    (firewall.project_id, canonical(config.get("network", ""), index.numbers))
                ].append(firewall)
    for o in observations:
        c, kind = o.configuration, o.resource_type
        resource = canonical(o.native_id or "", index.numbers)
        if not resource:
            continue
        identities = []
        checks = [
            condition(
                "observed workload",
                "AVAILABLE",
                "normalized workload configuration",
                o.observation_id,
            )
        ]
        if kind == "GCP::ComputeInstance":
            interfaces = c.get("networkInterfaces")
            public = isinstance(interfaces, list) and any(
                a.get("natIP") or a.get("externalIpv6")
                for n in interfaces
                for a in [*n.get("accessConfigs", []), *n.get("ipv6AccessConfigs", [])]
            )
            checks.append(
                condition(
                    "direct public VM address",
                    "AVAILABLE" if public else "UNCOLLECTED",
                    "public address observed" if public else "public addressing not established",
                    o.observation_id if public else "",
                )
            )
            # VPC denies are potential blockers: hierarchical policies/priority may override.
            networks = {canonical(n.get("network", ""), index.numbers) for n in interfaces or []}
            tags = set((c.get("tags") or {}).get("items") or [])
            attached = {s.get("email") for s in c.get("serviceAccounts") or []}
            denies = [
                f
                for network in networks
                for f in network_denies.get((o.project_id, network), [])
                if (
                    not f.configuration.get("targetTags")
                    or tags.intersection(f.configuration["targetTags"])
                )
                and (
                    not f.configuration.get("targetServiceAccounts")
                    or attached.intersection(f.configuration["targetServiceAccounts"])
                )
            ]
            checks.append(
                condition(
                    "network path and active listener",
                    "UNCOLLECTED",
                    "routes, firewall priority/targets, hierarchical policy and listener unresolved"
                    + ("; collected VPC deny rules are potential blockers" if denies else ""),
                    *(d.observation_id for d in denies),
                )
            )
            identities = [s.get("email") for s in c.get("serviceAccounts", []) if s.get("email")]
            family = "public-vm-identity"
        elif kind in {"GCP::RunService", "GCP::Function"}:
            spec = c.get("spec") or {}
            template = spec.get("template") or c.get("template") or {}
            tspec = template.get("spec") or template
            service = c.get("serviceConfig") or {}
            sa = (
                tspec.get("serviceAccountName")
                or tspec.get("serviceAccount")
                or service.get("serviceAccountEmail")
                or c.get("serviceAccountEmail")
            )
            identities = [sa] if sa else []
            ingress = (
                c.get("ingress")
                or c.get("ingressSettings")
                or service.get("ingressSettings")
                or ((c.get("metadata") or {}).get("annotations") or {}).get(
                    "run.googleapis.com/ingress"
                )
            )
            closed = ingress in {"INGRESS_TRAFFIC_INTERNAL_ONLY", "internal", "ALLOW_INTERNAL_ONLY"}
            checks.append(
                condition(
                    "direct internet ingress",
                    "CONTRADICTED" if closed else "UNCOLLECTED",
                    "internal-only ingress blocks direct internet endpoint"
                    if closed
                    else "ingress and external frontends require verification",
                    o.observation_id,
                )
            )
            perm = (
                "run.routes.invoke"
                if kind == "GCP::RunService"
                else "cloudfunctions.functions.invoke"
            )
            p = index.evaluate("allUsers", perm, resource, o.project_id)
            checks.append(
                Condition.model_validate(p.model_dump(include=set(Condition.model_fields)))
            )
            family = "public-serverless-identity"
        elif kind in {"GCP::GKECluster", "GCP::GKENodePool"}:
            sa = (c.get("nodeConfig") or c.get("config") or {}).get("serviceAccount")
            identities = [sa] if sa and sa != "default" else []
            checks.append(
                condition(
                    "GKE control plane / workload identity authorization",
                    "UNCOLLECTED",
                    "endpoint authorization, Kubernetes RBAC, KSA annotation and "
                    "federation mapping unresolved",
                )
            )
            family = "gke-identity"
        else:
            continue
        checks.append(
            condition(
                "application or workload compromise",
                "UNCOLLECTED",
                "configuration relationships do not establish attacker code execution",
            )
        )
        for email in identities or [""]:
            grants = index.by_member.get("serviceAccount:" + email, [])
            for grant in grants or [None]:
                extra = condition(
                    "runtime identity permissions",
                    "UNCOLLECTED",
                    "effective identity authorization and service-specific restrictions unresolved",
                    grant.observation_id if grant else "",
                )
                emit(
                    family,
                    o.project_id,
                    resource,
                    grant.resource if grant else "unresolved identity scope",
                    email,
                    "workload-compromise",
                    "Workload entry and identity permissions at " + resource,
                    [*checks, extra],
                    [f"{resource} references runtime identity {email or 'not collected'}"]
                    + ([f"{email} has observed {grant.role} on {grant.resource}"] if grant else []),
                    "Potential use of runtime identity permissions after workload compromise.",
                    "Restrict ingress/invocation, harden workloads and minimize "
                    "runtime identity permissions.",
                    ["Successful workload compromise", "Runtime token possession"],
                )


def discover(
    observations: list[Normalized],
    sources: list[dict],
    *,
    run_id: str,
    findings: list[Candidate] | None = None,
    legacy_paths: list[dict] | None = None,
    limits: DiscoveryLimits | None = None,
) -> GCPAttackPathRegister:
    start = perf_counter()
    limits = limits or DiscoveryLimits()
    sources = list(sources)
    truncated = []
    if len(observations) > limits.max_nodes:
        truncated.append("node limit reached; omitted resources and authorization context")
    observations = observations[: limits.max_nodes]
    index = PermissionIndex(observations, sources, limits.max_bindings)
    if index.truncated:
        truncated.append("binding limit reached")
    by_id = {o.observation_id: o for o in observations}
    by_artifact = {s.get("artifact_id"): s for s in sources}
    paths: dict[str, GCPPathEvaluation] = {}
    findings = findings or []
    legacy_paths = legacy_paths or []
    if len(legacy_paths) > limits.max_candidates:
        raise InputError("LEGACY_PATH_COMPARISON_LIMIT")

    def emit(
        family,
        project,
        entry,
        target,
        identity,
        mechanism,
        root,
        conditions,
        relationships,
        impact,
        remediation,
        exploitation=(),
    ):
        if len(conditions) > limits.max_depth:
            if "depth limit reached; chains omitted" not in truncated:
                truncated.append("depth limit reached; chains omitted")
            return
        key = stable_id(
            "gcp-chain", [project, entry, target, identity, mechanism, root, relationships]
        )
        if key in paths:
            return
        if len(paths) >= limits.max_candidates:
            if "candidate limit reached" not in truncated:
                truncated.append("candidate limit reached")
            return
        # A truncated inventory cannot establish full configuration support.
        if any(
            (s.get("gcp_metadata") or {}).get("composition", {}).get("temporally_mixed")
            for s in sources
        ):
            # An older blocker remains evidence, but cannot establish that a route
            # was blocked when the supplementary grant/configuration was collected.
            conditions = [
                c.model_copy(
                    update={
                        "state": "UNCOLLECTED",
                        "reason": "Historical blocking evidence; concurrent applicability is "
                        "unverified across collection dates. " + c.reason,
                    }
                )
                if c.state == "CONTRADICTED"
                else c
                for c in conditions
            ]
            conditions = [
                *conditions,
                condition(
                    "temporal coherence",
                    "UNCOLLECTED",
                    (
                        "Evidence composition retains separate collection dates; concurrent "
                        "prerequisites are not established."
                    ),
                ),
            ]
        if truncated and all(c.state == "AVAILABLE" for c in conditions):
            conditions = [
                *conditions,
                condition("complete discovery", "UNCOLLECTED", "discovery budget reached"),
            ]
        oids = {oid for c in conditions for oid in c.observation_ids}
        resources = {by_id[oid].resource_id for oid in oids if oid in by_id}
        fids = sorted({f.finding_id for f in findings if f.resource_id in resources})
        provenance = []
        for oid in sorted(oids):
            if oid not in by_id:
                continue
            ref = by_id[oid].evidence.model_dump(mode="json")
            source = by_artifact.get(ref.get("artifact_id"), {})
            provenance.append(
                {
                    "observation_id": oid,
                    **ref,
                    "source_sha256": source.get("sha256") or by_id[oid].integrity_sha256,
                    "collection_coverage": source.get("effective_coverage", "UNKNOWN"),
                    "collected_at": source.get("collected_at")
                    or (by_id[oid].collected_at.isoformat() if by_id[oid].collected_at else None),
                }
            )
        state = classify(conditions)
        previous = []
        for old in legacy_paths:
            old_oids = {oid for h in old.get("hops", []) for oid in h.get("observation_ids", [])}
            # Evidence overlap alone is not identity: require exact entry and target identity.
            old_text = " ".join(old.get("steps", []))
            if (
                old.get("entry_point") == entry
                and old.get("project_id", project) == project
                and identity
                and identity in set(re.findall(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+", old_text))
                and old_oids.intersection(oids)
            ):
                previous.append(
                    {
                        "path_id": old["path_id"],
                        "prior_status": old.get("proof_status", old.get("status", "UNKNOWN")),
                        "prior_feasibility": old.get("feasibility"),
                        "reconciliation": "configuration chain split by canonical identity and "
                        "mechanism",
                        "reason": "Recomputed permission and mandatory prerequisite semantics; "
                        "legacy approval and proof labels are not inherited.",
                    }
                )
        paths[key] = GCPPathEvaluation(
            path_id=stable_id("gcp-path-v2", [key, VERSION]),
            canonical_key=key,
            root_cause_id=stable_id("gcp-root", [project, entry, root]),
            family=family,
            project_id=project,
            root_security_gap=root,
            entry_point=entry,
            target=target,
            identity=identity,
            mechanism=mechanism,
            relationships=relationships,
            prerequisites=conditions,
            classification=state,
            exploitation_requirements=list(exploitation),
            potential_impact=impact,
            severity="HIGH"
            if any(
                role in relationship
                for relationship in relationships
                for role in ("roles/owner", "roles/editor")
            )
            else "MEDIUM",
            severity_rationale=(
                "Collected administrative binding indicates potentially high technical impact "
                "if the unresolved attack prerequisites are met."
                if any(
                    role in relationship
                    for relationship in relationships
                    for role in ("roles/owner", "roles/editor")
                )
                else "Observed delegation, invocation or data relationship; downstream privilege, "
                "access scope and data sensitivity remain unresolved."
            ),
            evidence_provenance=provenance,
            original_finding_ids=fids,
            legacy_paths=previous,
            recommended_remediation=remediation,
            remaining_verification=[
                c.name + ": " + c.reason for c in conditions if c.state != "AVAILABLE"
            ]
            + list(exploitation),
        )

    _discover_identities(observations, index, limits, truncated, paths, emit)
    _discover_data(observations, index, emit)
    _discover_workloads(observations, index, emit)
    if index.truncated:
        truncated.append("binding or permission evaluation budget reached")

    if len(paths) >= limits.max_candidates:
        truncated.append("candidate limit reached; discovery may be incomplete")
    if truncated:
        for key, path in paths.items():
            if path.classification == "SUPPORTED":
                data = path.model_dump()
                data["prerequisites"].append(
                    condition(
                        "complete discovery", "UNCOLLECTED", "discovery budget reached"
                    ).model_dump()
                )
                data["classification"] = "INSUFFICIENT_EVIDENCE"
                data["remaining_verification"].append("Complete discovery within raised limits")
                paths[key] = GCPPathEvaluation.model_validate(data)
    groups = defaultdict(list)
    for path in paths.values():
        groups[path.root_cause_id].append(path.path_id)
    return GCPAttackPathRegister(
        run_id=run_id,
        evaluated_at=datetime.now(UTC),
        paths=list(paths.values()),
        active_path_ids=[p.path_id for p in paths.values() if p.classification != "BLOCKED"],
        root_cause_groups=dict(groups),
        limits=limits,
        truncated=bool(truncated),
        truncation_reasons=sorted(set(truncated)),
        elapsed_seconds=perf_counter() - start,
        visited_nodes=len(observations),
        inspected_bindings=len(index.grants),
        limitations=LIMITATIONS,
    )


def evaluate(
    store,
    run_id: str,
    *,
    limits: DiscoveryLimits | None = None,
    legacy_paths: list[dict] | None = None,
) -> GCPAttackPathRegister:
    store.require_run(run_id)
    limits = limits or DiscoveryLimits()
    return discover(
        list(islice(store.observations(run_id, provider="GCP"), limits.max_nodes + 1)),
        list(store.source_data(run_id)),
        run_id=run_id,
        findings=list(store.candidates(run_id)),
        limits=limits,
        legacy_paths=legacy_paths,
    )
