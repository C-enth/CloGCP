"""Per-principal GCP role lookup over collected evidence (analyzer only, no effective IAM).

For one principal (service account, user or group) every allow binding found in the
collected evidence of the imported projects is listed: role, scope (project, service
account, bucket, folder, organization or other resource), condition, source dataset, and for
service accounts the ownership class (PLATFORM_AGENT, DEFAULT_SA, USER_MANAGED), owner project
and trust class relative to the binding's project (rules/gcp_identity.account_class).
Groups are listed as groups; group membership is never collected, so no member is inferred
and a user's access through groups is never attributed to the user.

Resolution status (per project, and for the principal over every project in view):
RESOLVED only when the project's IAM policy was collected AND every parent (folder /
organization) IAM policy was collected. Parent IAM that is denied or missing, or a project
under a parent whose IAM was not collected, gives "project-level roles only; inherited roles
not collected" and UNRESOLVED. A project with no parent recorded anywhere is UNRESOLVED with
the separate reason NO_PARENT_RECORDED: a missing `parent` field is not proof of a standalone
project. Rules use it only through rules/gcp_principal_context.py (E5, opt-in), built over
the assessed run alone. A custom
role without collected detail (custom_role_detail) is UNRESOLVED as well. Privilege summary
for severity decisions: PRIVILEGED on positive evidence of a privileged role; NARROW only when
RESOLVED and every role is a classified, non-privileged predefined role; NONE_OBSERVED when
RESOLVED with no binding; otherwise UNRESOLVED (never NARROW).

Privileged predefined roles (the single documented list, `privileged()`): roles/owner,
roles/editor, every role whose name ends in "admin" or "Admin" (optionally followed by a
.vN suffix, e.g. roles/compute.instanceAdmin.v1, roles/iam.securityAdmin),
roles/iam.serviceAccountTokenCreator, roles/iam.serviceAccountUser,
roles/iam.serviceAccountKeyAdmin and the IAM escalation roles in IAM_ESCALATION. Custom-role
permissions are shown but not classified.
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from types import SimpleNamespace

from offline_analyzer.rules.gcp_identity import Scope, account_class

IAM_ESCALATION = frozenset(
    {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.serviceAccountOpenIdTokenCreator",
        "roles/iam.workloadIdentityUser",
        "roles/iam.roleAdmin",
        "roles/iam.organizationRoleAdmin",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
        "roles/resourcemanager.projectIamAdmin",
        "roles/resourcemanager.folderIamAdmin",
        "roles/resourcemanager.organizationAdmin",
    }
)
PRIVILEGED_ROLES = frozenset({"roles/owner", "roles/editor"}) | IAM_ESCALATION
ADMIN_ROLE = re.compile(r"roles/[A-Za-z0-9_.]*[Aa]dmin(?:\.v[0-9]+)?")


def privileged(role: str) -> bool:
    return role in PRIVILEGED_ROLES or bool(ADMIN_ROLE.fullmatch(role))


KINDS = (
    "GCP::IAMBinding",
    "GCP::AssetIAMSearchResult",
    "GCP::CustomRole",
    "GCP::Project",
    "GCP::Folder",
)
POLICY_OPERATIONS = {
    "gcp:projects.getIamPolicy",
    "gcp:folders.getIamPolicy",
    "gcp:organizations.getIamPolicy",
}
USABLE = {"COMPLETE", "PARTIAL"}
INHERITED_GAP = "project-level roles only; inherited roles not collected"
NO_PARENT_RECORDED = "no parent recorded — verify standalone project"
MEMBER = re.compile(
    r"(serviceAccount|user|group|domain|deleted:serviceAccount|deleted:user|deleted:group):.+"
)
CUSTOM_ROLE = re.compile(r"(?:projects/[^/]+|organizations/\d+)/roles/[^/]+")


def candidates(principal: str) -> list[str]:
    """Member strings a principal may appear as; a bare email is matched in every form."""
    principal = principal.strip()
    if MEMBER.fullmatch(principal) or principal in {"allUsers", "allAuthenticatedUsers"}:
        return [principal]
    if "@" in principal:
        return [f"{kind}:{principal}" for kind in ("serviceAccount", "user", "group")]
    return [principal]


def base_member(member: str) -> str:
    return member.split("?", 1)[0]


def scope_kind(subject: str, asset_type: str = "") -> str:
    if re.fullmatch(r"projects/[^/]+", subject) or asset_type.endswith("/Project"):
        return "project"
    if "/serviceAccounts/" in subject or asset_type == "iam.googleapis.com/ServiceAccount":
        return "service account"
    if subject.startswith("buckets/") or asset_type == "storage.googleapis.com/Bucket":
        return "bucket"
    if re.fullmatch(r"folders/\d+", subject) or asset_type.endswith("/Folder"):
        return "folder"
    if re.fullmatch(r"organizations/\d+", subject) or asset_type.endswith("/Organization"):
        return "organization"
    return "other"


def parent_name(value) -> str | None:
    """Parent from a project/folder record: v3 'folders/N' or v1 {'type','id'}."""
    if isinstance(value, str) and re.fullmatch(r"(?:folders|organizations)/\d+", value):
        return value
    if isinstance(value, dict) and value.get("type") in {"folder", "organization"}:
        if re.fullmatch(r"\d+", str(value.get("id", ""))):
            return f"{value['type']}s/{value['id']}"
    return None


@dataclass
class Index:
    bindings: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    custom_roles: dict[str, dict] = field(default_factory=dict)  # role name -> detail
    projects: dict[str, dict] = field(default_factory=dict)  # project ID -> status
    scope: Scope = field(default_factory=lambda: Scope(None, None))
    runs: tuple[str, ...] = ()

    def lookup(self, principal: str) -> dict:
        forms = candidates(principal)
        found = [b for form in forms for b in self.bindings.get(form, [])]
        members = sorted({b["member"] for b in found}) or forms
        rows = []
        for binding in sorted(
            found, key=lambda b: (b["project_id"] or "", b["scope"], b["role"], b["resource"])
        ):
            rows.append({**binding, **self.role_info(binding["role"])})
        status = (
            "RESOLVED"
            if self.projects and all(p["status"] == "RESOLVED" for p in self.projects.values())
            else "UNRESOLVED"
        )
        unresolved_roles = sorted({r["role"] for r in rows if r["role_status"] == "UNRESOLVED"})
        if unresolved_roles:
            status = "UNRESOLVED"
        privileged = [r for r in rows if r["privileged"] is True]
        if privileged:
            privilege = "PRIVILEGED"
        elif status != "RESOLVED" or any(r["privileged"] is None for r in rows):
            privilege = "UNRESOLVED"
        else:
            privilege = "NARROW" if rows else "NONE_OBSERVED"
        kinds = sorted({m.split(":", 1)[0] for m in members if ":" in m})
        notes = [
            "Bindings observed in collected allow policies only; deny policies, principal "
            "access boundaries and condition evaluation are not resolved."
        ]
        if "group" in kinds:
            notes.append("Group membership is not collected; members are not listed or inferred.")
        if "user" in kinds or len(forms) > 1:
            notes.append("Access a user receives through groups is not attributed to the user.")
        if unresolved_roles:
            notes.append(
                "Custom role permissions not collected (custom_role_detail): "
                + ", ".join(unresolved_roles[:10])
            )
        return {
            "principal": principal,
            "members": members,
            "principal_kinds": kinds,
            "status": status,
            "privilege": privilege,
            "bindings": rows,
            "binding_count": len(rows),
            "projects": [
                {"project_id": pid, **info} for pid, info in sorted(self.projects.items())
            ],
            "notes": notes,
            "runs": list(self.runs),
        }

    def directory(self, q: str = "", offset: int = 0, limit: int = 50) -> dict:
        """Principals with at least one observed binding, filtered by a substring."""
        q = q.strip().lower()
        names = sorted(m for m in self.bindings if not q or q in m.lower())
        rows = []
        for member in names[offset : offset + limit]:
            found = self.bindings[member]
            rows.append(
                {
                    "member": member,
                    "principal_kind": member.split(":", 1)[0] if ":" in member else "other",
                    "bindings": len(found),
                    "privileged_bindings": sum(
                        self.role_info(b["role"])["privileged"] is True for b in found
                    ),
                    "projects": len({b["project_id"] for b in found if b["project_id"]}),
                    "trust": sorted({b["trust"] for b in found if b["trust"]}),
                }
            )
        return {"items": rows, "total": len(names), "offset": offset, "limit": limit}

    def project_status(self, project_id: str) -> dict:
        return self.projects.get(
            project_id,
            {"status": "UNRESOLVED", "reason": "project IAM not collected", "parents": []},
        )

    def role_info(self, role: str) -> dict:
        if role.startswith("roles/"):
            return {
                "role_type": "PREDEFINED",
                "privileged": privileged(role),
                "role_status": "RESOLVED",
                "permissions": None,
            }
        if CUSTOM_ROLE.fullmatch(role):
            detail = self.custom_roles.get(role)
            if detail is None:
                return {
                    "role_type": "CUSTOM",
                    "privileged": None,
                    "role_status": "UNRESOLVED",
                    "permissions": None,
                }
            return {
                "role_type": "CUSTOM",
                "privileged": None,  # permissions are shown, not classified
                "role_status": "RESOLVED",
                "permissions": detail,
            }
        return {
            "role_type": "UNKNOWN",
            "privileged": None,
            "role_status": "UNRESOLVED",
            "permissions": None,
        }


def principal_runs(store, run: str) -> list[str]:
    """The selected enterprise snapshot, or the latest active import per GCP project plus the
    selected run (all imported projects)."""
    if store.db.execute("SELECT 1 FROM enterprise_snapshots WHERE run_id=?", [run]).fetchone():
        return [run]
    rows = store.rows(
        "SELECT r.run_id, r.created_at, json_extract_string(s.data,'$.project_id') FROM runs r "
        "JOIN sources s ON s.run_id=r.run_id WHERE json_extract_string(s.data,'$.format')="
        "'gcp-json-v1' AND r.run_id NOT IN (SELECT run_id FROM enterprise_snapshots) AND "
        "r.run_id NOT IN (SELECT run_id FROM scope_retired_runs) GROUP BY 1,2,3"
    )
    latest: dict[str, tuple[str, str]] = {}
    selected_projects = set()
    for run_id, created, project in rows:
        if run_id == run:
            selected_projects.add(project)
        if project and (project not in latest or (created or "") > latest[project][1]):
            latest[project] = (run_id, created or "")
    chosen = {run} | {r for p, (r, _) in latest.items() if p not in selected_projects}
    return sorted(chosen)


def build(store, runs: list[str]) -> Index:
    from offline_analyzer.rules.gcp_identity import scope_from
    from offline_analyzer.rules.gcp_org import project_index, resource_project

    index = Index(runs=tuple(runs))
    marks = ",".join("?" for _ in runs)
    sources = [
        json.loads(raw)
        for (raw,) in store.rows(f"SELECT data FROM sources WHERE run_id IN ({marks})", runs)
    ]
    sources = [s for s in sources if s.get("format") == "gcp-json-v1"]
    by_artifact = {s.get("artifact_id"): s for s in sources}
    observations = [
        {**json.loads(raw), "_run": run_id}
        for run_id, raw in store.rows(
            f"SELECT run_id, data FROM observations WHERE run_id IN ({marks}) AND kind IN "
            f"({','.join('?' for _ in KINDS)})",
            [*runs, *KINDS],
        )
    ]
    search = [o for o in observations if o["resource_type"] == "GCP::AssetIAMSearchResult"]
    org = project_index([SimpleNamespace(configuration=o["configuration"]) for o in search])
    index.scope = scope_from(sources, org)

    def dataset(obs: dict) -> str:
        source = by_artifact.get((obs.get("evidence") or {}).get("artifact_id"), {})
        meta = source.get("gcp_metadata") or {}
        return meta.get("dataset") or source.get("operation") or obs.get("operation") or ""

    def add(member, role, subject, kind, condition, project, obs, resource):
        # Folder/organization bindings are judged relative to the collected project whose
        # parent chain they belong to.
        reference = project or obs.get("project_id")
        identity = account_class(member, index.scope.for_project(reference, None))
        row = {
            "member": base_member(member),
            "role": role,
            "scope": kind,
            "resource": resource,
            "subject": subject,
            "project_id": project,
            "conditional": bool(condition),
            "condition": (
                {k: condition.get(k) for k in ("title", "expression") if condition.get(k)}
                if isinstance(condition, dict)
                else None
            ),
            "dataset": dataset(obs),
            "observation_id": obs.get("observation_id"),
            "run_id": obs.get("_run"),
            "binding_resource_id": obs.get("resource_id"),
            "account_class": identity.account_class if identity else None,
            "owner_project_id": identity.owner_project_id if identity else None,
            "owner_project_number": identity.owner_project_number if identity else None,
            "trust": identity.relation if identity else None,
            "home_project": identity.owner if identity else None,
            "trust_evidence": identity.evidence if identity else None,
        }
        row["datasets"] = [row["dataset"]]
        index.bindings[base_member(member)].append(row)
        return row

    seen: dict[tuple, dict] = {}
    for obs in observations:
        config = obs.get("configuration") or {}
        kind = obs["resource_type"]
        if kind == "GCP::IAMBinding":
            subject = str(config.get("subject") or "")
            project = obs.get("project_id")
            if subject.startswith(("folders/", "organizations/")):
                project = None
            for member in config.get("members") or []:
                if not isinstance(member, str):
                    continue
                key = (
                    base_member(member),
                    config.get("role"),
                    subject,
                    json.dumps(config.get("condition"), sort_keys=True),
                )
                if key in seen:
                    seen[key]["datasets"] = sorted({*seen[key]["datasets"], dataset(obs)})
                    continue
                seen[key] = add(
                    member,
                    config.get("role", ""),
                    subject,
                    scope_kind(subject),
                    config.get("condition"),
                    project,
                    obs,
                    subject,
                )
        elif kind == "GCP::AssetIAMSearchResult":
            resource = str(config.get("resource") or "")
            subject = re.sub(r"^//[^/]+/", "", resource)
            project, _ = resource_project(config, org)
            policy = config.get("policy") or {}
            for binding in policy.get("bindings", []) if isinstance(policy, dict) else []:
                if not isinstance(binding, dict):
                    continue
                for member in binding.get("members") or []:
                    if not isinstance(member, str):
                        continue
                    key = (
                        base_member(member),
                        binding.get("role"),
                        subject,
                        json.dumps(binding.get("condition"), sort_keys=True),
                    )
                    if key in seen:
                        seen[key]["datasets"] = sorted({*seen[key]["datasets"], dataset(obs)})
                        continue
                    seen[key] = add(
                        member,
                        binding.get("role", ""),
                        subject,
                        scope_kind(subject, config.get("assetType", "")),
                        binding.get("condition"),
                        project,
                        obs,
                        resource,
                    )
        elif kind == "GCP::CustomRole" and obs.get("operation") == "gcp:iam.roles.get":
            name = config.get("name")
            permissions = config.get("includedPermissions")
            if isinstance(name, str) and isinstance(permissions, list):
                index.custom_roles[name] = sorted(p for p in permissions if isinstance(p, str))

    # Per-project resolution status from the collected policy sources and the parent chain.
    policies: dict[str, str] = {}  # subject -> best coverage reason
    for source in sources:
        if source.get("operation") not in POLICY_OPERATIONS:
            continue
        subject = (source.get("request_parameters") or {}).get("subject")
        if not subject:
            continue
        usable = source.get("effective_coverage") in USABLE
        meta = source.get("gcp_metadata") or {}
        reason = (
            "collected"
            if usable
            else (meta.get("error_category") or meta.get("original_status") or "not collected")
        )
        if policies.get(subject) != "collected":
            policies[subject] = reason
    records: dict[str, dict] = {}
    folders: dict[str, str | None] = {}
    for obs in observations:
        config = obs.get("configuration") or {}
        if obs["resource_type"] == "GCP::Project" and config.get("projectId"):
            records[config["projectId"]] = config
        elif obs["resource_type"] == "GCP::Folder" and isinstance(config.get("name"), str):
            folders[config["name"]] = parent_name(config.get("parent"))
    ancestors: dict[str, set[str]] = defaultdict(set)
    projects = set()
    for source in sources:
        if source.get("project_id"):
            projects.add(source["project_id"])
            ancestors[source["project_id"]] |= set(
                (source.get("gcp_metadata") or {}).get("scope_ancestors") or []
            )
    for project in sorted(projects):
        own = policies.get(f"projects/{project}")
        record = records.get(project)
        chain = set(ancestors[project])
        direct = parent_name(record.get("parent")) if record else None
        if direct:
            chain.add(direct)
        pending, top = list(chain), False
        while pending:
            scope = pending.pop()
            if scope.startswith("organizations/"):
                top = True
            elif scope in folders:
                parent = folders[scope]
                if parent is None:
                    top = True
                elif parent not in chain:
                    chain.add(parent)
                    pending.append(parent)
        parents = [
            {"scope": scope, "iam": policies.get(scope, "not collected")} for scope in sorted(chain)
        ]
        if own != "collected":
            status, reason = "UNRESOLVED", f"project IAM {own or 'not collected'}"
        elif not chain:
            # A missing parent field is not proof of a standalone project (owner decision).
            status = "UNRESOLVED"
            reason = (
                NO_PARENT_RECORDED
                if record is not None
                else INHERITED_GAP + " (parent hierarchy not established)"
            )
        elif any(p["iam"] != "collected" for p in parents):
            missing = [f"{p['scope']}: {p['iam']}" for p in parents if p["iam"] != "collected"]
            status, reason = "UNRESOLVED", INHERITED_GAP + " (" + "; ".join(missing[:5]) + ")"
        elif not top:
            status, reason = "UNRESOLVED", INHERITED_GAP + " (folder ancestry not collected)"
        else:
            status, reason = "RESOLVED", "project and parent IAM collected"
        index.projects[project] = {"status": status, "reason": reason, "parents": parents}
    return index


def lookup(store, run: str, principal: str) -> dict:
    if not principal or len(principal) > 320:
        from offline_analyzer.ingestion.json_input import InputError

        raise InputError("INVALID_PRINCIPAL")
    return build(store, principal_runs(store, run)).lookup(principal)


def directory(store, run: str, q: str = "", offset: int = 0, limit: int = 50) -> dict:
    index = build(store, principal_runs(store, run))
    result = index.directory(q, offset, limit)
    result["projects"] = [{"project_id": p, **i} for p, i in sorted(index.projects.items())]
    return result
