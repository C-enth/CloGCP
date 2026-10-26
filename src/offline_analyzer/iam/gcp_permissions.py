"""Bounded, offline GCP permission semantics, never a general IAM simulator.

An observed allow is separate from effective availability. Unknown roles, CEL, deny
exceptions, PABs, federation and service restrictions fail closed. Empty project deny
exports do not establish absence of inherited restrictions.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import unquote

from offline_analyzer.contracts.gcp_attack_path import PermissionEvidence
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.iam.gcp_principals import parent_name
from offline_analyzer.rules.gcp_identity import PLATFORM_AGENT, account_class, scope_from

ACT_AS = "iam.serviceAccounts.actAs"
ACCESS_TOKEN: str = "iam.serviceAccounts.getAccessToken"
ID_TOKEN = "iam.serviceAccounts.getOpenIdToken"
SIGN_JWT = "iam.serviceAccounts.signJwt"
SIGN_BLOB = "iam.serviceAccounts.signBlob"
AUTH = {ACT_AS, ACCESS_TOKEN, ID_TOKEN, SIGN_JWT, SIGN_BLOB}
# Exact reviewed permission projections, not complete role definitions. Unlisted
# permissions outside AUTH are unknown, never inferred from an 'Admin' suffix.
ROLE_PERMISSIONS = {
    "roles/iam.serviceAccountUser": {ACT_AS},
    "roles/iam.serviceAccountTokenCreator": {
        ACCESS_TOKEN,
        ID_TOKEN,
        SIGN_JWT,
        SIGN_BLOB,
        "iam.serviceAccounts.implicitDelegation",
    },
    "roles/iam.serviceAccountOpenIdTokenCreator": {ID_TOKEN},
    "roles/iam.workloadIdentityUser": {ACCESS_TOKEN, ID_TOKEN},
    "roles/run.invoker": {"run.routes.invoke", "run.jobs.run"},
    "roles/cloudfunctions.invoker": {"cloudfunctions.functions.invoke"},
    "roles/storage.objectViewer": {"storage.objects.get", "storage.objects.list"},
    "roles/bigquery.dataViewer": {"bigquery.tables.getData"},
}
AUTH_ROLES = {r for r in ROLE_PERMISSIONS if r.startswith("roles/iam.")}
AUTH_MECHANISMS = {
    "access-token": ACCESS_TOKEN,
    "id-token": ID_TOKEN,
    "sign-jwt": SIGN_JWT,
    "sign-blob": SIGN_BLOB,
    "workload-attachment": ACT_AS,
}
# Creation/attachment and execution are intentionally independent requirements.
# Resource/image/network/service restrictions are additional prerequisites in discovery.
WORKLOAD_MECHANISMS = {
    "compute-create-start": (
        "compute.instances.create",
        "compute.instances.setServiceAccount",
        "compute.instances.setMetadata",
        "compute.disks.create",
        "compute.subnetworks.use",
    ),
    "run-job-create-execute": ("run.jobs.create", "run.jobs.run"),
    "run-service-create-revision": ("run.services.create", "run.services.update"),
}


def canonical(value: str, numbers: dict[str, str]) -> str:
    value = re.sub(r"^https://www.googleapis.com/compute/v1/|^//[^/]+/|^gcp://", "", value)
    value = value.replace("gs://", "buckets/")
    value = re.sub(r"^projects/_/buckets/", "buckets/", value)
    return re.sub(r"(^projects/)([^/]+)", lambda m: m[1] + numbers.get(m[2], m[2]), value)


@dataclass(frozen=True)
class Grant:
    member: str
    role: str
    resource: str
    project: str
    conditional: bool
    observation_id: str


class PermissionIndex:
    def __init__(
        self, observations: list[Normalized], sources: list[dict], max_bindings: int = 50000
    ) -> None:
        sources = list(sources)
        self.observations, self.sources = observations, sources
        self.identity_scope = scope_from(sources)
        self.numbers = {
            str(s["project_number"]): s["project_id"]
            for s in sources
            if s.get("project_number") and s.get("project_id")
        }
        self.ancestors: dict[str, set[str]] = defaultdict(set)
        self.roles: dict[str, list[tuple[set[str], str]]] = defaultdict(list)
        self.inactive_roles: dict[str, list[str]] = defaultdict(list)
        self.grants: list[Grant] = []
        self.by_member: dict[str, list[Grant]] = defaultdict(list)
        self.by_subject_member: dict[tuple[str, str], list[Grant]] = defaultdict(list)
        self._restriction_cache: dict[str, tuple[bool, str]] = {}
        self._permission_budget = max_bindings * 10
        self._deny_observations = [
            o for o in observations if o.resource_type == "GCP::IAMDenyPolicy"
        ]
        self._restricted_projects = {
            o.project_id
            for o in observations
            if o.resource_type in {"GCP::IAMDenyPolicy", "GCP::PrincipalAccessBoundaryBinding"}
        }
        self.truncated = False
        for s in sources:
            self.ancestors[s.get("project_id", "")].update(
                (s.get("gcp_metadata") or {}).get("scope_ancestors") or []
            )
        folders = {}
        for o in observations:
            c = o.configuration
            if o.resource_type == "GCP::Project":
                if p := parent_name(c.get("parent")):
                    self.ancestors[o.project_id].add(p)
            if o.resource_type == "GCP::Folder":
                folders[c.get("name")] = parent_name(c.get("parent"))
            if o.resource_type == "GCP::CustomRole" and o.operation == "gcp:iam.roles.get":
                permissions = c.get("includedPermissions")
                if c.get("name") and (c.get("deleted") or c.get("stage") == "DISABLED"):
                    self.inactive_roles[c["name"]].append(o.observation_id)
                elif isinstance(permissions, list) and c.get("name"):
                    self.roles[c["name"]].append(
                        ({p for p in permissions if isinstance(p, str)}, o.observation_id)
                    )
        for chain in self.ancestors.values():
            pending = list(chain)
            while pending:
                if (parent := folders.get(pending.pop())) and parent not in chain:
                    chain.add(parent)
                    pending.append(parent)
        seen = set()
        for o in observations:
            c = o.configuration
            bindings = []
            if o.resource_type == "GCP::IAMBinding":
                resource, bindings = c.get("subject", ""), [c]
            elif o.resource_type == "GCP::AssetIAMSearchResult":
                resource = c.get("resource", "")
                policy = c.get("policy") or {}
                bindings = policy.get("bindings", []) if isinstance(policy, dict) else []
            else:
                continue
            resource = canonical(resource, self.numbers)
            if resource.startswith("projects/-/serviceAccounts/"):
                target = account_class(
                    "serviceAccount:" + resource.split("/serviceAccounts/", 1)[1],
                    self.identity_scope.for_project(o.project_id, None),
                )
                if target and target.owner_project_id:
                    resource = resource.replace(
                        "projects/-/", "projects/" + target.owner_project_id + "/", 1
                    )
            for b in bindings:
                if not isinstance(b, dict):
                    continue
                for member in b.get("members") or []:
                    if not isinstance(member, str) or member.startswith("deleted:"):
                        continue
                    key = (member, b.get("role"), resource, b.get("condition") is not None)
                    if key in seen:
                        continue
                    if len(self.grants) >= max_bindings:
                        self.truncated = True
                        break
                    seen.add(key)
                    g = Grant(
                        member,
                        b.get("role", ""),
                        resource,
                        o.project_id,
                        b.get("condition") is not None,
                        o.observation_id,
                    )
                    self.grants.append(g)
                    self.by_member[member].append(g)
                    self.by_subject_member[(member, resource)].append(g)

    def scope(self, grant: Grant, resource: str, project: str) -> bool:
        return bool(grant.resource) and (
            grant.resource == resource
            or grant.resource == f"projects/{project}"
            or grant.resource in self.ancestors.get(project, set())
        )

    def role_permission(self, role: str, permission: str) -> tuple[str, list[str]]:
        if role in self.inactive_roles:
            return ("UNSUPPORTED" if role in self.roles else "CONTRADICTED"), self.inactive_roles[
                role
            ]
        if role in self.roles:
            details = self.roles[role]
            values = {permission in permissions for permissions, _ in details}
            if len(values) != 1:
                return "UNSUPPORTED", [oid for _, oid in details]
            return ("AVAILABLE" if True in values else "CONTRADICTED"), [oid for _, oid in details]
        if permission in ROLE_PERMISSIONS.get(role, set()):
            return "AVAILABLE", []
        if role in AUTH_ROLES and permission in AUTH:
            return "CONTRADICTED", []
        return ("UNCOLLECTED" if "/roles/" in role else "UNSUPPORTED"), []

    def restrictions(self, project: str) -> tuple[bool, str]:
        if project not in self._restriction_cache:
            self._restriction_cache[project] = self._restrictions(project)
        return self._restriction_cache[project]

    def _restrictions(self, project: str) -> tuple[bool, str]:
        scopes = {f"projects/{project}", *self.ancestors.get(project, set())}
        if project in self._restricted_projects:
            return False, (
                "nonempty deny/PAB observations require applicability and exception evaluation"
            )
        if not any(s.startswith("organizations/") for s in scopes):
            return False, "parent hierarchy and inherited restrictions not established"
        for scope in scopes:
            for op in ("deny_policies", "principal_access_boundaries"):
                matching = [
                    s
                    for s in self.sources
                    if op in s.get("operation", "")
                    and canonical(
                        (s.get("request_parameters") or {}).get("subject", ""), self.numbers
                    )
                    == scope
                ]
                if not matching or any(
                    s.get("effective_coverage") != "COMPLETE" or s.get("record_count") != 0
                    for s in matching
                ):
                    return False, f"{op} and applicability/exception context unresolved at {scope}"
        return True, "complete empty deny and boundary collections at every known ancestor"

    def explicit_deny(
        self, principal: str, permission: str, resource: str, project: str
    ) -> str | None:
        """Only exact unconditional deny rules, without exception or principal-set semantics."""
        for o in self._deny_observations:
            c = o.configuration
            subject = canonical((c.get("_parameters") or {}).get("subject", ""), self.numbers)
            if not subject:
                name = unquote(unquote(str(c.get("name", ""))))
                match = re.search(
                    r"cloudresourcemanager.googleapis.com/"
                    r"((?:projects|folders|organizations)/[^/]+)",
                    name,
                )
                if match:
                    subject = canonical(match[1], self.numbers)
                elif o.operation == "gcp:expanded.deny_policies_project":
                    subject = f"projects/{o.project_id}"
            if subject not in {
                resource,
                f"projects/{project}",
                *self.ancestors.get(project, set()),
            }:
                continue
            for rule in c.get("rules") or []:
                d = rule.get("denyRule") or {}
                if (
                    d.get("denialCondition") is not None
                    or d.get("exceptionPrincipals")
                    or d.get("exceptionPermissions")
                ):
                    continue
                principals = d.get("deniedPrincipals") or []
                # Google deny API uses fully qualified principal names.
                forms = set()
                if principal.startswith("user:"):
                    forms.add("principal://goog/subject/" + principal.split(":", 1)[1])
                elif principal.startswith("serviceAccount:"):
                    forms.add(
                        "principal://iam.googleapis.com/projects/-/serviceAccounts/"
                        + principal.split(":", 1)[1]
                    )
                denied = {
                    p.replace("iam.googleapis.com/", "iam.")
                    for p in d.get("deniedPermissions") or []
                }
                if forms.intersection(principals) and permission in denied:
                    return o.observation_id
        return None

    def evaluate(
        self, principal: str, permission: str, resource: str, project: str
    ) -> PermissionEvidence:
        resource = canonical(resource, self.numbers)
        scopes = {resource, f"projects/{project}", *self.ancestors.get(project, set())}
        grants = [
            g
            for scope in sorted(scopes)
            for g in self.by_subject_member.get((principal, scope), [])
        ]
        self._permission_budget -= len(grants) + len(self._deny_observations) + 1
        if self._permission_budget < 0:
            self.truncated = True
            return PermissionEvidence(
                name=permission,
                permission=permission,
                principal=principal,
                resource=resource,
                state="UNCOLLECTED",
                allow_state="UNCOLLECTED",
                reason="permission evaluation budget reached",
                observation_ids=[],
            )
        options = []
        for grant in grants:
            parent = grant.role.split("/roles/", 1)[0]
            invalid_scope = (
                grant.role.startswith("projects/")
                and (
                    parent != f"projects/{project}"
                    or grant.resource.startswith(("folders/", "organizations/"))
                )
            ) or (
                grant.role.startswith("organizations/")
                and parent not in self.ancestors.get(project, set())
            )
            result = (
                ("UNSUPPORTED", [])
                if invalid_scope
                else self.role_permission(grant.role, permission)
            )
            options.append((grant, *result))
        available = [(g, ids) for g, state, ids in options if state == "AVAILABLE"]
        unconditional = [(g, ids) for g, ids in available if not g.conditional]
        allow = "AVAILABLE" if unconditional else "CONDITIONAL" if available else "UNCOLLECTED"
        ids = sorted({oid for g, extra in available for oid in [g.observation_id, *extra]})
        reason = "no applicable observed allow with resolved role permissions"
        state = allow
        if not available and options and all(s == "CONTRADICTED" for _, s, _ in options):
            # Contradicts only these grants; an incomplete allow inventory cannot block access.
            allow = "CONTRADICTED"
            reason = "observed roles exclude this permission; other grants remain uncollected"
        elif not available and any(s == "UNSUPPORTED" for _, s, _ in options):
            state, reason = "UNSUPPORTED", "role permission semantics unavailable or conflicting"
        elif available:
            reason = "applicable observed allow; "
            clear, restriction_reason = self.restrictions(project)
            reason += restriction_reason
            if not clear:
                state = "UNCOLLECTED"
            elif not unconditional:
                state = "CONDITIONAL"
                reason += "; binding CEL condition requires evaluation"
            if principal.startswith("user:"):
                state = "UNCOLLECTED"
                reason += "; user principal PAB applicability scope is not collected"
            elif principal.startswith("serviceAccount:"):
                email = principal.split(":", 1)[1]
                owner = re.fullmatch(r"[^@]+@([^@]+)\.iam\.gserviceaccount\.com", email)
                owner_project = owner[1] if owner else None
                if owner_project is None:
                    number = re.fullmatch(r"(\d+)-compute@developer\.gserviceaccount\.com", email)
                    owner_project = self.numbers.get(number[1]) if number else None
                if owner_project is None:
                    state = "UNCOLLECTED"
                    reason += "; principal home and PAB applicability scope unresolved"
                elif owner_project != project:
                    principal_clear, principal_reason = self.restrictions(owner_project)
                    if not principal_clear:
                        state = "UNCOLLECTED"
                        reason += "; principal boundary context: " + principal_reason
            source_identity = account_class(
                principal, self.identity_scope.for_project(project, None)
            )
            if principal.startswith(("group:", "domain:", "principal")) or (
                source_identity and source_identity.account_class == PLATFORM_AGENT
            ):
                state = "UNSUPPORTED"
                reason += "; principal membership/federation/service-agent restrictions unresolved"
            if (
                permission in {ACCESS_TOKEN, ID_TOKEN}
                and any(g.role == "roles/iam.workloadIdentityUser" for g, _ in available)
                and not any(g.role != "roles/iam.workloadIdentityUser" for g, _ in unconditional)
            ):
                state = "UNSUPPORTED"
                reason += "; workload federation token exchange prerequisites not resolved"
        if denied := self.explicit_deny(principal, permission, resource, project):
            state, reason, ids = "CONTRADICTED", "exact unconditional IAM deny applies", [denied]
        elif "/serviceAccounts/" in resource:
            target_identity = account_class(
                "serviceAccount:" + resource.split("/serviceAccounts/", 1)[1],
                self.identity_scope.for_project(project, None),
            )
            if target_identity and target_identity.account_class == PLATFORM_AGENT:
                state = "UNSUPPORTED"
                reason += "; Google-managed target authentication restrictions unresolved"
        if principal not in {"allUsers", "allAuthenticatedUsers"} and not principal.startswith(
            ("user:", "serviceAccount:", "group:", "domain:", "principal://", "principalSet://")
        ):
            state = "UNSUPPORTED"
            reason += "; unsupported principal identifier syntax"
        if principal in {"allUsers", "allAuthenticatedUsers"} and permission in AUTH:
            state = "UNCOLLECTED"
            reason += "; authenticated API caller and principal-specific restrictions unresolved"
        if self.truncated and state != "CONTRADICTED":
            state, reason = "UNCOLLECTED", "binding budget reached; permission context incomplete"
        return PermissionEvidence(
            name=permission,
            permission=permission,
            principal=principal,
            resource=resource,
            state=state,
            allow_state=allow,
            reason=reason,
            observation_ids=ids,
        )
