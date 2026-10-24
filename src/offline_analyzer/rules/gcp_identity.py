"""Service-account identity resolution for the identity-aware GCP rules (E1/E2).

Only the rules listed in ``registry.IDENTITY_ENRICHED`` use this module. A member's home
project is resolved from its email form by project ID and by project number, against the
analyzed project, the other collected projects and the organization project index.

Trust classes (each classification carries the evidence used):

- PLATFORM_MANAGED: a Google-managed identity of the analyzed project, on positive pattern
  evidence only, with the number in the email equal to the analyzed project's number.
- SAME_PROJECT: home project ID or number equals the analyzed project.
- IN_SCOPE_OTHER_PROJECT: home is another project collected in this run (informational link).
- IN_ORG_NOT_ASSESSED: home is in the organization project index but was not collected.
- EXTERNAL_OR_UNKNOWN: home is resolved but known neither as collected nor in the organization.
- UNKNOWN: the home cannot be established (no parsable project in the email, or a number-form
  member while the analyzed project's number is missing). Never a PASS, never dropped.

Platform-managed patterns (NUM is the project number; matched case-sensitively, whole email):

- NUM@cloudservices.gserviceaccount.com             Google APIs service agent
- service-NUM@gcp-sa-<service>.iam.gserviceaccount.com   per-service service agents
- service-NUM@compute-system.iam.gserviceaccount.com      Compute Engine service agent
- service-NUM@container-engine-robot.iam.gserviceaccount.com   GKE service agent
- service-NUM@serverless-robot-prod.iam.gserviceaccount.com    Cloud Run/Functions agent
- service-NUM@firebase-sa-management.iam.gserviceaccount.com   Firebase service agent

The Compute Engine default service account (NUM-compute@developer.gserviceaccount.com) is a
customer-operated account, not platform-managed: it is resolved by number to SAME_PROJECT when
NUM is the analyzed project's number (so basic-role and privileged-SA rules still flag it),
otherwise like any other number-form member. Legacy Cloud Build default identities
are customer-operated workloads too; their standard email is not a role exception.
PLATFORM_MANAGED is an identity classification, never a blanket permission exception.

A pattern whose number belongs to another project is a Google-managed identity of that
project; it is resolved by number like any other member and is never PLATFORM_MANAGED here.
"""

import re
from dataclasses import dataclass, field

PLATFORM_MANAGED = "PLATFORM_MANAGED"
SAME_PROJECT = "SAME_PROJECT"
IN_SCOPE_OTHER_PROJECT = "IN_SCOPE_OTHER_PROJECT"
IN_ORG_NOT_ASSESSED = "IN_ORG_NOT_ASSESSED"
EXTERNAL_OR_UNKNOWN = "EXTERNAL_OR_UNKNOWN"
UNKNOWN = "UNKNOWN"
# Classes that are a cross-project trust outside the assessed scope.
OUT_OF_SCOPE = {IN_ORG_NOT_ASSESSED, EXTERNAL_OR_UNKNOWN}

PROJECT_ID = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
PLATFORM_PATTERNS = (
    ("Google APIs service agent", re.compile(r"(\d+)@cloudservices\.gserviceaccount\.com")),
    (
        "Google-managed service agent",
        re.compile(r"service-(\d+)@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com"),
    ),
    (
        "Google-managed service agent",
        re.compile(
            r"service-(\d+)@(?:compute-system|container-engine-robot|serverless-robot-prod"
            r"|firebase-sa-management|gs-project-accounts|gcf-admin-robot|containerregistry)\.iam\.gserviceaccount\.com"
        ),
    ),
)
# Customer-operated accounts whose email carries the home project number.
NUMBERED = (
    ("Legacy Cloud Build default account", re.compile(r"(\d+)@cloudbuild\.gserviceaccount\.com")),
    (
        "Compute Engine default service account",
        re.compile(r"(\d+)-compute@developer\.gserviceaccount\.com"),
    ),
)
BY_ID = (
    re.compile(rf"[^@]+@({PROJECT_ID})\.iam\.gserviceaccount\.com"),
    re.compile(rf"({PROJECT_ID})@appspot\.gserviceaccount\.com"),
)


@dataclass(frozen=True)
class Scope:
    """The analyzed project and the projects known to this run."""

    project_id: str | None
    project_number: str | None
    collected: dict[str, str | None] = field(default_factory=dict)  # project ID -> number
    org: dict[str, str] = field(default_factory=dict)  # project number -> project ID

    def for_project(self, project_id: str | None, project_number: str | None) -> "Scope":
        number = project_number or self.collected.get(project_id or "")
        if not number and project_id:
            number = next((n for n, p in self.org.items() if p == project_id), None)
        return Scope(project_id, number, self.collected, self.org)


@dataclass(frozen=True)
class Identity:
    member: str
    trust: str
    home: str | None  # project ID, or "number NUM" when only the number is known
    evidence: str

    @property
    def text(self) -> str:
        home = f"home project {self.home}" if self.home else "home project not determinable"
        return f"{self.member} ({home}; trust {self.trust}: {self.evidence})"


def scope_from(sources, org_index: dict[str, str] | None = None, project_id=None, number=None):
    collected: dict[str, str | None] = {}
    for s in sources:
        if s.get("project_id"):
            collected[s["project_id"]] = collected.get(s["project_id"]) or s.get("project_number")
    return Scope(project_id, number, collected, dict(org_index or {})).for_project(
        project_id, number
    )


def platform_pattern(email: str) -> tuple[str, str] | None:
    """(label, number) when the email matches a Google-managed pattern."""
    for label, pattern in PLATFORM_PATTERNS:
        if match := pattern.fullmatch(email):
            return label, match[1]
    return None


def classify_member(member: str, scope: Scope) -> Identity | None:
    """Trust class of a serviceAccount member; None for other principal types."""
    if not member.startswith("serviceAccount:"):
        return None
    email = member.split(":", 1)[1].split("?", 1)[0]
    pattern = platform_pattern(email)
    numbered = next(((label, m[1]) for label, p in NUMBERED if (m := p.fullmatch(email))), None)
    # Agent domains (gcp-sa-*, ...) are not the agent's home project: patterns win.
    home_id = (
        None
        if pattern or numbered
        else next((m[1] for p in BY_ID if (m := p.fullmatch(email))), None)
    )
    home_number = (pattern or numbered or (None, None))[1]
    if pattern and scope.project_number and home_number == scope.project_number:
        return Identity(
            member,
            PLATFORM_MANAGED,
            scope.project_id or f"number {home_number}",
            f"{pattern[0]} pattern; project number matches the analyzed project",
        )
    if home_id:
        if home_id == scope.project_id:
            return Identity(member, SAME_PROJECT, home_id, "project ID in the email matches")
        if home_id in scope.collected:
            return Identity(
                member, IN_SCOPE_OTHER_PROJECT, home_id, "project ID of a collected project"
            )
        if home_id in scope.org.values():
            return Identity(
                member, IN_ORG_NOT_ASSESSED, home_id, "project ID in the organization index"
            )
        return Identity(
            member, EXTERNAL_OR_UNKNOWN, home_id, "project ID not collected or in the organization"
        )
    if numbered and scope.project_number and home_number == scope.project_number:
        return Identity(
            member,
            SAME_PROJECT,
            scope.project_id or f"number {home_number}",
            f"{numbered[0]}; project number matches the analyzed project",
        )
    if home_number:
        label = f"{(pattern or numbered)[0]} of project number {home_number}"
        other = {n: p for p, n in scope.collected.items() if n}
        if home_number in other and other[home_number] != scope.project_id:
            return Identity(
                member,
                IN_SCOPE_OTHER_PROJECT,
                other[home_number],
                label + " (a collected project)",
            )
        if home_number in scope.org and scope.org[home_number] != scope.project_id:
            return Identity(
                member,
                IN_ORG_NOT_ASSESSED,
                scope.org[home_number],
                label + " (in the organization index)",
            )
        if not scope.project_number:
            return Identity(
                member,
                UNKNOWN,
                f"number {home_number}",
                label + "; analyzed project number missing, so same-project cannot be excluded",
            )
        return Identity(
            member,
            EXTERNAL_OR_UNKNOWN,
            f"number {home_number}",
            label + " (not collected or in the organization)",
        )
    return Identity(member, UNKNOWN, None, "email form does not name a project ID or number")


# Account ownership classes (owner brief, 2026-10-18). Used by GCP-IAM-CROSSPROJECT,
# GCP-IAM-BASIC, GCP-IAM-IMPERSONATION, GCP-ORG-SA-PRIVILEGED, GCP-ORG-CROSSPROJECT-SA and the
# per-principal view; attack paths keep classify_member above.
#
# PLATFORM_AGENT  NUM@cloudservices.gserviceaccount.com; service-NUM@<domain>.gserviceaccount.com
#                 (gcp-sa-*, compute-system, container-engine-robot, gs-project-accounts, ...);
#                 any other *.gserviceaccount.com domain that is neither *.iam.gserviceaccount.com
#                 nor a DEFAULT_SA form. Never a finding.
# DEFAULT_SA      NUM-compute@developer.gserviceaccount.com,
#                 <project-id>@appspot.gserviceaccount.com, NUM@cloudbuild.gserviceaccount.com.
# USER_MANAGED    <name>@<project-id>.iam.gserviceaccount.com.
# A service-NUM@<id>.iam.gserviceaccount.com address whose <id> is a collected or organization
# project is a customer-created account there (USER_MANAGED), not an agent.
PLATFORM_AGENT, DEFAULT_SA, USER_MANAGED = "PLATFORM_AGENT", "DEFAULT_SA", "USER_MANAGED"
AGENT_REASON = "Google-managed service agent (platform-managed)"
DEFAULT_FORMS = (
    (re.compile(r"(\d+)-compute@developer\.gserviceaccount\.com"), "number"),
    (re.compile(rf"({PROJECT_ID})@appspot\.gserviceaccount\.com"), "id"),
    (re.compile(r"(\d+)@cloudbuild\.gserviceaccount\.com"), "number"),
)


@dataclass(frozen=True)
class Account:
    member: str
    account_class: str  # PLATFORM_AGENT, DEFAULT_SA, USER_MANAGED or UNKNOWN
    owner_project_id: str | None
    owner_project_number: str | None
    relation: str  # trust class of the owner relative to the binding's project
    evidence: str

    @property
    def owner(self) -> str:
        if self.owner_project_id:
            return self.owner_project_id
        if self.owner_project_number:
            return f"number {self.owner_project_number}"
        return "unresolved"

    @property
    def text(self) -> str:
        return (
            f"{self.member} (class {self.account_class}; owner project {self.owner}; "
            f"{self.relation})"
        )


def account_class(member: str, scope: Scope) -> Account | None:
    """Ownership class and owner project of a serviceAccount member; None otherwise."""
    if not member.startswith("serviceAccount:"):
        return None
    email = member.split(":", 1)[1].split("?", 1)[0]
    local, _, domain = email.rpartition("@")
    known_ids = set(scope.collected) | set(scope.org.values()) | {scope.project_id} - {None}
    kind, owner_id, owner_number = "UNKNOWN", None, None
    for pattern, part in DEFAULT_FORMS:
        if match := pattern.fullmatch(email):
            kind = DEFAULT_SA
            owner_id, owner_number = (match[1], None) if part == "id" else (None, match[1])
            break
    else:
        user = re.fullmatch(rf"({PROJECT_ID})\.iam\.gserviceaccount\.com", domain)
        agent_number = re.fullmatch(r"service-(\d+)", local)
        if re.fullmatch(r"\d+", local) and domain == "cloudservices.gserviceaccount.com":
            kind, owner_number = PLATFORM_AGENT, local
        elif agent_number and platform_pattern(email) and not (user and user[1] in known_ids):
            kind, owner_number = PLATFORM_AGENT, agent_number[1]
        elif user:
            kind, owner_id = USER_MANAGED, user[1]
        elif platform_pattern(email):
            kind = PLATFORM_AGENT
    numbers = {p: n for p, n in scope.collected.items() if n}
    by_number = {n: p for p, n in numbers.items()} | {
        n: p for n, p in scope.org.items() if n not in numbers.values()
    }
    if kind == PLATFORM_AGENT:
        owner_id = by_number.get(owner_number) if owner_number else None
        if owner_number and scope.project_number and owner_number == scope.project_number:
            relation = PLATFORM_MANAGED
        elif owner_id in scope.collected:
            relation = IN_SCOPE_OTHER_PROJECT
        elif owner_id in scope.org.values():
            relation = IN_ORG_NOT_ASSESSED
        elif owner_number and scope.project_number:
            relation = EXTERNAL_OR_UNKNOWN
        else:
            relation = UNKNOWN
        return Account(member, kind, owner_id, owner_number, relation, AGENT_REASON)
    if kind == "UNKNOWN":
        return Account(member, kind, None, None, UNKNOWN, "not a recognised service-account form")
    if owner_number and not owner_id:
        owner_id = by_number.get(owner_number)
    if owner_id and not owner_number:
        owner_number = numbers.get(owner_id) or next(
            (n for n, p in scope.org.items() if p == owner_id), None
        )
    same = (owner_id and owner_id == scope.project_id) or (
        owner_number and scope.project_number and owner_number == scope.project_number
    )
    if same:
        relation, why = SAME_PROJECT, "owner is the binding's project"
    elif owner_id and owner_id in scope.collected:
        relation, why = IN_SCOPE_OTHER_PROJECT, "owner is another collected project"
    elif owner_id and owner_id in scope.org.values():
        relation, why = IN_ORG_NOT_ASSESSED, "owner is in the organization index, not collected"
    elif owner_id and scope.project_id:
        relation, why = EXTERNAL_OR_UNKNOWN, "owner project not collected or in the organization"
    elif owner_number and scope.project_number:
        relation, why = EXTERNAL_OR_UNKNOWN, "owner number not collected or in the organization"
    else:
        relation, why = UNKNOWN, "binding project number missing; owner cannot be compared"
    return Account(member, kind, owner_id, owner_number, relation, why)


def expected_agent_grant(member: str, role: str, scope: Scope, subject: str) -> bool:
    """Narrow documented project grants. A Google domain is never a blanket exemption."""
    identity = account_class(member, scope)
    if not identity or identity.account_class != PLATFORM_AGENT:
        return False
    if not scope.project_number or identity.owner_project_number != scope.project_number:
        return False
    if subject not in {f"projects/{scope.project_id}", f"projects/{scope.project_number}"}:
        return False
    email = member.removeprefix("serviceAccount:")
    if email == f"{scope.project_number}@cloudservices.gserviceaccount.com":
        return role in {
            "roles/editor",
            "roles/compute.instanceGroupManagerServiceAgent",
            "roles/dataproc.serviceAgent",
            "roles/cloudscheduler.serviceAgent",
        }
    expected = {
        "compute-system.iam.gserviceaccount.com": "roles/compute.serviceAgent",
        "container-engine-robot.iam.gserviceaccount.com": "roles/container.serviceAgent",
        "serverless-robot-prod.iam.gserviceaccount.com": "roles/run.serviceAgent",
        "gcf-admin-robot.iam.gserviceaccount.com": "roles/cloudfunctions.serviceAgent",
        "gcp-sa-cloudbuild.iam.gserviceaccount.com": "roles/cloudbuild.serviceAgent",
    }
    return role == expected.get(email.rsplit("@", 1)[-1])


def principal_kind(member: str, scope: Scope) -> str:
    if member.startswith("deleted:"):
        return "DELETED"
    if member.startswith("serviceAccount:"):
        account = account_class(member, scope)
        email = member.split(":", 1)[1]
        if email.endswith("-compute@developer.gserviceaccount.com"):
            return "COMPUTE_DEFAULT"
        if email.endswith("@appspot.gserviceaccount.com"):
            return "APP_ENGINE_DEFAULT"
        if email.endswith("@cloudservices.gserviceaccount.com"):
            return "GOOGLE_APIS_AGENT"
        return account.account_class
    for prefix, kind in [
        ("user:", "HUMAN"),
        ("group:", "GROUP"),
        ("domain:", "DOMAIN"),
        ("principal://", "FEDERATED"),
        ("principalSet://", "FEDERATED"),
    ]:
        if member.startswith(prefix):
            return kind
    return "PUBLIC" if member in {"allUsers", "allAuthenticatedUsers"} else "UNRESOLVED"
