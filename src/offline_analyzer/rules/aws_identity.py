"""AWS principal and role identity classification for the identity-aware AWS rules.

Only the rules listed in ``registry.AWS_IDENTITY_ENRICHED`` use this module; it mirrors
rules/gcp_identity.py. Accounts are matched by 12-digit account ID only, never by name.

Trust classes for a principal named in a trust policy, relative to the role's account
(each classification carries the evidence used):

- SAME_ACCOUNT: the principal's account is the role's account.
- PLATFORM_MANAGED: an AWS service principal (``<service>.amazonaws.com``); or the
  organization management account trusted by a role AWS Organizations or Control Tower
  creates (OrganizationAccountAccessRole, AWSControlTowerExecution), with the management
  account taken from DescribeOrganization evidence (never from the role name alone).
- IN_SCOPE_OTHER_ACCOUNT: another account collected in this run or listed in scope in the
  approved account registry.
- IN_ORG_NOT_ASSESSED: an account of the same organization per Organizations evidence
  (management account or listed member) that was not collected.
- EXTERNAL_OR_UNKNOWN: a resolved account known neither as collected, registered nor
  organization member, and the wildcard principal ``*``.
- UNKNOWN: the account cannot be established (unique principal IDs, malformed values).
  Never a PASS, never dropped.

Role classes for the role being evaluated:

- SERVICE_LINKED: path ``/aws-service-role/`` or name ``AWSServiceRoleFor*``; only the AWS
  service can assume it.
- IDENTITY_CENTER: ``AWSReservedSSO_*`` under ``/aws-reserved/sso.amazonaws.com/``; created and
  updated by IAM Identity Center from a customer-assigned permission set.
- ORGANIZATION_ACCESS: OrganizationAccountAccessRole or AWSControlTowerExecution (name only;
  the trust classification above decides whether the management account is evidenced).
- CUSTOMER: anything else.

Classification is context. A rule may reclassify a finding only where its docstring says
so, recording this evidence; severity is never lowered silently.
"""

import re
from dataclasses import dataclass, field, replace

SAME_ACCOUNT = "SAME_ACCOUNT"
PLATFORM_MANAGED = "PLATFORM_MANAGED"
IN_SCOPE_OTHER_ACCOUNT = "IN_SCOPE_OTHER_ACCOUNT"
IN_ORG_NOT_ASSESSED = "IN_ORG_NOT_ASSESSED"
EXTERNAL_OR_UNKNOWN = "EXTERNAL_OR_UNKNOWN"
UNKNOWN = "UNKNOWN"
OUT_OF_SCOPE = {IN_ORG_NOT_ASSESSED, EXTERNAL_OR_UNKNOWN}

SERVICE_LINKED, IDENTITY_CENTER, ORGANIZATION_ACCESS, CUSTOMER = (
    "SERVICE_LINKED",
    "IDENTITY_CENTER",
    "ORGANIZATION_ACCESS",
    "CUSTOMER",
)
ORGANIZATION_ROLES = {
    "OrganizationAccountAccessRole": "AWS Organizations account access role",
    "AWSControlTowerExecution": "AWS Control Tower execution role",
}
ACCOUNT = re.compile(r"[0-9]{12}")
PRINCIPAL_ARN = re.compile(r"arn:(?:aws|aws-cn|aws-us-gov):(?:iam|sts)::([0-9]{12}):(.+)")
SERVICE = re.compile(r"[a-z0-9.-]+\.amazonaws\.com(?:\.cn)?")
ROLE_ARN = re.compile(r"arn:[^:]+:iam::([0-9]{12}):role/(.*)")


@dataclass(frozen=True)
class Scope:
    """Accounts known to this run: collected, registered in scope, organization evidence."""

    collected: frozenset[str] = frozenset()
    registered: frozenset[str] = frozenset()
    organization_members: frozenset[str] = frozenset()
    management: frozenset[str] = frozenset()
    management_evidence: dict[str, str] = field(default_factory=dict)  # account -> obs ID


@dataclass(frozen=True)
class Identity:
    principal: str
    trust: str
    account: str | None
    evidence: str

    @property
    def text(self) -> str:
        home = f"account {self.account}" if self.account else "account not determinable"
        return f"{self.principal} ({home}; trust {self.trust}: {self.evidence})"


def scope_from(sources, registry=None, organization=None) -> Scope:
    """Scope from source records, the approved registry and an OrganizationModel."""
    collected = frozenset(s["account_id"] for s in sources if s.get("account_id"))
    # Every registry entry is a known, approved account (as R1-IAM-ROLE-TRUST-CONDITIONS uses).
    registered = frozenset(registry.accounts) if registry else frozenset()
    members, management, evidence = set(), set(), {}
    if organization is not None:
        members = {a for a in organization.parents if ACCOUNT.fullmatch(a)}
        for native, config in organization.organizations.items():
            master = config.get("MasterAccountId") or config.get("ManagementAccountId")
            if isinstance(master, str) and ACCOUNT.fullmatch(master):
                management.add(master)
                evidence[master] = f"DescribeOrganization {native}"
    return Scope(collected, registered, frozenset(members | management), frozenset(management),
                 evidence)  # fmt: skip


def role_class(arn: str) -> tuple[str, str]:
    """(role class, evidence) from the role ARN's path and name."""
    match = ROLE_ARN.fullmatch(arn or "")
    path = match.group(2) if match else ""
    name = path.rsplit("/", 1)[-1]
    if path.startswith("aws-service-role/") or name.startswith("AWSServiceRoleFor"):
        return SERVICE_LINKED, "service-linked role path or name"
    if path.startswith("aws-reserved/sso.amazonaws.com/") or name.startswith("AWSReservedSSO_"):
        return IDENTITY_CENTER, "IAM Identity Center reserved role path or name"
    if name in ORGANIZATION_ROLES:
        return ORGANIZATION_ACCESS, ORGANIZATION_ROLES[name]
    return CUSTOMER, "customer-managed role"


def classify(principal: str, kind: str, role_arn: str, scope: Scope) -> Identity:
    """Trust class of one trust-policy principal for the role `role_arn`."""
    owner = (ROLE_ARN.fullmatch(role_arn or "") or [None, None])[1]
    if kind == "Service":
        if SERVICE.fullmatch(principal):
            return Identity(principal, PLATFORM_MANAGED, None, "AWS service principal")
        return Identity(principal, UNKNOWN, None, "unrecognized service principal form")
    if kind != "AWS":
        return Identity(principal, UNKNOWN, None, f"{kind} principal is not classified here")
    if principal == "*":
        return Identity(principal, EXTERNAL_OR_UNKNOWN, None, "wildcard: any AWS principal")
    if ACCOUNT.fullmatch(principal):
        account = principal
    elif match := PRINCIPAL_ARN.fullmatch(principal):
        account = match.group(1)
    else:
        return Identity(principal, UNKNOWN, None, "principal account not determinable")
    if not owner:
        return Identity(principal, UNKNOWN, account, "role account not determinable")
    if account == owner:
        return Identity(principal, SAME_ACCOUNT, account, "same account as the role")
    name = role_arn.rsplit("/", 1)[-1]
    if account in scope.management and name in ORGANIZATION_ROLES:
        return Identity(
            principal,
            PLATFORM_MANAGED,
            account,
            f"organization management account ({scope.management_evidence.get(account)}) "
            f"trusted by the {ORGANIZATION_ROLES[name]}",
        )
    if account in scope.collected or account in scope.registered:
        basis = "collected in this run" if account in scope.collected else "registered in scope"
        return Identity(principal, IN_SCOPE_OTHER_ACCOUNT, account, basis)
    if account in scope.organization_members:
        basis = (
            "organization management account, not collected"
            if account in scope.management
            else "organization member per Organizations evidence, not collected"
        )
        return Identity(principal, IN_ORG_NOT_ASSESSED, account, basis)
    return Identity(principal, EXTERNAL_OR_UNKNOWN, account, "not collected, registered or "
                    "evidenced as an organization member")  # fmt: skip


# --- Rule enrichment (opt-in via registry.AWS_IDENTITY_ENRICHED and
# registry.AWS_PRINCIPAL_CONTEXT_RULES). The base rule decides FAIL/PASS/UNKNOWN as before;
# enrichment adds context and may change class/severity only as stated here, with evidence.
#
# | Rule | Context added | Class/severity change |
# |---|---|---|
# | R1-IAM-ROLE-TRUST-CONDITIONS | each trust principal's class; rendered conditions
#   (sts:ExternalId presence only, aws:PrincipalOrgID, aws:SourceArn, aws:SourceAccount);
#   "UNCONDITIONED EXTERNAL TRUST" label; organization-controls statement | FAIL whose every
#   unconditioned external principal is PLATFORM_MANAGED (management account per
#   DescribeOrganization trusted by OrganizationAccountAccessRole/AWSControlTowerExecution):
#   BASELINE_DEVIATION, MEDIUM if the role is elevated else LOW, with the previous class and
#   severity and the evidence recorded. Otherwise unchanged. |
# | R1-IAM-INSTANCE-ROLE-PRIVILEGE, SEC-IAM-ROLE-WILDCARD | role class (service-linked,
#   Identity Center, organization access, customer); organization-controls statement |
#   none: severity kept |
# | R1-EC2-SG-SENSITIVE-INGRESS (workload context, E5 analogue) | for each exposed instance:
#   instance-profile role and its privilege from iam/evaluator.py | POTENTIAL_EXPOSURE below
#   HIGH raised to HIGH when an exposed instance's role is ADMIN_EQUIVALENT or
#   ESCALATION_CAPABLE (supported); never lowered; NOT_SHOWN_PRIVILEGED is labelled least
#   privilege; anything unresolved is labelled UNRESOLVED, never narrow |

TRUST_RULE = "R1-IAM-ROLE-TRUST-CONDITIONS"
ROLE_RULES = ("R1-IAM-INSTANCE-ROLE-PRIVILEGE", "SEC-IAM-ROLE-WILDCARD")
SG_RULE = "R1-EC2-SG-SENSITIVE-INGRESS"
RENDERED_KEYS = {
    "sts:externalid": "sts:ExternalId",
    "aws:principalorgid": "aws:PrincipalOrgID",
    "aws:principalorgpaths": "aws:PrincipalOrgPaths",
    "aws:sourcearn": "aws:SourceArn",
    "aws:sourceaccount": "aws:SourceAccount",
    "aws:sourceorgid": "aws:SourceOrgID",
}
RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SUPPORTED = {"ADMIN_EQUIVALENT", "ESCALATION_CAPABLE"}
ELEVATED = SUPPORTED | {"POTENTIALLY_PRIVILEGED"}
ROLE_NOTES = {
    SERVICE_LINKED: "only the AWS service can assume it; its policy is AWS-managed",
    IDENTITY_CENTER: "created by IAM Identity Center; the permission set and its assignments "
    "are customer-controlled",
    ORGANIZATION_ACCESS: "created by AWS Organizations or Control Tower for management access",
}


def scope_for(context) -> Scope:
    """Run-wide classification scope, built once per evaluation context."""
    if "_aws_scope" not in context.__dict__:
        context._aws_scope = scope_from(context.sources, context.registry, context.iam.org)
    return context._aws_scope


def organization_note(analysis, account: str) -> str | None:
    """Plain statement when SCP/RCP evidence cannot be evaluated for the account."""
    state = analysis.org.applicability(account, "SERVICE_CONTROL_POLICY", False)
    if state == "NOT_COLLECTED":
        return (
            f"Organization controls not assessed for account {account}: no Organizations "
            "SCP/RCP evidence was collected; IAM conclusions exclude SCP and RCP effects"
        )
    if state is None:
        path, why = analysis.org.path(account)
        if path is None:
            return (
                f"Organization controls not fully assessed for account {account}: {why}; "
                "IAM conclusions treat SCP and RCP effects as unknown"
            )
    return None


def render_conditions(statement) -> str:
    """Binding and confused-deputy condition keys of one statement; ExternalId values are
    never shown. Other keys are listed by operator and name only."""
    if not statement.conditions:
        return "no Condition"
    parts, others = [], []
    for condition in statement.conditions:
        name = RENDERED_KEYS.get(condition.key.lower())
        if name == "sts:ExternalId":
            parts.append(f"{condition.operator} sts:ExternalId (value set, not shown)")
        elif name:
            parts.append(f"{condition.operator} {name}={','.join(condition.values)}")
        else:
            others.append(f"{condition.operator} {condition.key}")
    if others:
        parts.append("other conditions: " + ", ".join(others))
    return "; ".join(parts)


LIMIT = 500  # contract Identifier fields hold at most 512 characters


def chunks(text: str) -> tuple[str, ...]:
    """Split a long statement at '; ' into entries that fit the contract (nothing dropped)."""
    if len(text) <= LIMIT:
        return (text,)
    out, current = [], ""
    for part in text.split("; "):
        piece = part if not current else current + "; " + part
        if len(piece) <= LIMIT:
            current = piece
            continue
        if current:
            out.append(current)
        while len(part) > LIMIT:
            out.append(part[:LIMIT])
            part = part[LIMIT:]
        current = part
    if current:
        out.append(current)
    return tuple(out[:1] + [f"(continued) {o}" for o in out[1:]])


def with_exposure(verdict, prefix: str):
    """Prefix the exposure statement; when the result would not fit, the previous statement
    moves to a limitation entry so nothing is lost."""
    base = verdict.exposure or ""
    if len(prefix) + len(base) <= 512:
        return replace(verdict, exposure=prefix + base)
    short = prefix if len(prefix) <= 440 else prefix[:437] + "..."
    return replace(
        verdict,
        exposure=short + "(Previous exposure statement in limitations.)",
        limitations=verdict.limitations + chunks("Exposure: " + base) + chunks(prefix),
    )


def _role(obs, context):
    return context.iam.inventory.roles.get(
        (obs.account_id, (obs.native_id or "").rsplit("/", 1)[-1])
    )


def trust_context(obs, verdict, context):
    analysis = context.iam
    role = _role(obs, context)
    if role is None or role.trust is None:
        return verdict
    scope = scope_for(context)
    lines, unconditioned = [], []
    for index, statement in enumerate(role.trust.statements):
        if statement.effect != "Allow":
            continue
        found = [
            classify(value, kind, role.arn, scope)
            for kind, values in sorted((statement.principals or {}).items())
            for value in values
        ]
        if not found:
            continue
        lines += [f"Trust statement {index} principal: {i.text}" for i in found]
        lines += chunks(f"Trust statement {index} conditions: {render_conditions(statement)}")
        if not statement.conditions:
            unconditioned += [
                i
                for i in found
                if i.trust not in {SAME_ACCOUNT} and (i.account or i.principal == "*")
            ]
    note = organization_note(analysis, role.account)
    extra = tuple(lines) + ((note,) if note else ())
    verdict = replace(verdict, limitations=verdict.limitations + extra)
    if str(verdict.outcome) != "FAIL" or not unconditioned:
        return verdict
    classes = sorted({i.trust for i in unconditioned})
    label = (
        f"UNCONDITIONED EXTERNAL TRUST ({len(unconditioned)} principal(s): "
        + ", ".join(classes)
        + "; see trust statement limitations). "
    )
    if all(i.trust == PLATFORM_MANAGED for i in unconditioned):
        level, notes = analysis.privilege(role)
        elevated = level in ELEVATED or any("AdministratorAccess attached" in n for n in notes)
        severity = "MEDIUM" if elevated else "LOW"
        evidence = tuple(
            f"Platform-managed reclassification evidence: {text}"
            for text in sorted({i.text for i in unconditioned})
        )
        before = f"{verdict.finding_class}/{verdict.severity}"
        if (verdict.finding_class, verdict.severity) != ("BASELINE_DEVIATION", severity):
            verdict = replace(
                verdict,
                finding_class="BASELINE_DEVIATION",
                severity=severity,
                limitations=verdict.limitations + evidence,
            )
            return with_exposure(
                verdict,
                f"Reclassified from {before} to BASELINE_DEVIATION/{severity}: the trusted "
                "principal is the "
                "evidenced organization management account for an AWS-created access role. "
                + label,
            )
        return with_exposure(replace(verdict, limitations=verdict.limitations + evidence), label)
    return with_exposure(verdict, label)


def role_context(obs, verdict, context):
    analysis = context.iam
    role = _role(obs, context)
    if role is None:
        return verdict
    kind, basis = role_class(role.arn)
    extra = [f"Role class {kind} ({basis})" + (f": {ROLE_NOTES[kind]}" if kind in ROLE_NOTES
                                               else "") + "; severity kept"]  # fmt: skip
    note = organization_note(analysis, role.account)
    if note:
        extra.append(note)
    return replace(verdict, limitations=verdict.limitations + tuple(extra))


def workload_context(obs, verdict, context):
    """Exposed instances' instance-profile roles and privilege (E5 analogue)."""
    if str(verdict.outcome) != "FAIL":
        return verdict
    analysis = context.iam
    interfaces = [
        o
        for o in context.observations_by_id(verdict.related)
        if o.resource_type == "AWS::EC2::NetworkInterface"
    ]
    instances = context.instances(obs.region)
    lines, supported = [], []
    for interface in interfaces:
        instance_id = interface.configuration.get("AttachmentInstanceId")
        if not isinstance(instance_id, str):
            continue
        instance = instances.get((interface.account_id, instance_id))
        profile = instance.configuration.get("InstanceProfileArn") if instance else None
        if instance is None:
            lines.append(f"{instance_id}: instance configuration not collected (UNRESOLVED)")
            continue
        if not isinstance(profile, str):
            lines.append(f"{instance_id}: no instance profile in the collected configuration")
            continue
        roles = analysis.inventory.profiles.get(profile)
        if not roles:
            lines.append(f"{instance_id}: role of {profile} not collected (UNRESOLVED)")
            continue
        for arn in roles:
            role = analysis.inventory.by_arn.get(arn)
            if role is None:
                lines.append(f"{instance_id}: role {arn} not collected (UNRESOLVED)")
                continue
            level, _ = analysis.privilege(role)
            if level in SUPPORTED:
                supported.append(f"{instance_id} uses {arn} ({level})")
                lines.append(f"{instance_id}: role {arn} {level} (supported by evidence)")
            elif level == "NOT_SHOWN_PRIVILEGED":
                lines.append(
                    f"{instance_id}: role {arn} least privilege for the evaluated probes "
                    "(all escalation probes denied by evidence)"
                )
            else:
                lines.append(
                    f"{instance_id}: role {arn} privilege UNRESOLVED ({level}); not narrowed"
                )
    if not lines:
        return verdict
    verdict = replace(
        verdict,
        limitations=verdict.limitations + tuple("Workload identity: " + x for x in lines),
    )
    current = verdict.severity or "INFO"
    if (
        supported
        and verdict.finding_class == "POTENTIAL_EXPOSURE"
        and RANK.get(current, 0) < RANK["HIGH"]
    ):
        return with_exposure(
            replace(verdict, severity="HIGH"),
            f"Raised from {current} to HIGH: {len(supported)} internet-exposed instance "
            "role(s) with supported privileged permissions (see workload identity "
            "limitations). ",
        )
    if supported:
        return with_exposure(
            verdict,
            f"{len(supported)} exposed instance role(s) with supported privileged permissions "
            "(see workload identity limitations). ",
        )
    return verdict


def enrich(rule_id: str, obs, verdict, context):
    """Apply the opted-in enrichment for one rule result (see the table above)."""
    if context is None:
        return verdict
    if rule_id == TRUST_RULE:
        return trust_context(obs, verdict, context)
    if rule_id in ROLE_RULES:
        return role_context(obs, verdict, context)
    if rule_id == SG_RULE:
        return workload_context(obs, verdict, context)
    return verdict
