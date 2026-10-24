"""Cross-account assume-role trust conditions (methodology AWS-04 clauses P1/F1).

Deterministic reading of one role's trust policy. It does not evaluate role permission
policies, SCPs/RCPs, principal-side permissions or Access Analyzer findings, so it never
establishes that a principal can actually assume the role.
"""

import re

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Verdict

ARN_PRINCIPAL = re.compile(r"^arn:(?:aws|aws-cn|aws-us-gov):(?:iam|sts)::([0-9]{12}):(.+)$")
# Only these keys bind the caller to the organization or to a shared external secret.
BINDING_KEYS = {"aws:principalorgid", "sts:externalid"}
# Positive single-value operators. *IfExists and set operators can match when the key is
# absent; Null only tests presence. Those are never treated as binding.
BINDING_OPERATORS = {"stringequals", "stringequalsignorecase", "stringlike"}
LIMITATIONS = (
    "Outcome reflects the trust clause only; authorization of specific callers is reported "
    "separately as IAM investigations",
    "Trust configuration alone does not establish that any principal can or did assume the role",
)


def as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def grants_assume_role(action) -> bool | None:
    actions = as_list(action)
    if not actions or not all(isinstance(a, str) and a for a in actions):
        return None
    for pattern in actions:
        # IAM action wildcards are only * and ?; everything else is literal.
        regex = re.escape(pattern.lower()).replace(r"\*", ".*").replace(r"\?", ".")
        if re.fullmatch(regex, "sts:assumerole"):
            return True
    return False


def aws_principals(statement: dict) -> tuple[list[str], str | None]:
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"], None
    if not isinstance(principal, dict) or not principal:
        return [], "statement principal missing or malformed"
    values = []
    for kind, value in principal.items():
        if kind not in {"AWS", "Service", "Federated", "CanonicalUser"}:
            return [], "unrecognized principal type"
        items = as_list(value)
        if not items or not all(isinstance(item, str) and item for item in items):
            return [], "malformed principal value"
        if kind == "AWS":
            values.extend(items)
    return values, None


def principal_account(value: str) -> tuple[str | None, bool]:
    """Return (account, account_root_or_wildcard); account None means unresolved."""
    if value == "*":
        return "*", True
    if re.fullmatch(r"[0-9]{12}", value):
        return value, True
    match = ARN_PRINCIPAL.fullmatch(value)
    if match:
        return match.group(1), match.group(2) == "root"
    return None, False


def concrete(values, wildcard_operator: bool) -> bool:
    items = as_list(values)
    if not items or not all(isinstance(item, str) and item for item in items):
        return False
    return not (wildcard_operator and any("*" in item or "?" in item for item in items))


def conditions(statement: dict) -> tuple[bool, tuple[str, ...], str | None]:
    """Return (binding condition present, other condition operator:key pairs, error)."""
    block = statement.get("Condition")
    if block is None:
        return False, (), None
    if not isinstance(block, dict):
        return False, (), "malformed Condition block"
    binding, others = False, []
    for operator, keys in block.items():
        if not isinstance(operator, str) or not isinstance(keys, dict) or not keys:
            return False, (), "malformed Condition block"
        for key, value in keys.items():
            op = operator.lower()
            if (
                isinstance(key, str)
                and key.lower() in BINDING_KEYS
                and op in BINDING_OPERATORS
                and concrete(value, op == "stringlike")
            ):
                binding = True
            else:
                others.append(f"{operator}:{key}")
    return binding, tuple(sorted(others)), None


def statement_list(document) -> list | None:
    if not isinstance(document, dict):
        return None
    statements = document.get("Statement")
    statements = as_list(statements) if statements is not None else None
    if not statements or not all(isinstance(s, dict) for s in statements):
        return None
    return statements


ELEVATED = {"ADMIN_EQUIVALENT", "ESCALATION_CAPABLE", "POTENTIALLY_PRIVILEGED"}
SUPPORTED_PRIVILEGE = {"ADMIN_EQUIVALENT", "ESCALATION_CAPABLE"}


def canonical_role(obs: Normalized, context):
    if context is None or not hasattr(context, "iam") or not obs.native_id:
        return None
    return context.iam.inventory.roles.get((obs.account_id, obs.native_id.rsplit("/", 1)[-1]))


def classify_failure(obs, context, external: set[str], wildcard: bool) -> dict:
    """Class/severity for a source-F1 failure. CRITICAL needs supported access AND
    supported privilege; trust configuration alone never establishes either."""
    role = canonical_role(obs, context)
    analysis = context.iam if role else None
    level, notes = analysis.privilege(role) if role else ("UNRESOLVED", [])
    indicated = any("AdministratorAccess attached" in n for n in notes)
    elevated = level in ELEVATED or indicated
    registered = context.registry.accounts if context and context.registry else {}
    needed = ["IAM Access Analyzer external-access findings"]
    compensating = []
    if role and analysis.org.applicability(role.account, "SERVICE_CONTROL_POLICY", False) == (
        "NOT_COLLECTED"
    ):
        needed.append("Organizations SCP/RCP evidence")
    if wildcard:
        scope = "any AWS principal"
        rcp_state = "NOT_COLLECTED"
        if role:
            from offline_analyzer.iam.evaluator import Request, evaluate_rcp_documents

            layer = analysis.org.evaluate(
                role.account,
                "RESOURCE_CONTROL_POLICY",
                Request("sts:AssumeRole", role.arn, {"aws:resourceaccount": (role.account,)}),
                evaluate_rcp_documents,
            )
            rcp_state = layer.state
            if layer.state == "FALSE":
                compensating.append("RCP blocks: " + "; ".join(layer.blocking))
            needed += layer.missing
        if rcp_state == "FALSE":
            finding_class, severity = "BASELINE_DEVIATION", "MEDIUM" if elevated else "LOW"
        elif rcp_state in {"TRUE", "NOT_APPLICABLE"}:
            # External callers control their own identity policies and SCPs; the target
            # side (trust, RCP) is evidenced, so assumption by an outside principal is
            # supported. CRITICAL only with a resolved escalation-capable role.
            finding_class = "SUPPORTED_SECURITY_GAP"
            severity = "CRITICAL" if level in SUPPORTED_PRIVILEGE else "HIGH"
        else:
            finding_class, severity = "POTENTIAL_EXPOSURE", "HIGH" if elevated else "MEDIUM"
            needed.append(f"RCP evidence for account {obs.account_id}")
        scope += f" (target RCP state: {rcp_state})"
    elif external <= set(registered):
        finding_class, severity = "BASELINE_DEVIATION", "MEDIUM" if elevated else "LOW"
        scope = f"registered assessment account(s) {', '.join(sorted(external))}"
    else:
        finding_class, severity = "POTENTIAL_EXPOSURE", "HIGH" if elevated else "MEDIUM"
        unknown = sorted(external - set(registered))
        scope = f"account(s) not in the approved registry: {', '.join(unknown)}"
        needed.append("ownership of the trusted account (registry or vendor inventory)")
        needed.append("identity policies of principals in the trusted account")
    transitions = ""
    if role:
        records = [r for r in analysis.transitions() if r.target == role.arn]
        counts = {}
        for record in records:
            counts[record.classification] = counts.get(record.classification, 0) + 1
        transitions = "; investigated transitions: " + (
            ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
        )
        # Source-side gaps stay on the investigation records; only uncollected trusted
        # accounts are surfaced on the target finding.
        needed += [
            m for r in records for m in r.missing if m.startswith("IAM evidence for account")
        ]
        needed += [m for m in analysis.privilege_missing(role) if "evidence for account" not in m]
        if role.boundary_arn:
            compensating.append(f"Permissions boundary attached: {role.boundary_arn}")
    return dict(
        finding_class=finding_class,
        severity=severity,
        exposure=f"Trust allows sts:AssumeRole from {scope} without binding conditions; "
        f"role privilege {level}"
        + (" (AdministratorAccess indicated, unresolved)" if indicated else "")
        + transitions
        + ". Trust configuration alone does not establish effective access",
        evidence_needed=tuple(sorted(set(needed))),
        compensating=tuple(compensating),
    )


def trust_conditions(obs: Normalized, context=None) -> Verdict:
    owner = obs.account_id
    role = canonical_role(obs, context)
    if role is not None and role.trust_raw is None:
        return Verdict(
            Outcome.UNKNOWN,
            "Trust policy is missing or conflicts across collected sources for this role.",
            ("consistent AssumeRolePolicyDocument",),
            limitations=LIMITATIONS,
        )
    document = role.trust_raw if role else obs.configuration.get("AssumeRolePolicyDocument")
    statements = statement_list(document)
    if statements is None or not owner:
        return Verdict(
            Outcome.UNKNOWN,
            "Trust policy document or role owner account is missing or unparseable.",
            ("parseable AssumeRolePolicyDocument and role ARN",),
            limitations=LIMITATIONS,
        )
    if any({"NotPrincipal", "NotAction"} & set(s) or s.get("Effect") == "Deny" for s in statements):
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            "Trust policy uses Deny, NotPrincipal or NotAction; these can offset or widen "
            "Allow statements and are not evaluated automatically.",
            ("analyst review of Deny/NotPrincipal/NotAction trust semantics",),
            limitations=LIMITATIONS,
        )
    failures, manual, unknown, bound = [], [], [], []
    failed_accounts, wildcard = set(), False
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            unknown.append(f"statement {index}: Effect missing or unrecognized")
            continue
        granted = grants_assume_role(statement.get("Action"))
        if granted is None:
            unknown.append(f"statement {index}: Action missing or malformed")
            continue
        if not granted:
            continue  # Federated/other STS actions are outside AWS-04 (see AWS-27).
        principals, error = aws_principals(statement)
        has_binding, other_conditions, condition_error = conditions(statement)
        if error or condition_error:
            unknown.append(f"statement {index}: {error or condition_error}")
            continue
        external, unresolved, root_like = [], [], False
        for value in principals:
            account, is_root = principal_account(value)
            if account is None:
                unresolved.append(value)
            elif account != owner:
                external.append(account)
                root_like |= is_root
        if unresolved:
            manual.append(
                f"statement {index}: principal format unresolved (for example a deleted "
                "principal's unique ID)"
            )
        if not external:
            continue
        accounts = ", ".join(sorted(set(external)))
        if has_binding:
            bound.append(f"statement {index}: cross-account trust ({accounts}) is bound")
        elif root_like and not statement.get("Condition"):
            failed_accounts |= set(external) - {"*"}
            wildcard |= "*" in external
            failures.append(
                f"statement {index}: sts:AssumeRole allowed for "
                + ("any AWS principal" if "*" in external else f"account principal(s) {accounts}")
                + " with no Condition"
            )
        elif other_conditions:
            manual.append(
                f"statement {index}: cross-account trust ({accounts}) has conditions "
                f"({', '.join(other_conditions)}) but no PrincipalOrgID/ExternalId binding"
            )
        else:
            registered = context.registry.accounts if context and context.registry else {}
            known = set(external) <= set(registered)
            manual.append(
                f"statement {index}: specific cross-account principal(s) in {accounts} without "
                "PrincipalOrgID/ExternalId; "
                + (
                    "principal is in a registered assessment account (likely internal; the "
                    "source PASS clause still requires a binding condition)"
                    if known
                    else "third-party status needs organization or vendor evidence"
                )
            )
    if failures:
        return Verdict(
            Outcome.FAIL,
            "Unconditioned cross-account trust: " + "; ".join(failures) + ".",
            limitations=LIMITATIONS + tuple(manual + unknown),
            **classify_failure(obs, context, failed_accounts, wildcard),
        )
    if unknown:
        return Verdict(
            Outcome.UNKNOWN,
            "Trust policy could not be fully interpreted: " + "; ".join(unknown) + ".",
            ("well-formed trust policy statements",),
            limitations=LIMITATIONS,
        )
    if manual:
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            "Cross-account trust needs analyst validation: " + "; ".join(manual) + ".",
            (
                "Organizations account list or approved vendor inventory",
                "methodology clarification of acceptable non-ExternalId/OrgID conditions",
            ),
            limitations=LIMITATIONS,
        )
    if bound:
        return Verdict(
            Outcome.PASS,
            "Every cross-account sts:AssumeRole grant carries a concrete PrincipalOrgID or "
            "ExternalId condition: " + "; ".join(bound) + ".",
            limitations=LIMITATIONS,
        )
    return Verdict(
        Outcome.NOT_APPLICABLE,
        "Trust policy grants sts:AssumeRole to no AWS principal outside the role's account.",
        limitations=LIMITATIONS,
    )
