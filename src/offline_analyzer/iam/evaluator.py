"""Bounded deterministic IAM authorization reasoning (analyzer conclusions, not AWS answers).

Supported scenarios, and nothing else:
1. Identity-based decision for a role principal: identity policies, permissions boundary
   and applicable SCPs. Used for iam:PassRole, service operations and sts:AssumeRole.
   No resource-based policy participates; generic same-account resource authorization
   (S3/KMS/etc.) is out of scope.
2. Cross-account sts:AssumeRole: source identity decision AND target trust policy AND
   target-account RCPs. Same-account AssumeRole is not evaluated (different semantics).

States: ALLOWED_WITH_SUPPORTED_CONTEXT, DENIED_BY_EVIDENCE, POTENTIALLY_ALLOWED, UNKNOWN.
Session policies are not evaluated (an attacker controlling the principal need not use
them); this is recorded on every decision.
"""

import re
from dataclasses import dataclass, field

from offline_analyzer.iam.organizations import NOT_APPLICABLE, NOT_COLLECTED, RCP, SCP
from offline_analyzer.iam.policy import (
    FALSE,
    TRUE,
    UNKNOWN,
    PolicyDocument,
    evaluate_conditions,
    match_action,
    match_resource,
)

ALLOWED = "ALLOWED_WITH_SUPPORTED_CONTEXT"
DENIED = "DENIED_BY_EVIDENCE"
POTENTIAL = "POTENTIALLY_ALLOWED"
UNKNOWN_DECISION = "UNKNOWN"
SESSION_NOTE = "Session policies not evaluated"
ROLE_ARN = re.compile(r"^arn:[^:]+:iam::([0-9]{12}):role/(?:.*/)?([^/]+)$")


@dataclass(frozen=True)
class Request:
    action: str
    resource: str | None  # None = service-scoped (multiple resource types)
    context: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass
class Decision:
    state: str
    supporting: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "state": self.state,
            "supporting": sorted(set(self.supporting)),
            "blocking": sorted(set(self.blocking)),
            "missing": sorted(set(self.missing)),
        }


def worst(*states: str) -> str:
    order = {TRUE: 0, UNKNOWN: 1, FALSE: 2}
    return max(states, key=order.__getitem__)


STRUCTURAL = "STRUCTURAL"  # statement shape cannot be evaluated (stronger than UNKNOWN)


def statement_applies(
    statement, request: Request, principal_match=None
) -> tuple[str, tuple[str, ...]]:
    action = match_action(statement, request.action)
    if action == FALSE:
        return FALSE, ()
    if statement.unsupported:
        return STRUCTURAL, statement.unsupported
    resource, reason = match_resource(statement, request.resource)
    if resource == FALSE:
        return FALSE, ()
    reasons = (reason,) if reason else ()
    principal = TRUE
    if principal_match is not None:
        principal = principal_match(statement)
        if principal == FALSE:
            return FALSE, ()
        if principal == UNKNOWN:
            reasons += ("principal match unresolved",)
    elif statement.principals is not None or statement.not_principal:
        return STRUCTURAL, ("Principal element in an identity policy",)
    condition, condition_reasons = evaluate_conditions(statement, request.context)
    if condition == FALSE:
        return FALSE, ()
    return worst(action, resource, principal, condition), reasons + condition_reasons


def evaluate_documents(
    documents: list[PolicyDocument], request: Request, principal_match=None
) -> dict:
    result = {
        "allow_true": [],
        "allow_unknown": [],
        "allow_unsupported": [],
        "deny_true": [],
        "deny_unknown": [],
        "reasons": [],
    }
    for document in documents:
        if document.unsupported:
            result["allow_unsupported"].append(document.origin)
            result["deny_unknown"].append(document.origin)
            result["reasons"] += list(document.unsupported)
        for statement in document.statements:
            state, reasons = statement_applies(statement, request, principal_match)
            if state == FALSE:
                continue
            if state == STRUCTURAL or statement.effect not in {"Allow", "Deny"}:
                # Unevaluable shape: may allow or deny; never counted as a resolved Allow.
                result["allow_unsupported"].append(statement.origin)
                result["deny_unknown"].append(statement.origin)
            else:
                key = f"{statement.effect.lower()}_{'true' if state == TRUE else 'unknown'}"
                result[key].append(statement.origin)
            result["reasons"] += list(reasons)
    return result


def rcp_principal(statement) -> str:
    """RCP statements use Principal "*"; narrower principals are unresolved here."""
    values = (statement.principals or {}).get("AWS", ())
    return TRUE if values == ("*",) else UNKNOWN


def evaluate_rcp_documents(documents, request: Request) -> dict:
    return evaluate_documents(documents, request, rcp_principal)


def evaluate_identity(inventory, org, role, request: Request) -> Decision:
    """Identity policies + permissions boundary + SCPs for one role principal."""
    documents, unresolved = inventory.identity_documents(role)
    identity = evaluate_documents(documents, request)
    decision = Decision(UNKNOWN_DECISION, missing=list(unresolved), notes=[SESSION_NOTE])
    decision.supporting += identity["allow_true"]
    decision.missing += identity["reasons"]
    if identity["deny_true"]:
        decision.state, decision.blocking = DENIED, identity["deny_true"]
        return decision
    boundary_state = TRUE
    if role.boundary_arn:
        boundary = inventory.managed_document(role.boundary_arn)
        if boundary is None:
            boundary_state = UNKNOWN
            decision.missing.append(f"permissions boundary document {role.boundary_arn}")
        else:
            bound = evaluate_documents([boundary], request)
            decision.missing += bound["reasons"]
            if bound["deny_true"]:
                decision.state, decision.blocking = DENIED, bound["deny_true"]
                return decision
            if bound["allow_true"] and not bound["deny_unknown"]:
                decision.supporting += [f"boundary {o}" for o in bound["allow_true"]]
            elif bound["allow_true"] or bound["allow_unknown"]:
                boundary_state = UNKNOWN
            else:
                decision.state = DENIED
                decision.blocking = [
                    f"permissions boundary {role.boundary_arn} does not allow {request.action}"
                ]
                return decision
    scp = org.evaluate(role.account, SCP, request, evaluate_documents, role.service_linked)
    if scp.state == FALSE:
        decision.state, decision.blocking = DENIED, scp.blocking
        return decision
    decision.missing += scp.missing
    decision.supporting += scp.supporting
    if scp.state == NOT_APPLICABLE:
        decision.notes.append(scp.reason)
    if identity["allow_true"]:
        clean = not (identity["deny_unknown"] or unresolved)
        if clean and boundary_state == TRUE and scp.state in {TRUE, NOT_APPLICABLE}:
            decision.state = ALLOWED
        else:
            decision.state = POTENTIAL
    elif identity["allow_unknown"]:
        decision.state = POTENTIAL
    elif identity["allow_unsupported"]:
        decision.state = UNKNOWN_DECISION
    elif not unresolved:
        decision.state = DENIED
        decision.blocking = [f"no identity policy statement allows {request.action}"]
        decision.missing = []  # implicit deny does not depend on missing evidence
    return decision


def trust_principal_match(source_arn: str, source_account: str):
    """AWS principal matching for a role source; sessions and unique IDs are unresolved."""

    def match(statement) -> str:
        if statement.not_principal:
            return UNKNOWN
        values = (statement.principals or {}).get("AWS", ())
        state = FALSE
        for value in values:
            if value == "*" or value == source_account or value == source_arn:
                return TRUE
            if value == f"arn:{source_arn.split(':')[1]}:iam::{source_account}:root":
                return TRUE
            if ":assumed-role/" in value or re.fullmatch(r"A[A-Z0-9]{15,}", value):
                state = UNKNOWN
        return state

    return match


def evaluate_trust(target, source_arn: str, source_account: str, request: Request) -> Decision:
    if target.trust is None:
        return Decision(UNKNOWN_DECISION, missing=[f"trust policy of {target.arn}"])
    result = evaluate_documents(
        [target.trust], request, trust_principal_match(source_arn, source_account)
    )
    decision = Decision(
        UNKNOWN_DECISION, supporting=result["allow_true"], missing=result["reasons"]
    )
    if result["deny_true"]:
        decision.state, decision.blocking = DENIED, result["deny_true"]
    elif result["allow_true"] and not result["deny_unknown"]:
        decision.state = ALLOWED
    elif result["allow_true"] or result["allow_unknown"]:
        decision.state = POTENTIAL
    elif not target.trust.unsupported and not result["allow_unsupported"]:
        decision.state = DENIED
        decision.blocking = [f"trust policy of {target.arn} grants no matching principal"]
    return decision


def assume_context(source_arn, source_account, target_account, org) -> dict:
    context = {
        "aws:principalarn": (source_arn,),
        "aws:principalaccount": (source_account,),
        "aws:resourceaccount": (target_account,),
        "aws:principalisawsservice": ("false",),
    }
    organization = org.organization_id
    if organization and source_account in {
        a for a, parents in org.parents.items() if parents and a.isdigit()
    }:
        context["aws:principalorgid"] = (organization,)
    if source_account in org.outside:
        context["aws:principalorgid"] = ()
    return context


def evaluate_assume(inventory, org, source, target) -> Decision:
    """Cross-account only: source identity AND target trust AND target RCPs."""
    if source.account == target.account:
        return Decision(UNKNOWN_DECISION, missing=["same-account AssumeRole is not evaluated"])
    request = Request(
        "sts:AssumeRole",
        target.arn,
        assume_context(source.arn, source.account, target.account, org),
    )
    identity = evaluate_identity(inventory, org, source, request)
    trust = evaluate_trust(target, source.arn, source.account, request)
    rcp = org.evaluate(target.account, RCP, request, evaluate_rcp_documents)
    decision = Decision(
        UNKNOWN_DECISION,
        supporting=[f"source {s}" for s in identity.supporting]
        + [f"trust {s}" for s in trust.supporting],
        missing=identity.missing + trust.missing + rcp.missing,
        notes=identity.notes + [f"target {RCP}: {rcp.state}"],
    )
    for component in (identity, trust):
        if component.state == DENIED:
            decision.state, decision.blocking = DENIED, component.blocking
            return decision
    if rcp.state == FALSE:
        decision.state, decision.blocking = DENIED, rcp.blocking
        return decision
    if UNKNOWN_DECISION in (identity.state, trust.state):
        decision.state = UNKNOWN_DECISION
    elif identity.state == trust.state == ALLOWED and rcp.state in {TRUE, NOT_APPLICABLE}:
        decision.state = ALLOWED
    else:
        decision.state = POTENTIAL
        if rcp.state == NOT_COLLECTED:
            decision.missing.append(f"{RCP} evidence for target account {target.account}")
    return decision
