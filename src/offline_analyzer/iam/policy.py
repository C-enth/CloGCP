"""Typed IAM policy documents and three-valued statement matching.

Matching returns TRUE, FALSE or UNKNOWN. Anything outside the supported subset (policy
variables, unsupported condition operators, set operators, unknown request-context keys,
unrecognized elements) yields UNKNOWN with a reason; it is never treated as a match that
grants access. Supported subset is documented in docs/IAM_EVALUATION.md.
"""

import re
from dataclasses import dataclass, field

TRUE, FALSE, UNKNOWN = "TRUE", "FALSE", "UNKNOWN"
STATEMENT_KEYS = {
    "Sid",
    "Effect",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Principal",
    "NotPrincipal",
    "Condition",
}
STRING_OPERATORS = {
    "stringequals": (False, False, False),
    "stringnotequals": (True, False, False),
    "stringequalsignorecase": (False, True, False),
    "stringnotequalsignorecase": (True, True, False),
    "stringlike": (False, False, True),
    "stringnotlike": (True, False, True),
    "arnequals": (False, False, True),
    "arnlike": (False, False, True),
    "arnnotequals": (True, False, True),
    "arnnotlike": (True, False, True),
}


@dataclass(frozen=True)
class Condition:
    operator: str
    key: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class Statement:
    origin: str  # policy origin and statement index, for evidence trails
    effect: str
    actions: tuple[str, ...] | None = None
    not_actions: tuple[str, ...] | None = None
    resources: tuple[str, ...] | None = None
    not_resources: tuple[str, ...] | None = None
    principals: dict[str, tuple[str, ...]] | None = None
    not_principal: bool = False
    conditions: tuple[Condition, ...] = ()
    unsupported: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDocument:
    origin: str
    statements: tuple[Statement, ...]
    unsupported: tuple[str, ...] = field(default=())


def strings(value) -> tuple[str, ...] | None:
    items = value if isinstance(value, list) else [value]
    if not items or not all(isinstance(i, str) and i for i in items):
        return None
    return tuple(items)


def parse_statement(raw, origin: str) -> Statement:
    if not isinstance(raw, dict):
        return Statement(origin, "Unknown", unsupported=("statement is not an object",))
    issues = [f"unrecognized element {k}" for k in raw if k not in STATEMENT_KEYS]
    effect = raw.get("Effect")
    if effect not in {"Allow", "Deny"}:
        issues.append("Effect missing or unrecognized")
    values = {}
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        if key in raw:
            values[key] = strings(raw[key])
            if values[key] is None:
                issues.append(f"malformed {key}")
    if ("Action" in raw) == ("NotAction" in raw):
        issues.append("exactly one of Action/NotAction required")
    if "Resource" in raw and "NotResource" in raw:
        issues.append("both Resource and NotResource present")
    principals = None
    if "Principal" in raw:
        principal = raw["Principal"]
        if principal == "*":
            principals = {"AWS": ("*",)}
        elif isinstance(principal, dict) and principal:
            principals = {}
            for kind, value in principal.items():
                parsed = strings(value)
                if kind not in {"AWS", "Service", "Federated", "CanonicalUser"} or parsed is None:
                    issues.append("malformed Principal")
                else:
                    principals[kind] = parsed
        else:
            issues.append("malformed Principal")
    conditions = []
    block = raw.get("Condition")
    if block is not None:
        if not isinstance(block, dict):
            issues.append("malformed Condition")
        else:
            for operator, keys in block.items():
                if not isinstance(keys, dict) or not keys:
                    issues.append("malformed Condition")
                    continue
                for key, value in keys.items():
                    if isinstance(value, bool):
                        value = str(value).lower()
                    parsed = strings(value)
                    if parsed is None or not isinstance(key, str):
                        issues.append("malformed Condition value")
                    else:
                        conditions.append(Condition(str(operator), key, parsed))
    return Statement(
        origin=origin,
        effect=effect if effect in {"Allow", "Deny"} else "Unknown",
        actions=values.get("Action"),
        not_actions=values.get("NotAction"),
        resources=values.get("Resource"),
        not_resources=values.get("NotResource"),
        principals=principals,
        not_principal="NotPrincipal" in raw,
        conditions=tuple(conditions),
        unsupported=tuple(issues),
    )


def parse_policy(document, origin: str) -> PolicyDocument | None:
    """None when no document is available; never an empty 'allow nothing' stand-in."""
    if not isinstance(document, dict):
        return None
    raw = document.get("Statement")
    if raw is None:
        return PolicyDocument(origin, (), ("Statement missing",))
    items = raw if isinstance(raw, list) else [raw]
    return PolicyDocument(
        origin, tuple(parse_statement(s, f"{origin}#{i}") for i, s in enumerate(items))
    )


def wildcard(pattern: str, value: str, ignore_case: bool) -> bool:
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(regex, value, re.IGNORECASE if ignore_case else 0) is not None


def match_action(statement: Statement, action: str) -> str:
    if statement.actions is not None:
        return TRUE if any(wildcard(p, action, True) for p in statement.actions) else FALSE
    if statement.not_actions is not None:
        return FALSE if any(wildcard(p, action, True) for p in statement.not_actions) else TRUE
    return UNKNOWN


def match_resource(statement: Statement, resource: str | None) -> tuple[str, str | None]:
    """resource None = service-scoped request (several resource types, e.g. RunInstances):
    only a literal '*' Resource is supported; anything narrower needs service semantics."""
    patterns = statement.resources if statement.resources is not None else statement.not_resources
    if patterns is None:
        return (TRUE, None) if statement.principals is not None else (UNKNOWN, "Resource missing")
    if any("${" in p for p in patterns):
        return UNKNOWN, "policy variables not supported"
    negate = statement.resources is None
    if resource is None:
        if not negate and "*" in patterns:
            return TRUE, None
        return UNKNOWN, "service-specific resource semantics not supported"
    hit = any(wildcard(p, resource, False) for p in patterns)
    return (FALSE if hit else TRUE) if negate else (TRUE if hit else FALSE), None


def evaluate_condition(
    condition: Condition, context: dict[str, tuple[str, ...]]
) -> tuple[str, str | None]:
    operator = condition.operator.lower()
    if ":" in operator:  # ForAnyValue:/ForAllValues: set operators
        return UNKNOWN, f"set operator {condition.operator} not supported"
    if_exists = operator.endswith("ifexists")
    base = operator.removesuffix("ifexists")
    if base not in STRING_OPERATORS and base not in {"null", "bool"}:
        return UNKNOWN, f"condition operator {condition.operator} not supported"
    key = condition.key.lower()
    present = key in context
    if any("${" in v for v in condition.values):
        return UNKNOWN, "policy variables in condition values not supported"
    if base == "null":
        if condition.values not in {("true",), ("false",)}:
            return UNKNOWN, "malformed Null condition"
        if not present:
            return UNKNOWN, f"request context key {condition.key} unknown"
        absent = context[key] == ()
        return (TRUE if absent == (condition.values[0] == "true") else FALSE), None
    if not present:
        return UNKNOWN, f"request context key {condition.key} unknown"
    actual = context[key]
    if actual == ():  # key known to be absent from the request
        if if_exists:
            return TRUE, None
        negated = base in STRING_OPERATORS and STRING_OPERATORS[base][0]
        return (TRUE if negated else FALSE), None
    if base == "bool":
        values = {v.lower() for v in condition.values}
        return (TRUE if any(a.lower() in values for a in actual) else FALSE), None
    if base not in STRING_OPERATORS:
        return UNKNOWN, f"condition operator {condition.operator} not supported"
    negated, ignore_case, like = STRING_OPERATORS[base]
    if len(actual) != 1:
        return UNKNOWN, f"multi-valued key {condition.key} needs a set operator"

    def compare(pattern):
        if like:
            return wildcard(pattern, actual[0], ignore_case)
        return pattern.lower() == actual[0].lower() if ignore_case else pattern == actual[0]

    hit = any(compare(v) for v in condition.values)
    return (TRUE if hit != negated else FALSE), None


def evaluate_conditions(statement: Statement, context) -> tuple[str, tuple[str, ...]]:
    state, reasons = TRUE, []
    for condition in statement.conditions:
        result, reason = evaluate_condition(condition, context)
        if result == FALSE:
            return FALSE, ()
        if result == UNKNOWN:
            state = UNKNOWN
            reasons.append(reason)
    return state, tuple(reasons)
