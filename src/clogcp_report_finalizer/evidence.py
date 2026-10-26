"""Reconstruct exported excerpt parts, then select explicit fields without inventing data."""

import json
from collections import defaultdict
from dataclasses import dataclass, field

from .safety import FinalizerError, parse_json, pointer


@dataclass
class Evidence:
    mapping: str
    record: str
    project: str
    resource: str
    operation: str
    reference: str
    locator: str
    collected: str
    source_hash: str
    document: object = None
    limitation: str = ""


@dataclass
class Focus:
    record: str
    entries: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)


def table(sheet) -> list[dict]:
    rows = sheet.iter_rows(values_only=True)
    names = next(rows, ())
    if len(names) != len(set(names)):
        raise FinalizerError("DUPLICATE_TABLE_HEADERS")
    return [dict(zip(names, row, strict=False)) for row in rows if any(v is not None for v in row)]


def exported_evidence(books: list) -> dict[str, list[Evidence]]:
    found: dict[str, list[Evidence]] = defaultdict(list)
    for book in books:
        if "GCP_Evidence_Index" not in book:
            continue
        parts = defaultdict(list)
        if "GCP_Evidence_Details" in book:
            for row in table(book["GCP_Evidence_Details"]):
                parts[(row.get("Evidence mapping ID"), row.get("Record ID"))].append(row)
        for row in table(book["GCP_Evidence_Index"]):
            mapping, record = (
                str(row.get("Evidence mapping ID") or ""),
                str(row.get("Record ID") or ""),
            )
            e = Evidence(
                mapping,
                record,
                str(row.get("GCP project") or ""),
                str(row.get("Resource identifier") or ""),
                str(row.get("Source operation") or ""),
                str(row.get("Original evidence reference") or ""),
                str(row.get("JSON path") or ""),
                str(row.get("Collection time") or ""),
                str(row.get("SHA-256") or ""),
            )
            chunks = parts.get((mapping, record), [])
            try:
                ordered = sorted(chunks, key=lambda r: int(r.get("Excerpt part") or 0))
                if [int(r.get("Excerpt part") or 0) for r in ordered] != list(
                    range(1, len(ordered) + 1)
                ):
                    raise FinalizerError("EVIDENCE_PARTS_MISSING_OR_DUPLICATE")
                limitations = [str(r.get("Evidence limitation") or "") for r in ordered]
                if any(limitations):
                    raise FinalizerError("EXPORTED_EVIDENCE_LIMITED")
                text = "".join(str(r.get("Redacted original configuration") or "") for r in ordered)
                if not text:
                    raise FinalizerError("EVIDENCE_DETAIL_UNAVAILABLE")
                e.document = parse_json(text)
            except (ValueError, TypeError) as exc:
                if str(exc) == "CREDENTIAL_MATERIAL_REFUSED":
                    raise
                e.limitation = "Evidence detail unavailable: " + str(exc)
            found[record].append(e)
    return dict(found)


QUALIFIERS = {
    "condition",
    "conditions",
    "denyRule",
    "denyRules",
    "denied",
    "rules",
    "disabled",
    "priority",
    "direction",
    "targetTags",
    "targetServiceAccounts",
    "sourceRanges",
    "destinationRanges",
    "publicAccessPrevention",
    "uniformBucketLevelAccess",
    "ingress",
    "ingressSettings",
    "serviceAccount",
    "serviceAccountName",
    "serviceAccountEmail",
    "network",
    "privateClusterConfig",
    "enableAutopilot",
    "autopilot",
    "workloadIdentityConfig",
    "ipConfiguration",
    "settings",
    "auditConfigs",
    "exemptedMembers",
    "logType",
    "sinks",
    "exclusions",
    "filter",
    "enforced",
    "inheritFromParent",
    "reset",
    "spec",
    "policy",
    "etag",
    "version",
    "name",
    "parent",
}


def sibling_context(document: object, selectors: list[str]) -> dict:
    """Keep qualification fields along selected ancestor objects; never dump other bindings."""
    result = {}
    paths = {""}
    for path in selectors:
        bits = path.split("/")
        paths.update("/".join(bits[:n]) for n in range(1, len(bits)))
    for path in sorted(paths):
        node = pointer(document, path)
        if isinstance(node, dict):
            for key, value in node.items():
                # Whole 'policy/spec/settings' containers may hide unrelated bindings.
                deny_rules = (
                    key == "rules"
                    and isinstance(value, list)
                    and any(isinstance(r, dict) and "denyRule" in r for r in value)
                )
                if key in QUALIFIERS and (
                    key not in {"policy", "spec", "settings", "rules"} or deny_rules
                ):
                    result[path + "/" + key] = value
    return result


def focus(record: str, entries: list[Evidence], guidance: dict | None) -> Focus:
    result = Focus(record, context=guidance or {})
    if not entries:
        result.limitations.append("Evidence detail unavailable: no exported evidence index entry")
    for entry in entries:
        if entry.limitation:
            result.limitations.append(entry.limitation)
            continue
        selectors = (guidance or {}).get("selectors", {}).get(entry.mapping, [])
        if not isinstance(selectors, list) or any(not isinstance(v, str) for v in selectors):
            raise FinalizerError("INVALID_EVIDENCE_SELECTORS")
        try:
            if selectors:
                if (
                    "" in selectors
                    and isinstance(entry.document, dict)
                    and "bindings" in entry.document
                ):
                    raise FinalizerError("WHOLE_POLICY_SELECTOR_REFUSED")
                selected = {p: pointer(entry.document, p) for p in selectors}
                qualifiers = sibling_context(entry.document, selectors)
            elif (
                isinstance(entry.document, dict)
                and "bindings" not in entry.document
                and len(json.dumps(entry.document)) <= 1800
            ):
                selected, qualifiers = {entry.locator or "(exported object)": entry.document}, {}
            else:
                raise FinalizerError("PRECISE_SELECTOR_REQUIRED")
            result.entries.append(
                {
                    "mapping": entry.mapping,
                    "project": entry.project,
                    "resource": entry.resource,
                    "operation": entry.operation,
                    "reference": entry.reference,
                    "locator": entry.locator,
                    "collected": entry.collected,
                    "source_sha256": entry.source_hash,
                    "selected": selected,
                    "qualifying_controls": qualifiers,
                    "qualification": (
                        "Exported redacted configuration; original raw bytes not independently "
                        "verified by this tool"
                    ),
                }
            )
        except (FinalizerError, TypeError, KeyError) as exc:
            result.limitations.append("Evidence detail unavailable: " + str(exc))
    if not result.entries and not result.limitations:
        result.limitations.append("Evidence detail unavailable")
    return result
