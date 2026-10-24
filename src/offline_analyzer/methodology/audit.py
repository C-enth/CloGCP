"""Local-only methodology audit: reviewed-layout parse, integrity checks, private matrices.

Reads the approved workbook read-only from a verified snapshot, never evaluates formulas
and fails closed when the reviewed sheet/header layout changes. Outputs contain source
text and are private: write them only under ignored directories. The CLI prints counts.
"""

import argparse
import json
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from openpyxl import Workbook, load_workbook

from offline_analyzer.attack_paths.specs import BY_PATH, PATHS, THREAT_SCOPE
from offline_analyzer.contracts.r0 import AWS_OPERATIONS
from offline_analyzer.ingestion.safety import excel_literal, sha256_file
from offline_analyzer.methodology.coverage_spec import (
    BY_CONTROL,
    COVERAGE,
    REVIEW_ITEMS,
    REVIEWED_METHODOLOGY_SHA256,
)
from offline_analyzer.methodology.extract import MAX_FILE_BYTES, preflight
from offline_analyzer.reporting.tracker import TRACKER_COLUMNS

AUDIT_VERSION = "1.0.0"
# Reviewed layout of the approved workbook: (sheet, header row, exact headers).
LAYOUT = {
    "dictionary": (
        "Data Dictionary",
        3,
        ("Sheet", "Field / Column", "Definition", "Allowed values / format"),
    ),
    "reconciliation": (
        "Source Reconciliation",
        3,
        (
            "Source workbook",
            "Source sheet",
            "Record set",
            "Count",
            "Destination in master",
            "Reconciliation note",
        ),
    ),
    "accounts": (
        "Account Inventory",
        3,
        (
            "Account ID",
            "AWS Account # (12-digit)",
            "Account Name / Alias",
            "Environment",
            "Organizational Unit (OU)",
            "Account Owner",
            "Primary Region(s)",
            "Scope Status",
            "Onboarded to Control Tower?",
            "Notes",
        ),
    ),
    "controls": (
        "Control Library",
        3,
        (
            "Control ID",
            "Domain",
            "Control Area",
            "Check Item",
            "STRIDE Category",
            "Automation Type",
            "Assessment Tool",
            "Collection Instructions",
            "Validation Instructions",
            "Pass Criteria",
            "Fail Indicator",
            "Priority Tier",
            "Inherent Severity",
            "Exploitability",
            "Attack Phase",
            "Primary Asset",
            "Linked STRIDE #",
            "Linked Attack Path",
            "SEBI Ref",
            "Evidence Type",
            "Output Document",
            "Source",
        ),
    ),
    "results": ("Account Control Results", 3, TRACKER_COLUMNS),
    "findings": (
        "Findings Register",
        3,
        (
            "Finding ID",
            "Title",
            "Domain",
            "Asset / Component",
            "STRIDE",
            "CVSS v4.0 Base",
            "CVSS v4.0 Severity",
            "CVSS v4.0 Vector",
            "Status",
            "Affected Accounts",
            "Linked Control IDs",
            "Linked Attack Path",
            "SEBI Ref",
            "Business Impact",
            "Precondition / Weakness",
            "Remediation",
            "Remediation Owner",
            "Remediation Due",
            "Evidence Ref",
            "Identified By",
            "Identified Date",
            "Notes",
        ),
    ),
    "evidence": (
        "Technical Evidence",
        3,
        (
            "Evidence ID",
            "Linked Finding ID(s)",
            "Linked Control ID(s)",
            "Linked Account ID(s)",
            "Evidence Type",
            "Collection Tool / Method",
            "Description",
            "File / Artifact Reference",
            "Storage Location",
            "Integrity Hash (SHA-256)",
            "Sensitivity",
            "Collected By",
            "Collected Date",
        ),
    ),
    "stride_validation": (
        "STRIDE Validation",
        3,
        (
            "Validation ID",
            "Threat Ref",
            "Scenario Name",
            "STRIDE",
            "Domain",
            "Linked Checklist IDs",
            "Attack Path",
            "Scope Type",
            "Scope Ref (Account/Env/Org)",
            "Validation Status",
            "Exploitability Confirmed",
            "Linked Finding IDs",
            "Evidence Ref",
            "Validated By",
            "Validated Date",
            "Notes",
        ),
    ),
    "path_validation": (
        "Attack Path Validation",
        3,
        (
            "Validation ID",
            "Attack Path",
            "AP Name",
            "Domains",
            "Inherent Severity",
            "Scope Ref",
            "Chain Viability",
            "Entry Validated",
            "Escalation Validated",
            "Detection Validated",
            "Linked Finding IDs",
            "Evidence Ref",
            "Validated By",
            "Validated Date",
            "Notes",
        ),
    ),
    "threats": (
        "STRIDE Threat Library",
        3,
        (
            "Threat Ref",
            "Domain",
            "STRIDE",
            "Asset / Component",
            "Attacker Action",
            "Exploit Path",
            "Trust Boundary Crossed",
            "Objective",
            "Precondition / Weakness",
            "Impact if Successful",
            "Checklist IDs",
            "Attack Path",
            "Risk Level",
            "CVSS 3.1 (source)",
            "CVSS 3.1 Vector (source)",
            "Source Remediation",
        ),
    ),
    "paths": (
        "Attack Path Library",
        3,
        (
            "AP Code",
            "Attack Path Name",
            "Kill Chain Summary",
            "Domains Spanned",
            "STRIDE Categories",
            "Linked Controls / Checklist",
            "Linked Threats",
            "Inherent Severity",
            "Source",
            "Dedup / Cross-Reference Note",
        ),
    ),
    "scenarios": (
        "Adversary Scenarios",
        3,
        (
            "Scenario ID",
            "Scenario Name",
            "Attack Path",
            "Source Finding Ref",
            "Domain",
            "CVSS 3.1 (source)",
            "Entry Point",
            "Entry Technique",
            "Lateral Movement / Pivot",
            "Target / Crown Jewel",
            "Objective",
            "Detection Status",
            "SEBI CSCRF Ref",
            "SOW Validation Step",
            "Validation Status",
        ),
    ),
    "mitre": (
        "Kill Chain & MITRE",
        3,
        (
            "Scenario ID",
            "Attack Path",
            "CVSS 3.1",
            "MITRE Initial Access",
            "MITRE Credential Access",
            "MITRE Lateral Movement",
            "MITRE Privilege Escalation",
            "Target (Crown Jewel)",
            "Impact Category",
        ),
    ),
    "sebi": (
        "SEBI CSCRF Map",
        3,
        (
            "#",
            "Source Ref",
            "Asset",
            "STRIDE",
            "Risk",
            "CVSS 3.1",
            "SEBI Domain",
            "SEBI Control Objective",
            "SEBI Ref",
            "Gap Description",
            "Remediation Commitment",
        ),
    ),
    "lists": ("_Lists", 1, None),
}
# Data Dictionary vocabulary entries reconciled against the dropdown lists.
VOCABULARIES = {
    ("Account Inventory", "Environment"): "Environment",
    ("Account Inventory", "Status"): "AccountStatus",
    ("Control Library", "Automation Type"): "Automation",
    ("Account Control Results", "Analyst_Status"): "ResultStatus",
    ("Account Control Results", "Analyst_Validated"): "AnalystValidated",
    ("STRIDE Validation", "Validation Status"): "ValidationStatus",
    ("Attack Path Validation", "Chain Viability"): "ChainViability",
    ("Technical Evidence", "Sensitivity"): "Sensitivity",
}
CAPTIONS = {
    "controls": "controls",
    "threats": "threats",
    "paths": "paths",
    "scenarios": "scenarios",
}
BLANK = {None, "", "—", "-", "None"}
MAX_ROWS = 20000


class LayoutError(ValueError):
    """Fixed codes only; never includes workbook content."""


def text(value) -> str:
    return "" if value is None else str(value).strip()


def blank(value) -> bool:
    return text(value) in BLANK


def read_layout(workbook) -> tuple[dict[str, list[dict]], dict[str, list[str]]]:
    """Parse every reviewed table; return records and caption text (rows above headers)."""
    tables, captions = {}, {}
    for key, (name, header_row, headers) in LAYOUT.items():
        if name not in workbook.sheetnames:
            raise LayoutError(f"LAYOUT_SHEET_MISSING:{key}")
        sheet = workbook[name]
        sheet.reset_dimensions()
        rows = sheet.iter_rows(values_only=True)
        captions[key] = []
        for _ in range(header_row - 1):
            captions[key].extend(text(v) for v in next(rows, ()) if not blank(v))
        found = tuple(text(v) for v in next(rows, ()))
        if headers is None:
            headers = tuple(h for h in found if h)
        elif found[: len(headers)] != headers:
            raise LayoutError(f"LAYOUT_HEADER_MISMATCH:{key}")
        records = []
        for index, row in enumerate(rows, start=header_row + 1):
            if index > MAX_ROWS:
                raise LayoutError(f"LAYOUT_ROW_LIMIT:{key}")
            # Read-only rows stop at the last populated cell; pad to the reviewed header.
            values = {h: row[i] if i < len(row) else None for i, h in enumerate(headers)}
            if key != "lists" and blank(values.get(headers[0])):
                continue
            values["_row"] = index
            records.append(values)
        tables[key] = records
    return tables, captions


def ids(values) -> list[str]:
    return re.findall(r"AWS-\d\d|\d+\.\d+\.\d+", text(values))


def threat_refs(values) -> list[str]:
    """Normalize source '#N' and 'TS-NN' notations; '#N' equivalence is review item MR-H12."""
    raw = text(values)
    return sorted(
        {f"TS-{int(n):02}" for n in re.findall(r"#(\d+)", raw)} | set(re.findall(r"TS-\d\d", raw))
    )


def path_refs(values) -> list[str]:
    return sorted(set(re.findall(r"\b[A-Z]{2}-\d\d\b", text(values))) - {"TS"})


def issue(code, severity, category, affected, detail, automated=True) -> dict:
    return {
        "id": code,
        "severity": severity,
        "category": category,
        "automated": automated,
        "affected": sorted(set(affected)),
        "detail": detail,
    }


def lists(tables) -> dict[str, set[str]]:
    columns = defaultdict(set)
    for row in tables["lists"]:
        for key, value in row.items():
            if key != "_row" and not blank(value):
                columns[key].add(text(value))
    return columns


def checks(tables, captions, source_sha256: str) -> list[dict]:
    controls, threats = tables["controls"], tables["threats"]
    paths, scenarios = tables["paths"], tables["scenarios"]
    found = []
    control_ids = [text(c["Control ID"]) for c in controls]
    threat_ids = {text(t["Threat Ref"]) for t in threats}
    path_ids = {text(p["AP Code"]) for p in paths}
    originals = [c for c in controls if text(c["Source"]) == "original-checklist"]
    # Template criteria and generic validation.
    templates = defaultdict(list)
    for control in originals:
        key = (text(control["Pass Criteria"]), text(control["Fail Indicator"]))
        templates[key].append(text(control["Control ID"]))
    if originals and len(templates) < len(originals):
        found.append(
            issue(
                "AUD-01",
                "HIGH",
                "TEMPLATE_CRITERIA",
                [i for group in templates.values() if len(group) > 1 for i in group],
                {
                    "original_controls": len(originals),
                    "distinct_criteria_sets": len(templates),
                    "group_sizes": sorted((len(g) for g in templates.values()), reverse=True),
                },
            )
        )
    validations = Counter(text(c["Validation Instructions"]) for c in originals)
    if originals and len(validations) == 1:
        found.append(
            issue(
                "AUD-02",
                "HIGH",
                "GENERIC_VALIDATION_INSTRUCTION",
                [text(c["Control ID"]) for c in originals],
                {"distinct_validation_texts": 1},
            )
        )
    blank_sebi = [text(c["Control ID"]) for c in controls if blank(c["SEBI Ref"])]
    if blank_sebi:
        found.append(
            issue("AUD-03", "MEDIUM", "SEBI_REF_EMPTY", blank_sebi, {"count": len(blank_sebi)})
        )
    empty = [text(t["Threat Ref"]) for t in threats if blank(t["Checklist IDs"])]
    if empty:
        found.append(
            issue("AUD-04", "HIGH", "THREAT_CHECKLIST_LINKS_EMPTY", empty, {"count": len(empty)})
        )
    hashed = [text(c["Control ID"]) for c in controls if "#" in text(c["Linked STRIDE #"])]
    hashed += [text(p["AP Code"]) for p in paths if "#" in text(p["Linked Threats"])]
    if hashed:
        found.append(
            issue(
                "AUD-05",
                "LOW",
                "THREAT_NOTATION_INCONSISTENT",
                hashed,
                {"notation": "#N in links versus TS-NN identifiers"},
            )
        )
    unlinked = defaultdict(list)
    for control in controls:
        if blank(control["Linked STRIDE #"]):
            unlinked[text(control["Source"])].append(text(control["Control ID"]))
    if unlinked:
        found.append(
            issue(
                "AUD-06",
                "MEDIUM",
                "CONTROL_THREAT_LINK_MISSING",
                [i for group in unlinked.values() for i in group],
                {source: len(group) for source, group in sorted(unlinked.items())},
            )
        )
    citing = defaultdict(set)
    for control in controls:
        for path in path_refs(control["Linked Attack Path"]):
            citing[path].add(text(control["Control ID"]))
    asymmetric, unlisted = {}, []
    for path in paths:
        code, listed = text(path["AP Code"]), set(ids(path["Linked Controls / Checklist"]))
        if not listed:
            unlisted.append(code)
        elif listed != citing.get(code, set()):
            asymmetric[code] = {
                "listed_only": sorted(listed - citing.get(code, set())),
                "citing_only": sorted(citing.get(code, set()) - listed),
            }
    if asymmetric:
        found.append(
            issue("AUD-07", "MEDIUM", "PATH_CONTROL_LINK_ASYMMETRY", asymmetric, asymmetric)
        )
    if unlisted:
        found.append(
            issue("AUD-08", "MEDIUM", "PATH_CONTROL_LIST_EMPTY", unlisted, {"count": len(unlisted)})
        )
    uncited = sorted(path_ids - set(citing))
    if uncited:
        found.append(issue("AUD-09", "MEDIUM", "PATH_NOT_CITED_BY_ANY_CONTROL", uncited, {}))
    no_threat = [text(p["AP Code"]) for p in paths if not threat_refs(p["Linked Threats"])]
    if no_threat:
        found.append(
            issue("AUD-10", "LOW", "PATH_THREAT_LINK_MISSING", no_threat, {"count": len(no_threat)})
        )
    unknown = defaultdict(set)
    for control in controls:
        unknown["control_path"] |= set(path_refs(control["Linked Attack Path"])) - path_ids
        unknown["control_threat"] |= set(threat_refs(control["Linked STRIDE #"])) - threat_ids
    for path in paths:
        unknown["path_threat"] |= set(threat_refs(path["Linked Threats"])) - threat_ids
        unknown["path_control"] |= set(ids(path["Linked Controls / Checklist"])) - set(control_ids)
    for threat in threats:
        unknown["threat_path"] |= set(path_refs(threat["Attack Path"])) - path_ids
    for scenario in scenarios:
        unknown["scenario_path"] |= set(path_refs(scenario["Attack Path"])) - path_ids
    unknown = {k: sorted(v) for k, v in unknown.items() if v}
    if unknown:
        found.append(
            issue(
                "AUD-11",
                "HIGH",
                "UNKNOWN_REFERENCE",
                [i for v in unknown.values() for i in v],
                unknown,
            )
        )
    duplicates = {
        key: sorted(i for i, n in Counter(values).items() if n > 1)
        for key, values in (
            ("controls", control_ids),
            ("threats", [text(t["Threat Ref"]) for t in threats]),
            ("paths", [text(p["AP Code"]) for p in paths]),
            ("scenarios", [text(s["Scenario ID"]) for s in scenarios]),
        )
    }
    groups = defaultdict(set)
    for control_id in control_ids:
        if re.fullmatch(r"\d+\.\d+\.\d+", control_id):
            major, minor, item = map(int, control_id.split("."))
            groups[(major, minor)].add(item)
    gaps = [
        f"{a}.{b}.{n}"
        for (a, b), items in sorted(groups.items())
        for n in range(1, max(items) + 1)
        if n not in items
    ]
    if any(duplicates.values()) or gaps:
        found.append(
            issue(
                "AUD-12",
                "MEDIUM",
                "ID_DUPLICATE_OR_GAP",
                gaps + [i for v in duplicates.values() for i in v],
                {"duplicates": {k: v for k, v in duplicates.items() if v}, "gaps": gaps},
            )
        )
    declared = {}
    for key in CAPTIONS:
        numbers = [int(n) for line in captions[key] for n in re.findall(r"\b(\d{2,3})\b", line)]
        if numbers and numbers[0] != len(tables[key]):
            declared[key] = {"declared": numbers[0], "actual": len(tables[key])}
    if declared:
        found.append(issue("AUD-13", "MEDIUM", "DECLARED_COUNT_MISMATCH", declared, declared))
    unpopulated = {}
    for source in sorted({text(c["Source"]) for c in controls}):
        group = [c for c in controls if text(c["Source"]) == source]
        for field in ("Exploitability", "Attack Phase", "Linked STRIDE #", "SEBI Ref"):
            count = sum(blank(c[field]) for c in group)
            if count:
                unpopulated[f"{source}:{field}"] = f"{count}/{len(group)}"
    if unpopulated:
        found.append(issue("AUD-14", "LOW", "FIELDS_UNPOPULATED", unpopulated, unpopulated))
    placeholders = [
        text(a["Account ID"])
        for a in tables["accounts"]
        if not re.fullmatch(r"\d{12}", text(a["AWS Account # (12-digit)"]))
    ]
    if placeholders:
        found.append(
            issue(
                "AUD-15",
                "HIGH",
                "ACCOUNT_KEYS_UNRECONCILED",
                [],
                {"accounts": len(tables["accounts"]), "without_12_digit_id": len(placeholders)},
            )
        )
    vocab = lists(tables)
    mismatches = {}
    headers = {key: set(spec[2] or ()) for key, spec in LAYOUT.items()}
    sheet_keys = {spec[0]: key for key, spec in LAYOUT.items()}
    unknown_fields = []
    for row in tables["dictionary"]:
        sheet_name, field = text(row["Sheet"]), text(row["Field / Column"])
        allowed = {v.strip() for v in text(row["Allowed values / format"]).split("/") if v.strip()}
        if (sheet_name, field) in VOCABULARIES:
            expected = vocab.get(VOCABULARIES[(sheet_name, field)], set())
            if allowed != expected:
                mismatches[f"{sheet_name}:{field}"] = {
                    "dictionary_only": sorted(allowed - expected),
                    "list_only": sorted(expected - allowed),
                }
        key = sheet_keys.get(sheet_name)
        if key and headers[key] and "*" not in field and field not in headers[key]:
            unknown_fields.append(f"{sheet_name}:{field}")
    if mismatches:
        found.append(issue("AUD-16", "LOW", "VOCABULARY_MISMATCH", mismatches, mismatches))
    if unknown_fields:
        found.append(issue("AUD-17", "LOW", "DICTIONARY_FIELD_NOT_IN_SHEET", unknown_fields, {}))
    ordinal = {}
    threat_by_id = {text(t["Threat Ref"]): t for t in threats}
    for row in tables["sebi"]:
        match = re.fullmatch(r"D\d-0?(\d\d)", text(row["Source Ref"]))
        threat = threat_by_id.get(f"TS-{match.group(1)}") if match else None
        if not threat or text(threat["STRIDE"]) != text(row["STRIDE"]):
            ordinal[text(row["Source Ref"])] = "no STRIDE-consistent TS-NN by ordinal"
    found.append(
        issue(
            "AUD-18",
            "LOW" if not ordinal else "MEDIUM",
            "SCENARIO_THREAT_LINK_BY_ORDINAL",
            list(ordinal),
            {"explicit_link_column": False, "inconsistent": ordinal},
        )
    )
    spec_ids = {entry.control_id for entry in COVERAGE}
    reconciliation = {
        "missing_from_spec": sorted(set(control_ids) - spec_ids),
        "not_in_workbook": sorted(spec_ids - set(control_ids)),
        "reviewed_hash_matches": source_sha256 == REVIEWED_METHODOLOGY_SHA256,
    }
    by_id = {text(c["Control ID"]): c for c in controls}
    link_mismatch = {}
    from offline_analyzer.rules.registry import PROVIDER_RULES

    # Every AWS and GCP rule is classified under one checklist control; each link must
    # carry the control's source attack paths, STRIDE category and inherent severity.
    for rule in PROVIDER_RULES:
        if rule.methodology is None:
            link_mismatch[rule.rule_id] = "methodology-linked rule mapping missing"
            continue
        link, control = rule.methodology, by_id.get(rule.methodology.control_id)
        if control is None:
            link_mismatch[rule.rule_id] = "control missing"
            continue
        if (
            set(link.attack_paths) != set(path_refs(control["Linked Attack Path"]))
            or link.stride_category != text(control["STRIDE Category"])
            or link.inherent_severity != text(control["Inherent Severity"])
        ):
            link_mismatch[rule.rule_id] = "source metadata differs"
    path_mismatch = {
        text(p["AP Code"]): "threat links differ"
        for p in paths
        if text(p["AP Code"]) in BY_PATH
        and tuple(threat_refs(p["Linked Threats"]))
        != tuple(sorted(BY_PATH[text(p["AP Code"])].threats))
    }
    if (
        reconciliation["missing_from_spec"]
        or reconciliation["not_in_workbook"]
        or not reconciliation["reviewed_hash_matches"]
        or link_mismatch
        or path_mismatch
        or set(BY_PATH) != path_ids
        or set(THREAT_SCOPE) != threat_ids
    ):
        found.append(
            issue(
                "AUD-19",
                "HIGH",
                "SPECIFICATION_RECONCILIATION_FAILED",
                list(link_mismatch) + list(path_mismatch),
                {**reconciliation, "links": link_mismatch, "paths": path_mismatch},
            )
        )
    severity = Counter(
        (text(c["Inherent Severity"]), text(c["Priority Tier"]).split(" ")[0]) for c in controls
    )
    found.append(
        issue(
            "AUD-20",
            "LOW",
            "SEVERITY_PRIORITY_MATRIX",
            [],
            {f"{s}/{p}": n for (s, p), n in sorted(severity.items())},
        )
    )
    for code, category, affected in REVIEW_ITEMS:
        found.append(issue(code, "MEDIUM", category, affected, {}, automated=False))
    return found


def implementation_status(prerequisite) -> str:
    if prerequisite.rules:
        return "IMPLEMENTED_REQUIRES_VALIDATION"
    return {
        "CONFIG": "NOT_IMPLEMENTED",
        "IAM_ENGINE": "NOT_IMPLEMENTED",
        "REACHABILITY": "NOT_IMPLEMENTED",
        "ORG_EVIDENCE": "BLOCKED_BY_MISSING_EVIDENCE",
        "CLASSIFICATION": "BLOCKED_BY_MISSING_EVIDENCE",
    }.get(prerequisite.kind, "MANUAL_VALIDATION_REQUIRED")


def matrices(tables) -> dict[str, tuple[list[str], list[list]]]:
    controls = tables["controls"]
    template_index = {}
    for control in controls:
        if text(control["Source"]) == "original-checklist":
            key = (text(control["Pass Criteria"]), text(control["Fail Indicator"]))
            template_index.setdefault(key, f"T{len(template_index) + 1}")
    citing_threat = defaultdict(list)
    for control in controls:
        for ref in threat_refs(control["Linked STRIDE #"]):
            citing_threat[ref].append(text(control["Control ID"]))
    control_rows = []
    for control in controls:
        spec = BY_CONTROL.get(text(control["Control ID"]))
        template = template_index.get(
            (text(control["Pass Criteria"]), text(control["Fail Indicator"])), "control-specific"
        )
        control_rows.append(
            [
                *(control[h] for h in ("Control ID", "Domain", "Control Area", "Check Item")),
                control["Source"],
                spec.status if spec else "UNCLASSIFIED",
                list(spec.reasons) if spec else [],
                list(spec.evidence) if spec else [],
                list(spec.rules) if spec else [],
                list(spec.related) if spec else [],
                template,
                *(
                    control[h]
                    for h in (
                        "Automation Type",
                        "Assessment Tool",
                        "Collection Instructions",
                        "Validation Instructions",
                        "Pass Criteria",
                        "Fail Indicator",
                        "Linked Attack Path",
                    )
                ),
                threat_refs(control["Linked STRIDE #"]),
                control["STRIDE Category"],
                control["Inherent Severity"],
                control["Priority Tier"],
                control["_row"],
            ]
        )
    threat_rows = []
    for threat in tables["threats"]:
        ref = text(threat["Threat Ref"])
        scope, keys = THREAT_SCOPE.get(ref, ("UNCLASSIFIED", ()))
        threat_rows.append(
            [
                ref,
                *(
                    threat[h]
                    for h in (
                        "Domain",
                        "STRIDE",
                        "Asset / Component",
                        "Attacker Action",
                        "Exploit Path",
                        "Trust Boundary Crossed",
                        "Precondition / Weakness",
                        "Attack Path",
                        "Risk Level",
                    )
                ),
                sorted(citing_threat.get(ref, [])),
                scope,
                list(keys),
            ]
        )
    path_rows = []
    citing_path = defaultdict(list)
    for control in controls:
        for ref in path_refs(control["Linked Attack Path"]):
            citing_path[ref].append(text(control["Control ID"]))
    source_paths = {text(p["AP Code"]): p for p in tables["paths"]}
    for spec in PATHS:
        source = source_paths.get(spec.path_id, {})
        base = [
            spec.path_id,
            source.get("Attack Path Name"),
            spec.scope,
            source.get("Kill Chain Summary"),
            ids(source.get("Linked Controls / Checklist")),
            sorted(citing_path.get(spec.path_id, [])),
            list(spec.threats),
            source.get("Inherent Severity"),
            list(spec.blockers),
        ]
        if not spec.prerequisites:
            path_rows.append(base + [None, None, None, [], [], spec.scope])
        for p in spec.prerequisites:
            path_rows.append(
                base + [p.key, p.kind, p.summary, list(p.evidence), list(p.rules),
                        implementation_status(p)]
            )  # fmt: skip
    scenario_rows = [
        [
            *(
                s[h]
                for h in (
                    "Scenario ID",
                    "Scenario Name",
                    "Attack Path",
                    "Source Finding Ref",
                    "Entry Point",
                    "Target / Crown Jewel",
                    "SOW Validation Step",
                )
            ),
            BY_PATH[text(s["Attack Path"])].scope
            if text(s["Attack Path"]) in BY_PATH
            else "UNKNOWN_PATH_REFERENCE",
        ]
        for s in tables["scenarios"]
    ]
    requirement = defaultdict(lambda: {"controls": set(), "rules": set()})
    for entry in COVERAGE:
        for operation in entry.evidence:
            requirement[operation]["controls"].add(entry.control_id)
            requirement[operation]["rules"] |= set(entry.rules)
    evidence_rows = [
        [
            operation,
            "SUPPORTED_ADAPTER" if operation in AWS_OPERATIONS else "ADAPTER_MISSING",
            len(value["controls"]),
            sorted(value["controls"]),
            sorted(value["rules"]),
        ]
        for operation, value in sorted(
            requirement.items(), key=lambda item: (-len(item[1]["controls"]), item[0])
        )
    ]
    return {
        "Control Evidence Matrix": (
            [
                "Control ID",
                "Domain",
                "Control Area",
                "Check Item",
                "Source",
                "Implementation status",
                "Reason codes",
                "Evidence operations",
                "Executable rules",
                "Related controls",
                "Criteria template",
                "Automation Type (source)",
                "Assessment Tool (source)",
                "Collection Instructions (source)",
                "Validation Instructions (source)",
                "Pass Criteria (source)",
                "Fail Indicator (source)",
                "Linked Attack Path (source)",
                "Linked threats (normalized)",
                "STRIDE Category (source)",
                "Inherent Severity (source)",
                "Priority Tier (source)",
                "Source row",
            ],
            control_rows,
        ),
        "STRIDE Inventory": (
            [
                "Threat Ref",
                "Domain",
                "STRIDE",
                "Asset",
                "Attacker action",
                "Exploit path / entry",
                "Trust boundary",
                "Preconditions",
                "Attack path",
                "Risk level",
                "Controls citing (reverse link)",
                "AWS scope",
                "Evaluable prerequisites",
            ],
            threat_rows,
        ),
        "Attack Path Matrix": (
            [
                "AP",
                "Name",
                "Scope",
                "Kill chain (source)",
                "Listed controls (source)",
                "Controls citing (reverse)",
                "Threats",
                "Inherent severity (source)",
                "Blockers",
                "Prerequisite",
                "Kind",
                "Prerequisite summary",
                "Evidence operations",
                "Executable rules",
                "Implementation status",
            ],
            path_rows,
        ),
        "Adversary Scenarios": (
            [
                "Scenario",
                "Name",
                "Attack path",
                "Source finding ref",
                "Entry point",
                "Target",
                "SOW validation steps (source)",
                "Path scope",
            ],
            scenario_rows,
        ),
        "Evidence Requirements": (
            ["Operation", "Analyzer adapter", "Controls needing it", "Controls", "Rules"],
            evidence_rows,
        ),
    }


def cell(value):
    if isinstance(value, (list, tuple, dict)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return excel_literal(value) if isinstance(value, str) else value


def write_outputs(result: Path, tables, findings, inventory) -> None:
    (result / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    (result / "audit.json").write_text(
        json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    workbook = Workbook(write_only=True)
    sheets = {
        "Inventory": (["Item", "Value"], [[k, v] for k, v in inventory.items()]),
        "Inconsistencies": (
            ["ID", "Severity", "Category", "Automated", "Affected", "Detail"],
            [
                [f["id"], f["severity"], f["category"], f["automated"], f["affected"], f["detail"]]
                for f in findings
            ],
        ),
        **matrices(tables),
    }
    for name, (headers, rows) in sheets.items():
        sheet = workbook.create_sheet(name)
        sheet.append(headers)
        for row in rows:
            sheet.append([cell(v) for v in row])
    workbook.save(result / "methodology-audit.xlsx")


def audit_workbook(source: Path) -> tuple[dict, list[dict], dict]:
    """In-memory audit of a verified snapshot. Returns (tables, findings, inventory)."""
    original = sha256_file(source, MAX_FILE_BYTES)
    with tempfile.TemporaryDirectory() as temp:
        snapshot = Path(temp) / "source.xlsx"
        snapshot.write_bytes(source.read_bytes())
        if sha256_file(snapshot) != original:
            raise LayoutError("SOURCE_CHANGED_DURING_SNAPSHOT")
        preflight(snapshot)
        workbook = load_workbook(snapshot, read_only=True, data_only=False, keep_links=False)
        try:
            tables, captions = read_layout(workbook)
            sheet_names = list(workbook.sheetnames)
        finally:
            workbook.close()
    if sha256_file(source, MAX_FILE_BYTES) != original:
        raise LayoutError("SOURCE_CHANGED_DURING_AUDIT")
    findings = checks(tables, captions, original)
    statuses = Counter(
        BY_CONTROL[text(c["Control ID"])].status
        for c in tables["controls"]
        if text(c["Control ID"]) in BY_CONTROL
    )
    inventory = {
        "audit_version": AUDIT_VERSION,
        "source_sha256": original,
        "source_bytes": source.stat().st_size,
        "reviewed_hash_matches": original == REVIEWED_METHODOLOGY_SHA256,
        "sheets": len(sheet_names),
        "controls": len(tables["controls"]),
        "controls_by_source": dict(Counter(text(c["Source"]) for c in tables["controls"])),
        "threats": len(tables["threats"]),
        "attack_paths": len(tables["paths"]),
        "adversary_scenarios": len(tables["scenarios"]),
        "mitre_rows": len(tables["mitre"]),
        "sebi_rows": len(tables["sebi"]),
        "account_placeholders": len(tables["accounts"]),
        "live_rows": {k: len(tables[k]) for k in ("results", "findings", "evidence")},
        "implementation_status": dict(sorted(statuses.items())),
        "issues": len(findings),
    }
    return tables, findings, inventory


def audit(source: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("output directory already exists")
    tables, findings, inventory = audit_workbook(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        result = Path(temp) / "result"
        result.mkdir(mode=0o700)
        write_outputs(result, tables, findings, inventory)
        result.rename(output)
    return inventory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = audit(args.source, args.output)
    except LayoutError as exc:
        print(f"Audit failed: {exc}", file=__import__("sys").stderr)
        return 1
    except Exception:  # noqa: BLE001 -- workbook-derived exception text must not be printed
        print(
            "Audit failed; inspect locally without sharing contents.", file=__import__("sys").stderr
        )
        return 1
    # Counts and status totals only; no workbook text.
    print(json.dumps({k: v for k, v in inventory.items() if k != "source_bytes"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
