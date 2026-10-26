"""A separate client-facing register; never rewrites existing assessment reports."""

import csv
import json
from pathlib import Path

from offline_analyzer.contracts.gcp_attack_path import GCPAttackPathRegister
from offline_analyzer.ingestion.safety import excel_literal

COLUMNS = (
    "Path ID",
    "Root cause ID",
    "Root security gap",
    "Entry point",
    "Target",
    "Identity",
    "Mechanism",
    "Confirmed configuration relationships",
    "Mandatory prerequisites",
    "Satisfied conditions",
    "Unresolved conditions",
    "Blocking controls",
    "Qualified state",
    "Exploitation verification",
    "Finding validation",
    "Potential impact",
    "Severity",
    "Severity rationale",
    "Evidence provenance",
    "Original finding IDs",
    "Legacy history",
    "Remediation",
    "Remaining verification",
)


def rows(register: GCPAttackPathRegister, *, active: bool = False):
    for p in register.paths:
        if active and p.classification == "BLOCKED":
            continue

        def checks(states, path=p):
            return [c.name + ": " + c.reason for c in path.prerequisites if c.state in states]

        yield [
            p.path_id,
            p.root_cause_id,
            p.root_security_gap,
            p.entry_point,
            p.target,
            p.identity,
            p.mechanism,
            p.relationships,
            [c.model_dump() for c in p.prerequisites],
            checks({"AVAILABLE"}),
            checks({"UNCOLLECTED", "UNSUPPORTED", "CONDITIONAL"}),
            checks({"CONTRADICTED"}),
            p.classification,
            p.exploitation_verification,
            p.finding_validation,
            p.potential_impact,
            p.severity,
            p.severity_rationale,
            p.evidence_provenance,
            p.original_finding_ids,
            p.legacy_paths,
            p.recommended_remediation,
            p.remaining_verification,
        ]


def write_register(
    register: GCPAttackPathRegister, output: Path, *, legacy_paths: list[dict] | None = None
) -> None:
    """New private directory only. Full JSON preserves text beyond spreadsheet cell limits."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "attack-path-evaluation-v2.json").write_text(
        register.model_dump_json(indent=2), encoding="utf-8"
    )
    reconciliation = []
    for old in legacy_paths or []:
        matched = [
            p
            for p in register.paths
            if any(previous["path_id"] == old["path_id"] for previous in p.legacy_paths)
        ]
        reconciliation.append(
            {
                "legacy_path_id": old["path_id"],
                "prior_status": old.get("proof_status", old.get("status", "UNKNOWN")),
                "new_paths": [
                    {
                        "path_id": p.path_id,
                        "canonical_key": p.canonical_key,
                        "project_id": p.project_id,
                        "resource": p.target,
                        "identity": p.identity,
                        "mechanism": p.mechanism,
                        "root_cause_id": p.root_cause_id,
                        "classification": p.classification,
                    }
                    for p in matched
                ],
                "match_status": "MATCHED_FOR_REVIEW" if matched else "UNMATCHED",
                "reason": "Canonical evidence/identity match; mechanism split needs review"
                if matched
                else (
                    "Missing or ambiguous canonical identity, resource or mechanism; "
                    "no inferred mapping"
                ),
            }
        )
    (output / "legacy-reconciliation.json").write_text(
        json.dumps(reconciliation, indent=2), encoding="utf-8"
    )
    for name, active in (("attack-path-history.csv", False), ("active-attack-paths.csv", True)):
        with (output / name).open("x", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(COLUMNS)
            for row in rows(register, active=active):
                writer.writerow(
                    [excel_literal(v if isinstance(v, str) else json.dumps(v)) for v in row]
                )
    (output / "README.txt").write_text(
        "CloGCP attack-path evaluation 2.0.0\n"
        "SUPPORTED describes mandatory modeled configuration prerequisites, not execution.\n"
        "Execution remains UNVERIFIED; analyst approval and finding validation are not inherited.\n"
        "BLOCKED paths remain in history and are excluded from active candidates.\n"
        "Root cause groups deduplicate gaps while retaining individual technical chains.\n"
        + "\n".join(register.limitations + register.truncation_reasons),
        encoding="utf-8",
    )
