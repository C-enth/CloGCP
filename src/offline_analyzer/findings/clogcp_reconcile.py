"""Read-only historical reconciliation. Historical approval never becomes current status.

Only exact canonical resource, rule semantics, evidence and severity can offer carry-forward.
No database writes or decision creation occur here. Missing history is supported.
"""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from offline_analyzer.contracts.r0 import Candidate, Decision
from offline_analyzer.ingestion.json_input import InputError


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding: Candidate
    evidence_signature: tuple[str, ...] = ()
    decisions: tuple[dict, ...] = ()
    decision_ids: tuple[str, ...] = ()
    sre_history: tuple[dict, ...] = ()
    sre_validation_ids: tuple[str, ...] = ()
    report_history: tuple[dict, ...] = ()
    report_revision_keys: tuple[tuple[str, int], ...] = ()
    exclusion_history: tuple[dict, ...] = ()
    source_run: str = ""

    @field_validator("decisions")
    @classmethod
    def validate_decisions(cls, value):
        return tuple(Decision.model_validate(d).model_dump(mode="json") for d in value)

    @field_validator("exclusion_history")
    @classmethod
    def validate_exclusions(cls, value):
        from offline_analyzer.contracts.exclusion import FindingExclusion

        checked = []
        for item in value:
            if set(item) != {"record_id", "data"} or not isinstance(item["record_id"], str):
                raise ValueError("Invalid historical exclusion provenance")
            checked.append(
                {
                    "record_id": item["record_id"],
                    "data": FindingExclusion.model_validate(item["data"]).model_dump(mode="json"),
                }
            )
        return tuple(checked)


class History(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = Field(default="clogcp-history-1", pattern="^clogcp-history-1$")
    records: tuple[Snapshot, ...] = ()


def snapshots(store: Any, run: str) -> tuple[Snapshot, ...]:
    artifacts = dict(store.rows("SELECT artifact_id,sha256 FROM artifacts WHERE run_id=?", [run]))
    decisions = defaultdict(list)
    sre = defaultdict(list)
    reports = defaultdict(list)
    ids, sre_ids, report_keys, exclusions = (
        defaultdict(list),
        defaultdict(list),
        defaultdict(list),
        defaultdict(list),
    )
    for table, column, target, target_ids in [
        ("decisions", "decision_id", decisions, ids),
        ("sre_validations", "validation_id", sre, sre_ids),
    ]:
        for record_id, finding_id, data in store.rows(
            f"SELECT {column},finding_id,data FROM {table}"
        ):
            target[finding_id].append(json.loads(data))
            target_ids[finding_id].append(record_id)
    for report_id, revision, finding_id, data in store.rows(
        "SELECT report_id,revision,primary_finding,data FROM report_revisions"
    ):
        reports[finding_id].append(json.loads(data))
        report_keys[finding_id].append((report_id, revision))
    for record_id, finding_id, data in store.rows(
        "SELECT exclusion_id,finding_id,data FROM finding_exclusions"
    ):
        exclusions[finding_id].append({"record_id": record_id, "data": json.loads(data)})
    return tuple(
        Snapshot(
            finding=f,
            source_run=run,
            evidence_signature=tuple(
                sorted(
                    {
                        artifacts.get(r.artifact_id, "UNAVAILABLE") + ":" + r.locator
                        for r in f.evidence
                    }
                )
            ),
            decisions=tuple(decisions[f.finding_id]),
            decision_ids=tuple(ids[f.finding_id]),
            sre_history=tuple(sre[f.finding_id]),
            sre_validation_ids=tuple(sre_ids[f.finding_id]),
            report_history=tuple(reports[f.finding_id]),
            report_revision_keys=tuple(report_keys[f.finding_id]),
            exclusion_history=tuple(exclusions[f.finding_id]),
        )
        for f in store.candidates(run)
        if f.provider == "GCP"
    )


def load_history(path: Path | None) -> History:
    if path is None:
        return History()
    if path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
        raise InputError("CLOGCP_HISTORY_INPUT_LIMIT")
    # Existing bounded JSON inspection rejects duplicate keys, unsafe nesting and secrets.
    from offline_analyzer.ingestion.json_input import inspect_json

    inspect_json(path)
    history = History.model_validate_json(path.read_bytes())
    if len(history.records) > 100000:
        raise InputError("CLOGCP_HISTORY_RECORD_LIMIT")
    return history


def export_readonly_history(workspace: Path, run: str, output: Path) -> None:
    """Read a closed original workspace without Store, recovery, migration or writes."""
    import os

    import duckdb

    root = workspace.resolve()
    if output.resolve().is_relative_to(root) or output.exists():
        raise InputError("CLOGCP_HISTORY_OUTPUT_MUST_BE_NEW_AND_OUTSIDE_SOURCE_WORKSPACE")
    database = root / "assessment.duckdb"
    if (
        not database.is_file()
        or database.is_symlink()
        or database.with_suffix(".duckdb.wal").exists()
    ):
        raise InputError("CLOGCP_HISTORY_REQUIRES_CLOSED_CLEAN_WORKSPACE")

    class Reader:
        def __init__(self, db):
            self.db = db

        def rows(self, sql, parameters=None):
            return self.db.execute(sql, parameters or []).fetchall()

        def candidates(self, run_id):
            return [
                Candidate.model_validate_json(r[0])
                for r in self.rows("SELECT data FROM findings WHERE run_id=?", [run_id])
            ]

    with duckdb.connect(
        str(database),
        read_only=True,
        config={
            "enable_external_access": False,
            "autoload_known_extensions": False,
            "autoinstall_known_extensions": False,
        },
    ) as connection:
        reader = Reader(connection)
        if not reader.rows("SELECT 1 FROM runs WHERE run_id=?", [run]):
            raise InputError("CLOGCP_HISTORY_RUN_NOT_FOUND")
        records = snapshots(reader, run)
        history = History(records=records)
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with output.open("x") as file:
        file.write(history.model_dump_json(indent=2))
    os.chmod(output, 0o600)


def key(record: Snapshot) -> tuple:
    f = record.finding
    return f.project_id, f.resource_id, f.rule_id


SEMANTIC_FIELDS = (
    "rule_id",
    "rule_version",
    "technical_observation",
    "security_risk",
    "remediation",
    "severity_rationale",
    "validation_requirements",
    "methodology_id",
    "methodology_criteria",
    "mapping_status",
    "finding_class",
    "suggested_severity",
    "compensating_controls",
    "exposure_status",
    "evidence_confidence",
)


def current_approval(records: list[Snapshot]) -> str:
    """Report an already recorded local decision, never derive one from old history."""
    if not records:
        return "NO_CURRENT_FINDING"
    if len(records) != 1:
        return "AMBIGUOUS"
    record = records[0]
    decision = max(
        record.decisions,
        key=lambda d: datetime.fromisoformat(d["decided_at"]),
        default=None,
    )
    if decision is None:
        return "PENDING"
    from offline_analyzer.findings.generate import fingerprint

    if decision["evidence_fingerprint"] != fingerprint(record.finding):
        return "NEEDS_REVALIDATION"
    return decision["status"]


def reconcile(current: tuple[Snapshot, ...], historical: History | None = None) -> list[dict]:
    historical = historical or History()
    before, after = defaultdict(list), defaultdict(list)
    for record in historical.records:
        before[key(record)].append(record)
    for record in current:
        after[key(record)].append(record)
    rows = []
    for identity in sorted(set(before) | set(after), key=str):
        old, new = before[identity], after[identity]
        old_ids = [o.finding.finding_id for o in old]
        new_ids = [n.finding.finding_id for n in new]
        carry = False
        latest = (
            max(
                old[0].decisions,
                key=lambda d: datetime.fromisoformat(d["decided_at"]),
                default=None,
            )
            if len(old) == 1
            else None
        )
        last_exclusion = (
            max(
                old[0].exclusion_history,
                key=lambda e: datetime.fromisoformat(e["data"]["recorded_at"]),
                default=None,
            )
            if len(old) == 1
            else None
        )
        rejected = bool(
            last_exclusion
            and last_exclusion["data"].get("action") == "EXCLUDE"
            and last_exclusion["data"].get("reason") == "FALSE_POSITIVE"
        )
        if len(old) > 1 or len(new) > 1:
            status = "DUPLICATE_OR_RELATED"
        elif not old:
            status = "NEW_FINDING"
        elif not new:
            status = (
                "PREVIOUSLY_APPROVED_NO_LONGER_DETECTED"
                if latest and latest["status"] == "CONFIRMED"
                else "PREVIOUSLY_DETECTED_NO_LONGER_DETECTED"
            )
        else:
            o, n = old[0], new[0]
            if rejected or latest and latest["status"] == "REJECTED":
                status = "PREVIOUSLY_REJECTED_DETECTED_AGAIN"
            elif any(
                getattr(o.finding, field) != getattr(n.finding, field) for field in SEMANTIC_FIELDS
            ):
                status = "SEVERITY_OR_INTERPRETATION_CHANGED"
            elif not o.evidence_signature or "UNAVAILABLE" in "".join(o.evidence_signature):
                status = "UNABLE_TO_RECONCILE"
            elif o.evidence_signature != n.evidence_signature:
                status = "EQUIVALENT_CHANGED_EVIDENCE"
            else:
                # Even matching source hashes require a still-current original approval fingerprint.
                from offline_analyzer.findings.generate import fingerprint

                approved = (
                    latest
                    and latest["status"] == "CONFIRMED"
                    and latest["evidence_fingerprint"] == fingerprint(o.finding)
                )
                carry = (
                    bool(approved)
                    and o.finding.technical_observation == n.finding.technical_observation
                )
                status = "EQUIVALENT_PREVIOUSLY_VALIDATED" if carry else "EQUIVALENT_UNVALIDATED"
        rows.append(
            {
                "project": identity[0],
                "resource": identity[1],
                "rule": identity[2],
                "historical_ids": old_ids,
                "current_ids": new_ids,
                "status": status,
                "carry_forward_available": carry,
                "current_approval": current_approval(new),
                "automatic_approval_applied": False,
                "current_decision_ids": [i for n in new for i in n.decision_ids],
                "historical_records": [o.model_dump(mode="json") for o in old],
                "limitation": (
                    "Absence from new findings is not proof of remediation; consult "
                    "coverage and evidence limitations."
                )
                if not new
                else "",
            }
        )
    return rows
