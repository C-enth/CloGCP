"""Explicit immutable report editions; never automatically freezes an in-progress run."""

import copy
import json
from datetime import UTC, datetime

from offline_analyzer.contracts.finalisation import FrozenAssessment
from offline_analyzer.ingestion.json_input import InputError


def frozen(store, run: str) -> dict | None:
    row = store.db.execute(
        "SELECT data FROM finalized_assessments WHERE run_id=?", [run]
    ).fetchone()
    if not row:
        return None
    record = FrozenAssessment.model_validate_json(row[0]).model_dump(mode="json")
    # A purge override marks an edition superseded; its preserved content is unchanged.
    record["superseded"] = superseded(store, run)
    return record


def superseded(store, run: str) -> list[dict]:
    return [
        json.loads(data)
        for (data,) in store.db.execute(
            "SELECT data FROM finalized_supersessions WHERE run_id=? ORDER BY superseded_at",
            [run],
        ).fetchall()
    ]


def require_editable(store, run: str) -> None:
    if store.db.execute("SELECT 1 FROM finalized_assessments WHERE run_id=?", [run]).fetchone():
        raise InputError("ASSESSMENT_FINALIZED")


def freeze(store, run: str, analyst: str, confirmed: bool) -> dict:
    from offline_analyzer.enterprise.validation import validate_snapshot
    from offline_analyzer.reporting.sre_reports import finalized, finalized_document

    store.require_run(run)
    if not confirmed:
        raise InputError("FINALISATION_CONFIRMATION_REQUIRED")
    old = frozen(store, run)
    if old:
        return old
    validation = validate_snapshot(store, run)
    if validation["status"] != "PASS":
        raise InputError("FINALISATION_REQUIRES_COMPLETE_ENTERPRISE_SNAPSHOT")
    view = finalized(store, run)
    if not view["findings"]:
        raise InputError("NO_CONFIRMED_FINDINGS")
    document = finalized_document(store, run)
    document.pop("coverage", None)  # internal tuple-key index is not part of the report edition
    record = FrozenAssessment(
        run_id=run, created_at=datetime.now(UTC), analyst=analyst, view=view, document=document
    )
    with store.transaction():
        store.db.execute(
            "INSERT INTO finalized_assessments VALUES (?,?,?)",
            [run, record.created_at.isoformat(), record.model_dump_json()],
        )
    return frozen(store, run)


def filtered(record: dict, section: str, provider: str = "", scope: str = "") -> dict:
    from collections import Counter

    result = copy.deepcopy(record[section])

    def wanted(item):
        return (not provider or item["provider"] == provider) and (
            not scope
            or (item.get("project_id") or item.get("account_id") or item.get("scope")) == scope
        )

    result["findings"] = [f for f in result["findings"] if wanted(f)]
    ids = {f["id"] for f in result["findings"]}
    result["paths"] = [
        p for p in result["paths"] if wanted(p) and ids & set(p.get("finding_ids", []))
    ]
    for key in ("accounts", "scopes", "unknown_areas", "coverage_notes"):
        if key in result:
            result[key] = [a for a in result[key] if wanted(a)]
    if "path_coverage" in result:  # per provider; not tied to one account or project
        result["path_coverage"] = [
            r for r in result["path_coverage"] if not provider or r["provider"] == provider
        ]
    if provider and "provider_scope" in result:
        result["provider_scope"] = provider
    result["severity"] = dict(Counter(f["severity"] for f in result["findings"]))
    if "controls" in result:
        result["controls"] = [
            {"control": c, "count": n}
            for c, n in sorted(Counter(f["control"] for f in result["findings"]).items())
        ]
    result.update(
        frozen=True,
        frozen_at=record["created_at"],
        frozen_by=record["analyst"],
        superseded=record.get("superseded", []),
    )
    return result
