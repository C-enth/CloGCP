"""History is synthetic and read only; approval is never applied to current findings."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from offline_analyzer.contracts.r0 import Decision
from offline_analyzer.findings.clogcp_reconcile import (
    History,
    Snapshot,
    export_readonly_history,
    load_history,
    reconcile,
    snapshots,
)
from offline_analyzer.findings.generate import fingerprint, record_decision
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.gcp_fixture import build


@pytest.fixture(scope="module")
def historical(tmp_path_factory):
    root = tmp_path_factory.mktemp("clogcp-synthetic-history")
    package = build(root / "package")
    work = root / "workspace"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        run = import_package(store, package)
        assess(store, run)
        finding = next(store.candidates(run))
        record_decision(
            store, run, finding.finding_id, "CONFIRMED", "Synthetic reviewer", "Synthetic approval"
        )
        old = next(s for s in snapshots(store, run) if s.finding.finding_id == finding.finding_id)
    return old, work, run


def changed(snapshot, **fields):
    return snapshot.model_copy(update={"finding": snapshot.finding.model_copy(update=fields)})


def test_exact_equivalence_offers_carry_forward_without_applying(historical):
    old, _, _ = historical
    before = old.model_dump_json()
    current = old.model_copy(update={"decisions": (), "decision_ids": ()})
    row = reconcile((current,), History(records=(old,)))[0]
    assert row["status"] == "EQUIVALENT_PREVIOUSLY_VALIDATED"
    assert row["carry_forward_available"] is True
    assert row["current_approval"] == "PENDING"
    assert row["historical_ids"] == [old.finding.finding_id]
    assert old.model_dump_json() == before
    assert row["historical_records"][0]["decisions"]


@pytest.mark.parametrize(
    "change,status",
    [
        ({"rule_version": "changed-semantics"}, "SEVERITY_OR_INTERPRETATION_CHANGED"),
        ({"suggested_severity": "CRITICAL"}, "SEVERITY_OR_INTERPRETATION_CHANGED"),
        ({"finding_class": "SUPPORTED_SECURITY_GAP"}, "SEVERITY_OR_INTERPRETATION_CHANGED"),
        (
            {"security_risk": "Changed technical interpretation"},
            "SEVERITY_OR_INTERPRETATION_CHANGED",
        ),
    ],
)
def test_semantics_require_revalidation(historical, change, status):
    old, _, _ = historical
    row = reconcile((changed(old, **change),), History(records=(old,)))[0]
    assert row["status"] == status and not row["carry_forward_available"]


def test_changed_missing_new_duplicate_and_unavailable_evidence(historical):
    old, _, _ = historical
    history = History(records=(old,))
    newer = old.model_copy(update={"evidence_signature": ("different-hash:/0",)})
    assert reconcile((newer,), history)[0]["status"] == "EQUIVALENT_CHANGED_EVIDENCE"
    assert reconcile((), history)[0]["status"] == "PREVIOUSLY_APPROVED_NO_LONGER_DETECTED"
    assert "not proof of remediation" in reconcile((), history)[0]["limitation"]
    assert reconcile((old,))[0]["status"] == "NEW_FINDING"
    assert reconcile((old, old), history)[0]["status"] == "DUPLICATE_OR_RELATED"
    absent = old.model_copy(update={"evidence_signature": ()})
    assert reconcile((old,), History(records=(absent,)))[0]["status"] == "UNABLE_TO_RECONCILE"
    other = changed(old, project_id="synth-other")
    assert {r["status"] for r in reconcile((other,), history)} == {
        "NEW_FINDING",
        "PREVIOUSLY_APPROVED_NO_LONGER_DETECTED",
    }


def test_latest_review_is_used_and_stale_fingerprint_is_not_approval(historical):
    old, _, _ = historical
    original = old.decisions[0]
    rejected = {
        **original,
        "status": "REJECTED",
        "decided_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    }
    history = old.model_copy(update={"decisions": (original, rejected)})
    row = reconcile((old,), History(records=(history,)))[0]
    assert row["status"] == "PREVIOUSLY_REJECTED_DETECTED_AGAIN"
    reapproved = {**original, "decided_at": (datetime.now(UTC) + timedelta(days=2)).isoformat()}
    history = old.model_copy(update={"decisions": (original, rejected, reapproved)})
    assert reconcile((old,), History(records=(history,)))[0]["carry_forward_available"]
    stale = old.model_copy(update={"decisions": ({**original, "evidence_fingerprint": "0" * 64},)})
    assert not reconcile((old,), History(records=(stale,)))[0]["carry_forward_available"]
    assert Decision.model_validate(reapproved).evidence_fingerprint == fingerprint(old.finding)


def test_readonly_adapter_preserves_database_and_handles_no_history(historical, tmp_path):
    _, work, run = historical
    database = work / "assessment.duckdb"
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    target = tmp_path / "history.json"
    export_readonly_history(work, run, target)
    assert load_history(target).records
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    assert not list(work.glob("*.wal"))
    assert load_history(None).records == ()
    with pytest.raises(Exception, match="OUTPUT_MUST_BE_NEW"):
        export_readonly_history(work, run, target)
    bad = tmp_path / "invalid.json"
    bad.write_text(
        json.dumps({"schema_version": "clogcp-history-1", "records": [], "unexpected": True})
    )
    with pytest.raises(ValueError):
        load_history(bad)


def test_sre_and_report_history_are_retained_without_becoming_approval(historical):
    old, _, _ = historical
    snapshot = Snapshot(
        finding=old.finding,
        evidence_signature=old.evidence_signature,
        sre_history=({"verdict": "VALID", "validation_id": "synthetic-sre"},),
        report_history=({"included": True, "approved_by": "Synthetic assessor"},),
    )
    current = old.model_copy(update={"decisions": (), "decision_ids": ()})
    row = reconcile((current,), History(records=(snapshot,)))[0]
    assert row["historical_records"][0]["sre_history"][0]["validation_id"] == "synthetic-sre"
    assert not row["carry_forward_available"] and row["current_approval"] == "PENDING"


def test_recorded_current_review_is_reported_without_applying_historical_approval(historical):
    old, _, _ = historical
    before = old.model_dump_json()
    row = reconcile((old,), History(records=(old,)))[0]
    assert row["current_approval"] == "CONFIRMED"
    assert row["automatic_approval_applied"] is False
    assert row["current_decision_ids"] == list(old.decision_ids)
    stale = old.model_copy(
        update={"decisions": ({**old.decisions[0], "evidence_fingerprint": "0" * 64},)}
    )
    assert reconcile((stale,))[0]["current_approval"] == "NEEDS_REVALIDATION"
    assert old.model_dump_json() == before
