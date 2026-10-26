"""Real worker transactions, journal recovery and sanitized local diagnostics."""

import json
import time
from datetime import UTC, datetime
from threading import Event

import pytest

from offline_analyzer.api.coordinator import Coordinator
from offline_analyzer.api.diagnostics import job_diagnostic
from offline_analyzer.api.runtime import RuntimeIdentity
from offline_analyzer.contracts.errors import InputError
from offline_analyzer.provenance.execution import checkpoint
from offline_analyzer.storage.store import Store


def finished(coordinator, job, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        current = coordinator.status(job["id"])
        if current["status"] not in {"QUEUED", "RUNNING"}:
            return current
        time.sleep(0.01)
    raise AssertionError("Worker did not reach a terminal state")


def test_completed_job_journal_survives_workspace_restart(tmp_path):
    coordinator = Coordinator(tmp_path)
    job = coordinator.submit("Synthetic work", lambda store: {"result_count": 1})
    done = finished(coordinator, job)
    assert done["state"] == "COMPLETED" and done["finished_at"] >= done["submitted_at"]
    coordinator.close()
    restarted = Coordinator(tmp_path)
    try:
        assert restarted.status(job["id"])["state"] == "COMPLETED"
        assert (tmp_path / "jobs" / f"{job['id']}.json").stat().st_mode & 0o777 == 0o600
        log = (tmp_path / "jobs/operations.jsonl").read_text()
        assert "COMPLETED" in log and "workspace" not in log
    finally:
        restarted.close()


def test_cancellation_rolls_back_running_writer_transaction(tmp_path):
    coordinator = Coordinator(tmp_path)
    began = Event()
    run = "run-" + "a" * 64

    def transaction(store):
        with store.transaction():
            store.db.execute(
                "INSERT INTO runs VALUES (?,?,?)", [run, datetime.now(UTC).isoformat(), "{}"]
            )
            began.set()
            while True:
                checkpoint("RESOURCE_NORMALIZATION")
                time.sleep(0.01)

    job = coordinator.submit("Synthetic transaction", transaction, cancellable=True)
    try:
        assert began.wait(5)
        coordinator.cancel(job["id"])
        done = finished(coordinator, job)
        assert done["state"] == "CANCELLED" and done["error"] == "JOB_CANCELLED"
        with Store(tmp_path) as store:
            assert (
                store.db.execute("SELECT count(*) FROM runs WHERE run_id=?", [run]).fetchone()[0]
                == 0
            )
    finally:
        coordinator.close()


def test_restart_marks_unscheduled_transfer_interrupted(tmp_path):
    first = Coordinator(tmp_path)
    job = first.prepare(
        "Package validation",
        context={"provider": "GCP", "import_mode": "FOLDER", "files_total": 65},
        cancellable=True,
    )
    scratch = tmp_path / ".upload-staging" / f"upload-{job['id']}-synthetic"
    scratch.mkdir(parents=True)
    (scratch / "incomplete.json").write_text("{}")
    preserved = tmp_path / "existing-work"
    preserved.mkdir()
    (preserved / "keep.json").write_text("{}")
    # Read the crash journal in a fresh owner. The old synthetic owner has no future or DB.
    second = Coordinator(tmp_path)
    try:
        recovered = second.status(job["id"])
        assert recovered["state"] == "INTERRUPTED" and recovered["error"] == "JOB_INTERRUPTED"
        assert not recovered["cancel_supported"]
        # Opening a new application preserves historical files. Interrupted status is
        # projected in memory; explicit maintenance owns scratch cleanup.
        assert scratch.exists() and (preserved / "keep.json").is_file()
        persisted = json.loads((tmp_path / "jobs" / (job["id"] + ".json")).read_text())
        assert persisted["status"] == "QUEUED"
    finally:
        first.close()
        second.close()


def test_job_execution_budget_terminates_and_can_retry(tmp_path):
    coordinator = Coordinator(tmp_path)
    began, release = Event(), Event()

    def work(store):
        began.set()
        release.wait(5)
        while True:
            checkpoint()
            time.sleep(0.01)

    job = coordinator.submit("Synthetic budget", work, cancellable=True)
    try:
        assert began.wait(5)
        coordinator.signals[job["id"]].budget_seconds = 0.05
        release.set()
        done = finished(coordinator, job)
        assert done["state"] == "FAILED" and done["error"] == "JOB_TIME_LIMIT"
        retry = coordinator.submit("Synthetic retry", lambda store: {"retry": True})
        assert finished(coordinator, retry)["state"] == "COMPLETED"
    finally:
        release.set()
        coordinator.close()


def test_journal_write_failure_does_not_leave_running_job_and_retry_works(tmp_path, monkeypatch):
    coordinator = Coordinator(tmp_path)
    original = coordinator.journal.save

    def unavailable(job):
        raise OSError("Synthetic disk failure without customer text")

    try:
        monkeypatch.setattr(coordinator.journal, "save", unavailable)
        with pytest.raises(InputError, match="JOB_JOURNAL_UNAVAILABLE"):
            coordinator.prepare("Synthetic disk failure")
        assert coordinator.history() == []
        monkeypatch.setattr(coordinator.journal, "save", original)
        began, release = Event(), Event()

        def work(store):
            began.set()
            release.wait(5)
            checkpoint("RESOURCE_NORMALIZATION")
            return {"success": True}

        job = coordinator.submit("Synthetic disk failure", work, cancellable=True)
        assert began.wait(5)
        monkeypatch.setattr(coordinator.journal, "save", unavailable)
        release.set()
        done = finished(coordinator, job)
        assert done["state"] == "FAILED" and done["error"] == "JOB_JOURNAL_UNAVAILABLE"
        monkeypatch.setattr(coordinator.journal, "save", original)
        retry = coordinator.submit("Synthetic disk retry", lambda store: {"retry": True})
        assert finished(coordinator, retry)["state"] == "COMPLETED"
    finally:
        monkeypatch.setattr(coordinator.journal, "save", original)
        coordinator.close()


def test_diagnostic_projection_excludes_paths_values_and_unknown_operation_names(tmp_path):
    coordinator = Coordinator(tmp_path)
    marker = "CUSTOMER_PRIVATE_CONFIGURATION_MARKER"
    job = coordinator.submit(
        "Synthetic diagnostic",
        lambda store: {
            "private_path": marker,
            "diagnostics": {
                "project_id": marker,
                "sources": [
                    {
                        "operation": marker,
                        "profile": marker,
                        "original_status": "FAILED",
                        "effective_coverage": "ERROR",
                    }
                ],
            },
        },
    )
    try:
        done = finished(coordinator, job)
        diagnostic = job_diagnostic(RuntimeIdentity(), done)
        assert marker not in json.dumps(diagnostic)
        assert diagnostic["unsupported_dataset_count"] == 1
        assert diagnostic["collection_error_count"] == 1
        assert diagnostic["real_evidence_compatibility"] == "NOT_ESTABLISHED"
        assert not diagnostic["raw_values_included"] and not diagnostic["customer_paths_included"]
    finally:
        coordinator.close()


def test_report_cancel_during_workbook_publication_removes_partial_files(tmp_path):
    from offline_analyzer.api.services import Views
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.rules.engine import assess
    from tools.fixtures.r12_demo import build

    package = tmp_path / "package"
    build(package)
    workspace = tmp_path / "workspace"
    with Store(workspace) as store:
        run = import_package(store, package)
        assess(store, run)
    coordinator = Coordinator(workspace)
    saving, release = Event(), Event()

    def progress(stage, completed, total):
        coordinator.progress(stage, completed, total)
        if stage == "Saving workbook":
            saving.set()
            release.wait(5)

    try:
        job = coordinator.submit(
            "Report",
            lambda store: Views(workspace).export(store, run, "excel", progress=progress),
            cancellable=True,
        )
        assert saving.wait(5)
        coordinator.cancel(job["id"])
        release.set()
        done = finished(coordinator, job)
        assert done["state"] == "CANCELLED"
        assert list((workspace / "reports").iterdir()) == []
        retry = coordinator.submit(
            "Report", lambda store: Views(workspace).export(store, run, "excel"), cancellable=True
        )
        assert finished(coordinator, retry)["state"] == "COMPLETED"
    finally:
        release.set()
        coordinator.close()
