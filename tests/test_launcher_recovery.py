"""Unmocked launcher restart/cancel tests against private, deterministic byte-scale data."""

import json
import os
import time
from pathlib import Path

import pytest

from tests.launcher_support import LauncherSession
from tools.fixtures.large_import import large_aws

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in launcher")


def terminal(session, job_id, *, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = session.client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["state"] not in {"PENDING", "RUNNING"}:
            return job
        time.sleep(0.02)
    raise AssertionError("Actual local worker exceeded acceptance deadline")


def running(session, job_id, *, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = session.client.get(f"/api/jobs/{job_id}").json()
        if job["state"] == "RUNNING" and job["stage"] not in {"PENDING", "DATABASE_COMMIT"}:
            return job
        assert job["state"] in {"PENDING", "RUNNING"}
        time.sleep(0.01)
    raise AssertionError("Actual local worker did not start")


def post(session, path, body):
    response = session.client.post(path, json=body, headers=session.headers)
    assert response.status_code == 200, response.status_code
    return response.json()


def test_actual_process_cancel_interrupt_retry_and_database_recovery(tmp_path):
    from offline_analyzer.storage.store import Store

    package = large_aws(tmp_path / "package")
    work = tmp_path / "workspace"
    outcomes = []
    session = LauncherSession(work)
    try:
        with package["archive"].open("rb") as stream:
            response = session.client.post(
                "/api/uploads",
                headers=session.headers,
                files={"files": ("synthetic-large-aws.zip", stream, "application/zip")},
                data={
                    "paths": '["synthetic-large-aws.zip"]',
                    "context": '{"origin":"synthetic","background_validation":true}',
                },
            )
        assert response.status_code == 200
        validation = response.json()["id"]
        running(session, validation)
        post(session, f"/api/jobs/{validation}/cancel", {})
        cancelled = terminal(session, validation)
        assert cancelled["state"] == "CANCELLED"
        outcomes.append(cancelled)
        assert session.client.get("/api/runs").json() == []

        with package["archive"].open("rb") as stream:
            response = session.client.post(
                "/api/uploads",
                headers=session.headers,
                files={"files": ("synthetic-large-aws.zip", stream, "application/zip")},
                data={
                    "paths": '["synthetic-large-aws.zip"]',
                    "context": '{"origin":"synthetic","background_validation":true}',
                },
            )
        assert response.status_code == 200
        validated = terminal(session, response.json()["id"])
        assert validated["state"] == "COMPLETED" and validated["result"]["can_import"]
        outcomes.append(validated)
        upload = validated["result"]["upload_id"]
        body = {"upload_id": upload}
        importing = post(session, "/api/import", body)
        running(session, importing["id"])
        post(session, f"/api/jobs/{importing['id']}/cancel", {})
        cancelled = terminal(session, importing["id"])
        assert cancelled["state"] == "CANCELLED"
        outcomes.append(cancelled)
        assert session.client.get("/api/runs").json() == []

        interrupted = post(session, "/api/import", body)
        running(session, interrupted["id"])
        session.process.kill()  # Only the child owned by this synthetic test.
        session.process.wait(timeout=10)
        session.close(force=True)
        session = LauncherSession(work)
        recovered = session.client.get(f"/api/jobs/{interrupted['id']}").json()
        assert recovered["state"] == "INTERRUPTED" and recovered["error"] == "JOB_INTERRUPTED"
        outcomes.append(recovered)
        assert session.client.get("/api/runs").json() == []
        imported = terminal(session, post(session, "/api/import", body)["id"])
        assert imported["state"] == "COMPLETED"
        outcomes.append(imported)
        run = imported["result"]["run_id"]
        interrupted = post(session, f"/api/runs/{run}/assess", {})
        running(session, interrupted["id"])
        session.process.kill()
        session.process.wait(timeout=10)
        session.close(force=True)
        session = LauncherSession(work)
        recovered = session.client.get(f"/api/jobs/{interrupted['id']}").json()
        assert recovered["state"] == "INTERRUPTED"
        outcomes.append(recovered)
        runs = session.client.get("/api/runs").json()
        assert len(runs) == 1 and runs[0]["run_id"] == run and not runs[0]["assessed"]
        assessed = terminal(session, post(session, f"/api/runs/{run}/assess", {})["id"])
        assert assessed["state"] == "COMPLETED"
        outcomes.append(assessed)
        assert session.client.get("/api/runs").json()[0]["assessed"]
    finally:
        session.close()
    with Store(work) as store:
        assert len(list(store.observations(run))) > 0
        assert len(list(store.results(run))) > 0
        assert len(list(store.candidates(run))) > 0
        assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 1
        assert store.db.execute("SELECT count(*) FROM assessments").fetchone()[0] == 1
        store.db.execute("CHECKPOINT")
    output = Path("artifacts/recovery-process-acceptance")
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_text(
        json.dumps(
            {
                "origin": "SYNTHETIC_ONLY",
                "launcher": "ACTUAL",
                "run_id": run,
                "expanded_bytes": package["expanded_bytes"],
                "jobs": [
                    {
                        key: row.get(key)
                        for key in (
                            "id",
                            "kind",
                            "state",
                            "stage",
                            "error",
                            "duration_seconds",
                            "timings",
                        )
                    }
                    for row in outcomes
                ],
                "database_consistency": "REOPENED_AND_CHECKPOINTED",
            },
            indent=2,
        )
        + "\n"
    )
