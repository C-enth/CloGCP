"""Synthetic individual-file backend deletion: explicit preview, exact confirmation."""

import time

import pytest
from fastapi.testclient import TestClient
from test_api import ORIGIN, TOKEN, authenticated, await_job
from test_scope_management import mixed  # noqa: F401  (fixture)

from offline_analyzer.api.app import create_app
from offline_analyzer.assessment import manage
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.reporting.cloud import dashboard
from offline_analyzer.rules.engine import verify_raw
from offline_analyzer.storage.store import Store


def cited_file(store, provider="GCP", scope="demo-alpha"):
    listed = manage.files(store, provider, scope)
    assert listed and all(len(f["sha256"]) == 64 for f in listed)
    plans = [manage.file_plan(store, f["sha256"]) for f in listed]
    return max(plans, key=lambda p: (p["findings"], p["observations"]))


@pytest.mark.parametrize("provider,scope", [("GCP", "demo-alpha"), ("AWS", "111111111111")])
def test_file_delete_removes_only_that_file_and_reassesses(mixed, provider, scope):  # noqa: F811
    work, _ = mixed
    with Store(work) as store:
        before = {(s["provider"], s["scope_id"]): s["resources"] for s in manage.scopes(store)}
        preview = cited_file(store, provider, scope)
        sha = preview["sha256"]
        assert preview["observations"] > 0 and preview["findings"] > 0
        assert preview["scopes"] == [{"provider": provider, "scope_id": scope}]
        assert f"raw/{sha}.json" in preview["files"] and (work / "raw" / f"{sha}.json").exists()
        result = manage.delete_file(store, sha, preview["preview_token"], sha[:12], True)
        assert result["action"] == "DELETE_FILE"
        assert not (work / "raw" / f"{sha}.json").exists()
        assert not (work / ".scope-journal.json").exists()
        assert not store.db.execute("SELECT 1 FROM artifacts WHERE sha256=?", [sha]).fetchone()
        assert not store.db.execute(manage.FILE_OBSERVATIONS, [sha]).fetchone()
        after = {(s["provider"], s["scope_id"]): s["resources"] for s in manage.scopes(store)}
        for key in before:
            if key != (provider, scope):
                assert after[key] == before[key]
        assert after.get((provider, scope), 0) <= before[(provider, scope)]
        if (provider, scope) in after:
            assert sha not in {f["sha256"] for f in manage.files(store, provider, scope)}
        for (run,) in store.rows("SELECT run_id FROM runs"):
            verify_raw(store, run)
        assert dashboard(store, result["run_id"])
        assert store.db.execute("SELECT count(*) FROM scope_audit").fetchone()[0] == 1
        with pytest.raises(InputError, match="FILE_NOT_FOUND"):
            manage.file_plan(store, sha)


@pytest.mark.parametrize("cut,confirmed", [(0, True), (11, True), (12, False), (64, True)])
def test_file_confirmation_never_approximates(mixed, cut, confirmed):  # noqa: F811
    work, _ = mixed
    with Store(work) as store:
        preview = cited_file(store)
        sha = preview["sha256"]
        with pytest.raises(InputError, match="FILE_CONFIRMATION_REQUIRED"):
            manage.delete_file(store, sha, preview["preview_token"], sha[:cut], confirmed)
        with pytest.raises(InputError, match="FILE_PREVIEW_STALE"):
            manage.delete_file(store, sha, preview["preview_token"] + "x", sha[:12], True)
        with pytest.raises(InputError, match="INVALID_FILE_DIGEST"):
            manage.file_plan(store, "../" + sha[:61])
        assert store.db.execute("SELECT 1 FROM artifacts WHERE sha256=?", [sha]).fetchone()
        assert (work / "raw" / f"{sha}.json").exists()


def test_file_delete_api_requires_preview_and_confirmation(mixed):  # noqa: F811
    work, _ = mixed
    with TestClient(create_app(work, origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN) as client:
        headers = authenticated(client)
        listed = client.post(
            "/api/assessment-data/files",
            headers=headers,
            json={"provider": "GCP", "scope_id": "demo-alpha"},
        )
        assert listed.status_code == 200
        sha = listed.json()[0]["sha256"]
        preview = client.post(
            "/api/assessment-data/file-delete-preview", headers=headers, json={"sha256": sha}
        ).json()
        body = {"sha256": sha, "preview_token": preview["preview_token"]}
        job = client.post("/api/assessment-data/file-delete", headers=headers, json=body).json()
        for _ in range(200):
            if job["status"] not in {"QUEUED", "RUNNING"}:
                break
            time.sleep(0.03)
            job = client.get("/api/jobs/" + job["id"]).json()
        assert job["status"] == "FAILED" and "FILE_CONFIRMATION_REQUIRED" in str(job)
        assert (work / "raw" / f"{sha}.json").exists()
        done = await_job(
            client,
            client.post(
                "/api/assessment-data/file-delete",
                headers=headers,
                json={**body, "confirmation": sha[:12], "confirmed": True},
            ),
        )
        assert done["action"] == "DELETE_FILE"
        assert not (work / "raw" / f"{sha}.json").exists()
