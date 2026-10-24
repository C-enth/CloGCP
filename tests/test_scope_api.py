"""Real protected APIs over synthetic imports and managed files."""

import json

from fastapi.testclient import TestClient
from test_api import ORIGIN, TOKEN, authenticated, await_job
from test_gcp_legacy import PROJECT, pilot, zip_pilot

from offline_analyzer.api.app import create_app
from tools.gcp_fixture import build


def upload(client, headers, path, provider="GCP"):
    names = (
        [p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()]
        if path.is_dir()
        else [path.name]
    )
    files = [
        (
            "files",
            (
                name,
                (path / name if path.is_dir() else path).read_bytes(),
                "application/octet-stream",
            ),
        )
        for name in names
    ]
    response = client.post(
        "/api/uploads",
        headers=headers,
        files=files,
        data={
            "paths": json.dumps(names),
            "context": json.dumps({"provider": provider, "origin": "synthetic"}),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_legacy_zip_api_import_acknowledgment_and_scope_delete(tmp_path):
    folder = pilot(tmp_path / "pilot")
    archive = zip_pilot(folder, tmp_path / "pilot.zip")
    work = tmp_path / "work"
    with TestClient(create_app(work, origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN) as client:
        headers = authenticated(client)
        checked = upload(client, headers, archive)
        assert (
            len(checked["sources"]) == 32
            and checked["diagnostics"]["original_status_totals"]["FAILED"] == 19
        )
        original = work / "uploads" / (checked["upload_id"] + ".zip")
        assert original.read_bytes() == archive.read_bytes()
        refused = client.post(
            "/api/import", headers=headers, json={"upload_id": checked["upload_id"]}
        )
        assert (
            refused.status_code == 400
            and refused.json()["error"] == "LEGACY_INTEGRITY_ACKNOWLEDGMENT_REQUIRED"
        )
        imported = await_job(
            client,
            client.post(
                "/api/import",
                headers=headers,
                json={"upload_id": checked["upload_id"], "acknowledge_legacy_integrity": True},
            ),
        )["run_id"]
        await_job(client, client.post(f"/api/runs/{imported}/assess", headers=headers, json={}))
        scoped = client.get("/api/assessment-data/scopes").json()
        assert any(
            s["scope_id"] == PROJECT and s["project_number"] == "123456789012" for s in scoped
        )
        body = {"provider": "GCP", "scope_id": PROJECT}
        preview = client.post(
            "/api/assessment-data/delete-preview", headers=headers, json=body
        ).json()
        result = await_job(
            client,
            client.post(
                "/api/assessment-data/delete",
                headers=headers,
                json={
                    **body,
                    "preview_token": preview["preview_token"],
                    "confirmation": PROJECT,
                    "confirmed": True,
                },
            ),
        )
        assert result["action"] == "DELETE"
        assert client.get("/api/assessment-data/scopes").json() == []
        assert not original.exists() and archive.exists()
        assert not list((work / "uploads" / checked["upload_id"]).glob("**/*.*"))
        checked = upload(client, headers, archive)
        await_job(
            client,
            client.post(
                "/api/import",
                headers=headers,
                json={"upload_id": checked["upload_id"], "acknowledge_legacy_integrity": True},
            ),
        )
        assert client.get("/api/assessment-data/scopes").json()


def test_replacement_endpoint_keeps_other_project(tmp_path):
    work = tmp_path / "work"
    with TestClient(create_app(work, origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN) as client:
        headers = authenticated(client)
        for name, number in [("demo-alpha", "123456789012"), ("demo-beta", "222222222222")]:
            folder = build(tmp_path / name, name, number)
            checked = upload(client, headers, folder)
            run = await_job(
                client,
                client.post(
                    "/api/import", headers=headers, json={"upload_id": checked["upload_id"]}
                ),
            )["run_id"]
            await_job(client, client.post(f"/api/runs/{run}/assess", headers=headers, json={}))
        fresh = build(tmp_path / "fresh", "demo-alpha", "123456789012")
        checked = upload(client, headers, fresh)
        result = await_job(
            client,
            client.post(
                "/api/assessment-data/replace",
                headers=headers,
                json={
                    "provider": "GCP",
                    "scope_id": "demo-alpha",
                    "upload_id": checked["upload_id"],
                },
            ),
        )
        dashboard = client.get(f"/api/runs/{result['run_id']}/cloud/dashboard").json()
        assert dashboard["providers"]["GCP"]["imported_scopes"] == ["demo-alpha", "demo-beta"]
        assert (
            client.post(
                "/api/assessment-data/delete",
                headers=headers,
                json={"provider": "AWS", "scope_id": "demo-alpha", "preview_token": "invalid"},
            ).status_code
            == 422
        )
        assert client.post("/api/assessment-data/delete", json={}).status_code == 403
