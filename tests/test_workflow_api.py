"""Guided workflow API: pending validated packages, import-and-analyze and run identity."""

import time

from fastapi.testclient import TestClient

from offline_analyzer.api.app import create_app
from tools.fixtures.aws_v030_native import ACCOUNT, package


def client(workspace):
    app = create_app(workspace, origin="http://127.0.0.1:8765", bootstrap="workflow-token")
    test = TestClient(app, base_url="http://127.0.0.1:8765")
    headers = {"Origin": "http://127.0.0.1:8765"}
    session = test.post(
        "/api/session", json={}, headers={**headers, "X-Bootstrap-Token": "workflow-token"}
    ).json()
    return test, {**headers, "X-CSRF-Token": session["csrf"]}


def wait(test, headers, job):
    for _ in range(600):
        current = test.get(f"/api/jobs/{job['id']}", headers=headers).json()
        if current["status"] not in {"QUEUED", "RUNNING"}:
            return current
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_validated_package_is_pending_until_import_and_analysis(tmp_path):
    archive = package(tmp_path / "evidence", archive=True)
    test, headers = client(tmp_path / "workspace")
    with test:
        start = test.post(
            "/api/uploads/start",
            json={"provider": "AWS", "import_mode": "ZIP", "files_total": 1},
            headers=headers,
        ).json()
        with archive.open("rb") as handle:
            response = test.post(
                "/api/uploads",
                files={"files": (archive.name, handle, "application/zip")},
                data={
                    "paths": f'["{archive.name}"]',
                    "context": '{"provider": "AWS", "origin": "synthetic"}',
                },
                headers={**headers, "X-Upload-Job": start["id"]},
            )
        assert response.status_code == 200, response.text
        validated = response.json()
        assert validated["can_import"]
        pending = test.get("/api/workflow", headers=headers).json()["pending_imports"]
        assert [p["upload_id"] for p in pending] == [validated["upload_id"]]
        assert pending[0]["provider"] == "AWS" and pending[0]["scopes"] == [ACCOUNT]
        assert pending[0]["legacy_acknowledgment_required"] is False
        assert test.get("/api/runs", headers=headers).json() == []
        job = test.post(
            "/api/import",
            json={"upload_id": validated["upload_id"], "analyze": True},
            headers=headers,
        ).json()
        done = wait(test, headers, job)
        assert done["status"] == "SUCCEEDED" and done["kind"] == "Import and analysis"
        run = done["result"]["run_id"]
        assert test.get("/api/workflow", headers=headers).json()["pending_imports"] == []
        [entry] = test.get("/api/runs", headers=headers).json()
        assert entry["run_id"] == run and entry["assessed"]
        assert entry["provider"] == "AWS" and entry["aws_accounts"] == [ACCOUNT]
        assert entry["finding_count"] >= 5 and entry["evaluation_count"] > entry["finding_count"]


def test_collectors_are_downloadable_with_listed_hashes(tmp_path):
    import hashlib
    import io
    import zipfile

    test, headers = client(tmp_path / "workspace")
    with test:
        items = {i["id"]: i for i in test.get("/api/collectors", headers=headers).json()}
        assert items["aws"]["name"] == "CloSec_AWS_Collector_v0.3.2.zip"
        assert items["gcp"]["name"] == "CloSec_GCP_Collector_v2.2.5.zip"
        assert set(items) == {"aws", "gcp", "contract"}
        for key, item in items.items():
            response = test.get(f"/api/collectors/{key}/download", headers=headers)
            assert response.status_code == 200
            assert hashlib.sha256(response.content).hexdigest() == item["sha256"]
            assert item["name"] in response.headers["content-disposition"]
        archive = zipfile.ZipFile(io.BytesIO(test.get("/api/collectors/aws/download").content))
        assert sorted(archive.namelist()) == sorted(
            f"CloSec_AWS_Collector/{name}"
            for name in [
                "assessment.py",
                "README.md",
                "config.example.json",
                "approved_accounts.example.txt",
                "collector-analyzer-contract.json",
                "evidence/",
            ]
        )
        assert b'VERSION = "0.3.2"' in archive.read("CloSec_AWS_Collector/assessment.py")
        gcp = zipfile.ZipFile(io.BytesIO(test.get("/api/collectors/gcp/download").content))
        assert sorted(gcp.namelist()) == sorted(
            f"CloSec_GCP_Collector/{name}"
            for name in [
                "GCP_Security_Evidence_Collector.ps1",
                "README.md",
                "collector-analyzer-contract.json",
                "organization/",
                "projects/",
            ]
        )
        assert b"$CollectorVersion = '2.2.5'" in gcp.read(
            "CloSec_GCP_Collector/GCP_Security_Evidence_Collector.ps1"
        )
        assert test.get("/api/collectors/..%2Fpyproject/download").status_code >= 400
