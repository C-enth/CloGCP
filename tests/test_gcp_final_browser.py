"""Compiled GUI acceptance for the mandatory independent-action workflow (synthetic)."""

import os
import socket
import threading
import time
from pathlib import Path

import pytest
from test_gcp_final_workflow import (  # noqa: F401, F811
    MATRIX_HASH,
    FakeTransport,
    baseline,
    delta_plan,
)

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


def test_preserved_upgrade_delta_composition_path_comparison_and_finalizer(
    request, tmp_path, monkeypatch
):
    import zipfile

    import uvicorn
    from openpyxl import load_workbook
    from playwright.sync_api import expect, sync_playwright

    from clogcp_delta.collector import collect
    from clogcp_report_finalizer.core import finalize
    from offline_analyzer.api.app import create_app
    from offline_analyzer.storage.side_by_side import (
        database_inventory,
        file_inventory,
        recover_copy,
    )

    original, b1, b2, run = request.getfixturevalue("baseline")
    before_files, before_tables = file_inventory(original), database_inventory(original)
    work = tmp_path / "upgraded"
    recover_copy(original, work)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    listener.listen(128)
    app = create_app(work, origin=origin, bootstrap="synthetic-integration")
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    artifacts = Path("artifacts/gcp-final-workflow-browser") / tmp_path.parent.name
    artifacts.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                accept_downloads=True, viewport={"width": 1600, "height": 1050}
            )
            errors, external = [], []

            def route(request):
                if request.request.url.startswith(origin):
                    request.continue_()
                else:
                    external.append(request.request.url)
                    request.abort()

            context.route("**/*", route)
            page = context.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(origin + "/#token=synthetic-integration")
            expect(page.get_by_label("Active evidence run")).to_be_visible()
            page.get_by_label("Active evidence run").select_option(run)
            page.get_by_role("tab", name="GCP", exact=True).click()
            page.get_by_role("tab", name="Attack Paths", exact=True).click()

            # Path-only action cannot invoke rules, reimport or enterprise rebuilding.
            def forbidden(*args, **kwargs):
                raise AssertionError("Independent path action crossed analysis/import boundary")

            with monkeypatch.context() as patch:
                patch.setattr("offline_analyzer.rules.engine.assess", forbidden)
                patch.setattr("offline_analyzer.ingestion.importer.import_package", forbidden)
                patch.setattr("offline_analyzer.enterprise.snapshot.build_snapshot", forbidden)
                for version in (1, 2):
                    page.get_by_role("button", name="Recalculate Attack Paths", exact=True).click()
                    expect(
                        page.get_by_label("Versioned attack-path recalculation")
                    ).to_contain_text(f"{version} version(s) retained", timeout=120000)
                expect(
                    page.get_by_role("table", name="Old versus new attack paths")
                ).to_be_visible()
                page.screenshot(path=str(artifacts / "independent-comparison.png"), full_page=True)
            assert database_inventory(work) == before_tables
            package = tmp_path / "delta"
            collect(
                delta_plan(),
                package,
                execute=True,
                transport=FakeTransport(),
                matrix_sha256=MATRIX_HASH,
                origin="synthetic",
            )
            # Import the complete multi-project package through the real local API.
            csrf = context.request.get(origin + "/api/session").json()["csrf"]
            headers = {"Origin": origin, "X-CSRF-Token": csrf}
            page.get_by_role("button", name="Evidence import", exact=True).click()
            with page.expect_file_chooser() as chooser:
                page.get_by_role("button", name="Import GCP Evidence Folder", exact=True).click()
            chooser.value.set_files(str(package))
            page.get_by_role("button", name="Validate evidence", exact=True).click()
            page.get_by_role("button", name="Import validated evidence", exact=True).wait_for(
                timeout=120000
            )
            page.get_by_role("button", name="Import validated evidence", exact=True).click()
            expect(page.get_by_role("button", name="Run assessment", exact=True)).to_be_enabled(
                timeout=120000
            )
            imports = context.request.get(origin + "/api/supplementary-imports").json()["items"]
            assert len(imports) == 1
            delta = imports[0]["run_id"]
            page.get_by_label("Active evidence run").select_option(run)
            page.get_by_role("tab", name="GCP", exact=True).click()
            page.get_by_role("tab", name="Attack Paths", exact=True).click()
            page.get_by_label("Imported supplementary snapshot").select_option(delta)
            page.get_by_role("button", name="Create affected analysis version", exact=True).click()
            expect(page.get_by_label("Supplementary evidence analysis")).to_contain_text(
                "New analysis version:", timeout=120000
            )
            expect(
                page.get_by_role("table", name="Supplementary findings reconciliation")
            ).to_be_visible()
            # The fixture retains one original B1 import as well; use job result for exact new ID.
            jobs = context.request.get(origin + "/api/jobs").json()
            jobs = jobs.get("items", jobs) if isinstance(jobs, dict) else jobs
            job = next(j for j in jobs if j["kind"] == "Supplementary evidence analysis")
            detail = context.request.get(origin + "/api/jobs/" + job["id"]).json()
            derived = detail["result"]["run_id"]
            page.get_by_role("button", name="Refresh assessments", exact=True).click()
            page.get_by_label("Active evidence run").select_option(derived)
            page.get_by_role("tab", name="GCP", exact=True).click()
            page.get_by_role("tab", name="Attack Paths", exact=True).click()
            page.get_by_role("button", name="Recalculate Attack Paths", exact=True).click()
            expect(page.get_by_label("Versioned attack-path recalculation")).to_contain_text(
                "1 version(s) retained", timeout=120000
            )
            expect(page.get_by_label("Versioned attack-path recalculation")).to_contain_text(
                "BASE_ANALYSIS_PATH_EVALUATION"
            )
            page.screenshot(path=str(artifacts / "supplementary-version.png"), full_page=True)
            # Export uses the same authenticated API as the established report button.
            response = context.request.post(
                origin + f"/api/runs/{derived}/reports",
                headers=headers,
                data={
                    "kind": "assessment",
                    "include": "valid",
                    "provider": "GCP",
                    "grouped": False,
                },
            )
            assert response.ok, response.text()
            job = response.json()
            for _ in range(300):
                if job["status"] not in {"QUEUED", "RUNNING"}:
                    break
                time.sleep(0.1)
                job = context.request.get(origin + "/api/jobs/" + job["id"]).json()
            assert job["status"] == "SUCCEEDED", job
            # Download link shape is checked against the existing export contract below.
            result = job["result"]
            response = context.request.get(origin + f"/api/reports/{result['id']}/download")
            assert response.ok
            exported = tmp_path / "export.zip"
            exported.write_bytes(response.body())
            with zipfile.ZipFile(exported) as z:
                source = tmp_path / "consolidated.xlsx"
                source.write_bytes(z.read(next(n for n in z.namelist() if n.endswith(".xlsx"))))
                assert "attack-path-evaluation-v2.json" in z.namelist()
            finalized = finalize(source, artifacts / "client-report", origin="SYNTHETIC")
            assert finalized["qa_issues"] and finalized["client_observations"]
            book = load_workbook(artifacts / "client-report" / "CloGCP-client-report.xlsx")
            assert "GCP_Path_Evaluations_v2" in book
            book.close()
            assert not errors and not external
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        listener.close()
    assert file_inventory(original) == before_files
    assert database_inventory(original) == before_tables
