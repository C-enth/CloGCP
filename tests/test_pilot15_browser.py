"""Production GUI pilot-1.5 import/rejection; real launcher/API/DuckDB/engine."""

import json
import os
import time

import pytest

from tests.launcher_support import LauncherSession
from tests.test_gcp_legacy import zip_pilot
from tools.fixtures.gcp_pilot15 import build

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


@pytest.mark.parametrize("transport", ["Folder"])
def test_pilot15_gui_rejection_retry_import_assess_and_export(tmp_path, transport):
    from playwright.sync_api import expect, sync_playwright

    from offline_analyzer.storage.store import Store

    folder = build(tmp_path / "valid")
    archive = zip_pilot(folder, tmp_path / "valid.zip")
    bad = build(tmp_path / "unsupported")
    manifest = bad / "collection_manifest.json"
    data = json.loads(manifest.read_text())
    data["schema_version"] = "pilot-1.6"
    manifest.write_text(json.dumps(data))
    work = tmp_path / "workspace"
    with LauncherSession(work) as session, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(accept_downloads=True)
        errors = []
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(session.url)
        page.get_by_role("tab", name="GCP", exact=True).click()
        page.get_by_role("button", name="Evidence import", exact=True).click()

        def select(package, mode):
            with page.expect_file_chooser() as chooser:
                page.get_by_role("button", name=f"Import GCP Evidence {mode}", exact=True).click()
            chooser.value.set_files(str(package))

        select(bad, "Folder")
        page.get_by_role("button", name="Validate evidence", exact=True).click()
        details = page.get_by_label("Manifest detection details")
        expect(details).to_contain_text("pilot-1.6")
        expect(details).to_contain_text("NONE")
        expect(details).to_contain_text("pilot-1.2.2, pilot-1.5")
        expect(details).to_contain_text("root schema_version is not a supported collector version")
        expect(details).to_contain_text("Do not rename or edit the manifest")
        expect(page.get_by_role("alert").first).to_contain_text("UNSUPPORTED_MANIFEST_VERSION")

        select(folder if transport == "Folder" else archive, transport)
        if transport == "Folder":
            paths = page.get_by_label("Select package folder").evaluate(
                "input => Array.from(input.files).map(file => file.webkitRelativePath)"
            )
            assert len(paths) == 65 and all("/" in path for path in paths)
            assert any(path.endswith("/collection_manifest.json") for path in paths)
        page.get_by_role("button", name="Validate evidence", exact=True).click()
        button = page.get_by_role("button", name="Import validated evidence", exact=True)
        button.wait_for()
        expect(details).to_contain_text("gcp-pilot-1.5-adapter-1")
        page.get_by_role(
            "checkbox", name="I acknowledge that this legacy package", exact=False
        ).check()
        button.click()
        assess = page.get_by_role("button", name="Run assessment", exact=True)
        expect(assess).to_be_enabled(timeout=30000)
        run = page.get_by_label("Active evidence run").input_value()
        with page.expect_response(
            lambda response: response.url.endswith(f"/api/runs/{run}/assess")
        ) as submitted:
            assess.click()
        job_id = submitted.value.json()["id"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            job = context.request.get(session.origin + "/api/jobs/" + job_id).json()
            if job["state"] not in {"PENDING", "RUNNING"}:
                break
            page.wait_for_timeout(50)
        assert job["state"] == "COMPLETED"
        expect(assess).to_be_enabled(timeout=30000)
        page.get_by_role("tab", name="Security Findings", exact=True).click()
        expect(page.locator(".cloud-records tbody tr").first).to_be_visible()
        page.get_by_role("button", name="Report center", exact=True).click()
        page.get_by_role("button", name="Generate Excel", exact=True).click()
        report = (
            page.locator("tr")
            .filter(has_text="CloSec-assessment-excel.xlsx")
            .filter(has_text=run[:20])
            .first
        )
        report.get_by_role("link", name="Download", exact=True).wait_for()
        with page.expect_download() as download:
            report.get_by_role("link", name="Download", exact=True).click()
        download.value.save_as(tmp_path / "result.xlsx")
        assert not errors
        browser.close()
    with Store(work) as store:
        assert len(list(store.source_data(run))) == 63
        assert (
            list(store.observations(run))
            and list(store.results(run))
            and list(store.candidates(run))
        )
