"""Visible refusal, safe diagnostics, retry and navigation during real assessment."""

import json
import os
import time

import pytest

from tests.launcher_support import LauncherSession
from tools.fixtures.gcp_pilot import PROJECT, pilot

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in browser")


@pytest.mark.parametrize("browser_name", ["chromium", "webkit"])
def test_failed_folder_retry_navigation_and_reopened_workspace(tmp_path, browser_name):
    from playwright.sync_api import expect, sync_playwright

    from offline_analyzer.storage.backup import backup, restore

    invalid = pilot(tmp_path / "unsupported", full_transport=True)
    manifest = invalid / "collection_manifest.json"
    data = json.loads(manifest.read_text())
    data["schema_version"] = "pilot-unsupported"
    manifest.write_text(json.dumps(data))
    valid = pilot(tmp_path / "corrected", full_transport=True)
    work = tmp_path / "workspace"
    with sync_playwright() as p:
        browser = getattr(p, browser_name).launch(headless=True)
        with LauncherSession(work) as session:
            context = browser.new_context(accept_downloads=True)
            page = context.new_page()
            page.goto(session.url)

            def validate(folder):
                page.get_by_role("button", name="Evidence import", exact=True).click()
                with page.expect_file_chooser() as chooser:
                    page.get_by_role(
                        "button", name="Import GCP Evidence Folder", exact=True
                    ).click()
                chooser.value.set_files(str(folder))
                expect(page.get_by_text("65 selected files", exact=True)).to_be_visible()
                with page.expect_response(lambda r: r.url.endswith("/api/uploads")) as response:
                    page.get_by_role("button", name="Validate evidence", exact=True).click()
                assert response.value.status == 200
                return response.value.json()["id"]

            failed_id = validate(invalid)
            details = page.get_by_label("Local operation details")
            expect(details).to_contain_text("UNSUPPORTED_MANIFEST_VERSION", timeout=30000)
            assert session.client.get(f"/api/jobs/{failed_id}").json()["state"] == "FAILED"
            assert session.client.get("/api/runs").json() == []
            with page.expect_download() as diagnostic:
                details.get_by_role("link", name="Export Sanitized Diagnostic Report").click()
            safe = json.loads(__import__("pathlib").Path(diagnostic.value.path()).read_text())
            assert (
                safe["job_id"] == failed_id and safe["error_code"] == "UNSUPPORTED_MANIFEST_VERSION"
            )
            assert PROJECT not in json.dumps(safe) and not safe["raw_values_included"]
            validate(valid)
            button = page.get_by_role("button", name="Import validated evidence", exact=True)
            button.wait_for(timeout=30000)
            page.get_by_role(
                "checkbox", name="I acknowledge that this legacy package", exact=False
            ).check()
            button.click()
            expect(page.get_by_role("button", name="Run assessment", exact=True)).to_be_enabled(
                timeout=30000
            )
            run = page.get_by_label("Active evidence run").input_value()
            with page.expect_response(
                lambda r: r.url.endswith(f"/api/runs/{run}/assess")
            ) as response:
                page.get_by_role("button", name="Run assessment", exact=True).click()
            assessment = response.value.json()["id"]
            page.get_by_role("button", name="Evidence import", exact=True).click()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                job = session.client.get(f"/api/jobs/{assessment}").json()
                if job["state"] not in {"PENDING", "RUNNING"}:
                    break
                page.wait_for_timeout(20)
            assert job["state"] == "COMPLETED"
            expect(page.get_by_role("button", name="Run assessment", exact=True)).to_be_enabled(
                timeout=30000
            )
            expect(
                page.get_by_role("button", name="Evidence import", exact=True)
            ).to_have_attribute("aria-current", "page")
            context.close()
        backup(work, tmp_path / "backup")
        restored = tmp_path / "restored"
        restore(tmp_path / "backup", restored)
        with LauncherSession(restored) as session:
            page = browser.new_page()
            page.goto(session.url)
            expect(
                page.get_by_label("Active evidence run").locator("option:checked")
            ).to_contain_text("Assessed")
            page.get_by_role("tab", name="GCP", exact=True).click()
            expect(page.get_by_label("GCP scope summary")).to_be_visible()
            page.get_by_role("tab", name="Security Findings", exact=True).click()
            expect(page.locator(".cloud-records tbody tr").first).to_be_visible()
            assert page.get_by_label("Active evidence run").input_value() == run
            page.close()
        browser.close()
