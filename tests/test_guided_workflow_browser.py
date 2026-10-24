"""Regression for the stuck PACKAGE_READY workflow, on the real launcher and compiled GUI.

Reproduces the field report: an expanded GCP package was validated, the application was
reopened, and every page kept showing the Package validation card with no run selected.
The Evidence import workflow restores the pending import while other dashboards stay
uncluttered. Import + analysis uses the validated importer and opens assessment results.
"""

import os
import socket
import time

import pytest

from tests.launcher_support import LauncherSession
from tools.fixtures.gcp_expanded import expanded

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in browser")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_job(session, job_id: str) -> dict:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        job = session.client.get("/api/jobs/" + job_id, headers=session.headers).json()
        if job["state"] not in {"PENDING", "RUNNING"}:
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_validated_package_reaches_results_after_restart(tmp_path):
    from playwright.sync_api import expect, sync_playwright

    folder = expanded(tmp_path / "collection", mixed=True)
    work = tmp_path / "workspace"
    port = free_port()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        # Session 1: validate only, exactly as in the field report, then stop the app.
        with LauncherSession(work, port=port) as session:
            page = browser.new_page(viewport={"width": 1500, "height": 1000})
            page.goto(session.url)
            page.get_by_role("button", name="Evidence import", exact=True).click()
            page.get_by_label("Select package folder").set_input_files(str(folder))
            page.get_by_role("button", name="Validate evidence", exact=True).click()
            expect(page.get_by_role("button", name="Import and analyze", exact=True)).to_be_visible(
                timeout=30000
            )
            page.close()
        # Session 2: reopen. The validation is restored as a pending step, not page content.
        with LauncherSession(work, port=port) as session:
            page = browser.new_page(viewport={"width": 1500, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(session.url)
            workflow = page.get_by_label("Assessment workflow")
            expect(workflow).not_to_contain_text("Validated package not yet imported")
            for screen in ("Dashboard", "Findings workbench", "IAM intelligence", "Report center"):
                page.get_by_role("button", name=screen, exact=True).click()
                # The historical validation job card is not repeated on unrelated pages.
                expect(page.get_by_label("Local operation details")).to_have_count(0)
                expect(page.locator("main")).to_contain_text("has not been imported yet")
                expect(workflow).not_to_contain_text("Validated package not yet imported")
            page.get_by_role("button", name="Evidence import", exact=True).click()
            expect(page.get_by_role("heading", name="Validation preview")).to_be_visible()
            expect(page.get_by_label("Manifest detection details")).to_contain_text(
                "assessment-expanded-2.1"
            )
            # The restored preview owns its actions; no duplicate pending-import card.
            expect(page.get_by_role("button", name="Import and analyze", exact=True)).to_have_count(
                1
            )
            page.get_by_role(
                "checkbox", name="I acknowledge that this legacy package", exact=False
            ).check()
            with page.expect_response(lambda r: r.url.endswith("/api/import")) as submitted:
                page.get_by_role("button", name="Import and analyze", exact=True).click()
            job = wait_job(session, submitted.value.json()["id"])
            assert job["state"] == "COMPLETED", job.get("error")
            assert job["kind"] == "Import and analysis"
            run = job["result"]["run_id"]
            open_results = page.get_by_role("button", name="Open assessment results")
            expect(page.get_by_label("Active evidence run")).to_have_value(run, timeout=30000)
            # The completed run is analyzed and labelled by provider/project, not internal IDs.
            checked = page.get_by_label("Active evidence run").locator("option:checked")
            expect(checked).to_contain_text("GCP")
            expect(checked).to_contain_text("Assessed")
            # Auto-navigation already shows the right dashboard; from elsewhere, one click.
            page.get_by_role("button", name="Findings workbench", exact=True).click()
            expect(open_results).to_be_visible()
            open_results.click()
            expect(page.get_by_role("heading", name="Dashboard", level=1)).to_be_visible()
            expect(page.get_by_role("tab", name="GCP", exact=True)).to_have_attribute(
                "aria-selected", "true"
            )
            expect(workflow).not_to_contain_text("Validated package not yet imported")
            runs = session.client.get("/api/runs", headers=session.headers).json()
            entry = next(r for r in runs if r["run_id"] == run)
            assert entry["assessed"] and entry["provider"] == "GCP"
            assert entry["evaluation_count"] > 0
            pending = session.client.get("/api/workflow", headers=session.headers).json()
            assert pending["pending_imports"] == []
            # Same run survives a browser refresh.
            page.reload()
            expect(page.get_by_label("Active evidence run")).to_have_value(run, timeout=30000)
            assert errors == []
        browser.close()
