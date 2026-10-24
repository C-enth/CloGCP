"""Real production GUI must scope selection and filters to persisted workspace data."""

import os

import pytest

from tests.launcher_support import LauncherSession

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in browser")


@pytest.mark.parametrize("action", ["reload", "filters"])
def test_active_run_and_filters_do_not_drift(tmp_path, action):
    from playwright.sync_api import expect, sync_playwright

    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import record_run_origin, set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.gcp_fixture import build

    workspace = tmp_path / "synthetic-workspace"
    set_environment(workspace, "SYNTHETIC")
    runs = []
    with Store(workspace) as store:
        for i, project in enumerate(["demo-first", "demo-second"], 1):
            folder = build(tmp_path / project, project, str(i) * 12)
            run = import_package(store, folder)
            record_run_origin(workspace, run, "synthetic")
            assess(store, run)
            runs.append(run)
    with LauncherSession(workspace) as session, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(session.url)
        selector = page.get_by_label("Active evidence run")
        expect(selector.locator("option")).to_have_count(3)
        page.get_by_role("tab", name="GCP", exact=True).click()
        selector.select_option(runs[0])
        page.get_by_role("button", name="Evidence explorer", exact=True).click()
        search = page.get_by_label("Search evidence", exact=True)
        expect(
            page.locator(".records").filter(has=search).locator("tbody tr").first
        ).to_be_visible()
        if action == "reload":
            page.reload()
            expect(selector).to_have_value(runs[0])
        else:
            search.select_option(index=1)
            expect(
                page.locator(".records").filter(has=search).locator("tbody tr").first
            ).to_be_visible()
            selector.select_option(runs[1])
            expect(search).to_have_value("")
            records = page.locator(".records").filter(has=search)
            expect(records.locator("tbody tr").first).to_be_visible()
            expected = session.client.get(
                f"/api/runs/{runs[1]}/records/evidence?provider=GCP"
            ).json()
            expect(records.locator("tbody tr")).to_have_count(min(30, expected["total"]))
        origin = session.origin
        port = int(origin.rsplit(":", 1)[1])
        workspace_id = session.client.get("/api/environment").json()["workspace_id"]
        session.close()
        with LauncherSession(workspace, port=port) as restarted:
            page.goto(restarted.url)
            expect(selector).to_have_value(runs[0] if action == "reload" else runs[1])
            expect(page.get_by_role("tab", name="GCP", exact=True)).to_have_attribute(
                "aria-selected", "true"
            )
        with LauncherSession(tmp_path / "empty-workspace", port=port) as clean:
            page.goto(clean.url)
            assert clean.client.get("/api/environment").json()["workspace_id"] != workspace_id
            expect(selector).to_have_value("")
            expect(selector.locator("option")).to_have_count(1)
            for provider in ["AWS", "GCP", "Consolidated"]:
                page.get_by_role("tab", name=provider, exact=True).click()
                expect(page.get_by_text("No assessment imported.", exact=False)).to_be_visible()
            assert clean.client.get("/api/runs").json() == []
        browser.close()
