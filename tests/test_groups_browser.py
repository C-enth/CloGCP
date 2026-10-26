"""Root-cause groups in the compiled GUI (synthetic data)."""

import os

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


def test_group_view_and_group_mark_valid(tmp_path):
    from playwright.sync_api import expect, sync_playwright
    from test_theme_browser import serve
    from test_theme_browser import workspace as synthetic_workspace

    work = synthetic_workspace(tmp_path)
    with serve(work, "synthetic-groups") as origin, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1500, "height": 1000}).new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-groups")
        page.get_by_role("button", name="Findings workbench", exact=True).wait_for()
        page.get_by_role("tab", name="GCP", exact=True).click()
        page.get_by_role("button", name="Findings workbench", exact=True).click()
        page.get_by_text("Root-cause groups (").click()
        table = page.get_by_label("Root-cause groups", exact=True)
        first = table.locator("tbody tr").first
        expect(first).to_be_visible()
        first.get_by_role("button", name="Mark valid").click()
        expect(table.locator("tbody tr").first).to_contain_text("confirmed vulnerability")
        page.get_by_role("button", name="Report center", exact=True).click()
        expect(page.get_by_label("Group findings by root cause").first).to_be_checked()
        assert not errors
        browser.close()
