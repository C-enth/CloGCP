"""Compiled GUI: a frozen edition blocks removal unless explicitly marked superseded."""

import os
import re

import pytest

from tests.test_theme_browser import serve, workspace

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


def test_frozen_edition_blocks_then_explicit_supersede_override(tmp_path):
    from playwright.sync_api import expect, sync_playwright

    from offline_analyzer.findings.finalisation import freeze, frozen
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.storage.store import Store

    work = workspace(tmp_path)
    with Store(work) as store:
        run = store.db.execute(
            "SELECT run_id FROM enterprise_snapshots ORDER BY run_id LIMIT 1"
        ).fetchone()[0]
        for scope in ("demo-alpha", "demo-beta"):
            f = next(c for c in store.candidates(run) if c.project_id == scope)
            record_decision(store, run, f.finding_id, "CONFIRMED", "Synthetic", "Synthetic")
        freeze(store, run, "Synthetic analyst", True)
    with serve(work, "synthetic-override") as origin, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1100})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-override")
        page.get_by_role("button", name="Manage Assessment Data", exact=True).click()
        page.get_by_role("button", name="demo-alpha", exact=True).click()

        # A3 single-file removal follows the same rule.
        page.get_by_role("button", name="Delete One Imported File", exact=True).click()
        page.get_by_label("Imported files").locator("tbody tr").first.get_by_role("button").click()
        file_preview = page.get_by_label("File deletion preview")
        expect(file_preview.get_by_label("Frozen edition decision")).to_be_visible()
        digest = file_preview.locator("code").first.inner_text()
        file_preview.get_by_label("File deletion confirmation digest").fill(digest[:12])
        file_preview.get_by_role("checkbox", name=re.compile("I confirm permanently")).check()
        expect(
            file_preview.get_by_role("button", name="Permanently delete selected file")
        ).to_be_disabled()

        page.get_by_role("button", name="Delete Project Data", exact=True).click()
        preview = page.get_by_label("Deletion preview")
        decision = preview.get_by_label("Frozen edition decision")
        expect(decision).to_contain_text("never altered or deleted automatically")
        final = preview.get_by_role("button", name="Permanently delete selected scope")
        preview.get_by_label("Deletion confirmation identifier").fill("demo-alpha")
        preview.get_by_role("checkbox", name=re.compile("I confirm permanently")).check()
        expect(final).to_be_disabled()  # blocked by default

        decision.get_by_role("checkbox", name=re.compile("Purge and mark edition")).check()
        backup = preview.get_by_role("checkbox", name=re.compile("Back up the workspace"))
        expect(backup).to_be_checked()
        expect(backup).to_be_disabled()
        decision.get_by_label("Supersede confirmation identifier").fill("demo-beta")
        decision.get_by_label("Supersede reason").fill("Synthetic: withdrawn from scope")
        expect(final).to_be_disabled()
        decision.get_by_label("Supersede confirmation identifier").fill("demo-alpha")
        expect(final).to_be_enabled()
        final.click()
        result = page.get_by_label("Purge result")
        expect(result).to_contain_text("marked superseded (records kept): 1", timeout=120000)
        expect(result.get_by_role("status")).to_contain_text("not clean")
        expect(result).to_contain_text("Superseded frozen editions retained by decision: 1")
        expect(result).to_contain_text("same rules as the evidence")
        assert not errors
        browser.close()
    with Store(work) as store:
        record = frozen(store, run)
        assert record and record["superseded"][0]["status"] == "SUPERSEDED"
