"""False-positive disposition in the compiled GUI and the pitch-black theme (synthetic data)."""

import os
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")
OUTPUT = Path("artifacts/false-positive-browser")
PRESET = "Google-managed service agent (platform-managed)"
GCP_SCREENS = (
    "Dashboard",
    "Findings workbench",
    "Cross-account explorer",
    "IAM intelligence",
    "Network analysis",
    "Evidence explorer",
)


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_mark_false_positive_single_bulk_and_restore(tmp_path, theme):
    from playwright.sync_api import expect, sync_playwright
    from test_theme_browser import serve
    from test_theme_browser import workspace as synthetic_workspace

    work = synthetic_workspace(tmp_path)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with serve(work, "synthetic-fp") as origin, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1500, "height": 1000})
        if theme == "light":
            context.add_init_script("localStorage.setItem('closec-theme', 'light')")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-fp")
        page.get_by_role("button", name="Dashboard", exact=True).wait_for()
        expect(page.locator("html")).to_have_attribute("data-theme", theme)
        page.get_by_role("tab", name="GCP", exact=True).click()

        # Single finding: mandatory reason (preset), then the FP state is shown.
        page.get_by_role("button", name="Findings workbench", exact=True).click()
        filter_ = page.get_by_label("False positives", exact=True)
        expect(filter_).to_have_value("hide")
        page.get_by_role("button", name="View", exact=True).first.click()
        page.get_by_role("tab", name="Client Reporting", exact=True).click()
        control = page.get_by_label("False-positive disposition")
        mark = control.get_by_role("button", name="Mark as false positive")
        expect(mark).to_be_disabled()  # reason is mandatory
        control.get_by_label("False-positive reason preset").select_option(PRESET)
        mark.click()  # saving closes the details, as for every review action
        expect(page.get_by_text("1 excluded as false positive")).to_be_visible()

        # Show with the FP tag; the finding shows its disposition and previous state.
        filter_.select_option("show")
        expect(page.locator(".records tbody .badge.fp")).to_have_count(1)
        page.locator(".records tbody tr", has=page.locator(".badge.fp")).get_by_role(
            "button", name="View"
        ).click()
        page.get_by_role("tab", name="Client Reporting", exact=True).click()
        control = page.get_by_label("False-positive disposition")
        expect(control).to_contain_text("Marked as false positive")
        expect(control).to_contain_text("previous state CANDIDATE")
        page.get_by_role("button", name="Close details").click()

        # Bulk-mark two more, then restore all three.
        boxes = page.get_by_role("checkbox", name=re.compile(r"^Select (?!all)"))
        unmarked = [
            i
            for i in range(boxes.count())
            if not page.locator(".records tbody tr").nth(i).locator(".badge.fp").count()
        ][:2]
        for i in unmarked:
            boxes.nth(i).check()
        bulk = page.get_by_label("Bulk false positive")
        bulk.get_by_label("Bulk false-positive reason", exact=True).fill("Synthetic bulk reason")
        bulk.get_by_role("button", name="Mark as false positive").click()
        filter_.select_option("only")
        expect(page.locator(".records tbody .badge.fp")).to_have_count(3)
        page.screenshot(path=str(OUTPUT / f"{theme}-findings-fp.png"), full_page=True)
        page.get_by_role("button", name=re.compile(r"^Select all \d+ matching")).click()
        expect(page.get_by_label("Bulk marking")).to_contain_text("3 selected")
        bulk.get_by_role("button", name="Restore").click()
        filter_.select_option("hide")
        expect(page.get_by_text(re.compile(r"excluded as false positive"))).to_have_count(0)

        # Screens in this theme (reviewed by hand for the pitch-black palette).
        for screen in GCP_SCREENS:
            page.get_by_role("button", name=screen, exact=True).click()
            page.wait_for_load_state("networkidle")
            expect(page.get_by_text(re.compile(r"^Loading"))).to_have_count(0, timeout=60000)
            name = screen.lower().replace(" ", "-")
            page.screenshot(path=str(OUTPUT / f"{theme}-{name}.png"), full_page=True)
        # Dashboard tabs: attack-path diagrams (path view) and assessment coverage.
        page.get_by_role("button", name="Dashboard", exact=True).click()
        for tab, name in (("Attack Paths", "attack-paths"), ("Assessment Coverage", "coverage")):
            page.get_by_role("tab", name=tab, exact=True).click()
            page.wait_for_load_state("networkidle")
            expect(page.get_by_text(re.compile(r"^Loading"))).to_have_count(0, timeout=60000)
            page.screenshot(path=str(OUTPUT / f"{theme}-{name}.png"), full_page=True)
        if theme == "dark":
            assert page.evaluate("getComputedStyle(document.body).backgroundColor") in {
                "rgb(0, 0, 0)",
                "rgb(10, 10, 10)",
            }
        assert not errors
        browser.close()
