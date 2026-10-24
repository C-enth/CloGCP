"""Compiled GUI on synthetic data: theme toggle/persistence/screenshots, exclusion and purge."""

import os
import re
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")

OUTPUT = Path("artifacts/theme-browser")
SCREENS = (
    "Dashboard",
    "Findings workbench",
    "Finalized findings",
    "Cross-account explorer",
    "IAM intelligence",
    "Network analysis",
    "Manage Assessment Data",
)


def workspace(tmp_path: Path) -> Path:
    from offline_analyzer.enterprise.snapshot import assess_enterprise
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import record_run_origin, set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.fixtures.r12_demo import build as aws_build
    from tools.gcp_fixture import build as gcp_build

    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        aws_build(tmp_path / "aws")
        members = [import_package(store, tmp_path / "aws")]
        for project, number in [("demo-alpha", "123456789012"), ("demo-beta", "222222222222")]:
            members.append(import_package(store, gcp_build(tmp_path / project, project, number)))
        for run in members:
            record_run_origin(work, run, "synthetic")
            assess(store, run)
        record_run_origin(work, assess_enterprise(store, members), "synthetic")
    return work


@contextmanager
def serve(work: Path, token: str):
    import uvicorn

    from offline_analyzer.api.app import create_app

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(work, origin=origin, bootstrap=token), log_level="critical", access_log=False
        )
    )
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    try:
        yield origin
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def background(page) -> str:
    return page.evaluate("getComputedStyle(document.body).backgroundColor")


def test_theme_toggle_persistence_no_flash_and_screens(tmp_path):
    from playwright.sync_api import expect, sync_playwright

    work = workspace(tmp_path)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with serve(work, "synthetic-theme") as origin, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # System preference is dark; nothing stored yet, so System applies dark.
        context = browser.new_context(color_scheme="dark", viewport={"width": 1500, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-theme")
        page.get_by_role("button", name="Dashboard", exact=True).wait_for()
        html = page.locator("html")
        expect(html).to_have_attribute("data-theme", "dark")
        expect(html).to_have_attribute("data-theme-preference", "system")
        toggle = page.get_by_label("Colour theme")
        expect(toggle).to_have_value("system")
        dark_bg = background(page)

        # Explicit Light persists across reload although the system stays dark.
        toggle.select_option("light")
        expect(html).to_have_attribute("data-theme", "light")
        assert page.evaluate("localStorage.getItem('closec-theme')") == "light"
        light_bg = background(page)
        assert light_bg != dark_bg
        page.reload()
        page.get_by_role("button", name="Dashboard", exact=True).wait_for()
        expect(html).to_have_attribute("data-theme", "light")
        expect(page.get_by_label("Colour theme")).to_have_value("light")

        # No flash: the theme is applied before the application bundle runs at all.
        context.route(re.compile(r".*/assets/index-.*\.js$"), lambda r: r.abort())
        page.reload()
        expect(html).to_have_attribute("data-theme", "light")
        context.unroute(re.compile(r".*/assets/index-.*\.js$"))

        # Back to System removes the stored choice and follows the OS again.
        page.reload()
        page.get_by_label("Colour theme").select_option("system")
        assert page.evaluate("localStorage.getItem('closec-theme')") is None
        expect(html).to_have_attribute("data-theme", "dark")
        page.emulate_media(color_scheme="light")
        expect(html).to_have_attribute("data-theme", "light")
        page.emulate_media(color_scheme="dark")

        # Severity colours keep their meaning: identical slices in both themes.
        fills = {}
        for theme in ("light", "dark"):
            page.get_by_label("Colour theme").select_option(theme)
            page.get_by_role("button", name="Dashboard", exact=True).click()
            slices = page.get_by_label("Criticality pie chart").locator("[role=button]")
            expect(slices.first).to_be_visible()
            fills[theme] = slices.evaluate_all(
                "els => els.map(e => [e.getAttribute('aria-label'), getComputedStyle(e).fill])"
            )
            expect(page.get_by_label("Observed findings by criticality")).to_contain_text(
                "excluded from reporting"
            )
            for screen in SCREENS:
                page.get_by_role("button", name=screen, exact=True).click()
                page.wait_for_load_state("networkidle")
                # Diagrams and tables are captured after they finish loading.
                expect(page.get_by_text(re.compile(r"^Loading"))).to_have_count(0, timeout=60000)
                assert background(page) == (light_bg if theme == "light" else dark_bg)
                name = screen.lower().replace(" ", "-")
                shot = OUTPUT / f"{theme}-{name}.png"
                page.screenshot(path=str(shot), full_page=True)
                assert shot.stat().st_size > 10_000
        assert fills["light"] == fills["dark"] and fills["light"]
        assert not errors
        context.close()

        # Storage unavailable: the page still renders with the System theme.
        blocked = browser.new_context(color_scheme="dark")
        blocked.add_init_script(
            "Object.defineProperty(window, 'localStorage', "
            "{get() { throw new Error('blocked'); }});"
        )
        page = blocked.new_page()
        page.goto(origin + "/#token=synthetic-theme")
        page.get_by_role("button", name="Dashboard", exact=True).wait_for()
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        page.get_by_label("Colour theme").select_option("light")
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        browser.close()


def test_exclusion_undo_and_purge_with_backup_and_verification(tmp_path):
    from playwright.sync_api import expect, sync_playwright

    work = workspace(tmp_path)
    with serve(work, "synthetic-purge") as origin, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1100})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-purge")

        # Exclude a finding (reason required), see it listed, then undo.
        page.get_by_role("button", name="Findings workbench", exact=True).click()
        page.get_by_role("button", name=re.compile("Show findings by account")).click()
        page.locator("table").last.get_by_role("button", name="View").first.click()
        page.get_by_role("tab", name="Client Reporting", exact=True).click()
        control = page.get_by_label("Exclude from report", exact=True)
        exclude = control.get_by_role("button", name="Exclude from report")
        expect(exclude).to_be_disabled()
        assert "never hard-deleted" in exclude.get_attribute("title")
        control.get_by_label("Exclusion reason").select_option("OTHER")
        expect(exclude).to_be_disabled()
        control.get_by_label("Exclusion note").fill("Synthetic explanation")
        exclude.click()
        # Saving refreshes the workbench; the technical list still shows the finding.
        page.locator("table").last.get_by_role("button", name="View").first.click()
        page.get_by_role("tab", name="Client Reporting", exact=True).click()
        expect(control.get_by_role("status")).to_contain_text("Excluded from client reporting")
        expect(control.get_by_role("status")).to_contain_text("Synthetic explanation")
        page.get_by_role("button", name="Close details").click()
        page.get_by_role("button", name="Finalized findings", exact=True).click()
        listed = page.get_by_label("Excluded findings list")
        expect(listed.locator("tbody tr")).to_have_count(1)
        expect(page.locator(".excluded-count").first).to_contain_text("1")
        listed.get_by_role("button", name="Undo").click()
        expect(page.get_by_label("Excluded findings", exact=True)).to_contain_text(
            "No findings are excluded."
        )

        # Purge one project: preview, typed identifier, default-on backup, verification.
        page.get_by_role("button", name="Manage Assessment Data", exact=True).click()
        page.get_by_role("button", name="demo-alpha", exact=True).click()
        page.get_by_role("button", name="Delete Project Data", exact=True).click()
        preview = page.get_by_label("Deletion preview")
        expect(preview.get_by_label("Removed data")).to_contain_text("findings")
        expect(preview.get_by_label("Affected but kept")).to_contain_text("frozen editions")
        backup = preview.get_by_role("checkbox", name=re.compile("Back up the workspace"))
        expect(backup).to_be_checked()
        final = preview.get_by_role("button", name="Permanently delete selected scope")
        preview.get_by_label("Deletion confirmation identifier").fill("demo-alph")
        preview.get_by_role("checkbox", name=re.compile("I confirm permanently")).check()
        expect(final).to_be_disabled()
        preview.get_by_label("Deletion confirmation identifier").fill("demo-alpha")
        expect(final).to_be_enabled()
        final.click()
        result = page.get_by_label("Purge result")
        expect(result).to_contain_text("no remaining reference", timeout=120000)
        expect(result).to_contain_text("work-backups")
        expect(page.get_by_role("button", name="demo-alpha", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="demo-beta", exact=True)).to_be_visible()
        assert any((tmp_path / "work-backups").iterdir())
        assert not errors
        browser.close()
