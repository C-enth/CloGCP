"""Workspace location screen in the compiled GUI, light and dark themes (synthetic data)."""

import os
import shutil
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")
OUTPUT = Path("artifacts/workspace-browser")


@contextmanager
def serve(work: Path, token: str):
    import uvicorn

    from offline_analyzer.api.app import create_app

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    restarts = []
    app = create_app(
        work,
        origin=origin,
        bootstrap=token,
        restart=lambda: restarts.append(True),
        location={"source": "DEFAULT", "default_path": str(work), "open_report": None},
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        yield origin, restarts
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_workspace_location_screen(tmp_path, monkeypatch, theme):
    from playwright.sync_api import expect, sync_playwright
    from test_theme_browser import workspace as synthetic_workspace

    monkeypatch.setenv("CLOSEC_CONFIG_DIR", str(tmp_path / "config"))
    work = synthetic_workspace(tmp_path)
    other = tmp_path / "recovered copy"
    shutil.copytree(work, other)
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with serve(work, "synthetic-ws") as (origin, restarts), sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(color_scheme=theme, viewport={"width": 1440, "height": 1000})
        # The theme is chosen in the UI (Dark is the default); store the choice up front.
        context.add_init_script(f"localStorage.setItem('closec-theme', '{theme}')")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-ws")
        header = page.get_by_label("Active workspace", exact=True).first
        expect(header).to_contain_text(str(work.resolve()))
        expect(header.get_by_role("button", name="Copy path")).to_be_visible()
        page.get_by_role("button", name="Workspace location", exact=True).click()
        expect(page.get_by_role("heading", name="Active workspace")).to_be_visible()
        expect(page.get_by_text("CloSec keeps using the current workspace")).to_be_visible()

        # Open existing: read-only check with counts, then confirm (restart required).
        opening = page.get_by_label("Open existing workspace (recovery)", exact=True)
        opening.get_by_label("Existing workspace folder").fill(str(other))
        opening.get_by_role("button", name="Check location").click()
        expect(opening.get_by_label("Counts in the selected workspace")).to_be_visible()
        apply = opening.get_by_role("button", name="Open this workspace")
        expect(apply).to_be_disabled()
        accept = opening.get_by_label("I have read these warnings", exact=False)
        if accept.count():
            accept.check()
        opening.get_by_label("I confirm: open this workspace", exact=False).check()
        apply.click()
        expect(
            opening.get_by_text("Restart CloSec to open the selected workspace.")
        ).to_be_visible()
        expect(page.get_by_role("button", name="Restart CloSec now")).to_be_visible()

        # Not a workspace: refused with a clear message, no action button enabled.
        opening.get_by_label("Existing workspace folder").fill(str(backups))
        opening.get_by_role("button", name="Check location").click()
        expect(opening.get_by_role("alert").first).to_contain_text("no CloSec database")

        # Back up now: verified copy into a timestamped subfolder.
        backup = page.get_by_label("Back up now", exact=True)
        backup.get_by_label("Backup destination folder").fill(str(backups))
        backup.get_by_role("button", name="Check location").click()
        accept = backup.get_by_label("I have read these warnings", exact=False)
        if accept.count():
            accept.check()
        backup.get_by_label("I confirm: back up this workspace", exact=False).check()
        backup.get_by_role("button", name="Back up now", exact=True).click()
        expect(backup.get_by_text("Backup written and verified")).to_be_visible(timeout=60000)
        expect(backup).to_contain_text("counts match")
        assert len(list(backups.glob("closec-backup-*"))) == 1
        page.screenshot(path=str(OUTPUT / f"{theme}-workspace-location.png"), full_page=True)
        with page.expect_response(lambda r: r.url.endswith("/api/workspace/restart")):
            page.get_by_role("button", name="Restart CloSec now").click()
        expect(page.get_by_text("A new browser tab opens")).to_be_visible()
        assert restarts == [True]
        assert not errors
        browser.close()
