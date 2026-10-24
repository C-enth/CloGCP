"""Compiled GUI: one imported file is removed only after preview and exact confirmation."""

import os
import socket
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


def test_individual_file_delete_requires_explicit_confirmation(tmp_path):
    import uvicorn
    from playwright.sync_api import expect, sync_playwright

    from offline_analyzer.api.app import create_app
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import record_run_origin, set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.gcp_fixture import build as gcp_build

    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        run = import_package(store, gcp_build(tmp_path / "beta", "demo-beta", "222222222222"))
        record_run_origin(work, run, "synthetic")
        assess(store, run)
    raw_before = {p.name for p in (work / "raw").iterdir()}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(work, origin=origin, bootstrap="synthetic-file-delete"),
            log_level="critical",
            access_log=False,
        )
    )
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    output = Path("artifacts/file-delete-browser")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1600, "height": 1100})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(origin + "/#token=synthetic-file-delete")
            page.get_by_role("button", name="Manage Assessment Data", exact=True).click()
            page.get_by_role("button", name="demo-beta", exact=True).click()
            page.get_by_role("button", name="Delete One Imported File", exact=True).click()
            rows = page.get_by_label("Imported files").locator("tbody tr")
            expect(rows.first).to_be_visible()
            count = rows.count()
            rows.first.get_by_role("button").click()
            preview = page.get_by_label("File deletion preview")
            expect(preview).to_contain_text("GCP demo-beta")
            sha = preview.locator("code").first.inner_text()
            assert len(sha) == 64 and f"{sha}.json" in raw_before
            final = page.get_by_role("button", name="Permanently delete selected file", exact=True)
            expect(final).to_be_disabled()
            page.get_by_label("File deletion confirmation digest").fill(sha[:11])
            page.get_by_role("checkbox", name="I confirm permanently deleting", exact=False).check()
            expect(final).to_be_disabled()
            assert (work / "raw" / f"{sha}.json").exists()
            page.get_by_label("File deletion confirmation digest").fill(sha[:12])
            expect(final).to_be_enabled()
            page.screenshot(path=str(output / "file-delete-confirmation.png"), full_page=True)
            final.click()
            expect(rows).to_have_count(count - 1, timeout=60000)
            assert not (work / "raw" / f"{sha}.json").exists()
            assert {p.name for p in (work / "raw").iterdir()} == raw_before - {f"{sha}.json"}
            assert not errors
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
