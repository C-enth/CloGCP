"""Compiled GUI: legacy ZIP, exact deletion, refresh, keyboard tabs and reports."""

import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


def test_operational_import_scope_delete_and_navigation(tmp_path):
    import uvicorn
    from openpyxl import load_workbook
    from playwright.sync_api import expect, sync_playwright
    from test_gcp_legacy import PROJECT, pilot

    from offline_analyzer.api.app import create_app
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import record_run_origin, set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.fixtures.r12_demo import build as aws_build
    from tools.gcp_fixture import build as gcp_build

    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    aws = tmp_path / "aws"
    aws_build(aws)
    beta = gcp_build(tmp_path / "beta", "demo-beta", "222222222222")
    with Store(work) as store:
        for folder in (aws, beta):
            run = import_package(store, folder)
            record_run_origin(work, run, "synthetic")
            assess(store, run)
    archive = pilot(tmp_path / "legacy")  # evidence folder; the GUI imports folders

    def snapshot(folder: Path) -> dict:
        return {
            f.relative_to(folder).as_posix(): f.read_bytes()
            for f in folder.rglob("*")
            if f.is_file()
        }

    original = snapshot(archive)  # the source evidence folder must never be modified
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(work, origin=origin, bootstrap="synthetic-operations"),
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
    output = Path("artifacts/operational-051-browser")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                accept_downloads=True, viewport={"width": 1600, "height": 1100}
            )
            external = []
            errors = []
            context.route(
                "**/*",
                lambda r: (
                    r.continue_()
                    if r.request.url.startswith(origin)
                    else (external.append(r.request.url), r.abort())
                ),
            )
            page = context.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(origin + "/#token=synthetic-operations")

            def import_file(provider, file, transport, legacy=False):
                page.get_by_role("button", name="Evidence import", exact=True).click()
                with page.expect_file_chooser() as chooser:
                    page.get_by_role(
                        "button", name=f"Import {provider} Evidence {transport}", exact=True
                    ).click()
                chooser.value.set_files(str(file))
                page.get_by_role("button", name="Validate evidence", exact=True).click()
                button = page.get_by_role("button", name="Import validated evidence", exact=True)
                button.wait_for()
                if legacy:
                    expect(button).to_be_disabled()
                    expect(
                        page.get_by_text("Original collection outcomes:", exact=False)
                    ).to_contain_text("19")
                    page.get_by_role(
                        "checkbox", name="I acknowledge that this legacy package", exact=False
                    ).check()
                button.click()
                expect(
                    page.get_by_role("button", name="Run assessment", exact=True)
                ).to_be_enabled()
                page.get_by_role("button", name="Run assessment", exact=True).click()
                expect(
                    page.get_by_label("Active evidence run").locator("option:checked")
                ).to_contain_text("Assessed")

            import_file("GCP", archive, "Folder", True)
            page.get_by_role("tab", name="GCP", exact=True).click()
            page.get_by_role("tab", name="Assessment Coverage", exact=True).click()
            expect(page.get_by_label("GCP assessment")).to_contain_text("COLLECTOR_COMMAND_ERROR")
            expect(page.get_by_label("GCP assessment")).to_contain_text(
                "LOCAL_HASH_ONLY_NO_SOURCE_CHECKSUMS"
            )
            page.screenshot(path=str(output / "legacy-coverage.png"), full_page=True)
            page.get_by_role("tab", name="Security Findings", exact=True).click()
            expect(page.locator(".cloud-records tbody tr").first).to_be_visible()
            page.locator(".cloud-records tbody tr").first.get_by_role(
                "button", name="View", exact=True
            ).click()
            page.get_by_role("tab", name="Client Reporting", exact=True).click()
            expect(page.get_by_label("Analyst identity")).to_be_visible()
            page.get_by_role("button", name="Close details", exact=True).click()
            page.get_by_role("button", name="Build enterprise assessment", exact=True).click()
            expect(
                page.get_by_label("Active evidence run").locator("option:checked")
            ).to_contain_text("Enterprise")

            def delete(provider, scope):
                page.get_by_role("button", name="Manage Assessment Data", exact=True).click()
                page.get_by_role("button", name=scope, exact=True).click()
                page.get_by_role(
                    "button",
                    name="Delete Account Data" if provider == "AWS" else "Delete Project Data",
                    exact=True,
                ).click()
                expect(page.get_by_label("Deletion preview")).to_contain_text(scope)
                final = page.get_by_role(
                    "button", name="Permanently delete selected scope", exact=True
                )
                expect(final).to_be_disabled()
                page.get_by_label("Deletion confirmation identifier").fill(scope + "x")
                page.get_by_role(
                    "checkbox", name="I confirm permanently deleting", exact=False
                ).check()
                expect(final).to_be_disabled()
                page.get_by_label("Deletion confirmation identifier").fill(scope)
                expect(final).to_be_enabled()
                page.screenshot(
                    path=str(output / f"{provider.lower()}-delete-confirmation.png"), full_page=True
                )
                final.click()
                expect(page.get_by_role("button", name=scope, exact=True)).to_have_count(0)
                expect(page.get_by_role("button", name="demo-beta", exact=True)).to_be_visible()

            delete("AWS", "111111111111")
            import_file("AWS", aws, "Folder")
            delete("GCP", PROJECT)
            import_file("GCP", archive, "Folder", True)
            page.get_by_role("tab", name="GCP", exact=True).focus()
            page.keyboard.press("ArrowRight")
            selected = page.get_by_role("tab", name="Consolidated", exact=True)
            expect(selected).to_be_focused()
            expect(selected).to_have_attribute("aria-selected", "true")
            before = selected.bounding_box()
            selected.hover()
            page.wait_for_timeout(150)
            assert selected.bounding_box() == before
            page.mouse.move(1500, 1080)
            expect(selected).to_have_attribute("aria-selected", "true")
            assert selected.evaluate("e => getComputedStyle(e).textDecorationLine") == "underline"
            page.reload()
            expect(page.get_by_role("tab", name="Consolidated", exact=True)).to_have_attribute(
                "aria-selected", "true"
            )
            page.get_by_role("button", name="Build enterprise assessment", exact=True).click()
            expect(
                page.get_by_label("Active evidence run").locator("option:checked")
            ).to_contain_text("Enterprise")
            page.get_by_role("tab", name="Attack Paths", exact=True).click()
            expect(page.locator("tr").filter(has_text="demo-beta").first).to_be_visible()
            expect(
                page.locator("tr").filter(has_text="OBSERVED_ALLOW_BINDING").first
            ).to_be_visible()
            page.screenshot(path=str(output / "consolidated-after-reimport.png"), full_page=True)
            page.get_by_role("button", name="Report center", exact=True).click()
            page.get_by_role("button", name="Generate Excel", exact=True).click()
            row = page.locator("tr").filter(has_text="CloSec-assessment-excel.xlsx")
            row.get_by_role("link", name="Download", exact=True).wait_for()
            with page.expect_download() as downloaded:
                row.get_by_role("link", name="Download", exact=True).click()
            with open(downloaded.value.path(), "rb") as stream:
                workbook = load_workbook(stream, read_only=True)
                assert "Unified Findings Register" in workbook.sheetnames
                workbook.close()
            assert snapshot(archive) == original and not external and not errors
            (output / "result.json").write_text(
                json.dumps(
                    {
                        "legacy_datasets": 32,
                        "statuses": {"SUCCESS": 8, "EMPTY": 5, "FAILED": 19},
                        "aws_scoped_delete": "PASS",
                        "gcp_scoped_delete": "PASS",
                        "typed_confirmation": "PASS",
                        "keyboard_and_hover": "PASS",
                        "reimport_and_excel": "PASS",
                        "external_requests": 0,
                        "page_errors": 0,
                        "origin": "SYNTHETIC_ONLY",
                    }
                )
            )
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        listener.close()
