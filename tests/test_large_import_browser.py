"""Actual launcher + compiled GUI: byte-scale import, responsive health and persisted report."""

import json
import os
import threading
import time
from pathlib import Path

import httpx
import psutil
import pytest

from tests.launcher_support import LauncherSession
from tools.fixtures.large_import import large_aws

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


def test_222_mib_actual_launcher_import_assess_export_and_health(tmp_path):
    from openpyxl import load_workbook
    from playwright.sync_api import expect, sync_playwright

    info = large_aws(tmp_path / "package")
    samples, stopped = [], threading.Event()
    output = Path("artifacts/recovery-large-acceptance")
    output.mkdir(parents=True, exist_ok=True)
    work = tmp_path / "work"
    with LauncherSession(work) as session:
        process = psutil.Process(session.process.pid)

        def health():
            with httpx.Client(base_url=session.origin, trust_env=False, timeout=1) as client:
                while not stopped.is_set():
                    begin = time.monotonic()
                    try:
                        response = client.get("/api/health")
                        samples.append(
                            {"status": response.status_code, "seconds": time.monotonic() - begin}
                        )
                        samples[-1]["rss_bytes"] = process.memory_info().rss
                    except httpx.HTTPError as exc:
                        samples.append(
                            {"error": type(exc).__name__, "seconds": time.monotonic() - begin}
                        )
                    stopped.wait(0.1)

        monitor = threading.Thread(target=health, daemon=True)
        monitor.start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    accept_downloads=True, viewport={"width": 1440, "height": 900}
                )
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(type(error).__name__))
                page.goto(session.url)
                page.get_by_role("button", name="Evidence import", exact=True).click()
                with page.expect_file_chooser() as chooser:
                    page.get_by_role(
                        "button", name="Import AWS Evidence Folder", exact=True
                    ).click()
                chooser.value.set_files(str(info["folder"]))
                button = page.get_by_role("button", name="Validate evidence", exact=True)
                expect(button).to_be_enabled()
                assert button.bounding_box()["y"] < 900
                begin = time.monotonic()
                with page.expect_response(
                    lambda response: response.url.endswith("/api/uploads")
                ) as transfer:
                    button.click()
                submitted = transfer.value.json()
                assert submitted["id"]
                expect(page.get_by_label("Local operation details")).to_contain_text(
                    "Package validation"
                )
                import_button = page.get_by_role(
                    "button", name="Import validated evidence", exact=True
                )
                import_button.wait_for(timeout=180000)
                validation = session.client.get("/api/jobs/" + submitted["id"]).json()
                assert validation["state"] == "COMPLETED" and validation["result"]["can_import"]
                import_button.click()
                expect(page.get_by_role("button", name="Run assessment", exact=True)).to_be_enabled(
                    timeout=180000
                )
                run = page.get_by_label("Active evidence run").input_value()
                page.get_by_role("button", name="Run assessment", exact=True).click()
                expect(
                    page.get_by_label("Active evidence run").locator("option:checked")
                ).to_contain_text("Assessed", timeout=180000)
                expect(page.get_by_label("AWS scope summary")).to_be_visible()
                page.get_by_role("tab", name="Security Findings", exact=True).click()
                expect(page.locator(".cloud-records tbody tr").first).to_be_visible()
                page.get_by_role("button", name="Report center", exact=True).click()
                page.get_by_role("button", name="Generate Excel", exact=True).click()
                row = (
                    page.locator("tr")
                    .filter(has_text="CloSec-assessment-excel.xlsx")
                    .filter(has_text=run[:20])
                )
                row.get_by_role("link", name="Download", exact=True).wait_for(timeout=180000)
                with page.expect_download() as downloaded:
                    row.get_by_role("link", name="Download", exact=True).click()
                with open(downloaded.value.path(), "rb") as stream:
                    workbook = load_workbook(stream, read_only=True)
                    findings = list(workbook["Findings Register"].values)
                    assert findings[1] == ("Assessment run", run) and len(findings) > 3
                    workbook.close()
                jobs = session.client.get("/api/jobs").json()
                assert all(job["state"] == "COMPLETED" for job in jobs)
                page.screenshot(path=str(output / "complete.png"), full_page=True)
                assert not errors
                (output / "result.json").write_text(
                    json.dumps(
                        {
                            "input": "SYNTHETIC_BYTE_SCALE_NOT_ESTATE_CERTIFICATION",
                            "launcher": "ACTUAL",
                            "expanded_bytes": info["expanded_bytes"],
                            "archive_bytes": info["archive_bytes"],
                            "elapsed_seconds": time.monotonic() - begin,
                            "run_id": run,
                            "jobs": [
                                {
                                    key: job.get(key)
                                    for key in (
                                        "id",
                                        "kind",
                                        "state",
                                        "stage",
                                        "submitted_at",
                                        "finished_at",
                                    )
                                }
                                for job in jobs
                            ],
                            "health_samples": samples,
                            "findings_rows": len(findings) - 3,
                            "real_evidence": "NOT_VALIDATED",
                        },
                        indent=2,
                    )
                    + "\n"
                )
                browser.close()
        finally:
            stopped.set()
            monitor.join(timeout=3)
    assert samples and all(sample.get("status") == 200 for sample in samples)
    assert max(sample["seconds"] for sample in samples) < 1
