"""Integrated acceptance on the real launcher, compiled GUI, local API and DuckDB.

AWS collector v0.3 ZIP + GCP collector 2.2 folder -> Import and analyze -> results ->
analyst review/approval/copy -> consolidated snapshot -> Excel/RTF -> reconciliation in
the Report Center -> restart. SYNTHETIC evidence only; never real-export certification.
"""

import json
import os
import socket
import time
from pathlib import Path

import pytest

from offline_analyzer.reporting.reconciliation import register_rows
from tests.browser_diagnostics import word_text
from tests.launcher_support import LauncherSession
from tools.fixtures.aws_v030_native import ACCOUNT, package
from tools.fixtures.gcp_expanded import PROJECT, expanded22

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in browser")
ARTIFACTS = Path("artifacts/integrated-acceptance-browser")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_aws_gcp_consolidated_analyst_workflow(tmp_path):
    from openpyxl import load_workbook
    from playwright.sync_api import expect, sync_playwright

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    aws_folder = package(tmp_path / "aws")
    gcp_folder = expanded22(tmp_path / "gcp")
    work = tmp_path / "workspace"
    port = free_port()
    measured: dict = {"origin": "synthetic", "runs": {}}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            accept_downloads=True, viewport={"width": 1600, "height": 1100}
        )
        with LauncherSession(work, port=port) as session:
            context.grant_permissions(["clipboard-read", "clipboard-write"], origin=session.origin)
            outbound = []
            context.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(session.origin)
                    else (outbound.append("EXTERNAL"), route.abort())
                ),
            )
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(session.url)
            expect(page.get_by_label("Assessment workflow")).to_be_visible()

            def wait(job_id):
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline:
                    job = session.client.get(f"/api/jobs/{job_id}", headers=session.headers).json()
                    if job["state"] not in {"PENDING", "RUNNING"}:
                        return job
                    time.sleep(0.1)
                raise AssertionError("job timeout")

            def import_and_analyze(provider, button, target):
                page.get_by_role("button", name="Evidence import", exact=True).click()
                with page.expect_file_chooser() as chooser:
                    page.get_by_role("button", name=button, exact=True).click()
                chooser.value.set_files(str(target))
                page.get_by_role("button", name="Validate evidence", exact=True).click()
                action = page.get_by_role("button", name="Import and analyze", exact=True)
                expect(action).to_be_enabled(timeout=60000)
                with page.expect_response(lambda r: r.url.endswith("/api/import")) as submitted:
                    action.click()
                job = wait(submitted.value.json()["id"])
                assert job["state"] == "COMPLETED", job.get("error")
                assert job["kind"] == "Import and analysis"
                run = job["result"]["run_id"]
                expect(page.get_by_label("Active evidence run")).to_have_value(run, timeout=30000)
                expect(page.get_by_role("tab", name=provider, exact=True)).to_have_attribute(
                    "aria-selected", "true"
                )
                expect(page.get_by_role("heading", name="Dashboard", level=1)).to_be_visible()
                measured["runs"][provider] = run
                return run

            aws_run = import_and_analyze("AWS", "Import AWS Evidence Folder", aws_folder)
            expect(page.get_by_label("AWS scope summary")).to_contain_text(ACCOUNT)
            page.screenshot(path=str(ARTIFACTS / "aws-dashboard.png"), full_page=True)
            gcp_run = import_and_analyze("GCP", "Import GCP Evidence Folder", gcp_folder)
            expect(page.get_by_label("GCP scope summary")).to_contain_text(PROJECT)
            page.screenshot(path=str(ARTIFACTS / "gcp-dashboard.png"), full_page=True)

            # Every module uses the same selected run; the Findings Workbench total equals the API.
            page.get_by_label("Active evidence run").select_option(aws_run)
            page.get_by_role("tab", name="AWS", exact=True).click()
            api_total = session.client.get(
                f"/api/runs/{aws_run}/records/findings?provider=AWS&limit=1",
                headers=session.headers,
            ).json()["total"]
            assert api_total >= 5
            page.get_by_role("button", name="Findings workbench", exact=True).click()
            expect(page.get_by_text(f"{api_total} records", exact=True).first).to_be_visible()
            measured["gui_visible_findings_aws"] = api_total
            for screen in ("IAM intelligence", "Evidence explorer", "Network analysis"):
                page.get_by_role("button", name=screen, exact=True).click()
                expect(page.get_by_label("Active evidence run")).to_have_value(aws_run)
                expect(page.locator("main")).not_to_contain_text("has not been imported yet")

            # Analyst outcome: open finding -> evidence -> review -> remediation -> approve -> copy.
            page.get_by_role("button", name="Dashboard", exact=True).click()
            page.get_by_role("tab", name="Security Findings", exact=True).click()
            page.get_by_label("Cloud Search").select_option(
                "S3 bucket permits anonymous public access"
            )
            table = page.locator(".cloud-records tbody")
            expect(table.locator("tr")).to_have_count(1)
            table.get_by_role("button", name="View").click()
            page.get_by_role("tab", name="Client Reporting", exact=True).click()
            page.get_by_label("Analyst identity").fill("synthetic-aws-reviewer")
            page.get_by_label("Analyst remarks").fill("Synthetic bucket policy evidence reviewed")
            page.get_by_role("tab", name="Client Reporting", exact=True).click()
            page.get_by_role("button", name="Confirm", exact=True).click()
            expect(table).to_contain_text("CONFIRMED")
            table.get_by_role("button", name="View").click()
            page.get_by_role("tab", name="Client Reporting", exact=True).click()
            editor = page.get_by_label("Report finding editor")
            editor.get_by_label("Report reviewer").fill("synthetic-aws-reviewer")
            editor.get_by_label("Include in client report").check()
            editor.get_by_role("button", name="Save report draft", exact=True).click()
            expect(editor.get_by_role("status")).to_contain_text("Report draft saved")
            editor.get_by_role("button", name="Approve recommendation", exact=True).click()
            expect(editor.get_by_role("status")).to_contain_text("recommendation approval recorded")
            editor.get_by_role("button", name="Approve report narrative", exact=True).click()
            editor.get_by_role("button", name="Copy Report Finding").click()
            expect(editor.get_by_role("status")).to_contain_text("copied")
            assert "synthetic-public-bucket" in page.evaluate("navigator.clipboard.readText()")
            page.screenshot(path=str(ARTIFACTS / "aws-approved-finding.png"), full_page=True)
            page.get_by_role("button", name="Close details", exact=True).click()

            # Exports for the AWS run, then the reconciliation panel must reconcile them.
            page.get_by_role("button", name="Report center", exact=True).click()
            for name, suffix in (
                ("Generate Excel", "xlsx"),
                ("Export all approved findings (Word DOCX)", "docx"),
            ):
                page.get_by_role("button", name=name, exact=True).click()
                kind = "excel" if suffix == "xlsx" else "approved-docx"
                row = (
                    page.locator("tr")
                    .filter(has_text=f"CloSec-assessment-{kind}.{suffix}")
                    .filter(has_text=aws_run[:20])
                    .first
                )
                link = row.get_by_role("link", name="Download", exact=True)
                expect(link).to_be_visible(timeout=60000)
                with page.expect_download() as download:
                    link.click()
                target = tmp_path / f"aws.{suffix}"
                download.value.save_as(target)
                if suffix == "xlsx":
                    workbook = load_workbook(target, read_only=True)
                    exported = register_rows(workbook["Findings Register"])
                    workbook.close()
                    assert exported == api_total
                else:
                    assert "CloSec" in word_text(target)
                    assert "synthetic-public-bucket" in word_text(target)
            page.reload()
            page.get_by_role("button", name="Report center", exact=True).click()
            panel = page.get_by_label("Assessment reconciliation")
            for stage in ("API-returned findings", "GUI-visible findings", "Reported findings"):
                expect(panel.locator("tr").filter(has_text=stage)).to_contain_text("PASS")
            reconciliation = session.client.get(
                f"/api/runs/{aws_run}/reconciliation", headers=session.headers
            ).json()
            measured["reconciliation_aws"] = [
                {k: s[k] for k in ("stage", "count", "status")} for s in reconciliation["stages"]
            ]
            assert all(s["status"] == "PASS" for s in reconciliation["stages"])
            page.screenshot(path=str(ARTIFACTS / "reconciliation.png"), full_page=True)

            # Consolidated assessment over both providers; scopes stay distinct.
            page.get_by_role("button", name="Dashboard", exact=True).click()
            page.get_by_role("button", name="Build enterprise assessment", exact=True).click()
            expect(
                page.get_by_label("Active evidence run").locator("option:checked")
            ).to_contain_text("Enterprise", timeout=60000)
            consolidated = page.get_by_label("Active evidence run").input_value()
            page.get_by_role("tab", name="Consolidated", exact=True).click()
            expect(page.get_by_label("AWS scope summary")).to_contain_text(ACCOUNT)
            expect(page.get_by_label("GCP scope summary")).to_contain_text(PROJECT)
            page.screenshot(path=str(ARTIFACTS / "consolidated.png"), full_page=True)
            runs = {r["run_id"]: r for r in session.client.get("/api/runs").json()}
            assert runs[consolidated]["aws_accounts"] == [ACCOUNT]
            assert runs[consolidated]["gcp_projects"] == [PROJECT]
            assert runs[consolidated]["finding_count"] == (
                runs[aws_run]["finding_count"] + runs[gcp_run]["finding_count"]
            )
            measured["consolidated_findings"] = runs[consolidated]["finding_count"]
            assert errors == [] and outbound == []
        # Restart: the same consolidated assessment and provider are restored.
        with LauncherSession(work, port=port) as restarted:
            page.goto(restarted.url)
            expect(page.get_by_label("Active evidence run")).to_have_value(consolidated)
            expect(page.get_by_role("tab", name="Consolidated", exact=True)).to_have_attribute(
                "aria-selected", "true"
            )
        browser.close()
    (ARTIFACTS / "measured.json").write_text(json.dumps(measured, indent=2, sort_keys=True))
