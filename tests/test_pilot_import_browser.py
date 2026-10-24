"""Actual file choosers: 65-file pilot ZIP/folder and AWS through persisted reports."""

import hashlib
import json
import os
import time
import zipfile
from contextlib import nullcontext
from pathlib import Path

import pytest

from tests.browser_diagnostics import word_text
from tests.launcher_support import LauncherSession

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")


@pytest.mark.parametrize("browser_name", ["chromium", "webkit"])
@pytest.mark.parametrize("transport", ["Folder"])
def test_pilot_65_file_selection_import_assessment_and_export(tmp_path, transport, browser_name):
    from openpyxl import load_workbook
    from playwright.sync_api import expect, sync_playwright
    from test_gcp_legacy import PROJECT, pilot, zip_pilot

    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.storage.store import Store
    from tools.fixtures.r12_demo import build as aws_build

    work = tmp_path / "workspace"
    set_environment(work, "SYNTHETIC")
    folder = pilot(tmp_path / "Pilot evidence ü", full_transport=True)
    archive = zip_pilot(folder, tmp_path / "synthetic-pilot.zip")
    aws = tmp_path / "AWS evidence ü"
    aws_build(aws)
    aws_archive = tmp_path / "synthetic-aws.zip"
    with zipfile.ZipFile(aws_archive, "w", zipfile.ZIP_DEFLATED) as output:
        for path in sorted(aws.iterdir()):
            output.write(path, path.name)
    before = {
        path.relative_to(tmp_path).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [archive, aws_archive, *folder.rglob("*"), *aws.rglob("*")]
        if path.is_file()
    }
    diagnostics = Path("artifacts/recovery-acceptance") / f"{browser_name}-{transport.lower()}"
    diagnostics.mkdir(parents=True, exist_ok=True)
    session = LauncherSession(work)
    origin = session.origin
    jobs = []
    imports = {}
    exports = {}
    try:
        with sync_playwright() as playwright:
            browser = getattr(playwright, browser_name).launch(headless=True)
            context = browser.new_context(
                accept_downloads=True, viewport={"width": 1600, "height": 1100}
            )
            if browser_name == "chromium":
                context.grant_permissions(["clipboard-read", "clipboard-write"], origin=origin)
            external, errors = [], []
            context.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(origin)
                    else (external.append(route.request.url), route.abort())
                ),
            )
            with nullcontext():
                page = context.new_page()
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(session.url)
                expect(page.get_by_label("Application revision")).to_contain_text(
                    "frontend/backend compatible"
                )

                def submitting_import(route):
                    # Before POST returns, the previous run must not be assessable.
                    expect(page.get_by_label("Active evidence run")).to_be_disabled()
                    assess_button = page.get_by_role("button", name="Run assessment", exact=True)
                    if assess_button.count():
                        expect(assess_button).to_be_disabled()
                    expect(
                        page.get_by_role("button", name="Import validated evidence", exact=True)
                    ).to_be_disabled()
                    route.continue_()

                page.route("**/api/import", submitting_import)

                def import_and_assess(provider, selected, mode, *, legacy=False):
                    page.get_by_role("button", name="Evidence import", exact=True).click()
                    with page.expect_file_chooser() as chooser:
                        page.get_by_role(
                            "button", name=f"Import {provider} Evidence {mode}", exact=True
                        ).click()
                    chooser.value.set_files(str(selected))
                    if provider == "GCP" and mode == "Folder":
                        expect(page.get_by_text("65 selected files", exact=True)).to_be_visible()
                        paths = page.get_by_label("Select package folder").evaluate(
                            "input => Array.from(input.files).map(file => file.webkitRelativePath)"
                        )
                        assert len(paths) == 65
                        assert any(path.endswith("/collection_manifest.json") for path in paths)
                        assert any(path.endswith("/identity/project_iam.json") for path in paths)
                    with page.expect_response(
                        lambda response: response.url.endswith("/api/uploads")
                    ) as uploaded:
                        page.get_by_role("button", name="Validate evidence", exact=True).click()
                    assert uploaded.value.status == 200
                    submitted = uploaded.value.json()
                    assert submitted["id"] and submitted["state"] in {
                        "PENDING",
                        "RUNNING",
                        "COMPLETED",
                    }
                    button = page.get_by_role(
                        "button", name="Import validated evidence", exact=True
                    )
                    button.wait_for()
                    validation_job = context.request.get(
                        origin + "/api/jobs/" + submitted["id"]
                    ).json()
                    assert (
                        validation_job["status"] == "SUCCEEDED"
                        and validation_job["state"] == "COMPLETED"
                    )
                    jobs.append(
                        {
                            key: validation_job.get(key)
                            for key in (
                                "id",
                                "kind",
                                "state",
                                "stage",
                                "duration_seconds",
                                "timings",
                            )
                        }
                    )
                    preview = validation_job["result"]
                    assert preview["can_import"] is True
                    if legacy:
                        assert preview["diagnostics"]["contract_version"] == "pilot-1.2.2"
                        assert preview["diagnostics"]["original_status_totals"] == {
                            "SUCCESS": 8,
                            "EMPTY": 5,
                            "FAILED": 19,
                        }
                    button = page.get_by_role(
                        "button", name="Import validated evidence", exact=True
                    )
                    if legacy:
                        expect(button).to_be_disabled()
                        page.get_by_role(
                            "checkbox", name="I acknowledge that this legacy package", exact=False
                        ).check()
                    button.click()
                    expect(
                        page.get_by_role("button", name="Run assessment", exact=True)
                    ).to_be_enabled(timeout=30000)
                    run = page.get_by_label("Active evidence run").input_value()
                    assert run.startswith("run-")
                    with page.expect_response(
                        lambda response: response.url.endswith(f"/api/runs/{run}/assess")
                    ) as assessment:
                        page.get_by_role("button", name="Run assessment", exact=True).click()
                    assessment_id = assessment.value.json()["id"]
                    deadline = time.monotonic() + 60
                    while time.monotonic() < deadline:
                        assessed = context.request.get(origin + "/api/jobs/" + assessment_id).json()
                        if assessed["state"] not in {"PENDING", "RUNNING"}:
                            break
                        page.wait_for_timeout(50)
                    assert assessed["state"] == "COMPLETED", assessed.get("error")
                    expect(page.get_by_label("Local operation details")).to_contain_text(
                        assessment_id
                    )
                    expect(
                        page.get_by_role("button", name="Run assessment", exact=True)
                    ).to_be_enabled(timeout=30000)
                    expect(
                        page.get_by_label("Active evidence run").locator("option:checked")
                    ).to_contain_text("Assessed")
                    return run

                def inspect_and_export(provider, run):
                    page.get_by_role("tab", name=provider, exact=True).click()
                    expect(page.get_by_label(f"{provider} scope summary")).to_be_visible()
                    page.get_by_role("tab", name="Security Findings", exact=True).click()
                    rows = page.locator(".cloud-records tbody tr")
                    expect(rows.first).to_be_visible()
                    rows.first.get_by_role("button", name="View", exact=True).click()
                    page.get_by_role("tab", name="Client Reporting", exact=True).click()
                    page.get_by_label("Analyst identity").fill("synthetic-pilot-reviewer")
                    page.get_by_label("Analyst remarks").fill(
                        "Synthetic original package inspected"
                    )
                    page.get_by_role("tab", name="Client Reporting", exact=True).click()
                    page.get_by_role("button", name="Confirm", exact=True).click()
                    expect(page.get_by_role("dialog", name="Finding details")).to_have_count(0)
                    expect(rows.first).to_contain_text("CONFIRMED")
                    rows.first.get_by_role("button", name="View", exact=True).click()
                    page.get_by_role("tab", name="Client Reporting", exact=True).click()
                    editor = page.get_by_label("Report finding editor")
                    editor.get_by_label("Report reviewer").fill("synthetic-launcher-reviewer")
                    editor.get_by_label("Include in client report").check()
                    editor.get_by_label("Report recommended remediation").fill(
                        "Synthetic validated remediation: apply the stated restriction "
                        "after dependency review."
                    )
                    editor.get_by_role("button", name="Save report draft", exact=True).click()
                    expect(editor.get_by_role("status")).to_contain_text("Report draft saved")
                    editor.get_by_role("button", name="Approve recommendation", exact=True).click()
                    expect(editor.get_by_role("status")).to_contain_text(
                        "recommendation approval recorded"
                    )
                    editor.get_by_role(
                        "button", name="Approve report narrative", exact=True
                    ).click()
                    expect(
                        editor.get_by_role("button", name="Copy Report Finding", exact=True)
                    ).to_be_enabled()
                    editor.get_by_role("button", name="Copy Report Finding", exact=True).click()
                    expect(editor.get_by_role("status")).to_contain_text("copied")
                    if browser_name == "chromium":
                        assert "Synthetic validated remediation" in page.evaluate(
                            "navigator.clipboard.readText()"
                        )
                    page.get_by_role("button", name="Close details", exact=True).click()
                    page.get_by_role("button", name="Report center", exact=True).click()
                    page.get_by_role(
                        "button", name="Export all approved findings (Word DOCX)", exact=True
                    ).click()
                    rtf_row = (
                        page.locator("tr")
                        .filter(has_text="CloSec-assessment-approved-docx.docx")
                        .filter(has_text=run[:20])
                        .first
                    )
                    rtf_row.get_by_role("link", name="Download", exact=True).wait_for()
                    with page.expect_download() as rtf_download:
                        rtf_row.get_by_role("link", name="Download", exact=True).click()
                    assert "Synthetic validated remediation" in word_text(rtf_download.value.path())

                    page.get_by_role("button", name="Generate Excel", exact=True).click()
                    row = (
                        page.locator("tr")
                        .filter(has_text="CloSec-assessment-excel.xlsx")
                        .filter(has_text=run[:20])
                        .first
                    )
                    row.get_by_role("link", name="Download", exact=True).wait_for()
                    with page.expect_download() as downloaded:
                        row.get_by_role("link", name="Download", exact=True).click()
                    target = diagnostics / f"{provider.lower()}-assessment.xlsx"
                    downloaded.value.save_as(target)
                    with target.open("rb") as stream:
                        workbook = load_workbook(stream, read_only=True)
                        sheet = workbook[
                            "Unified Findings Register"
                            if provider == "GCP"
                            else "Findings Register"
                        ]
                        records = list(sheet.values)
                        assert records[1] == ("Assessment run", run)
                        assert len(records) > 3
                        if provider == "GCP":
                            assert any(provider in row for row in records[3:])
                        else:
                            assert any("111111111111" in row for row in records[3:])
                        workbook.close()
                    exports[provider] = {"rows": len(records) - 3, "run_id": run}

                imports["GCP"] = import_and_assess("GCP", folder, transport, legacy=True)
                inspect_and_export("GCP", imports["GCP"])
                # Re-select the same unmodified package; identical evidence keeps its run.
                assert import_and_assess("GCP", folder, transport, legacy=True) == imports["GCP"]
                imports["AWS"] = import_and_assess("AWS", aws, transport)
                inspect_and_export("AWS", imports["AWS"])
                page.get_by_role("button", name="Dashboard", exact=True).click()
                page.get_by_role("button", name="Build enterprise assessment", exact=True).click()
                expect(
                    page.get_by_label("Active evidence run").locator("option:checked")
                ).to_contain_text("Enterprise")
                page.get_by_role("tab", name="Consolidated", exact=True).click()
                expect(page.get_by_label("AWS scope summary")).to_be_visible()
                expect(page.get_by_label("GCP scope summary")).to_be_visible()
                page.reload()
                expect(page.get_by_role("tab", name="Consolidated", exact=True)).to_have_attribute(
                    "aria-selected", "true"
                )
                page.get_by_role("button", name="Report center", exact=True).click()
                page.get_by_role("button", name="Generate Excel", exact=True).click()
                consolidated = page.get_by_label("Active evidence run").input_value()
                consolidated_row = (
                    page.locator("tr")
                    .filter(has_text="CloSec-assessment-excel.xlsx")
                    .filter(has_text=consolidated[:20])
                    .first
                )
                consolidated_row.get_by_role("link", name="Download", exact=True).wait_for()
                with page.expect_download() as consolidated_download:
                    consolidated_row.get_by_role("link", name="Download", exact=True).click()
                with open(consolidated_download.value.path(), "rb") as stream:
                    workbook = load_workbook(stream, read_only=True)
                    records = list(workbook["Unified Findings Register"].values)
                    assert any("AWS" in row for row in records[3:]) and any(
                        "GCP" in row for row in records[3:]
                    )
                    workbook.close()
                runs = context.request.get(origin + "/api/runs").json()
                assert all(
                    any(row["run_id"] == run and row["assessed"] for row in runs)
                    for run in imports.values()
                )
                assert not external and not errors
            browser.close()
    finally:
        if session.process.poll() is None:
            history = session.client.get("/api/jobs").json()
            jobs = [
                {
                    key: job.get(key)
                    for key in ("id", "kind", "state", "stage", "duration_seconds", "timings")
                }
                for job in history
            ]
        session.close()
    assert session.process.returncode == 0
    # Reopen the database after the real server exits, not merely an in-memory API check.
    persisted = {}
    with Store(work) as store:
        for provider, run in imports.items():
            observations = list(store.observations(run))
            results = list(store.results(run))
            candidates = list(store.candidates(run))
            assert observations and results and candidates
            assert any(row.provider == provider for row in candidates)
            assert (
                store.db.execute(
                    "SELECT count(*) FROM assessments WHERE run_id=?", [run]
                ).fetchone()[0]
                == 1
            )
            if provider == "GCP":
                assert any(row.project_id == PROJECT for row in observations)
                sources = list(store.source_data(run))
                assert len(sources) == 32
                assert sum(row["gcp_metadata"]["status"] == "FAILED" for row in sources) == 19
            persisted[provider] = {
                "run_id": run,
                "observations": len(observations),
                "evaluations": len(results),
                "findings": len(candidates),
            }
    assert all(
        hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == value
        for name, value in before.items()
    )
    (diagnostics / "result.json").write_text(
        json.dumps(
            {
                "input_origin": "SYNTHETIC_ONLY",
                "first_transport": transport,
                "browser": browser_name,
                "launcher": "ACTUAL_CHILD_PROCESS",
                "jobs": jobs,
                "selected_pilot_files": 65,
                "persisted": persisted,
                "exports": exports,
                "zip_folder_same_run": True,
                "source_hashes_unchanged": True,
                "external_requests": 0,
                "page_errors": 0,
                "customer_compatibility": "NOT_ESTABLISHED",
            },
            indent=2,
        )
        + "\n"
    )
