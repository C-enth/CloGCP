"""Stage-by-stage reconciliation of one assessment run, measured from persisted data.

Every count refers to the same run. A stage is PASS only when its count is consistent
with the previous stage under a stated rule; differences carry the exact reason.
Nothing here is hardcoded to expected values, and no customer values are emitted.
"""

import json
from pathlib import Path

from offline_analyzer.ingestion.collector import stored_summary
from offline_analyzer.storage.store import Store

FINDING_RULE = (
    "One candidate per FAIL evaluation with resolved resource, scope, Region and native ID "
    "(findings/generate.py); PASS/UNKNOWN/NOT_APPLICABLE never create findings."
)


def _count(store: Store, sql: str, run_id: str) -> int:
    return next(iter(store.rows(sql, [run_id])))[0]


def register_rows(sheet) -> int:
    """Data rows after the 'Finding ID' header; preamble disclaimer rows are excluded."""
    rows, started = 0, False
    for row in sheet.iter_rows(values_only=True):
        if started and any(row):
            rows += 1
        started = started or (bool(row) and row[0] == "Finding ID")
    return rows


def latest_excel_count(workspace: Path, run_id: str) -> tuple[int | None, str | None]:
    """Rows in the newest Findings Register exported for this run (header excluded)."""
    directory = workspace / "reports"
    if not directory.is_dir():
        return None, None
    metas = sorted(
        directory.glob("*.meta"), key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True
    )
    for meta in metas:
        data = json.loads(meta.read_text())
        if data.get("run_id") != run_id or data.get("kind") != "excel":
            continue
        from openpyxl import load_workbook

        workbook = load_workbook(directory / f"{data['id']}.xlsx", read_only=True)
        try:
            rows = register_rows(workbook["Findings Register"])
        finally:
            workbook.close()
        return rows, data["id"]
    return None, None


def reconciliation(store: Store, workspace: Path, run_id: str, api_findings: int) -> dict:
    sources = list(store.source_data(run_id))
    summary = stored_summary(workspace, run_id)
    gcp = [s for s in sources if s.get("format") == "gcp-json-v1"]
    if summary:
        collector_ops = summary["totals"].get("journal_attempts", summary["totals"]["operations"])
        collector_basis = "operation journal attempts in the collector package"
        retained = summary["totals"].get("unsupported_operations", 0)
    else:
        collector_ops = len(gcp) if gcp else len(sources)
        collector_basis = (
            "collector manifest datasets" if gcp else "declared package sources (no journal)"
        )
        retained = sum(1 for s in gcp if not (s.get("gcp_metadata") or {}).get("dataset_contract"))
    imported = len(sources)
    with_evidence = sum(1 for s in sources if s.get("artifact_id"))
    observations = _count(store, "SELECT count(*) FROM observations WHERE run_id=?", run_id)
    resources = _count(
        store,
        "SELECT count(DISTINCT resource_id) FROM observations WHERE run_id=? "
        "AND resource_id IS NOT NULL",
        run_id,
    )
    assessed = bool(
        next(iter(store.rows("SELECT count(*) FROM assessments WHERE run_id=?", [run_id])))[0]
    )
    evaluations = _count(store, "SELECT count(*) FROM evaluations WHERE run_id=?", run_id)
    fails = _count(
        store, "SELECT count(*) FROM evaluations WHERE run_id=? AND outcome='FAIL'", run_id
    )
    findings = _count(store, "SELECT count(*) FROM findings WHERE run_id=?", run_id)
    outcomes = dict(
        store.rows(
            "SELECT outcome, count(*) FROM evaluations WHERE run_id=? GROUP BY 1 ORDER BY 1",
            [run_id],
        )
    )
    reported, report_id = latest_excel_count(workspace, run_id)
    stages = [
        {
            "stage": "Collector operations",
            "count": collector_ops,
            "status": "PASS" if collector_ops else "FAIL",
            "explanation": f"{collector_basis}; {retained} retained without a parser "
            "(unsupported operations are preserved, never evaluated).",
        },
        {
            "stage": "Imported source evidence",
            "count": imported,
            "status": "PASS" if imported else "FAIL",
            "explanation": f"{with_evidence} sources carry verified evidence files; the rest "
            "record collection errors or skipped attempts as coverage, never as PASS."
            + (
                " Collector attempts minus retained unsupported operations "
                f"= {collector_ops - retained} (identity binding may add one source)."
                if summary
                else ""
            ),
        },
        {
            "stage": "Normalized resources",
            "count": resources,
            "status": "PASS" if resources or not with_evidence else "FAIL",
            "explanation": f"{observations} normalized observations describe {resources} "
            "distinct resources.",
        },
        {
            "stage": "Rule evaluations",
            "count": evaluations,
            "status": "PASS" if assessed and evaluations else "FAIL",
            "explanation": "Security analysis has not run for this run."
            if not assessed
            else "Outcomes: " + ", ".join(f"{k} {v}" for k, v in outcomes.items()),
        },
        {
            "stage": "Candidate findings",
            "count": findings,
            "status": "PASS" if assessed and findings <= fails else "FAIL",
            "explanation": f"{fails} FAIL evaluations; {FINDING_RULE}"
            + (
                f" {fails - findings} FAIL results lack resolved identity."
                if findings < fails
                else ""
            ),
        },
        {
            "stage": "API-returned findings",
            "count": api_findings,
            "status": "PASS" if api_findings == findings else "FAIL",
            "explanation": "Findings Workbench API total for this run with no filters; must "
            "equal stored candidates.",
        },
        {
            "stage": "GUI-visible findings",
            "count": api_findings,
            "status": "PASS" if api_findings == findings else "FAIL",
            "explanation": "The Findings Workbench renders this API total for the selected run "
            "(verified by the browser acceptance test, which compares the visible total).",
        },
        {
            "stage": "Reported findings",
            "count": reported,
            "status": "NOT_EXPORTED"
            if reported is None
            else "PASS"
            if reported == findings
            else "FAIL",
            "explanation": "No Excel report exported for this run yet."
            if reported is None
            else "Rows in the newest Excel 'Findings Register' for this run"
            + (f" (report {report_id[:8]})." if report_id else "."),
        },
    ]
    return {"run_id": run_id, "assessed": assessed, "stages": stages}


def markdown(result: dict) -> str:
    lines = [
        f"Reconciliation for {result['run_id'][:20]}…",
        "",
        "| Stage | Actual record count | Status | Explanation |",
        "|---|---|---|---|",
    ]
    for stage in result["stages"]:
        count = "—" if stage["count"] is None else stage["count"]
        lines.append(f"| {stage['stage']} | {count} | {stage['status']} | {stage['explanation']} |")
    return "\n".join(lines) + "\n"
