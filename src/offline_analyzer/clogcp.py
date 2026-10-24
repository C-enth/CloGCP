"""CloGCP: isolated GUI launcher and offline multi-project assessment command."""

import argparse
import json
import sys
from pathlib import Path
from time import perf_counter

from offline_analyzer.clogcp_profile import configure, ensure_workspace


def analyze(args: argparse.Namespace) -> dict:
    from offline_analyzer.cli import private_copy
    from offline_analyzer.enterprise.snapshot import assess_enterprise
    from offline_analyzer.findings.clogcp_reconcile import load_history
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.ingestion.json_input import InputError
    from offline_analyzer.inventory.environment import record_run_origin, set_environment
    from offline_analyzer.reporting.assessment_report import export_assessment
    from offline_analyzer.reporting.clogcp_assurance import export_assurance
    from offline_analyzer.reporting.excel import export_excel
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store

    for source in args.packages:
        if source.is_dir() and (
            args.workspace.resolve().is_relative_to(source.resolve())
            or args.output.resolve().is_relative_to(source.resolve())
        ):
            raise InputError("CLOGCP_OUTPUT_AND_WORKSPACE_MUST_BE_OUTSIDE_EVIDENCE_PACKAGE")
    ensure_workspace(args.workspace)
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    set_environment(args.workspace, "SYNTHETIC" if args.synthetic else "ASSESSMENT", "CloGCP")
    origin = "synthetic" if args.synthetic else "tool-generated"
    started = perf_counter()
    imported = []
    history = load_history(args.history)
    with Store(args.workspace) as store:
        for source in args.packages:
            with private_copy(store.workspace, source) as package:
                run = import_package(store, package)
            record_run_origin(store.workspace, run, origin)
            imported.append(run)
        imported_at = perf_counter()
        if len(imported) > 1:
            run = assess_enterprise(store, imported)
            record_run_origin(store.workspace, run, origin)
        else:
            run = imported[0]
            assess(store, run)
        assessed_at = perf_counter()
        export_excel(store, run, args.output / "CloGCP_Assessment.xlsx")
        export_assessment(
            store, run, args.output / "CloGCP_Assessment_Report.zip", include="all", provider="GCP"
        )
        extra = export_assurance(
            store, run, args.output / "CloGCP_Analysis_Assurance.xlsx", history
        )
        from collections import Counter

        results = list(store.results(run))
        findings = list(store.candidates(run))
        summary = {
            "product": "CloGCP",
            "build": "0.8.4-clogcp.1",
            "origin": origin,
            "run": run,
            "projects": len(
                {s["project_id"] for s in store.source_data(run) if s.get("project_id")}
            ),
            "imported_packages": len(imported),
            "rule_executions": len(results),
            "resource_evaluations": sum(r.evaluation_scope == "RESOURCE" for r in results),
            "resources": len({r.resource_id for r in results if r.resource_id}),
            "outcomes": dict(Counter(str(r.outcome) for r in results)),
            "findings": len(findings),
            "findings_by_rule": dict(Counter(f.rule_id for f in findings)),
            "import_seconds": imported_at - started,
            "analysis_seconds": assessed_at - imported_at,
            "export_seconds": perf_counter() - assessed_at,
            "total_seconds": perf_counter() - started,
            "historical_records": len(history.records),
            "historical_approvals_applied": 0,
            "assurance": extra,
            "limitation": (
                "Named configuration criteria only; unassessed and "
                "insufficient-evidence registers remain mandatory. No verified "
                "exploitation or production acceptance claim."
            ),
        }
    (args.output / "CloGCP_Run_Summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    workspace = configure()
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in {"analyze", "export-history"}:
        from offline_analyzer.launcher import main as launcher

        sys.argv = ["clogcp", "--default-workspace", str(workspace), *argv]
        return launcher() or 0
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    analysis = sub.add_parser("analyze")
    analysis.add_argument("--packages", type=Path, nargs="+", required=True)
    analysis.add_argument("--workspace", type=Path, required=True)
    analysis.add_argument("--output", type=Path, required=True)
    analysis.add_argument("--history", type=Path)
    analysis.add_argument("--synthetic", action="store_true")
    export = sub.add_parser("export-history")
    export.add_argument("--workspace", type=Path, required=True)
    export.add_argument("--run", required=True)
    export.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            result = analyze(args)
        else:
            from offline_analyzer.findings.clogcp_reconcile import export_readonly_history

            export_readonly_history(args.workspace, args.run, args.output)
            result = {"history_export": "complete", "original_workspace_modified": False}
        # Console output contains engineering counts only, not resource or finding contents.
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        from offline_analyzer.ingestion.json_input import InputError

        if isinstance(exc, (InputError, FileExistsError)):
            print(
                "CloGCP operation refused: "
                + (str(exc) if isinstance(exc, InputError) else "OUTPUT_ALREADY_EXISTS"),
                file=sys.stderr,
            )
            return 2
        raise


if __name__ == "__main__":
    raise SystemExit(main())
