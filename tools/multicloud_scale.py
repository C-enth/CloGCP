"""Adjustable synthetic multi-cloud benchmark; never processes customer evidence."""

import argparse
import json
import resource
import sys
from pathlib import Path
from time import perf_counter

from openpyxl import load_workbook

from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import record_run_origin, set_environment
from offline_analyzer.release_audit import audit
from offline_analyzer.reporting.cloud import dashboard
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.storage.store import Store

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.fixtures.r12_demo import build as aws_build  # noqa: E402
from tools.gcp_fixture import build  # noqa: E402


def benchmark(output: Path, projects: int) -> dict:
    if not 1 <= projects <= 500:
        raise ValueError("Synthetic project count must be 1..500")
    output.mkdir(parents=True, exist_ok=False)
    workspace = output / "workspace"
    set_environment(workspace, "SYNTHETIC", "Multi-cloud engineering benchmark")
    started = perf_counter()
    with Store(workspace) as store:
        selected = []
        for index in range(projects):
            project = f"demo-project-{index:04}"
            package = build(output / "packages" / project, project, f"{800000000000 + index:012}")
            run = import_package(store, package)
            record_run_origin(workspace, run, "synthetic")
            selected.append(run)
        aws = output / "packages" / "aws"
        aws_build(aws)
        run = import_package(store, aws)
        record_run_origin(workspace, run, "synthetic")
        selected.append(run)
        imported = perf_counter()
        combined = assess_enterprise(store, selected)
        record_run_origin(workspace, combined, "synthetic")
        assessed = perf_counter()
        metrics = dashboard(store, combined)
        exported = output / "consolidated.xlsx"
        export_excel(store, combined, exported)
        finished = perf_counter()
        wb = load_workbook(exported, read_only=True)
        reconciled = {}
        for sheet, expected in (
            (
                "Unified Findings Register",
                sum(m["candidate_findings"] for m in metrics["providers"].values()),
            ),
            ("Cloud Evaluations", sum(m["evaluations"] for m in metrics["providers"].values())),
            (
                "Cloud Resource Inventory",
                sum(m["resources"] for m in metrics["providers"].values()),
            ),
        ):
            actual = sum(1 for _ in wb[sheet].values) - 3
            if actual != expected:
                raise RuntimeError("Synthetic consolidated workbook reconciliation failed")
            reconciled[sheet] = actual
        wb.close()
    result = {
        "origin": "SYNTHETIC",
        "projects": projects,
        "import_seconds": round(imported - started, 3),
        "assessment_seconds": round(assessed - imported, 3),
        "export_seconds": round(finished - assessed, 3),
        "reconciled_rows": reconciled,
        "release_audit": audit(workspace, combined)["result"],
        "peak_rss_mb": round(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            / (1024 * 1024 if sys.platform == "darwin" else 1024),
            2,
        ),
        "qualification": (
            "Synthetic configuration benchmark only; not real evidence or "
            "maximum-estate capacity certification"
        ),
    }
    (output / "result.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--projects", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.output, args.projects)))
