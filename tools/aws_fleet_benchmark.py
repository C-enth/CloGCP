"""Synthetic AWS fleet benchmark: batch collection to report, one account per package.

    PYTHONPATH=src:. python -m tools.aws_fleet_benchmark --work <dir> --accounts 143 --size 8

Stages (wall clock, this process): generate (collectors/aws/batch.py on the in-process fake
cloud, tools/fixtures/aws_fake_cloud.py; not an analyzer stage), bulk import with analysis,
snapshot build, snapshot assessment, correlation, attack paths, dashboard, facets, Word and
Excel. `--profile STAGE` also runs that stage under cProfile and reports both timings so
profiler overhead and caching effects can be compared. Synthetic data only.
"""

import argparse
import cProfile
import json
import pstats
import resource
import sys
import time
from io import StringIO
from pathlib import Path

GROUPS = ("Payments", "Retail", "Data platform", "Shared services", "Security", "Sandbox")


def generate(work: Path, accounts: int, size: int, concurrency: int) -> Path:
    from tools.fixtures import aws_fake_cloud as fake

    cloud = fake.fleet(accounts, size=size)
    ids = [fake.fleet_account(i) for i in range(accounts)]
    listing = work / "accounts.csv"
    listing.write_text(
        "account_id,business_group,name\n"
        + "".join(f"{a},{GROUPS[i % len(GROUPS)]},Synthetic {i:03d}\n" for i, a in enumerate(ids))
    )
    config = work / "config.json"
    config.write_text(json.dumps({"assessment_id": "SYNTHETIC-BENCH", "dataset_origin": "SYNTHETIC",
                                  "approved_regions": ["ap-south-1", "eu-west-1"],
                                  "spoke_role_name": "CloSecEvidenceReadOnly"}))  # fmt: skip
    with fake.installed(cloud, "batch") as batch:
        batch.main(
            [
                "--config", str(config),
                "--accounts", str(listing), "--role", "CloSecEvidenceReadOnly",
                "--regions", "ap-south-1", "eu-west-1", "--output", str(work / "batch"),
                "--assessment-id", "SYNTHETIC-BENCH", "--concurrency", str(concurrency),
            ]
        )  # fmt: skip
    return work / "batch" / "evidence"


def timed(results: dict, name: str, function, profile: str | None = None):
    started = time.perf_counter()
    value = function()
    results[name] = round(time.perf_counter() - started, 2)
    if profile == name:
        profiler = cProfile.Profile()
        started = time.perf_counter()
        profiler.runcall(function)
        results[name + "_under_cprofile"] = round(time.perf_counter() - started, 2)
        stream = StringIO()
        pstats.Stats(profiler, stream=stream).sort_stats("cumulative").print_stats(25)
        results[name + "_profile_top"] = stream.getvalue().splitlines()[:60]
    print(f"{name}: {results[name]} s", file=sys.stderr)
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--accounts", type=int, default=143)
    parser.add_argument("--size", type=int, default=8)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--profile", help="stage to repeat under cProfile")
    parser.add_argument("--reuse", action="store_true", help="reuse generated packages")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.enterprise.correlate import correlate
    from offline_analyzer.enterprise.snapshot import build_snapshot, members
    from offline_analyzer.ingestion.bulk import bulk_import
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.reporting.assessment_report import export_assessment
    from offline_analyzer.reporting.cloud import dashboard
    from offline_analyzer.reporting.excel import export_excel
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store

    args.work.mkdir(parents=True, exist_ok=True)
    results: dict = {"accounts": args.accounts, "size": args.size}
    evidence = args.work / "batch" / "evidence"
    if not (args.reuse and evidence.is_dir()):
        evidence = timed(
            results, "generate", lambda: generate(args.work, args.accounts, args.size,
                                                  args.concurrency)
        )  # fmt: skip
    results["package_bytes"] = sum(p.stat().st_size for p in evidence.glob("*.zip"))
    workspace = args.work / "workspace"
    if workspace.exists():
        import shutil

        shutil.rmtree(workspace)
    set_environment(workspace, "SYNTHETIC")
    store = Store(workspace)
    expected = [line.split(",")[0] for line in
                (args.work / "accounts.csv").read_text().splitlines()[1:]]  # fmt: skip
    report = timed(results, "bulk_import_and_assess",
                   lambda: bulk_import(store, evidence, expected=expected))  # fmt: skip
    results["bulk_counts"] = report["counts"]
    results["reconciliation"] = {k: v if not isinstance(v, list) else len(v)
                                 for k, v in report["reconciliation"].items()}  # fmt: skip
    selected = members(store)
    snapshot = timed(results, "snapshot_build", lambda: build_snapshot(store, selected))
    timed(results, "snapshot_assess", lambda: assess(store, snapshot), args.profile)
    timed(results, "correlate", lambda: correlate(store, snapshot), args.profile)
    paths = timed(results, "attack_paths", lambda: attack_paths(store, snapshot), args.profile)
    results["attack_paths_truncated"] = bool(paths.get("truncated"))
    timed(results, "dashboard", lambda: dashboard(store, snapshot), args.profile)

    from offline_analyzer.api.facets import facets
    from offline_analyzer.api.services import Views

    views = Views(workspace)
    timed(results, "facets", lambda: facets(views, store, snapshot, "findings", ""), args.profile)
    timed(
        results,
        "word_and_excel_report",
        lambda: export_assessment(store, snapshot, args.work / "report.zip", include="all"),
    )
    (args.work / "report.zip").unlink(missing_ok=True)
    workbook = args.work / "workspace.xlsx"
    workbook.unlink(missing_ok=True)
    timed(results, "excel_workbook", lambda: export_excel(store, snapshot, workbook), args.profile)
    counts = {}
    for table in ("observations", "findings", "evaluations", "enterprise_edges"):
        query = f"SELECT count(*) FROM {table} WHERE run_id=?"
        counts[table] = store.db.execute(query, [snapshot]).fetchone()[0]
    results["snapshot_rows"] = counts
    results["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 2**20, 1)
    text = json.dumps(results, indent=1, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
