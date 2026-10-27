"""Count-only, read-only snapshot of a CloGCP workspace. Run it yourself with CloGCP closed.

    python tools/workspace_counts.py <workspace folder>

Opens assessment.duckdb with DuckDB's read_only flag through its own connection; never
through the application Store, so no migration, recovery or write can happen. Nothing is
copied. A pending write-ahead log or a lock held by a running CloGCP stops the script
instead of being replayed or bypassed.

Prints counts only: run IDs are shortened content hashes; rule IDs, severities, statuses,
attack-path classes, timings and versions are product metadata. No project, resource,
principal, label, note or evidence value is printed.
"""

import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DATABASE = "assessment.duckdb"


def short(run_id: str) -> str:
    return run_id.removeprefix("run-")[:12]


def tables(db) -> set[str]:
    return {r[0] for r in db.execute("SHOW TABLES").fetchall()}


def path_classes(workspace: Path, run: str) -> dict | None:
    """Latest engine 2.0.1 evaluation of a run (hash-verified derived file), classes only."""
    from offline_analyzer.attack_paths.versioned import latest

    try:
        data = latest(workspace, run)
    except Exception as exc:  # noqa: BLE001 - counts only; report the failure class
        return {"unavailable": type(exc).__name__}
    if not data["latest"]:
        return None
    return {
        "engine_version": data["latest"].get("engine_version"),
        "versions": len(data["versions"]),
        "classes": dict(Counter(p.get("classification") for p in data["paths"])),
    }


def counts(workspace: Path) -> dict:
    import duckdb

    from offline_analyzer.findings.sre import REVIEWED_FINDINGS_SQL

    database = workspace / DATABASE
    if not database.is_file():
        raise SystemExit(f"No {DATABASE} in the selected folder.")
    if (workspace / (DATABASE + ".wal")).exists():
        raise SystemExit(
            "A write-ahead log is pending. Close CloGCP normally, then run this again. "
            "The script never replays or removes it."
        )
    start = time.perf_counter()
    try:
        db = duckdb.connect(str(database), read_only=True)
    except duckdb.Error:
        raise SystemExit(
            "The workspace database is in use or locked. Close CloGCP and run this again."
        ) from None
    try:
        present = tables(db)
        out: dict = {"schema_version": "clogcp-workspace-counts-1", "runs": []}
        frozen = (
            {r[0] for r in db.execute("SELECT run_id FROM finalized_assessments").fetchall()}
            if "finalized_assessments" in present
            else set()
        )
        snapshots = (
            dict(db.execute("SELECT run_id, members FROM enterprise_snapshots").fetchall())
            if "enterprise_snapshots" in present
            else {}
        )
        assessed = dict(db.execute("SELECT run_id, engine_version FROM assessments").fetchall())
        for (run,) in db.execute("SELECT run_id FROM runs ORDER BY created_at").fetchall():
            reviewed = db.execute(
                "SELECT json_extract_string(data,'$.rule_id') AS rule_id, "
                "json_extract_string(data,'$.suggested_severity') AS severity_level, "
                "json_extract_string(data,'$.provider') AS provider_name, review_state, stage "
                f"FROM {REVIEWED_FINDINGS_SQL} WHERE run_id=?",
                [run],
            ).fetchall()
            versions = Counter(
                v
                for (v,) in db.execute(
                    "SELECT coalesce(json_extract_string(data,'$.gcp_metadata.collector_version'),"
                    "json_extract_string(data,'$.collector_version'),'unrecorded') "
                    "FROM sources WHERE run_id=?",
                    [run],
                ).fetchall()
            )
            status = Counter(r[3] for r in reviewed)
            record = {
                "run": short(run),
                "frozen_edition": run in frozen,
                "enterprise_members": len(json.loads(snapshots[run])) if run in snapshots else 0,
                "assessment_engine": assessed.get(run),
                "sources": sum(versions.values()),
                "collector_versions": dict(versions),
                "findings": len(reviewed),
                "by_provider": dict(Counter(r[2] or "AWS" for r in reviewed)),
                "by_status": dict(status),
                "by_stage": dict(Counter(r[4] for r in reviewed)),
                "by_severity": dict(Counter(r[1] for r in reviewed)),
                "by_rule": dict(sorted(Counter(r[0] for r in reviewed).items())),
                "confirmed": status["CONFIRMED"],
                "unreviewed": status["CANDIDATE"],
                "needs_revalidation": status["NEEDS_REVALIDATION"],
                "needs_validation": status["NEEDS_VALIDATION"],
                "evaluations_by_outcome": dict(
                    db.execute(
                        "SELECT outcome, count(*) FROM evaluations WHERE run_id=? GROUP BY 1",
                        [run],
                    ).fetchall()
                ),
                "attack_paths_engine": path_classes(workspace, run),
            }
            if "path_reviews" in present:
                record["legacy_path_reviews"] = dict(
                    db.execute(
                        "SELECT json_extract_string(data,'$.status'), count(*) FROM path_reviews "
                        "WHERE run_id=? GROUP BY 1",
                        [run],
                    ).fetchall()
                )
            out["runs"].append(record)
        out["run_count"] = len(out["runs"])
        out["seconds"] = round(time.perf_counter() - start, 3)
        return out
    finally:
        db.close()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    workspace = Path(sys.argv[1]).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit("Workspace folder not found.")
    print(json.dumps(counts(workspace), indent=1, sort_keys=False, default=str))


if __name__ == "__main__":
    main()
