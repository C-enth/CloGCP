"""Reanalyze existing local GCP evidence without migrations, recollection or historical writes."""

import argparse
import json
from pathlib import Path

from offline_analyzer.attack_paths.gcp_engine import evaluate
from offline_analyzer.contracts.gcp_attack_path import DiscoveryLimits
from offline_analyzer.ingestion.json_input import InputError, inspect_json, records
from offline_analyzer.reporting.gcp_attack_path_register import write_register
from offline_analyzer.rules.engine import verify_raw
from offline_analyzer.storage.store import Store


def reanalyze(
    workspace: Path,
    run_id: str,
    output: Path,
    *,
    limits: DiscoveryLimits | None = None,
    legacy_paths: list[dict] | None = None,
):
    workspace, output = workspace.resolve(), output.resolve()
    if output == workspace or workspace in output.parents:
        raise InputError("REANALYSIS_REQUIRES_ISOLATED_OUTPUT")
    source_root = Path(__file__).resolve().parents[3]
    if source_root in output.parents and not any(
        root == output or root in output.parents
        for root in (source_root / "artifacts", source_root / "data/private")
    ):
        raise InputError("REANALYSIS_OUTPUT_MUST_BE_PRIVATE")
    # Stop the running application first: read-only DuckDB cannot share a different
    # connection configuration and must never recover a pending scope operation.
    if (workspace / ".scope-journal.json").exists():
        raise InputError("REANALYSIS_PENDING_SCOPE_OPERATION")
    with Store(workspace, read_only=True) as store:
        verify_raw(store, run_id)
        register = evaluate(store, run_id, limits=limits, legacy_paths=legacy_paths)
        verify_raw(store, run_id)
    write_register(register, output, legacy_paths=legacy_paths)
    return register


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--legacy-paths",
        type=Path,
        help="Optional original local JSON path array; no approvals are imported",
    )
    parser.add_argument("--max-nodes", type=int, default=10000)
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--max-candidates", type=int, default=1000)
    parser.add_argument("--max-bindings", type=int, default=50000)
    args = parser.parse_args()
    legacy = None
    if args.legacy_paths:
        shape = inspect_json(args.legacy_paths)
        if shape["root"] != "start_array":
            raise InputError("LEGACY_PATH_ARRAY_REQUIRED")
        legacy = [v for _, v in records(args.legacy_paths, "item")]
    if legacy is not None and (
        not isinstance(legacy, list) or any(not isinstance(p, dict) for p in legacy)
    ):
        raise InputError("LEGACY_PATH_ARRAY_REQUIRED")
    register = reanalyze(
        args.workspace,
        args.run,
        args.output,
        limits=DiscoveryLimits(
            max_nodes=args.max_nodes,
            max_depth=args.max_depth,
            max_candidates=args.max_candidates,
            max_bindings=args.max_bindings,
        ),
        legacy_paths=legacy,
    )
    # Counts only: customer identities and paths are never printed.
    print(
        json.dumps(
            {
                "engine_version": register.engine_version,
                "paths": len(register.paths),
                "truncated": register.truncated,
                "elapsed_seconds": register.elapsed_seconds,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except InputError as exc:
        raise SystemExit(str(exc)) from None
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit("REANALYSIS_INVALID_INPUT_OR_UNAVAILABLE") from None
