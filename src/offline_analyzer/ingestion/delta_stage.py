"""Optional explicit isolated-workspace wrapper around verified recovery and composition."""

import argparse
import json
from pathlib import Path

from offline_analyzer.attack_paths.versioned import recalculate
from offline_analyzer.evidence.composition import compose, description
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.storage.side_by_side import file_inventory, recover_copy
from offline_analyzer.storage.store import Store


def stage(base_workspace: Path, base_run: str, delta: Path, output: Path) -> dict:
    base_workspace, output = base_workspace.resolve(), output.resolve()
    if output.exists() or output == base_workspace or base_workspace in output.parents:
        raise InputError("NEW_ISOLATED_WORKSPACE_REQUIRED")
    before = file_inventory(base_workspace)
    work = output / "workspace"
    recovery = recover_copy(base_workspace, work)
    with Store(work) as store:
        delta_run = import_package(store, delta.resolve())
        run = compose(store, base_run, delta_run)
        report = description(store, run)
    paths = recalculate(work, run)
    if file_inventory(base_workspace) != before:
        raise InputError("BASE_WORKSPACE_CHANGED_DURING_STAGING")
    report.update(
        new_run=run,
        base_database_unchanged=True,
        recovery_verified=recovery["recovery_verified"],
        path_evaluation=paths["evaluation_id"],
    )
    (output / "historical-reconciliation.json").write_text(json.dumps(report, indent=2))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-workspace", type=Path, required=True)
    parser.add_argument("--base-run", required=True)
    parser.add_argument("--delta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = stage(args.base_workspace, args.base_run, args.delta, args.output)
    print(
        json.dumps(
            {
                "base_database_unchanged": report["base_database_unchanged"],
                "findings_reconciled": len(report["reconciliation"]),
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except InputError as exc:
        raise SystemExit(str(exc)) from None
    except (ValueError, OSError):
        raise SystemExit("DELTA_STAGE_INVALID_INPUT_OR_UNAVAILABLE") from None
