"""Dry-run by default. No token acquisition or cloud calls without --execute."""

import argparse
import json
from pathlib import Path

from .collector import DeltaError, Transport, collect, load, sha
from .models import Manifest, Plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-manifest", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--gcloud", default="gcloud")
    parser.add_argument("--matrix", type=Path)
    args = parser.parse_args()
    plan = Plan.model_validate(load(args.plan))
    baseline = (
        Manifest.model_validate(load(args.baseline_manifest)) if args.baseline_manifest else None
    )
    if args.execute and not args.matrix:
        raise DeltaError("APPROVED_MATRIX_FILE_REQUIRED")
    matrix_hash = sha(args.matrix.read_bytes()) if args.matrix else None
    # Constructor validates an executable only after explicit execution authorization.
    transport = Transport(args.gcloud) if args.execute else None
    result = collect(
        plan,
        args.output,
        execute=args.execute,
        transport=transport,
        baseline=baseline,
        matrix_sha256=matrix_hash,
    )
    print(
        json.dumps(
            {
                "executed": result.executed,
                "operations": len(result.results),
                "complete": sum(r.state in {"COMPLETE", "EMPTY"} for r in result.results),
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except DeltaError as exc:
        raise SystemExit(str(exc)) from None
    except (ValueError, TypeError, OSError):
        raise SystemExit("DELTA_PLAN_OR_INPUT_INVALID") from None
