"""Assess one synthetic estate and print stored identities for cross-version equality.

Run the same command from two source trees (for example the released tag and a candidate
branch) and compare the JSON outputs. Synthetic estates only; never point this at a client
workspace.

    PYTHONPATH=src:. python -m tools.finalization_equality --packages <dir> --output <json>
"""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings.generate import fingerprint, validation_status
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.storage.store import Store


def snapshot(store: Store, run: str) -> dict:
    """Stored identity fields only: IDs, fingerprints, rule versions, outcomes and status."""
    decisions = store.latest_decisions(run)
    findings = sorted(
        (
            f.finding_id,
            fingerprint(f),
            f.rule_id,
            f.rule_version,
            f.suggested_severity,
            f.finding_class,
            f.resource_id,
            f.region,
            validation_status(store, f, decisions)[0],
        )
        for f in store.candidates(run)
    )
    results = sorted((r.evaluation_id, r.rule_id, str(r.outcome)) for r in store.results(run))
    return {
        "findings": len(findings),
        "evaluations": len(results),
        "findings_sha256": hashlib.sha256(json.dumps(findings).encode()).hexdigest(),
        "evaluations_sha256": hashlib.sha256(json.dumps(results).encode()).hexdigest(),
        "finding_rows": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packages = sorted(p for p in args.packages.iterdir() if p.is_dir())
    with tempfile.TemporaryDirectory() as folder:
        work = Path(folder) / "workspace"
        set_environment(work, "SYNTHETIC")
        with Store(work) as store:
            imports = [import_package(store, p) for p in packages]
            run = assess_enterprise(store, imports)
            data = {"packages": len(packages), "run": run, **snapshot(store, run)}
    args.output.write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(
        json.dumps(
            {k: v for k, v in data.items() if k != "finding_rows"},
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
