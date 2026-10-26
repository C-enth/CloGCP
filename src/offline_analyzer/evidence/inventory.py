"""Export only the selected stored source inventory for offline delta planning."""

import argparse
import json
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import verify_raw
from offline_analyzer.storage.store import Store


def export_inventory(workspace: Path, run: str, output: Path) -> None:
    if output.exists():
        raise InputError("NEW_INVENTORY_OUTPUT_REQUIRED")
    with Store(workspace, read_only=True) as store:
        store.require_run(run)
        verify_raw(store, run)
        stored = list(store.source_data(run))
        by_artifact = {s.get("artifact_id"): s for s in stored}
        sources = [
            {
                k: s.get(k)
                for k in (
                    "project_id",
                    "project_number",
                    "operation",
                    "request_parameters",
                    "collected_at",
                    "effective_coverage",
                    "coverage",
                    "sha256",
                )
            }
            for s in stored
            if s.get("format") == "gcp-json-v1"
        ]
        for obs in store.observations(run, provider="GCP"):
            if (
                obs.resource_type
                in {
                    "GCP::Bucket",
                    "GCP::Folder",
                    "GCP::IAMPolicy",
                    "GCP::DiscoveryEngine",
                    "GCP::DiscoveryDataStore",
                }
                and obs.native_id
            ):
                parameters = {}
                if obs.resource_type in {"GCP::Folder", "GCP::IAMPolicy"}:
                    parameters = {"subject": obs.native_id}
                elif obs.resource_type in {"GCP::DiscoveryEngine", "GCP::DiscoveryDataStore"}:
                    parameters = {"parent": obs.native_id.rsplit("/", 2)[0]}
                sources.append(
                    {
                        "project_id": obs.project_id,
                        "operation": obs.operation,
                        "resource_type": obs.resource_type,
                        "resource_name": obs.native_id,
                        "request_parameters": parameters,
                        "effective_coverage": by_artifact.get(obs.evidence.artifact_id, {}).get(
                            "effective_coverage", "UNKNOWN"
                        ),
                        "collected_at": obs.collected_at.isoformat() if obs.collected_at else None,
                    }
                )
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(sources, stream, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    export_inventory(args.workspace, args.run, args.output)


if __name__ == "__main__":
    main()
