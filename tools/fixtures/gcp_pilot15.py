"""Deterministic pilot-1.5 structure from allowlisted metadata; synthetic payloads only."""

import json
from pathlib import Path

from tools.fixtures.gcp_pilot import TIME, pilot


def build(directory: Path) -> Path:
    pilot(directory)
    path = directory / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    manifest.update(
        schema_version="pilot-1.5",
        max_detail_items=1000,
        max_api_pages=5,
        enabled_api_count=1,
        discovered_asset_types=[{"asset_type": "synthetic.example/Resource", "count": 1}],
    )
    datasets = manifest["datasets"]
    for dataset in datasets:
        dataset["required_api"] = "cloudasset.googleapis.com"
        if dataset["status"] == "FAILED":
            dataset.update(file=None, status="API_DISABLED", record_count=None)
    # Keep the observed aggregate transport: 25 JSON + 38 stderr + metadata + manifest.
    for index in range(12):
        name = f"unsupported/synthetic-{index}.json"
        body = [{"name": f"synthetic-resource-{index}"}] if index < 4 else []
        target = directory / name
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(body))
        datasets.append(
            dict(
                domain="unsupported",
                dataset=f"synthetic-{index}",
                status="SUCCESS" if body else "EMPTY",
                record_count=len(body),
                exit_code=0,
                file=name,
                error_file=None,
                command="synthetic read-only collection",
                started_utc=TIME,
                finished_utc=TIME,
                required_api="synthetic.googleapis.com",
            )
        )
    for index in range(19):
        name = f"unsupported/error-{index}.stderr.txt"
        (directory / name).write_text("Synthetic collection unavailable")
        datasets.append(
            dict(
                domain="unsupported",
                dataset=f"error-{index}",
                status="API_DISABLED",
                record_count=None,
                exit_code=1,
                file=None,
                error_file=name,
                command="synthetic read-only collection",
                started_utc=TIME,
                finished_utc=TIME,
                required_api="synthetic.googleapis.com",
            )
        )
    failed = [row for row in datasets if row["status"] == "API_DISABLED"]
    for row in failed[:5]:
        row.update(status="ACCESS_DENIED", pages=1)
        row.pop("exit_code")
    for row in failed[5:10]:
        row["status"] = "AUTH_ERROR"
    (directory / "discovered_asset_types.json").write_text(
        json.dumps(manifest["discovered_asset_types"])
    )
    path.write_text(json.dumps(manifest))
    return directory
