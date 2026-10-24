"""Deterministic pilot-1.2.2 test evidence; no customer payloads or cloud calls."""

import json
from pathlib import Path

PROJECT = "sample-project"
TIME = "2026-10-12T00:00:00Z"


def pilot(directory: Path, *, full_transport: bool = False) -> Path:
    directory.mkdir()
    bodies = {
        "inventory/project.json": {
            "projectId": PROJECT,
            "projectNumber": "123456789012",
            "name": "Synthetic project",
        },
        "inventory/assets.json": [
            {
                "name": f"//cloudresourcemanager.googleapis.com/projects/{PROJECT}",
                "assetType": "cloudresourcemanager.googleapis.com/Project",
            }
        ],
        "inventory/asset_iam_search.json": [
            {
                "resource": f"//cloudresourcemanager.googleapis.com/projects/{PROJECT}",
                "policy": {"bindings": []},
            }
        ],
        "api/enabled_services.json": [
            {"name": "projects/123456789012/services/cloudasset.googleapis.com", "state": "ENABLED"}
        ],
        "identity/project_iam.json": {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["serviceAccount:worker@sample-project.iam.gserviceaccount.com"],
                }
            ]
        },
        "governance/org_policies.json": [
            {
                "name": f"projects/{PROJECT}/policies/iam.disableServiceAccountKeyCreation",
                "spec": {"rules": [{"enforce": False}]},
            }
        ],
        "logging/sinks.json": [
            {
                "name": "synthetic-sink",
                "destination": "logging.googleapis.com/projects/sample-project/"
                "locations/global/buckets/_Default",
            }
        ],
        "logging/buckets_global.json": [
            {"name": f"projects/{PROJECT}/locations/global/buckets/_Default", "retentionDays": 30}
        ],
        "api/api_keys.json": [],
        "identity/service_accounts.json": [],
        "identity/custom_roles.json": [],
        "storage/buckets.json": [],
        "network/networks.json": [],
    }
    datasets = []
    for file, body in bodies.items():
        path = directory / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body))
        datasets.append(
            dict(
                domain=file.split("/")[0],
                dataset=path.stem,
                status="EMPTY" if body == [] else "SUCCESS",
                record_count=len(body) if isinstance(body, list) else 1,
                exit_code=0,
                started_utc=TIME,
                finished_utc=TIME,
                file=file,
                error_file=None,
                command="gcloud synthetic read-only --format=json",
            )
        )
    for i in range(19):
        file = (
            ["compute/instances.json", "monitoring/alert_policies.json", "logging/exclusions.json"][
                i
            ]
            if i < 3
            else f"workloads/unavailable-{i}.json"
        )
        error_file = file.removesuffix(".json") + ".stderr.txt"
        path = directory / error_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            ["API is disabled", "PERMISSION_DENIED", "Invalid choice: exclusions"][i]
            if i < 3
            else "Collection failed"
        )
        datasets.append(
            dict(
                domain=file.split("/")[0],
                dataset=Path(file).stem,
                status="FAILED",
                record_count=0,
                exit_code=1,
                started_utc=TIME,
                finished_utc=TIME,
                file=file,
                error_file=error_file,
                command="gcloud synthetic failed operation",
            )
        )
    if full_transport:
        # Some collectors retain stdout and stderr for every attempted operation:
        # 32 JSON files + 32 stderr files + the original manifest = 65 selections.
        for dataset in datasets:
            output = directory / dataset["file"]
            if not output.exists():
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"")
            error_file = dataset["file"].removesuffix(".json") + ".stderr.txt"
            stderr = directory / error_file
            if not stderr.exists():
                stderr.write_bytes(b"")
            dataset["error_file"] = error_file
    (directory / "collection_manifest.json").write_text(
        json.dumps(
            dict(
                schema_version="pilot-1.2.2",
                collector="synthetic-pilot",
                project_id=PROJECT,
                project_name="Synthetic project",
                collected_utc=TIME,
                scope="project",
                limitations=["No hashes"],
                datasets=datasets,
                dataset_origin="synthetic",
            )
        )
    )
    return directory
