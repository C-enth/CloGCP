"""Explicitly synthetic native JSON packages for offline GCP acceptance only."""

import argparse
import json
from pathlib import Path

from offline_analyzer.contracts.gcp import GCPDataset, GCPManifest
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.normalization.gcp import PROFILES
from offline_analyzer.rules.gcp import GCP_RULES

PROJECT = "demo-alpha"
NUMBER = "111111111111"
TIME = "2026-10-12T00:00:00Z"


def build(directory: Path, project: str = PROJECT, number: str = NUMBER) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    sa = f"worker@{project}.iam.gserviceaccount.com"
    native = f"projects/{project}/serviceAccounts/{sa}"
    data = {
        "gcp:projects.get": {"projectId": project, "projectNumber": number},
        "gcp:apikeys.keys.list": [
            {"name": f"projects/{number}/locations/global/keys/demo-key", "restrictions": {}}
        ],
        "gcp:serviceusage.services.list": [
            {"name": f"projects/{number}/services/compute.googleapis.com", "state": "ENABLED"}
        ],
        "gcp:iam.serviceAccounts.list": [{"name": native, "email": sa, "uniqueId": number}],
        "gcp:iam.serviceAccountKeys.list": [
            {
                "name": native + "/keys/demo-key",
                "keyType": "USER_MANAGED",
                "validAfterTime": "2025-01-01T00:00:00Z",
                "disabled": False,
            }
        ],
        "gcp:projects.getIamPolicy": {
            "version": 3,
            "bindings": [
                {"role": "roles/owner", "members": ["serviceAccount:" + sa]},
                {
                    "role": "roles/editor",
                    "members": ["serviceAccount:worker@demo-beta.iam.gserviceaccount.com"],
                },
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": ["group:operators@example.invalid"],
                },
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
            ],
            "auditConfigs": [
                {
                    "service": "allServices",
                    "auditLogConfigs": [
                        {
                            "logType": "DATA_READ",
                            "exemptedMembers": ["user:reviewer@example.invalid"],
                        }
                    ],
                }
            ],
        },
        "gcp:orgpolicy.getEffectivePolicy": {
            "constraint": "constraints/iam.disableServiceAccountKeyCreation",
            "booleanPolicy": {"enforced": False},
        },
        "gcp:logging.sinks.list": [
            {
                "name": "_Default",
                "exclusions": [
                    {
                        "name": "demo-exclusion",
                        "filter": 'log_id("cloudaudit.googleapis.com/data_access")',
                        "disabled": False,
                    }
                ],
            }
        ],
        "gcp:securitycenter.findings.list": [],
    }
    datasets = []
    for i, (operation, payload) in enumerate(data.items()):
        name = f"source-{i:03}.json"
        (directory / name).write_text(json.dumps(payload), encoding="utf-8")
        params = (
            {"subject": f"projects/{project}"} if operation == "gcp:projects.getIamPolicy" else {}
        )
        if operation == "gcp:orgpolicy.getEffectivePolicy":
            params = {"constraint": payload["constraint"], "effective": "true"}
        datasets.append(
            GCPDataset(
                project_id=project,
                project_number=number,
                operation=operation,
                parameters=params,
                started_at=TIME,
                completed_at=TIME,
                status="EMPTY" if payload == [] else "SUCCESS",
                record_count=len(payload) if isinstance(payload, list) else 1,
                path=name,
                sha256=sha256_file(directory / name),
                pagination_complete=True,
                normalized_resource_types=[PROFILES[operation][0]],
                applicable_rules=[r.rule_id for r in GCP_RULES if r.operation == operation],
            )
        )
    manifest = GCPManifest(
        collector_version="synthetic-gcp-1",
        assessment_id="synthetic-demo",
        expected_projects=[project, "demo-missing"],
        collected_projects=[project],
        dataset_origin="synthetic",
        datasets=datasets,
    )
    (directory / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")
    return directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--project", default=PROJECT)
    args = parser.parse_args()
    build(args.output, args.project)
    print("Synthetic GCP package generated; never use as customer evidence.")
