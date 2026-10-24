"""Deterministic expanded-contract evidence, never customer-derived payloads."""

import json
import re
from pathlib import Path

from offline_analyzer.contracts.gcp_expanded_catalog import DATASETS

PROJECT = "sample-project"
TIME = "2026-10-12T00:00:00Z"
COLLECTION = f"projects/{PROJECT}/locations/global/collections/default_collection"


def example_name(row: dict) -> str:
    names = {
        "bq_dataset_details": "bq_dataset_sample_details",
        "bq_dataset_tables": "bq_dataset_sample_tables",
        "folder_iam": "folder_123_iam",
        "folder_policies": "folder_123_policies",
        "folder_iam_search": "folder_123_iam_search",
        "folder_describe": "folder_123_describe",
        "organization_iam": "organization_123_iam",
        "organization_iam_search": "organization_123_iam_search",
        "organization_policies": "organization_123_policies",
        "kms_keys": "kms_keys_1_1",
        "kms_versions": "kms_versions_1_1_1",
    }
    return (
        row["family"]
        if row["naming"] == "FIXED"
        else names.get(row["family"], row["family"] + "_1")
    )


def expanded(directory: Path, *, mixed: bool = False) -> Path:
    directory.mkdir(parents=True)
    datasets = []
    statuses = [
        "EMPTY",
        "FAILED",
        "API_DISABLED",
        "ACCESS_DENIED",
        "COMMAND_ERROR",
        "AUTH_ERROR",
        "TRUNCATED",
        "RATE_LIMITED",
        "NOT_FOUND",
        "HTTP_ERROR",
        "SERVER_ERROR",
    ]
    for index, row in enumerate(DATASETS):
        name = example_name(row)
        assert re.fullmatch(row["pattern"], name)
        kind = row["resource_type"]
        body = {"name": f"projects/{PROJECT}/locations/global/{row['family']}/sample"}
        command = "gcloud synthetic read-only --format=json --quiet"
        if kind == "GCP::Project":
            body = {"projectId": PROJECT, "projectNumber": "123456789012"}
        elif kind == "GCP::IAMPolicy":
            body = {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": [f"serviceAccount:worker@{PROJECT}.iam.gserviceaccount.com"],
                    }
                ]
            }
            command = (
                "gcloud iam service-accounts get-iam-policy "
                "worker@sample-project.iam.gserviceaccount.com --format=json"
            )
            if row["family"] == "bucket_iam":
                command = "gcloud storage buckets get-iam-policy gs://sample-bucket --format=json"
        elif kind == "GCP::ServiceAccountKey":
            body.update(
                name=f"projects/{PROJECT}/serviceAccounts/worker@{PROJECT}.iam.gserviceaccount.com/keys/sample",
                keyType="USER_MANAGED",
                validAfterTime="2020-01-01T00:00:00Z",
                disabled=False,
            )
        elif kind == "GCP::ServiceAccount":
            body.update(email=f"worker@{PROJECT}.iam.gserviceaccount.com", uniqueId="123")
        elif kind == "GCP::AssetIAMSearchResult":
            body = {
                "resource": f"//cloudresourcemanager.googleapis.com/projects/{PROJECT}",
                "policy": {"bindings": []},
            }
        elif kind in {"GCP::BigQueryDataset", "GCP::BigQueryTable"}:
            body = {"datasetReference": {"projectId": PROJECT, "datasetId": "sample"}}
            if kind == "GCP::BigQueryTable":
                body = {
                    "tableReference": {
                        "projectId": PROJECT,
                        "datasetId": "sample",
                        "tableId": "sample",
                    }
                }
        singleton = row["family"] in {
            "project",
            "project_iam",
            "parent_org_iam",
            "parent_folder_iam",
            "settings",
            "api_key_detail",
            "sa_iam",
            "bucket_iam",
            "bucket_details",
            "folder_describe",
            "folder_iam",
            "organization_iam",
            "custom_role_detail",
            "effective_policy",
            "run_iam",
            "function_iam",
        }
        output = body if row["method"] == "Run" and singleton else [body]
        if row["family"] in {"interconnect_attachments", "psc_forwarding_rules"}:
            field = (
                "interconnectAttachments"
                if row["family"] == "interconnect_attachments"
                else "forwardingRules"
            )
            output = [
                {"regions/us-central1": {field: [body, {**body, "name": body["name"] + "2"}]}}
            ]
        status = statuses[index - 70] if mixed and 70 <= index < 81 else "SUCCESS"
        file = (
            f"{row['domain']}/{name}.json" if status in {"SUCCESS", "EMPTY", "TRUNCATED"} else None
        )
        if status == "EMPTY":
            output = []
        if file:
            path = directory / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(output))
        error_file = None
        if status not in {"SUCCESS", "EMPTY", "TRUNCATED"}:
            error_file = f"{row['domain']}/{name}.stderr.txt"
            path = directory / error_file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Synthetic collection failure; no configuration values")
        datasets.append(
            dict(
                domain=row["domain"],
                dataset=name,
                status=status,
                record_count=(len(output) if isinstance(output, list) else 1) if file else None,
                exit_code=0 if row["method"] == "Run" and file else None,
                required_api=row["required_api_expression"].strip("'"),
                started_utc=TIME,
                finished_utc=TIME,
                file=file,
                error_file=error_file,
                command=command,
                **({"pages": 1} if row["method"] != "Run" and file else {}),
            )
        )
    (directory / "collection_manifest.json").write_text(
        json.dumps(
            dict(
                schema_version="assessment-expanded-2.1",
                collector="synthetic-contract-1",
                project_id=PROJECT,
                project_name="Synthetic project",
                collected_utc=TIME,
                scope="project",
                limitations=["Synthetic evidence"],
                max_detail_items=0,
                max_api_pages=0,
                enabled_api_count=0,
                discovered_asset_types=[],
                discovery_engine_detail_limit_reached=False,
                bigquery_dataset_detail_limit_reached=False,
                datasets=datasets,
                dataset_origin="synthetic",
            )
        )
    )
    (directory / "discovered_asset_types.json").write_text("[]")
    (directory / "iam_parent_hierarchy_attempted.json").write_bytes(b"\xef\xbb\xbf")
    return directory


FIELD_DISTRIBUTION = {
    "SUCCESS": 14,
    "EMPTY": 11,
    "ACCESS_DENIED": 39,
    "API_DISABLED": 61,
    "NOT_FOUND": 20,
}


def _rewrite(directory: Path, update) -> dict:
    path = directory / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    update(manifest)
    path.write_text(json.dumps(manifest))
    return manifest


def _reset_outputs(directory: Path, manifest: dict) -> None:
    for item in manifest["datasets"]:
        for key in ("file", "error_file"):
            if item.get(key):
                (directory / item[key]).unlink(missing_ok=True)


def field_distribution(directory: Path) -> Path:
    """Structural replica of the reported 145-dataset outcome mix (no customer values).

    31 Discovery Engine detail datasets carry 20 HTTP 404 and 11 HTTP 403 outcomes; the
    remaining families reproduce SUCCESS/EMPTY/ACCESS_DENIED/API_DISABLED counts.
    Successful rows keep catalog-shaped outputs; EMPTY rows are list-shaped families.
    """
    expanded(directory)
    template = json.loads((directory / "collection_manifest.json").read_text())
    by_name = {d["dataset"]: d for d in template["datasets"]}
    discovery = by_name.pop("discovery_resource_1")
    (directory / discovery["file"]).unlink()
    rows = list(by_name.values())
    rows += [{**discovery, "dataset": f"discovery_resource_{i}"} for i in range(1, 32)]
    assert len(rows) == 145

    def listed(item):
        return json.loads((directory / item["file"]).read_text()) if item.get("file") else None

    other = [d for d in rows if not d["dataset"].startswith("discovery_resource_")]
    project = [d for d in other if d["dataset"] == "project"]
    lists = [d for d in other if d["dataset"] != "project" and isinstance(listed(d), list)]
    rest = [d for d in other if d not in project and d not in lists[:11]]
    statuses = {d["dataset"]: "EMPTY" for d in lists[:11]}
    plan = ["SUCCESS"] * 13 + ["ACCESS_DENIED"] * 28 + ["API_DISABLED"] * 61
    statuses.update(zip((d["dataset"] for d in rest), plan, strict=True))
    statuses["project"] = "SUCCESS"
    for i in range(1, 32):
        statuses[f"discovery_resource_{i}"] = "NOT_FOUND" if i <= 20 else "ACCESS_DENIED"
    datasets = []
    for item in rows:
        status = statuses[item["dataset"]]
        item = {**item, "status": status}
        base = f"{item['domain']}/{item['dataset']}"
        if status == "EMPTY":
            (directory / item["file"]).write_text("[]")
            item["record_count"] = 0
        elif status != "SUCCESS":
            if item.get("file") and (directory / item["file"]).exists():
                (directory / item["file"]).unlink()
            item.update(file=None, record_count=None)
            item.pop("pages", None)
            item["exit_code"] = 1 if item["exit_code"] is not None else None
            if status != "API_DISABLED":
                item["error_file"] = base + ".stderr.txt"
                code = "HTTP 404 - Not Found" if status == "NOT_FOUND" else "HTTP 403 - Forbidden"
                (directory / item["error_file"]).parent.mkdir(parents=True, exist_ok=True)
                (directory / item["error_file"]).write_text(f"{code}; synthetic, no values")
        datasets.append(item)
    _rewrite(directory, lambda m: m.update(datasets=datasets))
    return directory


def expanded22(directory: Path, *, interrupted: bool = False) -> Path:
    """Collector 2.2.0 output: new gap statuses, Discovery Engine families, checksums."""
    import hashlib

    expanded(directory, mixed=True)
    extra = [
        (
            "ai",
            "discovery_datastores_1",
            "SUCCESS",
            [{"name": f"{COLLECTION}/dataStores/sample"}],
        ),
        (
            "ai",
            "discovery_engines_1",
            "PARTIAL",
            [{"name": f"{COLLECTION}/engines/sample"}],
        ),
        ("ai", "discovery_engines_2", "QUOTA_PROJECT_DENIED", None),
        ("ai", "discovery_datastores_2", "UNEXPECTED_SCHEMA", None),
        ("ai", "discovery_datastores_3", "TIMEOUT", None),
        ("ai", "discovery_unsupported_1", "UNSUPPORTED_ENDPOINT", None),
        ("ai", "discovery_engines_3", "INVALID_OUTPUT", None),
    ]

    def update(manifest):
        for domain, name, status, body in extra:
            item = dict(
                domain=domain,
                dataset=name,
                status=status,
                record_count=None,
                exit_code=None,
                required_api="discoveryengine.googleapis.com",
                started_utc=TIME,
                finished_utc=TIME,
                file=None,
                error_file=None,
                command="GET https://discoveryengine.googleapis.com/v1/synthetic",
            )
            if body is not None:
                item.update(file=f"{domain}/{name}.json", record_count=len(body), pages=1)
                (directory / item["file"]).write_text(json.dumps(body))
            if status not in {"SUCCESS", "UNSUPPORTED_ENDPOINT"}:
                item["error_file"] = f"{domain}/{name}.stderr.txt"
                (directory / item["error_file"]).write_text("Synthetic collection gap")
            manifest["datasets"].append(item)
        manifest.update(
            schema_version="assessment-expanded-2.2",
            collector="GCP_Security_Evidence_Collector.ps1",
            collector_version="2.2.0",
            collection_status="INTERRUPTED" if interrupted else "COMPLETE",
            quota_project=None,
            command_timeout_seconds=300,
            http_max_retries=3,
            page_hard_cap=2000,
        )

    _rewrite(directory, update)
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(directory).as_posix()}")
    (directory / "checksums.sha256").write_text("\n".join(lines) + "\n")
    return directory
