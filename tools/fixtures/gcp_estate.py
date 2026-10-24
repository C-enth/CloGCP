"""Synthetic multi-project GCP estate in the collector 2.2 package format (never real evidence).

Each project is derived from the expanded 2.2 contract fixture, given its own identity and
deterministic, varied records for the datasets the GCP rules read, with a realistic mix of
dataset statuses (API_DISABLED, ACCESS_DENIED, QUOTA_PROJECT_DENIED for Cloud Asset with user
credentials, EMPTY, TRUNCATED, TIMEOUT). Identifiers are synthetic: project IDs
`synth-gcp-NN`, project numbers computed from a documented synthetic base, example.com
principals and documentation IP ranges.

    python -m tools.fixtures.gcp_estate --output <dir> --projects 41
"""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from tools.fixtures.gcp_expanded import expanded22

BASE = "sample-project"
BASE_NUMBER = "123456789012"
NUMBER_BASE = 900000000000  # computed numbers only; never literal customer values


def number(index: int) -> str:
    return str(NUMBER_BASE + index)


def project(index: int) -> str:
    return f"synth-gcp-{index:02d}"


def _manifest(directory: Path) -> dict:
    return json.loads((directory / "collection_manifest.json").read_text())


def _write_manifest(directory: Path, manifest: dict) -> None:
    (directory / "collection_manifest.json").write_text(json.dumps(manifest))


def set_dataset(directory: Path, manifest: dict, dataset: str, status: str, body=None) -> None:
    """Give one dataset a status and (for SUCCESS/EMPTY/TRUNCATED) its records; ABSENT removes
    it (the collector did not run it)."""
    item = next(d for d in manifest["datasets"] if d["dataset"] == dataset)
    for key in ("file", "error_file"):
        if item.get(key):
            (directory / item[key]).unlink(missing_ok=True)
    if status == "ABSENT":
        manifest["datasets"].remove(item)
        return
    item.update(status=status, file=None, error_file=None, record_count=None)
    item.pop("pages", None)
    if status in {"SUCCESS", "EMPTY", "TRUNCATED", "PARTIAL"}:
        body = [] if status == "EMPTY" else body
        item["file"] = f"{item['domain']}/{dataset}.json"
        path = directory / item["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body))
        item["record_count"] = len(body) if isinstance(body, list) else 1
        if not item.get("command", "").startswith("gcloud"):
            item["pages"] = 1
    else:
        item["error_file"] = f"{item['domain']}/{dataset}.stderr.txt"
        path = directory / item["error_file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Synthetic {status}; no configuration values")


def records(i: int) -> dict:
    """dataset -> (status, body) for project index i."""
    pid, num = project(i), number(i)
    app = f"app@{pid}.iam.gserviceaccount.com"
    default_sa = f"{num}-compute@developer.gserviceaccount.com"
    other = f"ci@{project((i + 1) % 41)}.iam.gserviceaccount.com"
    bindings = [
        {"role": "roles/owner", "members": ["user:admin@example.com"]},
        {"role": "roles/editor", "members": [f"serviceAccount:{default_sa}"]},
        {"role": "roles/viewer", "members": ["group:auditors@example.com"]},
    ]
    if i % 4 == 0:
        bindings.append({"role": "roles/editor", "members": [f"serviceAccount:{app}"]})
    if i % 6 == 1:
        bindings.append(
            {"role": "roles/iam.serviceAccountTokenCreator", "members": ["group:devs@example.com"]}
        )
    if i % 7 == 2:
        bindings.append({"role": "roles/editor", "members": [f"serviceAccount:{other}"]})
    if i % 9 == 3:
        bindings.append(
            {
                "role": "roles/editor",
                "members": ["user:contractor@example.com"],
                "condition": {
                    "title": "temporary",
                    "expression": 'request.time < timestamp("2027-01-01T00:00:00Z")',
                },
            }
        )
    if i == 4:
        bindings.append({"role": "roles/storage.admin", "members": ["allUsers"]})
    audit = {
        0: [
            {
                "service": "allServices",
                "auditLogConfigs": [
                    {"logType": "ADMIN_READ"},
                    {"logType": "DATA_READ"},
                    {"logType": "DATA_WRITE"},
                ],
            }
        ],
        1: [
            {
                "service": "allServices",
                "auditLogConfigs": [
                    {"logType": "DATA_READ", "exemptedMembers": ["user:batch@example.com"]},
                    {"logType": "DATA_WRITE"},
                ],
            }
        ],
        2: [{"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}],
    }.get(i % 4)
    policy = {"bindings": bindings, "etag": "BwX", "version": 3}
    if audit:
        policy["auditConfigs"] = audit
    key_time = "2020-01-01T00:00:00Z" if i % 3 == 0 else "2026-09-01T00:00:00Z"
    keys = [
        {
            "name": f"projects/{pid}/serviceAccounts/{app}/keys/{i:04d}a",
            "keyType": "SYSTEM_MANAGED",
            "validAfterTime": "2026-01-01T00:00:00Z",
        }
    ]
    if i % 2 == 0:
        keys.append(
            {
                "name": f"projects/{pid}/serviceAccounts/{app}/keys/{i:04d}b",
                "keyType": "USER_MANAGED",
                "validAfterTime": key_time,
                "disabled": False,
            }
        )
    api_key = {"name": f"projects/{num}/locations/global/keys/key-{i:02d}", "uid": f"uid-{i:02d}"}
    variants = [
        {
            "restrictions": {
                "browserKeyRestrictions": {"allowedReferrers": ["https://app.example.com/*"]},
                "apiTargets": [{"service": "maps.googleapis.com"}],
            }
        },
        {"restrictions": {"apiTargets": [{"service": "translate.googleapis.com"}]}},
        {},  # unrestricted: the API omits `restrictions`
    ]
    api_keys = [{**api_key, **variants[i % 3]}]
    api_status = "API_DISABLED" if i % 5 == 4 else "EMPTY" if i % 5 == 3 else "SUCCESS"
    instances = [
        {
            "name": f"vm-{i:02d}-web",
            "zone": f"projects/{pid}/zones/us-central1-a",
            "status": "RUNNING",
            "networkInterfaces": [
                {
                    "network": f"projects/{pid}/global/networks/vpc-{i:02d}",
                    "accessConfigs": [{"natIP": f"203.0.113.{i + 1}"}],
                }
            ],
            "serviceAccounts": [
                {"email": default_sa, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}
            ],
            "metadata": {"items": [{"key": "enable-oslogin", "value": "true"}]},
            "shieldedInstanceConfig": {
                "enableSecureBoot": True,
                "enableVtpm": True,
                "enableIntegrityMonitoring": True,
            },
            "canIpForward": False,
            "tags": {"items": ["web"]},
        },
        {
            "name": f"vm-{i:02d}-batch",
            "zone": f"projects/{pid}/zones/us-central1-b",
            "status": "RUNNING",
            # No external access: the API omits accessConfigs; no service account attached.
            "networkInterfaces": [{"network": f"projects/{pid}/global/networks/vpc-{i:02d}"}],
            "shieldedInstanceConfig": {
                "enableSecureBoot": False,
                "enableVtpm": True,
                "enableIntegrityMonitoring": True,
            },
            "canIpForward": i % 4 == 0,
        },
    ]
    firewalls = [
        {
            "name": f"allow-internal-{i:02d}",
            "network": f"projects/{pid}/global/networks/vpc-{i:02d}",
            "direction": "INGRESS",
            "priority": 1000,
            "sourceRanges": ["10.0.0.0/8"],
            "allowed": [{"IPProtocol": "all"}],
        }
    ]
    if i % 3 == 0:
        firewalls.append(
            {
                "name": f"allow-ssh-{i:02d}",
                "network": f"projects/{pid}/global/networks/vpc-{i:02d}",
                "direction": "INGRESS",
                "priority": 1000,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "targetTags": ["web"],
            }
        )
    subnet = {
        "name": f"subnet-{i:02d}",
        "region": "us-central1",
        "network": f"projects/{pid}/global/networks/vpc-{i:02d}",
        "ipCidrRange": "10.10.0.0/24",
        "privateIpGoogleAccess": i % 2 == 0,
    }
    if i % 3 != 2:
        subnet["logConfig"] = {"enable": i % 3 == 0}
    bucket = {
        "name": f"{pid}-data",
        "uniform_bucket_level_access": i % 4 != 1,
        "public_access_prevention": "enforced" if i % 2 == 0 else "inherited",
    }
    if i % 3 == 0:
        bucket["versioning_enabled"] = True
    sql = [
        {
            "name": f"db-{i:02d}",
            "instanceType": "CLOUD_SQL_INSTANCE",
            "settings": {
                "ipConfiguration": {"ipv4Enabled": True, "sslMode": "ENCRYPTED_ONLY"}
                if i % 2 == 0
                else {"ipv4Enabled": False, "requireSsl": True},
                "backupConfiguration": {"enabled": i % 4 != 2},
            },
        }
    ]
    kms = [
        {
            "name": f"projects/{pid}/locations/global/keyRings/ring/cryptoKeys/rotated",
            "purpose": "ENCRYPT_DECRYPT",
            "rotationPeriod": "7776000s",
            "nextRotationTime": "2026-12-01T00:00:00Z",
        },
        # No automatic rotation: the API omits rotationPeriod and nextRotationTime.
        {
            "name": f"projects/{pid}/locations/global/keyRings/ring/cryptoKeys/static",
            "purpose": "ENCRYPT_DECRYPT",
        },
    ]
    exclusions = (
        [{"name": "drop-data-access", "filter": 'log_id("cloudaudit.googleapis.com/data_access")'}]
        if i % 8 == 0
        else [{"name": "drop-debug", "filter": 'resource.type="gce_instance" AND severity<WARNING'}]
        if i % 8 == 1
        else []
    )
    org_policy = {
        "bindings": [
            {
                "role": "roles/resourcemanager.organizationAdmin",
                "members": ["group:org-admins@example.com"],
            }
        ]
    }
    if i == 10:  # one inherited Data Access exemption
        org_policy["auditConfigs"] = [
            {
                "service": "allServices",
                "auditLogConfigs": [
                    {"logType": "DATA_READ", "exemptedMembers": ["serviceAccount:scan@example.com"]}
                ],
            }
        ]
    folder_policy = {
        "bindings": [{"role": "roles/viewer", "members": ["group:auditors@example.com"]}]
    }
    search = [
        {
            "resource": f"//cloudresourcemanager.googleapis.com/projects/{pid}",
            "assetType": "cloudresourcemanager.googleapis.com/Project",
            "project": f"projects/{num}",
            "policy": {"bindings": bindings},
        }
    ]
    return {
        "project": (
            "SUCCESS",
            {"projectId": pid, "projectNumber": num, "lifecycleState": "ACTIVE"},
        ),
        "project_iam": ("SUCCESS", policy),
        "service_accounts": (
            "SUCCESS",
            [
                {
                    "email": app,
                    "uniqueId": f"{NUMBER_BASE + 1000 + i}",
                    "name": f"projects/{pid}/serviceAccounts/{app}",
                },
                {
                    "email": default_sa,
                    "uniqueId": f"{NUMBER_BASE + 2000 + i}",
                    "name": f"projects/{pid}/serviceAccounts/{default_sa}",
                },
            ],
        ),
        "sa_keys_1": ("SUCCESS", keys),
        "api_keys": (api_status, api_keys),
        "api_keys_rest": (api_status, api_keys),
        "instances": ("TRUNCATED" if i == 40 else "SUCCESS", instances),
        "firewall_rules": ("SUCCESS", firewalls),
        "vpcs": ("SUCCESS", [{"name": "default" if i % 4 == 0 else f"vpc-{i:02d}"}]),
        "subnets": ("SUCCESS", [subnet]),
        "buckets": ("SUCCESS", [bucket]),
        "cloud_sql": ("SUCCESS" if i % 3 == 0 else "API_DISABLED", sql),
        "kms_keys_1_1": ("SUCCESS" if i % 2 == 1 else "API_DISABLED", kms),
        "exclusions": ("SUCCESS" if exclusions else "EMPTY", exclusions),
        "buckets_global": (
            "SUCCESS",
            [
                {
                    "name": f"projects/{pid}/locations/global/buckets/_Required",
                    "retentionDays": 400,
                },
                {"name": f"projects/{pid}/locations/global/buckets/_Default", "retentionDays": 30},
            ],
        ),
        "scc_findings": ("ACCESS_DENIED" if i % 4 else "API_DISABLED", None),
        "scc_findings_rest": ("ACCESS_DENIED" if i % 4 else "API_DISABLED", None),
        # User credentials without a quota project: Cloud Asset is refused on most projects.
        "asset_iam_search": ("QUOTA_PROJECT_DENIED" if i % 4 else "SUCCESS", search),
        "folder_123_iam_search": ("ACCESS_DENIED", None),
        "organization_123_iam_search": ("ACCESS_DENIED", None),
        # parent_* and the per-ancestor datasets are the same two policies (one snapshot).
        "parent_org_iam": ("ACCESS_DENIED" if i % 3 == 0 else "SUCCESS", org_policy),
        "parent_folder_iam": ("SUCCESS", folder_policy),
        "organization_123_iam": ("SUCCESS" if i % 5 == 0 else "ACCESS_DENIED", org_policy),
        "folder_123_iam": ("SUCCESS" if i % 5 == 0 else "ACCESS_DENIED", folder_policy),
        "sinks": (
            "TIMEOUT" if i == 39 else "SUCCESS",
            [{"name": "_Default", "destination": "logging.googleapis.com"}],
        ),
        # Per-resource details mirror the list records (the same snapshot of the same resource).
        "bucket_details_1": ("SUCCESS", bucket),
        "bucket_iam_1": (
            "SUCCESS",
            {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"] if i == 7 else ["group:auditors@example.com"],
                    }
                ]
            },
        ),
        "sa_iam_1": ("SUCCESS", {"bindings": []}),
        "api_key_detail_1": (
            (api_status, api_keys[0]) if api_status != "EMPTY" else ("ABSENT", None)
        ),
    }


def build_project(directory: Path, index: int, template: Path) -> Path:
    shutil.copytree(template, directory)
    pid, num = project(index), number(index)
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".txt"}:
            text = path.read_text(encoding="utf-8", errors="strict") if path.stat().st_size else ""
            if BASE in text or BASE_NUMBER in text:
                path.write_text(text.replace(BASE, pid).replace(BASE_NUMBER, num))
    manifest = _manifest(directory)
    manifest.update(
        project_id=pid, project_name=f"Synthetic project {index:02d}", collector_version="2.2.7"
    )
    commands = {
        "parent_org_iam": "gcloud organizations get-iam-policy 123 --format=json",
        "parent_folder_iam": "gcloud resource-manager folders get-iam-policy 123 --format=json",
        "bucket_iam_1": f"gcloud storage buckets get-iam-policy gs://{pid}-data --format=json",
        "sa_iam_1": "gcloud iam service-accounts get-iam-policy "
        f"app@{pid}.iam.gserviceaccount.com --format=json",
    }
    for item in manifest["datasets"]:
        if item["dataset"] in commands:
            item["command"] = commands[item["dataset"]]
    for dataset, (status, body) in records(index).items():
        set_dataset(directory, manifest, dataset, status, body)
    # Effective organization policies, one dataset per constraint as the collector writes them
    # (gcloud org-policies describe <constraint> --effective; v2 policy shape).
    template_item = next(d for d in manifest["datasets"] if d["dataset"] == "effective_policy_1")
    for n, (constraint, enforce) in enumerate(
        (
            ("iam.disableServiceAccountKeyCreation", index % 3 != 0),
            ("iam.disableServiceAccountKeyUpload", index % 3 == 1),
            ("storage.publicAccessPrevention", index % 2 == 0),
        ),
        1,
    ):
        name = f"effective_policy_{n}"
        if not any(d["dataset"] == name for d in manifest["datasets"]):
            manifest["datasets"].append(
                {**template_item, "dataset": name, "file": None, "error_file": None}
            )
        item = next(d for d in manifest["datasets"] if d["dataset"] == name)
        item["command"] = (
            f"gcloud org-policies describe {constraint} --effective --project={pid} --format=json"
        )
        set_dataset(
            directory,
            manifest,
            name,
            "SUCCESS",
            {
                "name": f"projects/{num}/policies/{constraint}",
                "spec": {"rules": [{"enforce": enforce}]},
            },
        )
    _write_manifest(directory, manifest)
    return checksums(directory)


def checksums(directory: Path) -> Path:
    """Rewrite checksums.sha256 after edits (the collector's integrity file)."""
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(directory).as_posix()}"
        for path in sorted(
            p for p in directory.rglob("*") if p.is_file() and p.name != "checksums.sha256"
        )
    ]
    (directory / "checksums.sha256").write_text("\n".join(lines) + "\n")
    return directory


def edit(directory: Path, changes: dict, **manifest_fields) -> Path:
    """Apply {dataset: (status, body)} and manifest field changes to a built package."""
    manifest = _manifest(directory)
    manifest.update(manifest_fields)
    for dataset, (status, body) in changes.items():
        set_dataset(directory, manifest, dataset, status, body)
    _write_manifest(directory, manifest)
    return checksums(directory)


def estate(output: Path, projects: int = 41) -> list[Path]:
    if not 1 <= projects <= 41:
        raise ValueError("projects must be 1..41")
    output.mkdir(parents=True, exist_ok=False)
    template = expanded22(output / "_template")
    built = [build_project(output / project(i), i, template) for i in range(projects)]
    shutil.rmtree(output / "_template")
    return built


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--projects", type=int, default=41)
    args = parser.parse_args()
    print(json.dumps([str(p) for p in estate(args.output, args.projects)], indent=1))


if __name__ == "__main__":
    main()
