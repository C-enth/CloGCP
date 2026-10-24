"""Complete collector-2.2.8-shaped synthetic packages; no customer-derived values."""

import hashlib
import json
from pathlib import Path

from offline_analyzer.contracts.gcp_expanded_catalog import DATASETS, EXTENSIONS_22
from tools.fixtures.gcp_expanded import example_name

TIME = "2026-10-23T00:00:00Z"


def build(directory: Path, index: int = 0, *, secure: bool = False, instances: int = 8) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    project, number = f"synth-clogcp-{index:02d}", str(900000000000 + index)
    runtime = f"worker@{project}.iam.gserviceaccount.com"
    network = f"projects/{project}/global/networks/shared"
    run = f"projects/{project}/locations/us-central1/services/api"
    function = f"projects/{project}/locations/us-central1/functions/api"
    role = f"projects/{project}/roles/dataReader"
    basic = "roles/viewer" if secure else "roles/editor"
    policy = {
        "bindings": [
            {"role": basic, "members": ["serviceAccount:" + runtime]},
            {
                "role": "roles/editor",
                "members": [f"serviceAccount:{number}@cloudservices.gserviceaccount.com"],
            },
            {
                "role": basic,
                "members": [f"serviceAccount:{number}-compute@developer.gserviceaccount.com"],
            },
            {"role": role, "members": ["user:auditor@example.com" if secure else "allUsers"]},
        ],
        "auditConfigs": [
            {
                "service": "allServices",
                "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}],
            }
        ],
    }
    bucket = {
        "name": f"synth-clogcp-bucket-{index}",
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": secure},
            "publicAccessPrevention": "enforced" if secure else "inherited",
        },
        "versioning": {"enabled": secure},
    }
    sql = {
        "name": "database",
        "databaseVersion": "MYSQL_8_0",
        "instanceType": "CLOUD_SQL_INSTANCE",
        "settings": {
            "ipConfiguration": {
                "ipv4Enabled": not secure,
                "authorizedNetworks": [] if secure else [{"value": "0.0.0.0/0"}],
                "sslMode": "ENCRYPTED_ONLY" if secure else "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
            },
            "backupConfiguration": {"enabled": secure},
            "databaseFlags": [{"name": "local_infile", "value": "off" if secure else "on"}],
        },
    }
    cluster = {
        "name": f"projects/{project}/locations/us-central1/clusters/cluster",
        "location": "us-central1",
        "autopilot": {"enabled": False},
        "privateClusterConfig": {"enablePrivateEndpoint": secure, "enablePrivateNodes": secure},
        "masterAuthorizedNetworksConfig": {
            "enabled": secure,
            "cidrBlocks": [] if not secure else [{"cidrBlock": "192.0.2.0/24"}],
        },
        "legacyAbac": {"enabled": not secure},
        "workloadIdentityConfig": {"workloadPool": project + ".svc.id.goog"} if secure else {},
        "networkPolicy": {"enabled": secure},
        "shieldedNodes": {"enabled": secure},
        "masterAuth": {"clientCertificateConfig": {"issueClientCertificate": not secure}},
        "databaseEncryption": {"state": "ENCRYPTED" if secure else "DECRYPTED"},
    }
    ssl = f"projects/{project}/global/sslPolicies/policy"
    proxy = f"projects/{project}/global/targetHttpsProxies/proxy"
    vms = []
    for i in range(instances):
        vms.append(
            {
                "name": f"projects/{project}/zones/us-central1-a/instances/vm-{i}",
                "zone": "us-central1-a",
                "status": "RUNNING",
                "networkInterfaces": [
                    {
                        "network": network,
                        "accessConfigs": [] if secure else [{"natIP": f"192.0.2.{i % 200 + 1}"}],
                    }
                ],
                "serviceAccounts": [
                    {
                        "email": runtime
                        if secure
                        else f"{number}-compute@developer.gserviceaccount.com",
                        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    }
                ],
                "metadata": {
                    "items": [
                        {"key": "enable-oslogin", "value": str(secure).lower()},
                        {"key": "serial-port-enable", "value": str(not secure).lower()},
                        {"key": "block-project-ssh-keys", "value": str(secure).lower()},
                    ]
                },
                "shieldedInstanceConfig": {
                    "enableSecureBoot": secure,
                    "enableVtpm": True,
                    "enableIntegrityMonitoring": True,
                },
                "canIpForward": False,
            }
        )
    bodies = {
        "project": {"projectId": project, "projectNumber": number},
        "project_iam": policy,
        "parent_org_iam": {"bindings": []},
        "parent_folder_iam": {"bindings": []},
        "folder_iam": {"bindings": []},
        "organization_iam": {"bindings": []},
        "service_accounts": [
            {
                "name": f"projects/{project}/serviceAccounts/{runtime}",
                "email": runtime,
                "uniqueId": str(100000 + index),
            }
        ],
        "custom_roles": [{"name": role, "includedPermissions": ["bigquery.tables.getData"]}],
        "custom_role_detail": {"name": role, "includedPermissions": ["bigquery.tables.getData"]},
        "api_keys": [
            {
                "name": f"projects/{project}/locations/global/keys/key",
                "restrictions": {
                    "serverKeyRestrictions": {"allowedIps": ["192.0.2.0/24"]},
                    "apiTargets": [{"service": "example.googleapis.com"}],
                }
                if secure
                else {},
            }
        ],
        "vpcs": [{"name": "private" if secure else "default", "selfLink": network}],
        "subnets": [
            {
                "name": f"projects/{project}/regions/us-central1/subnetworks/subnet",
                "purpose": "PRIVATE",
                "privateIpGoogleAccess": secure,
                "logConfig": {"enable": secure},
            }
        ],
        "firewall_rules": [
            {
                "name": "administration",
                "network": network,
                "priority": 1000,
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["192.0.2.0/24"] if secure else ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
        ],
        "instances": vms,
        "buckets": [bucket],
        "bucket_details": bucket,
        "bucket_iam": {
            "bindings": []
            if secure
            else [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
        },
        "cloud_sql": [sql],
        "sql_instances_rest": [sql],
        "gke_clusters": [cluster],
        "gke_clusters_rest": [cluster],
        "gke_node_pools": [
            {"name": cluster["name"] + "/nodePools/pool", "config": {"serviceAccount": runtime}}
        ],
        "cloud_run": [
            {
                "apiVersion": "serving.knative.dev/v1",
                "kind": "Service",
                "metadata": {
                    "name": "api",
                    "namespace": number,
                    "labels": {"cloud.googleapis.com/location": "us-central1"},
                    "annotations": {
                        "run.googleapis.com/ingress": "internal" if secure else "all",
                        "run.googleapis.com/invoker-iam-disabled": str(not secure).lower(),
                    },
                },
                "spec": {"template": {"spec": {"serviceAccountName": runtime}}},
            }
        ],
        "run_services_rest": [
            {
                "name": run,
                "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY" if secure else "INGRESS_TRAFFIC_ALL",
                "invokerIamDisabled": not secure,
                "template": {"serviceAccount": runtime},
            }
        ],
        "functions": [
            {
                "name": function,
                "environment": "GEN_1",
                "serviceConfig": {
                    "ingressSettings": "ALLOW_INTERNAL_ONLY" if secure else "ALLOW_ALL",
                    "serviceAccountEmail": runtime,
                },
            }
        ],
        "functions_rest": [
            {
                "name": function,
                "environment": "GEN_1",
                "serviceConfig": {
                    "ingressSettings": "ALLOW_INTERNAL_ONLY" if secure else "ALLOW_ALL",
                    "serviceAccountEmail": runtime,
                },
            }
        ],
        "run_iam": {
            "bindings": [] if secure else [{"role": "roles/run.invoker", "members": ["allUsers"]}]
        },
        "function_iam": {
            "bindings": []
            if secure
            else [{"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}]
        },
        "bigquery_datasets_rest": [
            {"datasetReference": {"projectId": project, "datasetId": "dataset"}}
        ],
        "bq_dataset_details": {
            "datasetReference": {"projectId": project, "datasetId": "dataset"},
            "access": [
                {"role": "READER", "specialGroup": "projectReaders" if secure else "allUsers"}
            ],
        },
        "dns_managed_zones": [
            {
                "name": "zone",
                "visibility": "public",
                "dnssecConfig": {"state": "on" if secure else "off"},
            }
        ],
        "ssl_policies": [
            {"name": "policy", "selfLink": ssl, "minTlsVersion": "TLS_1_2" if secure else "TLS_1_0"}
        ],
        "forwarding_rules": [
            {"name": "frontend", "loadBalancingScheme": "EXTERNAL_MANAGED", "target": proxy}
        ],
        "asset_resource_list": [
            {
                "name": "//compute.googleapis.com/" + proxy,
                "assetType": "compute.googleapis.com/TargetHttpsProxy",
                "resource": {"data": {"selfLink": proxy, "sslPolicy": ssl}},
            }
        ],
        "backend_services": [
            {
                "name": "backend",
                "loadBalancingScheme": "EXTERNAL_MANAGED",
                "protocol": "HTTPS",
                "securityPolicy": "armor" if secure else "",
                "logConfig": {"enable": secure},
            }
        ],
        "effective_policy": {
            "name": f"projects/{project}/policies/compute.requireOsLogin",
            "spec": {"rules": [{"enforce": secure}]},
        },
        "workload_pool_providers": [
            {
                "name": (
                    f"projects/{project}/locations/global/"
                    "workloadIdentityPools/pool/providers/provider"
                ),
                "disabled": False,
                "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                "attributeCondition": "assertion.repository_owner_id=='123'" if secure else "",
            }
        ],
        "alert_policies": [{"name": f"projects/{project}/alertPolicies/alert", "enabled": secure}],
        "sinks": [
            {
                "name": "central-routing",
                "destination": (
                    "logging.googleapis.com/projects/synth-central/locations/global/buckets"
                    "/security"
                ),
                "disabled": False,
                "filter": "",
            }
        ],
        "secrets": [
            {"name": f"projects/{project}/secrets/config", "replication": {"automatic": {}}}
        ],
        "secrets_rest": [
            {"name": f"projects/{project}/secrets/config", "replication": {"automatic": {}}}
        ],
        "artifact_repositories": [
            {
                "name": f"projects/{project}/locations/us-central1/repositories/images",
                "format": "DOCKER",
                "dockerConfig": {"immutableTags": secure},
            }
        ],
        "artifact_repositories_rest": [
            {
                "name": f"projects/{project}/locations/us-central1/repositories/images",
                "format": "DOCKER",
                "dockerConfig": {"immutableTags": secure},
            }
        ],
        "cloudbuild_triggers": [
            {
                "name": f"projects/{project}/locations/global/triggers/trigger",
                "approvalConfig": {"approvalRequired": secure},
            }
        ],
        "cloudbuild_triggers_rest": [
            {
                "name": f"projects/{project}/locations/global/triggers/trigger",
                "approvalConfig": {"approvalRequired": secure},
            }
        ],
    }
    bodies["api_key_detail"] = bodies["api_keys"][0]
    bodies["sa_iam"] = {"bindings": []}
    bodies["sa_keys"] = [
        {
            "name": f"projects/{project}/serviceAccounts/{runtime}/keys/key",
            "keyType": "USER_MANAGED",
            "disabled": secure,
            "validAfterTime": "2020-01-01T00:00:00Z",
        }
    ]
    bodies["kms_keys"] = [
        {
            "name": f"projects/{project}/locations/us-central1/keyRings/ring/cryptoKeys/key",
            "purpose": "ENCRYPT_DECRYPT",
            "rotationPeriod": "7776000s" if secure else "31536000s",
        }
    ]
    bodies["firewall_policies"] = [
        {
            "name": "policy",
            "rules": []
            if secure
            else [
                {
                    "priority": 1000,
                    "action": "allow",
                    "direction": "INGRESS",
                    "disabled": False,
                    "match": {
                        "srcIpRanges": ["0.0.0.0/0"],
                        "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}],
                    },
                }
            ],
        }
    ]
    singletons = {
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
    datasets = []
    for row in DATASETS + EXTENSIONS_22:
        family = row["family"]
        name = example_name(row)
        body = bodies.get(family, {} if family in singletons else [])
        command = "gcloud synthetic read-only --format=json"
        commands = {
            "sa_iam": (
                f"gcloud iam service-accounts get-iam-policy {runtime} --project={project} "
                f"--format=json"
            ),
            "run_iam": (
                f"gcloud run services get-iam-policy api --region=us-central1 --project={project} "
                f"--format=json"
            ),
            "function_iam": (
                f"gcloud functions get-iam-policy api --region=us-central1 --project={project} "
                f"--format=json"
            ),
            "bucket_iam": (
                f"gcloud storage buckets get-iam-policy gs://synth-clogcp-bucket-{index} "
                f"--format=json"
            ),
            "parent_org_iam": "gcloud organizations get-iam-policy 123 --format=json",
            "organization_iam": "gcloud organizations get-iam-policy 123 --format=json",
            "parent_folder_iam": "gcloud resource-manager folders get-iam-policy 123 --format=json",
            "folder_iam": "gcloud resource-manager folders get-iam-policy 123 --format=json",
            "effective_policy": (
                f"gcloud org-policies describe compute.requireOsLogin --effective "
                f"--project={project} --format=json"
            ),
            "gke_node_pools": f"GET https://container.googleapis.com/v1/{cluster['name']}/nodePools",
        }
        command = commands.get(family, command)
        if row["method"] != "Run" and not isinstance(body, list):
            body = [body] if body else []
        path = f"{row['domain']}/{name}.json"
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(body))
        count = len(body) if isinstance(body, list) else 1
        datasets.append(
            dict(
                domain=row["domain"],
                dataset=name,
                status="SUCCESS" if count else "EMPTY",
                record_count=count,
                exit_code=0 if row["method"] == "Run" else None,
                required_api=row["required_api_expression"].strip("'"),
                started_utc=TIME,
                finished_utc=TIME,
                file=path,
                error_file=None,
                command=command,
                **({"pages": 1} if row["method"] != "Run" else {}),
            )
        )
    # Dynamic effective-policy datasets cover independent constraints, not invented defaults.
    for j, constraint in enumerate(
        (
            "iam.disableServiceAccountKeyCreation",
            "iam.disableServiceAccountKeyUpload",
            "storage.publicAccessPrevention",
            "compute.disableSerialPortAccess",
        ),
        start=2,
    ):
        row = next(d for d in datasets if d["dataset"] == "effective_policy_1")
        item = {
            **row,
            "dataset": f"effective_policy_{j}",
            "file": f"governance/effective_policy_{j}.json",
            "command": (
                f"gcloud org-policies describe {constraint} --effective --project={project} "
                f"--format=json"
            ),
        }
        body = {
            "name": f"projects/{project}/policies/{constraint}",
            "spec": {"rules": [{"enforce": secure}]},
        }
        target = directory / item["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(body))
        datasets.append(item)
    manifest = dict(
        schema_version="assessment-expanded-2.2",
        collector="GCP_Security_Evidence_Collector.ps1",
        collector_version="2.2.8",
        project_id=project,
        project_name="Synthetic CloGCP",
        collected_utc=TIME,
        scope="project",
        collection_status="COMPLETE",
        quota_project=None,
        command_timeout_seconds=300,
        http_max_retries=3,
        page_hard_cap=2000,
        limitations=["Synthetic evidence; not a production assessment"],
        max_detail_items=0,
        max_api_pages=0,
        enabled_api_count=0,
        discovered_asset_types=[],
        discovery_engine_detail_limit_reached=False,
        bigquery_dataset_detail_limit_reached=False,
        datasets=datasets,
        dataset_origin="synthetic",
    )
    (directory / "collection_manifest.json").write_text(json.dumps(manifest))
    (directory / "discovered_asset_types.json").write_text("[]")
    checksums(directory)
    return directory


def checksums(directory: Path):
    lines = []
    for p in sorted(directory.rglob("*")):
        if p.is_file() and p.name != "checksums.sha256":
            lines.append(
                hashlib.sha256(p.read_bytes()).hexdigest()
                + "  "
                + p.relative_to(directory).as_posix()
            )
    (directory / "checksums.sha256").write_text("\n".join(lines) + "\n")
