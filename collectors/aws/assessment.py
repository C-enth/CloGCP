#!/usr/bin/env python3
"""CloSec v0.3 AWS security evidence collector. Read-only, one account per immutable run.
Requires boto3/botocore. No AWS credentials persisted. Native page JSON retained.

0.3.1 corrections (journal schema closec-provisional-0.3 unchanged, fields only added):
CloudTrail GetEventSelectors uses TrailName; IAM policy-version enrichment runs in the
global phase and only for documents missing from authorization details; responses that
still carry pagination tokens are PARTIAL; WAFv2 NextMarker listings are followed;
AWS-defined absence codes are NOT_ENABLED; Prowler exit code 3 (FAIL checks) is a
completed scan; `resource` is optional so the collector also starts on Windows;
bounded per-operation pages; Organizations parent/SCP attempts; interrupted runs finalize.
"""

import argparse, base64, datetime, hashlib, json, os, pathlib, re, shutil, subprocess, sys, time, uuid, zipfile

try:
    import resource  # POSIX only; peak RSS is informational.
except ImportError:  # pragma: no cover - Windows
    resource = None
from collections import Counter
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

VERSION = "0.3.2"
UTC = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
CONFIG = Config(
    retries={"max_attempts": 4, "mode": "standard"}, connect_timeout=10, read_timeout=60
)
MAX_PAGES = 5000  # Per-operation page bound; reaching it is recorded as PARTIAL, never COMPLETE.
TOKENS = (
    "NextToken",
    "nextToken",
    "Marker",
    "NextMarker",
    "NextContinuationToken",
    "NextPageToken",
    "PaginationToken",
)
# Non-paginatable operations whose responses carry a continuation marker: (input, output).
MANUAL_PAGINATION = {("wafv2", "list_web_acls"): ("NextMarker", "NextMarker")}
# Operation registry: service, operation, scope, pagination/discovery handled by executor.
GLOBAL = {
    "iam": [
        "get_account_authorization_details",
        "get_account_summary",
        "list_instance_profiles",
        "get_account_password_policy",
        "list_users",
        "list_roles",
        "list_groups",
        "list_policies",
        "list_virtual_mfa_devices",
        "list_saml_providers",
        "list_open_id_connect_providers",
        "list_account_aliases",
    ],
    "s3": ["list_buckets"],
    "s3control": ["get_public_access_block"],
    "cloudfront": ["list_distributions"],
    "route53": ["list_hosted_zones"],
    "organizations": ["describe_organization", "list_roots"],
}
REGIONAL = {
    "ec2": [
        "describe_iam_instance_profile_associations",
        "describe_vpcs",
        "describe_subnets",
        "describe_route_tables",
        "describe_security_groups",
        "describe_security_group_rules",
        "describe_network_acls",
        "describe_instances",
        "describe_network_interfaces",
        "describe_addresses",
        "describe_internet_gateways",
        "describe_nat_gateways",
        "describe_egress_only_internet_gateways",
        "describe_vpc_peering_connections",
        "describe_vpc_endpoints",
        "describe_transit_gateways",
        "describe_transit_gateway_attachments",
        "describe_transit_gateway_route_tables",
        "describe_flow_logs",
        "describe_vpn_connections",
        "describe_vpn_gateways",
        "describe_customer_gateways",
        "describe_transit_gateway_vpc_attachments",
        "describe_prefix_lists",
        "describe_managed_prefix_lists",
    ],
    "rds": [
        "describe_db_instances",
        "describe_db_clusters",
        "describe_db_subnet_groups",
        "describe_db_snapshots",
        "describe_db_cluster_snapshots",
        "describe_db_parameter_groups",
        "describe_db_cluster_parameter_groups",
        "describe_db_proxies",
    ],
    "kms": ["list_keys", "list_aliases"],
    "cloudtrail": ["describe_trails", "list_trails"],
    "config": [
        "describe_configuration_recorders",
        "describe_configuration_recorder_status",
        "describe_delivery_channels",
        "describe_config_rules",
        "describe_aggregation_authorizations",
        "describe_configuration_aggregators",
    ],
    "guardduty": ["list_detectors"],
    "securityhub": ["describe_hub", "get_enabled_standards", "get_findings"],
    "accessanalyzer": ["list_analyzers"],
    "elbv2": ["describe_load_balancers", "describe_target_groups"],
    "lambda": ["list_functions", "list_layers", "list_event_source_mappings"],
    "ecs": ["list_clusters"],
    "eks": ["list_clusters"],
    "ecr": ["describe_repositories"],
    "dynamodb": ["list_tables"],
    "efs": ["describe_file_systems"],
    "fsx": ["describe_file_systems"],
    "secretsmanager": ["list_secrets"],
    "logs": ["describe_log_groups"],
    "cloudwatch": ["describe_alarms"],
    "events": ["list_rules"],
    "wafv2": ["list_web_acls"],
    "network-firewall": ["list_firewalls", "list_firewall_policies", "list_rule_groups"],
    "inspector2": ["list_findings"],
    "macie2": ["get_macie_session"],
    "apigateway": ["get_rest_apis"],
    "apigatewayv2": ["get_apis"],
    "resourcegroupstaggingapi": ["get_resources"],
    "resource-explorer-2": ["list_indexes"],
    "ram": ["list_resources"],
    "ssm": ["describe_instance_information"],
    "route53resolver": ["list_resolver_endpoints", "list_resolver_rules"],
}
# Extra per-resource calls: discovery inventory is prerequisite, never guess identifiers.
DEPENDENT = {
    "s3": [
        "get_bucket_location",
        "get_public_access_block",
        "get_bucket_policy",
        "get_bucket_policy_status",
        "get_bucket_encryption",
        "get_bucket_versioning",
        "get_bucket_logging",
        "get_bucket_acl",
        "get_bucket_ownership_controls",
        "get_bucket_replication",
        "get_bucket_lifecycle_configuration",
        "get_bucket_notification_configuration",
        "get_bucket_website",
        "get_bucket_cors",
        "get_bucket_tagging",
    ],
    "kms": [
        "describe_key",
        "get_key_policy",
        "get_key_rotation_status",
        "list_grants",
        "list_key_policies",
    ],
    "cloudtrail": ["get_trail_status", "get_event_selectors"],
    "guardduty": ["get_detector"],
    "lambda": ["get_policy"],
}
NOT_CONFIGURED = {
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchBucket",
    "NoSuchEntity",
    "NoSuchEntityException",
    "NoSuchConfigurationRecorderException",
    "NoSuchDeliveryChannelException",
    "ResourceNotFoundException",
    "InvalidAccessException",
    "NoSuchLifecycleConfiguration",
    "NoSuchReplicationConfiguration",
    "NoSuchTagSet",
    "OwnershipControlsNotFoundError",
    "NoSuchCORSConfiguration",
    "NoSuchWebsiteConfiguration",
    "NoSuchBucketEncryption",
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicyStatus",
    "InvalidAccessException",
    "ResourceNotFoundException",
    "ResourceNotFound",
    "NoSuchConfigurationAggregatorException",
    "ReplicationConfigurationNotFoundError",
    "AWSOrganizationsNotInUseException",
    "NoSuchBucketEncryption",
}
# NoSuchBucket is a deletion race, not an absent configuration.
NOT_CONFIGURED.discard("NoSuchBucket")
DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "UnauthorizedException",
    "AccessDeniedFault",
    "Forbidden",
    "UnrecognizedClientException",
}


def clean(obj):
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items() if k != "ResponseMetadata"}
    if isinstance(obj, list):
        return [clean(x) for x in obj]
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return {"__binary_base64__": base64.b64encode(obj).decode("ascii")}
    return obj


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(clean(obj), f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")
    temp.replace(path)


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def outcome(exc):
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in DENIED or "AccessDenied" in code:
            return "ACCESS_DENIED", code
        if code in NOT_CONFIGURED:
            return "NOT_ENABLED", code
        return "API_ERROR", code
    name = type(exc).__name__
    if name in ("EndpointConnectionError", "UnknownEndpointError", "UnknownRegionError"):
        return "API_ERROR", "ENDPOINT_UNAVAILABLE"
    if name == "ParamValidationError":
        return "API_ERROR", "COLLECTOR_PARAMETER_ERROR"
    if name in ("ConnectTimeoutError", "ReadTimeoutError"):
        return "API_ERROR", "TIMEOUT"
    return "API_ERROR", name


def residual_token(payload):
    if payload.get("IsTruncated") is True:
        return "IsTruncated"
    return next((k for k in TOKENS if payload.get(k)), None)


def record(root, rec):
    with (root / "operations.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def safe_segment(value):
    return re.sub(r"[^A-Za-z0-9_.=-]", "_", str(value))[:180]


def operation_params(service, operation, region, account):
    if service == "s3control":
        return {"AccountId": account}
    if service == "wafv2" and operation == "list_web_acls":
        return {"Scope": "REGIONAL"}
    if service == "ram" and operation == "list_resources":
        return {"resourceOwner": "SELF"}
    if service == "inspector2" and operation == "list_findings":
        return {"maxResults": 100}
    if service == "securityhub" and operation == "get_findings":
        return {"MaxResults": 100}
    if service == "resourcegroupstaggingapi" and operation == "get_resources":
        return {"ResourcesPerPage": 100}
    if service == "organizations" and operation == "list_roots":
        return {}
    if service == "kms" and operation == "list_aliases":
        return {}
    if service == "iam" and operation == "list_policies":
        return {"Scope": "All"}
    return {}


def scrub_params(params):
    # Collector only issues approved, read-only API parameters; never log credentials.
    return clean(params)


def load_approved_accounts(cfg):
    values = set(str(x) for x in cfg.get("approved_accounts", []))
    filename = cfg.get("approved_accounts_file")
    if filename:
        path = pathlib.Path(filename).expanduser()
        if not path.is_absolute():
            path = pathlib.Path(cfg["_config_dir"]) / path
        for line in path.read_text().splitlines():
            item = line.split("#", 1)[0].strip()
            if item:
                values.add(item)
    if not values or any(not re.fullmatch(r"\d{12}", v) for v in values):
        raise ValueError("Approved account inventory missing or invalid")
    return sorted(values)


def discovered(root, ctx, service, operation, region, why):
    return skipped(root, ctx, service, operation, region, why, status="NOT_COLLECTED")


def api(session, root, ctx, service, operation, region, params=None, rel=None):
    params = params or {}
    start = time.monotonic()
    began = UTC()
    pages = 0
    files = []
    count = 0
    error = None
    status = "COMPLETE"
    paginated = False
    truncation = None
    api_name = None
    key = (
        rel
        or f"accounts/{ctx['account_id']}/{'global' if region == 'global' else 'regions/' + region}/{service}/{operation}"
    )
    client = session.client(
        service, region_name=(ctx["home_region"] if region == "global" else region), config=CONFIG
    )
    try:
        method = getattr(client, operation)
        api_name = getattr(client.meta, "method_to_api_mapping", {}).get(operation)
        manual = MANUAL_PAGINATION.get((service, operation))
        if client.can_paginate(operation):
            paginated = True
            iterator = client.get_paginator(operation).paginate(**params)
        elif manual:
            paginated = True

            def follow():
                request = dict(params)
                while True:
                    page = method(**request)
                    yield page
                    marker = page.get(manual[1])
                    if not marker:
                        return
                    request[manual[0]] = marker

            iterator = follow()
        else:
            iterator = iter([method(**params)])
        for response in iterator:
            if pages >= MAX_PAGES:
                status = "PARTIAL"
                truncation = "PAGE_LIMIT_REACHED"
                break
            pages += 1
            path = root / key / f"page-{pages:06d}.json"
            # Write each page before requesting next; do not buffer entire inventory.
            payload = clean(response)
            write_json(path, payload)
            relpath = path.relative_to(root).as_posix()
            files.append({"path": relpath, "sha256": sha(path), "bytes": path.stat().st_size})
            count += sum(
                len(v)
                for k, v in payload.items()
                if isinstance(v, list) and k not in ("ResponseMetadata",)
            )
            if not paginated and residual_token(payload):
                status = "PARTIAL"
                truncation = "RESPONSE_TRUNCATED_" + residual_token(payload)
    except (AttributeError, ValueError, TypeError) as exc:
        status = "NOT_COLLECTED"
        code = "UNSUPPORTED_OR_INVALID_OPERATION"
        error = {"code": code, "message": str(exc)[:300].replace("\n", " ")}
        if pages:
            status = "PARTIAL"
    except Exception as exc:
        status, code = outcome(exc)
        error = {"code": code, "message": str(exc)[:300].replace("\n", " ")}
        if pages:
            status = "PARTIAL"
    rec = {
        "collection_id": ctx["collection_id"],
        "assessment_id": ctx["assessment_id"],
        "account_id": ctx["account_id"],
        "partition": ctx["partition"],
        "region": region,
        "service": service,
        "operation": operation,
        "source_tool": "boto3",
        "source_tool_version": boto3.__version__,
        "collector_version": VERSION,
        "started_at": began,
        "completed_at": UTC(),
        "duration_seconds": round(time.monotonic() - start, 3),
        "request_parameters": scrub_params(params),
        "pagination_expected": paginated,
        "pagination_complete": status == "COMPLETE",
        "pages_processed": pages,
        "records_returned": count,
        "output_bytes": sum(f["bytes"] for f in files),
        "outcome": status,
        "error": error,
        "files": files,
        "sensitivity": "CONFIDENTIAL",
        "api_operation": api_name,
        "truncation": truncation,
    }
    if truncation and not error:
        rec["error"] = {"code": truncation, "message": "Response incomplete; not complete coverage"}
    record(root, rec)
    return rec


def skipped(root, ctx, service, operation, region, reason, status="NOT_COLLECTED"):
    rec = {
        "collection_id": ctx["collection_id"],
        "assessment_id": ctx["assessment_id"],
        "account_id": ctx["account_id"],
        "partition": ctx["partition"],
        "region": region,
        "service": service,
        "operation": operation,
        "source_tool": "boto3",
        "source_tool_version": boto3.__version__,
        "collector_version": VERSION,
        "started_at": UTC(),
        "completed_at": UTC(),
        "duration_seconds": 0,
        "request_parameters": {},
        "pagination_expected": None,
        "pagination_complete": False,
        "pages_processed": 0,
        "records_returned": 0,
        "output_bytes": 0,
        "outcome": status,
        "error": {"code": status, "message": reason},
        "files": [],
        "sensitivity": "CONFIDENTIAL",
    }
    record(root, rec)
    return rec


def load_pages(root, rec, key):
    for f in rec["files"]:
        data = json.loads((root / f["path"]).read_text())
        for x in data.get(key, []):
            yield x


def account_session(master, account, role, region):
    # botocore refreshable assume-role provider via profile-free credential resolver.
    from botocore.credentials import DeferredRefreshableCredentials
    from botocore.session import get_session

    sts = master.client("sts", config=CONFIG)
    role_arn = f"arn:{master.client('sts').get_caller_identity()['Arn'].split(':')[1]}:iam::{account}:role/{role}"

    def refresh():
        c = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="csao-evidence", DurationSeconds=3600
        )["Credentials"]
        return {
            "access_key": c["AccessKeyId"],
            "secret_key": c["SecretAccessKey"],
            "token": c["SessionToken"],
            "expiry_time": c["Expiration"].isoformat(),
        }

    bc = get_session()
    bc._credentials = DeferredRefreshableCredentials(method="assume-role", refresh_using=refresh)
    bc.set_config_variable("region", region)
    return boto3.Session(botocore_session=bc), role_arn


def run_prowler(root, ctx, role, regions, executable):
    folder = root / "scanners" / "prowler" / ctx["account_id"]
    folder.mkdir(parents=True, exist_ok=True)
    if not executable or not pathlib.Path(executable).is_file():
        return {"status": "NOT_COLLECTED", "reason": "Prowler executable unavailable"}
    cmd = [
        executable,
        "aws",
        "--role",
        role,
        "--region",
        *regions,
        "--output-formats",
        "json-ocsf",
        "csv",
        "--output-directory",
        str(folder),
        "--no-banner",
    ]
    start = UTC()
    t = time.monotonic()
    try:
        with (folder / "execution.log").open("w") as f:
            result = subprocess.run(
                cmd, stdout=f, stderr=subprocess.STDOUT, timeout=7200, check=False
            )
        # Prowler exits 3 when the scan completed and some checks FAILED.
        outputs = any(folder.rglob("*.ocsf.json")) or any(folder.rglob("*.json"))
        status = (
            "COMPLETE"
            if result.returncode in (0, 3) and outputs
            else "PARTIAL"
            if outputs
            else "API_ERROR"
        )
        error = (
            None
            if status == "COMPLETE"
            else f"Prowler exit code {result.returncode}; inspect execution.log"
        )
    except Exception as e:
        status = "API_ERROR"
        error = f"{type(e).__name__}: {str(e)[:150]}"
    try:
        ver = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=20
        ).stdout.strip()[:120]
    except Exception:
        ver = "UNVERIFIED"
    files = [
        {"path": p.relative_to(root).as_posix(), "sha256": sha(p), "bytes": p.stat().st_size}
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    ]
    rec = {
        "collection_id": ctx["collection_id"],
        "assessment_id": ctx["assessment_id"],
        "account_id": ctx["account_id"],
        "partition": ctx["partition"],
        "region": ",".join(regions),
        "service": "prowler",
        "operation": "scan",
        "source_tool": "prowler",
        "source_tool_version": ver,
        "collector_version": VERSION,
        "started_at": start,
        "completed_at": UTC(),
        "duration_seconds": round(time.monotonic() - t, 3),
        "request_parameters": {"regions": regions},
        "pagination_expected": None,
        "pagination_complete": status == "COMPLETE",
        "pages_processed": 0,
        "records_returned": 0,
        "output_bytes": 0,
        "outcome": status,
        "error": {"message": error} if error else None,
        "files": files,
        "sensitivity": "CONFIDENTIAL",
    }
    record(root, rec)
    return rec


def finalize(root, ctx, allowed_ops):
    ops = [json.loads(x) for x in (root / "operations.jsonl").read_text().splitlines() if x.strip()]
    missing = []
    duplicates = []
    seen = set()
    bad = []
    paths = set()
    for r in ops:
        k = (
            r["account_id"],
            r["region"],
            r["service"],
            r["operation"],
            json.dumps(r["request_parameters"], sort_keys=True),
        )
        if k in seen:
            duplicates.append(k)
        seen.add(k)
        for f in r["files"]:
            p = f["path"]
            paths.add(p)
            target = (root / p).resolve()
            if (
                not target.is_relative_to(root.resolve())
                or not target.is_file()
                or target.is_symlink()
            ):
                bad.append(p)
                continue
            if sha(target) != f["sha256"]:
                bad.append(p)
            if p.endswith(".json"):
                try:
                    json.loads(target.read_text(encoding="utf-8"))
                except Exception:
                    bad.append(p)
    for r in ops:
        if r["outcome"] != "COMPLETE":
            missing.append(
                {
                    "account_id": r["account_id"],
                    "region": r["region"],
                    "service": r["service"],
                    "operation": r["operation"],
                    "reason": r["error"],
                    "status": r["outcome"],
                }
            )
    write_json(
        root / "retry-requests.json", {"collection_id": ctx["collection_id"], "requests": missing}
    )
    statuses = Counter(r["outcome"] for r in ops)
    total_bytes = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    summary = {
        "collection_id": ctx["collection_id"],
        "account_id": ctx["account_id"],
        "status": "FAILED_VALIDATION"
        if bad or duplicates
        else "INTERRUPTED"
        if ctx.get("interrupted")
        else "COMPLETE"
        if all(r["outcome"] == "COMPLETE" for r in ops)
        else "PARTIAL",
        "operations": dict(statuses),
        "operations_total": len(ops),
        "missing_or_failed": len(missing),
        "duplicate_operations": len(duplicates),
        "invalid_evidence_files": bad,
        "evidence_bytes_before_package": total_bytes,
        "peak_process_rss_kb": peak_rss_kb(),
        "completed_at": UTC(),
        "analyzer_compatibility": "UNVERIFIED",
    }
    write_json(root / "collection-summary.json", summary)
    manifest = {
        "schema_version": "closec-provisional-0.3",
        "assessment_id": ctx["assessment_id"],
        "collection_id": ctx["collection_id"],
        "account_id": ctx["account_id"],
        "partition": ctx["partition"],
        "started_at": ctx["started_at"],
        "completed_at": UTC(),
        "regions": ctx["regions"],
        "role_arn": ctx["role_arn"],
        "collector_version": VERSION,
        "operation_index": "operations.jsonl",
        "summary": "collection-summary.json",
        "retry_requests": "retry-requests.json",
        "status": summary["status"],
        "dataset_origin": ctx.get("dataset_origin", "TOOL_GENERATED"),
        "account_name": ctx.get("account_name") or None,
        "analyzer_contract_status": "CLOSEC_ANALYZER_ADAPTER_closec-v030-native-1",
    }
    write_json(root / "manifest.json", manifest)
    with (root / "checksums.sha256").open("w") as f:
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.name != "checksums.sha256":
                if p.is_symlink():
                    raise RuntimeError("Symlink in evidence tree")
                f.write(f"{sha(p)}  {p.relative_to(root).as_posix()}\n")
    return summary


def peak_rss_kb():
    if resource is None:
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value // 1024 if sys.platform == "darwin" else value  # macOS reports bytes


def verify(root):
    manifest = json.loads((root / "manifest.json").read_text())
    summary = json.loads((root / "collection-summary.json").read_text())
    entries = (root / "checksums.sha256").read_text().splitlines()
    if not all(
        k in manifest
        for k in (
            "collection_id",
            "account_id",
            "partition",
            "regions",
            "operation_index",
            "schema_version",
        )
    ):
        raise RuntimeError("Missing manifest fields")
    for line in entries:
        digest, rel = line.split("  ", 1)
        p = (root / rel).resolve()
        if (
            not p.is_relative_to(root.resolve())
            or not p.is_file()
            or p.is_symlink()
            or sha(p) != digest
        ):
            raise RuntimeError("Invalid checksum: " + rel)
    return {
        "status": "VERIFIED",
        "files": len(entries),
        "collection_status": summary["status"],
        "account_id": manifest["account_id"],
    }


def package(root):
    verify(root)
    target = root.parent / (root.name + ".zip")
    if target.exists():
        raise FileExistsError(target)
    with zipfile.ZipFile(
        target, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True
    ) as z:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                if p.is_symlink():
                    raise RuntimeError("Symlink not allowed")
                z.write(p, arcname="AWS-EVIDENCE/" + p.relative_to(root).as_posix())
    return target


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent


def discover_accounts(master, search=""):
    """Read-only account discovery with the operator's own credentials.

    Uses organizations:ListAccounts (management or delegated-administrator access). When
    that is denied or Organizations is not in use, falls back to the caller's account.
    Returns (accounts, source). Nothing is written to evidence.
    """
    accounts, source, reason = [], "organizations:ListAccounts", "no accounts returned"
    try:
        client = master.client("organizations", config=CONFIG)
        for page in client.get_paginator("list_accounts").paginate():
            for item in page.get("Accounts", []):
                accounts.append(
                    {"id": item["Id"], "name": item.get("Name") or "", "status": item.get("Status")}
                )
    except (ClientError, BotoCoreError) as exc:
        reason = exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else ""
        reason = reason or type(exc).__name__
    if not accounts:
        print(f"Organizations account listing unavailable ({reason}); "
              "showing the current account and the approved list only.")
        identity = master.client("sts", config=CONFIG).get_caller_identity()
        accounts, source = [{"id": identity["Account"], "name": "", "status": "ACTIVE"}], "sts"
    text = (search or "").strip().lower()
    if text:
        accounts = [a for a in accounts if text in a["id"] or text in a["name"].lower()]
    return sorted(accounts, key=lambda a: (a["name"].lower(), a["id"])), source


def choose_account(master, approved, search):
    """Interactive search -> numbered list -> typed confirmation. Allowlist enforced."""
    if not sys.stdin.isatty():
        raise ValueError("Interactive selection requires a terminal; supply --account for automation")
    if search is None:
        search = input("Search accounts by name or ID (blank lists all): ").strip()
    accounts, source = discover_accounts(master, search)
    known = {a["id"] for a in accounts}
    accounts += [{"id": a, "name": "", "status": "APPROVED_LIST"} for a in approved if a not in known
                 and (not search or search.lower() in a)]
    if not accounts:
        raise ValueError("No accounts match the search")
    print(f"\nAccounts ({source}):")
    for index, item in enumerate(accounts, 1):
        allowed = not approved or item["id"] in approved
        flag = "" if allowed else "  [not in approved list - cannot be selected]"
        print(f"{index:3}. {item['name'] or '(name unavailable)'} | {item['id']} | {item['status']}{flag}")
    choice = input("Enter the list number of the account to assess: ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(accounts):
        raise ValueError("Selection outside the list")
    item = accounts[int(choice) - 1]
    if approved and item["id"] not in approved:
        raise ValueError("Account is not in the approved allowlist")
    if item["status"] not in ("ACTIVE", "APPROVED_LIST"):
        raise ValueError("Account is not ACTIVE")
    if not approved:
        typed = input(f"No approved-account list is configured. Type {item['id']} to confirm "
                      "you are authorized to assess it: ").strip()
        if typed != item["id"]:
            raise ValueError("Authorization not confirmed; no collection performed")
    if input(f"Type YES to collect read-only evidence for {item['name'] or item['id']}: ") != "YES":
        raise ValueError("Cancelled; no collection performed")
    return item["id"], item["name"]


def collect(args):
    config_path = pathlib.Path(args.config) if args.config else SCRIPT_DIR / "config.json"
    if not config_path.is_file():
        raise ValueError(f"Configuration not found: {config_path}. Copy config.example.json to config.json")
    cfg = json.loads(config_path.read_text())
    cfg["_config_dir"] = str(config_path.resolve().parent)
    try:
        accounts = load_approved_accounts(cfg)
    except (ValueError, OSError):
        if cfg.get("approved_accounts") or cfg.get("approved_accounts_file"):
            raise
        accounts = []  # No allowlist: each selection requires typed authorization.
    approved = cfg["approved_regions"]
    selected = args.regions or approved
    if not selected or any(r not in approved for r in selected):
        raise ValueError("Requested regions outside allowlist")
    master = boto3.Session(region_name=selected[0])
    account_name = ""
    if not args.account:
        args.account, account_name = choose_account(master, accounts, args.search)
    if not re.fullmatch(r"\d{12}", args.account):
        raise ValueError("Account ID must be 12 digits")
    if accounts and args.account not in accounts:
        raise ValueError("Account not in approved allowlist")
    # Evidence is written next to this script unless the configuration names a folder.
    base = pathlib.Path(cfg.get("output_directory") or SCRIPT_DIR / "evidence").expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    session, role = account_session(master, args.account, cfg["spoke_role_name"], selected[0])
    ident = session.client("sts", config=CONFIG).get_caller_identity()
    if ident["Account"] != args.account:
        raise RuntimeError("Assumed identity does not match target account")
    partition = ident["Arn"].split(":")[1]
    enabled = session.client("ec2", region_name=selected[0], config=CONFIG).describe_regions(
        AllRegions=True
    )["Regions"]
    enabled_names = {
        r["RegionName"]
        for r in enabled
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    }
    if any(r not in enabled_names for r in selected):
        raise ValueError("Requested region not enabled: " + str(set(selected) - enabled_names))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{uuid.uuid4().hex[:8]}"
    label = safe_segment(account_name or "account")[:60]
    root = base / f"{label}__{args.account}__{run_id}"
    root.mkdir(parents=True, exist_ok=False)
    origin = cfg.get("dataset_origin", "TOOL_GENERATED")
    if origin not in ("TOOL_GENERATED", "SYNTHETIC"):
        raise ValueError("dataset_origin must be TOOL_GENERATED or SYNTHETIC")
    ctx = {
        "account_id": args.account,
        "assessment_id": cfg["assessment_id"],
        "collection_id": run_id,
        "partition": partition,
        "home_region": selected[0],
        "regions": selected,
        "role_arn": role,
        "started_at": UTC(),
        "dataset_origin": origin,
        "account_name": account_name,
    }
    write_json(root / "accounts" / args.account / "identity.json", ident)
    write_json(
        root / "accounts" / args.account / "regions.json",
        {
            "enabled_regions": sorted(enabled_names),
            "approved_regions": approved,
            "selected_regions": selected,
        },
    )
    try:
        collect_all(session, root, ctx, args, selected)
    except KeyboardInterrupt:
        ctx["interrupted"] = True
        skipped(
            root,
            ctx,
            "collector",
            "remaining_operations",
            "global",
            "Interrupted by operator; remaining operations not attempted",
        )
    if not ctx.get("interrupted"):
        if not args.no_prowler:
            run_prowler(root, ctx, role, selected, cfg.get("prowler_executable"))
        else:
            skipped(root, ctx, "prowler", "scan", ",".join(selected), "Disabled by operator")
        for tool in ("cloudsplaining", "steampipe"):
            skipped(
                root,
                ctx,
                tool,
                "scan",
                ",".join(selected),
                "Supplementary scanner deferred; native collection continues",
            )
    summary = finalize(root, ctx, GLOBAL)
    print(json.dumps({"run_directory": str(root), "summary": summary}, indent=2))
    if not args.no_package:
        if summary["status"] == "FAILED_VALIDATION":
            raise RuntimeError("Evidence integrity validation failed; ZIP not finalized")
        print("ZIP:", package(root))


def organization_scope(session, root, ctx):
    """Attempt the account's SCP inheritance chain. Member accounts normally receive
    AccessDenied; that is journaled and never interpreted as an absent policy."""
    account = ctx["account_id"]
    base = f"accounts/{account}/global/organizations"
    node = account
    for depth in range(10):
        rec = api(
            session,
            root,
            ctx,
            "organizations",
            "list_policies_for_target",
            "global",
            {"TargetId": node, "Filter": "SERVICE_CONTROL_POLICY"},
            f"{base}/targets/{safe_segment(node)}/list_policies_for_target",
        )
        if rec["outcome"] == "COMPLETE":
            for policy in load_pages(root, rec, "Policies"):
                pid = policy.get("Id")
                if pid:
                    api(
                        session,
                        root,
                        ctx,
                        "organizations",
                        "describe_policy",
                        "global",
                        {"PolicyId": pid},
                        f"{base}/policies/{safe_segment(pid)}/describe_policy",
                    )
        parents = api(
            session,
            root,
            ctx,
            "organizations",
            "list_parents",
            "global",
            {"ChildId": node},
            f"{base}/targets/{safe_segment(node)}/list_parents",
        )
        if parents["outcome"] != "COMPLETE":
            return
        found = [p.get("Id") for p in load_pages(root, parents, "Parents")]
        if not found or not found[0]:
            return
        node = found[0]
        if node.startswith("r-"):
            api(
                session,
                root,
                ctx,
                "organizations",
                "list_policies_for_target",
                "global",
                {"TargetId": node, "Filter": "SERVICE_CONTROL_POLICY"},
                f"{base}/targets/{safe_segment(node)}/list_policies_for_target",
            )
            return


def collect_all(session, root, ctx, args, selected):
    for service, operations in GLOBAL.items():
        for op in operations:
            params = operation_params(service, op, "global", args.account)
            rec = api(session, root, ctx, service, op, "global", params)
            if service == "s3" and op == "list_buckets" and rec["outcome"] == "COMPLETE":
                buckets = list(load_pages(root, rec, "Buckets"))
                for bucket in buckets:
                    name = bucket["Name"]
                    loc = api(
                        session,
                        root,
                        ctx,
                        "s3",
                        "get_bucket_location",
                        "global",
                        {"Bucket": name},
                        f"accounts/{args.account}/global/s3/buckets/{safe_segment(name)}/get_bucket_location",
                    )
                    bucket_region = ctx["home_region"]
                    if loc["outcome"] == "COMPLETE" and loc["files"]:
                        location = json.loads((root / loc["files"][0]["path"]).read_text()).get(
                            "LocationConstraint"
                        )
                        bucket_region = (
                            "us-east-1"
                            if location is None
                            else "eu-west-1"
                            if location == "EU"
                            else location
                        )
                    for dep in DEPENDENT["s3"]:
                        if dep == "get_bucket_location":
                            continue
                        if bucket_region not in selected:
                            skipped(
                                root,
                                ctx,
                                "s3",
                                dep,
                                bucket_region,
                                "Bucket Region not in approved collection scope",
                            )
                            continue
                        api(
                            session,
                            root,
                            ctx,
                            "s3",
                            dep,
                            bucket_region,
                            {"Bucket": name},
                            f"accounts/{args.account}/regions/{bucket_region}/s3/buckets/{safe_segment(name)}/{dep}",
                        )
            elif service == "s3" and op == "list_buckets":
                skipped(
                    root,
                    ctx,
                    "s3",
                    "bucket_detail_collection",
                    "global",
                    "Bucket inventory incomplete",
                )
            if (
                service == "iam"
                and op == "get_account_authorization_details"
                and rec["outcome"] == "COMPLETE"
            ):
                # Authorization details already embed PolicyVersionList documents. Fetch a
                # default version only when its document is absent (never guess versions).
                for pol in load_pages(root, rec, "Policies"):
                    arn = pol.get("Arn")
                    ver = pol.get("DefaultVersionId")
                    embedded = any(
                        v.get("IsDefaultVersion") and v.get("Document")
                        for v in pol.get("PolicyVersionList") or []
                    )
                    if arn and ver and not embedded:
                        api(
                            session,
                            root,
                            ctx,
                            "iam",
                            "get_policy_version",
                            "global",
                            {"PolicyArn": arn, "VersionId": ver},
                            f"accounts/{args.account}/global/iam/policy_versions/{safe_segment(arn)}/{safe_segment(ver)}",
                        )
    organization_scope(session, root, ctx)
    for region in selected:
        for service, operations in REGIONAL.items():
            for op in operations:
                params = operation_params(service, op, region, args.account)
                rec = api(session, root, ctx, service, op, region, params)
                if rec["outcome"] != "COMPLETE":
                    continue
                if service == "kms" and op == "list_keys":
                    for k in load_pages(root, rec, "Keys"):
                        for dep in DEPENDENT["kms"]:
                            # Key ARNs identify the key unambiguously for offline correlation.
                            params = {"KeyId": k.get("KeyArn") or k["KeyId"]}
                            if dep == "get_key_policy":
                                params["PolicyName"] = "default"
                            if dep == "list_key_policies":
                                pass
                            api(
                                session,
                                root,
                                ctx,
                                "kms",
                                dep,
                                region,
                                params,
                                f"accounts/{args.account}/regions/{region}/kms/keys/{k['KeyId']}/{dep}",
                            )
                if service == "cloudtrail" and op == "describe_trails":
                    for trail in load_pages(root, rec, "trailList"):
                        for dep in DEPENDENT["cloudtrail"]:
                            key = "TrailName" if dep == "get_event_selectors" else "Name"
                            api(
                                session,
                                root,
                                ctx,
                                "cloudtrail",
                                dep,
                                region,
                                {key: trail["TrailARN"]},
                                f"accounts/{args.account}/regions/{region}/cloudtrail/trails/{safe_segment(trail['Name'])}/{dep}",
                            )
                if service == "guardduty" and op == "list_detectors":
                    for detector in load_pages(root, rec, "DetectorIds"):
                        api(
                            session,
                            root,
                            ctx,
                            "guardduty",
                            "get_detector",
                            region,
                            {"DetectorId": detector},
                            f"accounts/{args.account}/regions/{region}/guardduty/detectors/{safe_segment(detector)}",
                        )
                if service == "lambda" and op == "list_functions":
                    # Resource-based policies decide who may invoke; absence is ResourceNotFoundException.
                    for fn in load_pages(root, rec, "Functions"):
                        name = fn.get("FunctionArn")
                        if name:
                            api(
                                session,
                                root,
                                ctx,
                                "lambda",
                                "get_policy",
                                region,
                                {"FunctionName": name},
                                f"accounts/{args.account}/regions/{region}/lambda/functions/{safe_segment(fn.get('FunctionName', name))}/get_policy",
                            )
                if service == "elbv2" and op == "describe_load_balancers":
                    for lb in load_pages(root, rec, "LoadBalancers"):
                        arn = lb.get("LoadBalancerArn")
                        if arn:
                            for dep in ("describe_listeners", "describe_target_groups"):
                                dr = api(
                                    session,
                                    root,
                                    ctx,
                                    "elbv2",
                                    dep,
                                    region,
                                    {"LoadBalancerArn": arn},
                                    f"accounts/{args.account}/regions/{region}/elbv2/load_balancers/{safe_segment(arn)}/{dep}",
                                )
                                if dep == "describe_listeners" and dr["outcome"] == "COMPLETE":
                                    for listener in load_pages(root, dr, "Listeners"):
                                        larn = listener.get("ListenerArn")
                                        if larn:
                                            api(
                                                session,
                                                root,
                                                ctx,
                                                "elbv2",
                                                "describe_rules",
                                                region,
                                                {"ListenerArn": larn},
                                                f"accounts/{args.account}/regions/{region}/elbv2/listeners/{safe_segment(larn)}/describe_rules",
                                            )
                if service == "ec2" and op == "describe_transit_gateway_route_tables":
                    for rt in load_pages(root, rec, "TransitGatewayRouteTables"):
                        rtid = rt.get("TransitGatewayRouteTableId")
                        if rtid:
                            for dep in (
                                "get_transit_gateway_route_table_associations",
                                "get_transit_gateway_route_table_propagations",
                            ):
                                api(
                                    session,
                                    root,
                                    ctx,
                                    "ec2",
                                    dep,
                                    region,
                                    {"TransitGatewayRouteTableId": rtid},
                                    f"accounts/{args.account}/regions/{region}/ec2/tgw_routes/{safe_segment(rtid)}/{dep}",
                                )
                            # AWS SearchTransitGatewayRoutes is filtered; do not label as exhaustive.
                            api(
                                session,
                                root,
                                ctx,
                                "ec2",
                                "search_transit_gateway_routes",
                                region,
                                {
                                    "TransitGatewayRouteTableId": rtid,
                                    "Filters": [
                                        {"Name": "state", "Values": ["active", "blackhole"]}
                                    ],
                                },
                                f"accounts/{args.account}/regions/{region}/ec2/tgw_routes/{safe_segment(rtid)}/search_routes",
                            )
                if service == "ecs" and op == "list_clusters":
                    for arn in load_pages(root, rec, "clusterArns"):
                        api(
                            session,
                            root,
                            ctx,
                            "ecs",
                            "describe_clusters",
                            region,
                            {"clusters": [arn], "include": ["SETTINGS", "STATISTICS", "TAGS"]},
                            f"accounts/{args.account}/regions/{region}/ecs/clusters/{safe_segment(arn)}/describe_clusters",
                        )
                if service == "eks" and op == "list_clusters":
                    for name in load_pages(root, rec, "clusters"):
                        api(
                            session,
                            root,
                            ctx,
                            "eks",
                            "describe_cluster",
                            region,
                            {"name": name},
                            f"accounts/{args.account}/regions/{region}/eks/clusters/{safe_segment(name)}/describe_cluster",
                        )
                if service == "dynamodb" and op == "list_tables":
                    for name in load_pages(root, rec, "TableNames"):
                        api(
                            session,
                            root,
                            ctx,
                            "dynamodb",
                            "describe_table",
                            region,
                            {"TableName": name},
                            f"accounts/{args.account}/regions/{region}/dynamodb/tables/{safe_segment(name)}/describe_table",
                        )
                # Lambda list_functions includes function configuration metadata; avoid retrieving code or secret payloads.
    # Resource control policies, delegated administration and effective policy evaluation remain unenumerated.
    skipped(
        root,
        ctx,
        "organizations",
        "effective_scp_rcp_hierarchy",
        "global",
        "RCPs and effective SCP evaluation not enumerated; SCP chain attempted separately",
    )


def main():
    p = argparse.ArgumentParser(description="CloSec AWS evidence collector v" + VERSION)
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--account", required=False)
    c.add_argument("--config", help="default: config.json next to this script")
    c.add_argument("--search", help="account name or ID text; prompted when omitted")
    c.add_argument("--regions", nargs="+")
    c.add_argument("--no-prowler", action="store_true")
    c.add_argument("--no-package", action="store_true")
    v = sub.add_parser("verify")
    v.add_argument("run_directory")
    z = sub.add_parser("package")
    z.add_argument("run_directory")
    r = sub.add_parser("registry")
    a = p.parse_args()
    if a.command == "collect":
        collect(a)
    elif a.command == "verify":
        print(json.dumps(verify(pathlib.Path(a.run_directory)), indent=2))
    elif a.command == "package":
        print(package(pathlib.Path(a.run_directory)))
    elif a.command == "registry":
        print(
            json.dumps({"global": GLOBAL, "regional": REGIONAL, "dependent": DEPENDENT}, indent=2)
        )


if __name__ == "__main__":
    main()
