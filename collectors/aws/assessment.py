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

import argparse, base64, datetime, hashlib, json, os, pathlib, platform, random, re, shutil, subprocess, sys, threading, time, uuid, zipfile

try:
    import resource  # POSIX only; peak RSS is informational.
except ImportError:  # pragma: no cover - Windows
    resource = None
from collections import Counter
import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

VERSION = "0.3.3"
UTC = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
# Defaults; `timeouts` and `retries` in config.json (or batch options) override them.
DEFAULT_OPTIONS = {
    "connect_timeout": 10,
    "read_timeout": 60,
    "operation_timeout": 900,  # wall-clock bound for one operation including all pages
    "max_attempts": 4,  # collector-managed attempts per operation (botocore retries off)
    "backoff_base": 1.0,
    "backoff_cap": 20.0,
    "session_duration": 3600,
}


def client_config(options):
    # botocore's own retries are disabled so that every retry is journaled by the collector.
    return Config(
        retries={"max_attempts": 1, "mode": "standard"},
        connect_timeout=options["connect_timeout"],
        read_timeout=options["read_timeout"],
    )


CONFIG = client_config(DEFAULT_OPTIONS)
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
# Per-resource calls issued inline in collect_all/organization_scope (outside DEPENDENT).
# The contract and access-policy generators read this registry; a static test checks that
# every api() call site uses a registered operation.
INLINE = [
    ("iam", "get_policy_version"),
    ("elbv2", "describe_listeners"),
    ("elbv2", "describe_rules"),
    ("ec2", "get_transit_gateway_route_table_associations"),
    ("ec2", "get_transit_gateway_route_table_propagations"),
    ("ec2", "search_transit_gateway_routes"),
    ("ecs", "describe_clusters"),
    ("eks", "describe_cluster"),
    ("dynamodb", "describe_table"),
    ("organizations", "list_policies_for_target"),
    ("organizations", "describe_policy"),
    ("organizations", "list_parents"),
]
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
    # UTF-8 with LF line ends on every OS, so package bytes do not depend on the host.
    with temp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(clean(obj), f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")
    temp.replace(path)


def read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# botocore standard-mode throttling codes.
THROTTLED = {
    "Throttling",
    "ThrottlingException",
    "ThrottledException",
    "RequestThrottledException",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "TransactionInProgressException",
    "RequestLimitExceeded",
    "BandwidthLimitExceeded",
    "LimitExceededException",
    "RequestThrottled",
    "SlowDown",
    "PriorRequestNotComplete",
    "EC2ThrottledException",
}
EXPIRED = {"ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired"}
# Credential-provider failures (SSO sign-in expired, no credentials, refresh failed).
CREDENTIAL_ERRORS = {
    "NoCredentialsError",
    "PartialCredentialsError",
    "CredentialRetrievalError",
    "UnauthorizedSSOTokenError",
    "SSOTokenLoadError",
    "TokenRetrievalError",
    "RefreshWithMFAUnsupportedError",
    "CredentialsExpired",
}
# The account is not subscribed to the service (AWS-defined codes only, never inferred).
NOT_IN_USE = {"SubscriptionRequiredException", "OptInRequired"}
SERVER_ERRORS = {
    "InternalError",
    "InternalFailure",
    "InternalServerError",
    "InternalServerException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "RequestTimeout",
    "RequestTimeoutException",
}
TIMEOUTS = {"ConnectTimeoutError", "ReadTimeoutError"}
CONNECTION = {
    "EndpointConnectionError",
    "ConnectionClosedError",
    "ProxyConnectionError",
    "SSLError",
    "HTTPClientError",
    "ConnectionError",
}
# Journal outcomes added in 0.3.3. All are evidence gaps; none is ever compliant.
RETRYABLE = {"THROTTLED", "TIMEOUT", "CONNECTION_ERROR", "SERVER_ERROR"}


class CredentialsExpired(Exception):
    """Credentials could not be obtained or refreshed; stop the run and finalize it."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class NoEnabledRegion(ValueError):
    """No requested Region is enabled in the account; nothing can be collected."""


class AssumeRoleFailed(Exception):
    """The member role could not be assumed (not deployed, trust mismatch, SCP denial)."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def classify(exc):
    """(journal outcome, code) for an exception. SERVER_ERROR is retried, then journaled as
    API_ERROR with the AWS code."""
    if isinstance(exc, CredentialsExpired):
        return "CREDENTIALS_EXPIRED", exc.code
    if isinstance(exc, AssumeRoleFailed):
        return ("THROTTLED" if "_THROTTLED_" in exc.code else "ACCESS_DENIED"), exc.code
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in EXPIRED:
            return "CREDENTIALS_EXPIRED", code
        if code in THROTTLED:
            return "THROTTLED", code
        if code in DENIED or "AccessDenied" in code:
            return "ACCESS_DENIED", code
        if code in NOT_CONFIGURED:
            return "NOT_ENABLED", code
        if code in NOT_IN_USE:
            return "SERVICE_NOT_IN_USE", code
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in SERVER_ERRORS or (isinstance(status, int) and status >= 500):
            return "SERVER_ERROR", code
        return "API_ERROR", code
    name = type(exc).__name__
    if name in CREDENTIAL_ERRORS:
        return "CREDENTIALS_EXPIRED", name
    if name in TIMEOUTS:
        return "TIMEOUT", name
    if name in CONNECTION:
        return "CONNECTION_ERROR", name
    if name in ("UnknownEndpointError", "UnknownRegionError"):
        return "SERVICE_NOT_IN_USE", "ENDPOINT_NOT_OFFERED_IN_REGION"
    if name == "ParamValidationError":
        return "API_ERROR", "COLLECTOR_PARAMETER_ERROR"
    return "API_ERROR", name


def outcome(exc):
    """0.3.2 interface: journal outcome after retries are exhausted."""
    status, code = classify(exc)
    return ("API_ERROR" if status == "SERVER_ERROR" else status), code


class Throttle:
    """Throttle-aware pause shared by every worker of one process (batch collection).

    A throttled call widens a global pause; every call waits for it first, so concurrent
    accounts back off together instead of amplifying the throttling."""

    def __init__(self, base=1.0, cap=30.0):
        self.base, self.cap = base, cap
        self.lock = threading.Lock()
        self.until = 0.0
        self.level = 0
        self.events = 0

    def wait(self):
        with self.lock:
            delay = self.until - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    def signal(self):
        with self.lock:
            self.events += 1
            self.level = min(self.level + 1, 6)
            pause = min(self.cap, self.base * (2 ** self.level)) * random.uniform(0.5, 1.0)
            self.until = max(self.until, time.monotonic() + pause)

    def relax(self):
        with self.lock:
            self.level = max(0, self.level - 1)


def backoff(options, attempt):
    """Exponential backoff with full jitter for retry `attempt` (1-based)."""
    ceiling = min(options["backoff_cap"], options["backoff_base"] * (2 ** (attempt - 1)))
    return round(random.uniform(0, ceiling), 3)


def residual_token(payload):
    if payload.get("IsTruncated") is True:
        return "IsTruncated"
    return next((k for k in TOKENS if payload.get(k)), None)


JOURNAL_LOCK = threading.Lock()


def record(root, rec):
    with JOURNAL_LOCK, (root / "operations.jsonl").open("a", encoding="utf-8", newline="\n") as f:
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
        for line in path.read_text(encoding="utf-8").splitlines():
            item = line.split("#", 1)[0].strip()
            if item:
                values.add(item)
    if not values or any(not re.fullmatch(r"\d{12}", v) for v in values):
        raise ValueError("Approved account inventory missing or invalid")
    return sorted(values)


def discovered(root, ctx, service, operation, region, why):
    return skipped(root, ctx, service, operation, region, why, status="NOT_COLLECTED")


FACTS_LOCK = threading.Lock()


def note(ctx, kind, entry):
    """Append a manifest fact (retry, detail limit, dependency fallback); thread-safe."""
    with FACTS_LOCK:
        ctx.setdefault(kind, []).append(entry)


def attempt(session, root, ctx, service, operation, region, params, key, options):
    """One collection attempt of an operation (all pages). Never raises."""
    began = time.monotonic()
    result = {
        "status": "COMPLETE",
        "retry_status": None,
        "error": None,
        "files": [],
        "pages": 0,
        "count": 0,
        "paginated": False,
        "truncation": None,
        "api_name": None,
    }
    client = session.client(
        service,
        region_name=(ctx["home_region"] if region == "global" else region),
        config=ctx.get("config", CONFIG),
    )
    try:
        method = getattr(client, operation)
        result["api_name"] = getattr(client.meta, "method_to_api_mapping", {}).get(operation)
        manual = MANUAL_PAGINATION.get((service, operation))
        if client.can_paginate(operation):
            result["paginated"] = True
            iterator = client.get_paginator(operation).paginate(**params)
        elif manual:
            result["paginated"] = True

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
            limit = None
            if result["pages"] >= MAX_PAGES:
                limit = "PAGE_LIMIT_REACHED"
            elif time.monotonic() - began > options["operation_timeout"]:
                limit = "OPERATION_TIME_LIMIT_REACHED"
            if limit:
                result["status"], result["truncation"] = "PARTIAL", limit
                note(
                    ctx,
                    "detail_limits_reached",
                    {"service": service, "operation": operation, "region": region, "limit": limit},
                )
                break
            result["pages"] += 1
            path = root / key / f"page-{result['pages']:06d}.json"
            # Write each page before requesting next; do not buffer entire inventory.
            payload = clean(response)
            write_json(path, payload)
            relpath = path.relative_to(root).as_posix()
            result["files"].append(
                {"path": relpath, "sha256": sha(path), "bytes": path.stat().st_size}
            )
            result["count"] += sum(
                len(v)
                for k, v in payload.items()
                if isinstance(v, list) and k not in ("ResponseMetadata",)
            )
            if not result["paginated"] and residual_token(payload):
                result["status"] = "PARTIAL"
                result["truncation"] = "RESPONSE_TRUNCATED_" + residual_token(payload)
    except (AttributeError, ValueError, TypeError) as exc:
        result["status"] = "PARTIAL" if result["pages"] else "NOT_COLLECTED"
        result["error"] = {
            "code": "UNSUPPORTED_OR_INVALID_OPERATION",
            "message": str(exc)[:300].replace("\n", " "),
        }
    except Exception as exc:
        status, code = classify(exc)
        if status == "CONNECTION_ERROR" and region != "global":
            # A Region missing from botocore's endpoint data does not offer the service.
            try:
                offered = session.get_available_regions(service, ctx["partition"])
            except Exception:
                offered = []
            if offered and region not in offered:
                status, code = "SERVICE_NOT_IN_USE", "ENDPOINT_NOT_OFFERED_IN_REGION"
        result["retry_status"] = status
        final = "API_ERROR" if status == "SERVER_ERROR" else status
        result["status"] = "PARTIAL" if result["pages"] and final not in RETRYABLE else final
        result["error"] = {"code": code, "message": str(exc)[:300].replace("\n", " ")}
    return result


def discard(root, files):
    for item in files:
        try:
            (root / item["path"]).unlink()
        except FileNotFoundError:
            pass


def api(session, root, ctx, service, operation, region, params=None, rel=None):
    params = params or {}
    key = (
        rel
        or f"accounts/{ctx['account_id']}/{'global' if region == 'global' else 'regions/' + region}/{service}/{operation}"
    )
    carried = carry(root, ctx, service, operation, region, params)
    if carried is not None:
        return carried
    options = ctx.get("options", DEFAULT_OPTIONS)
    throttle = ctx.get("throttle")
    start = time.monotonic()
    began = UTC()
    attempts, retried = 0, []
    while True:
        attempts += 1
        if throttle:
            throttle.wait()
        result = attempt(session, root, ctx, service, operation, region, params, key, options)
        status = result["retry_status"]
        if status not in RETRYABLE or attempts >= options["max_attempts"]:
            break
        # Bounded read-only retry: discard this attempt's pages, back off, try again.
        if status == "THROTTLED" and throttle:
            throttle.signal()
        delay = backoff(options, attempts)
        retried.append(status)
        note(
            ctx,
            "retries",
            {
                "service": service,
                "operation": operation,
                "region": region,
                "attempt": attempts,
                "status": status,
                "code": result["error"]["code"],
                "delay_seconds": delay,
                "at": UTC(),
            },
        )
        discard(root, result["files"])
        time.sleep(delay)
    if result["status"] == "COMPLETE" and throttle:
        throttle.relax()
    status, files, error = result["status"], result["files"], result["error"]
    if status in RETRYABLE and files:
        # Retries exhausted mid-listing: pages already written stay, coverage is partial.
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
        "pagination_expected": result["paginated"],
        "pagination_complete": status == "COMPLETE",
        "pages_processed": result["pages"],
        "records_returned": result["count"],
        "output_bytes": sum(f["bytes"] for f in files),
        "outcome": status,
        "error": error,
        "files": files,
        "sensitivity": "CONFIDENTIAL",
        "api_operation": result["api_name"],
        "truncation": result["truncation"],
        "attempts": attempts,
        "retried_statuses": retried,
    }
    if result["truncation"] and not error:
        rec["error"] = {
            "code": result["truncation"],
            "message": "Response incomplete; not complete coverage",
        }
    record(root, rec)
    if result["retry_status"] == "CREDENTIALS_EXPIRED":
        ctx["credentials_expired"] = error["code"]
        raise CredentialsExpired(error["code"])
    return rec


def carry(root, ctx, service, operation, region, params):
    """Resume: reuse a verified COMPLETE (or AWS-defined absence) row of the previous run
    instead of calling AWS again. Rows outside the resume filter are carried as they were."""
    previous = ctx.get("carry")
    if not previous:
        return None
    key = (region, service, operation, json.dumps(scrub_params(params), sort_keys=True))
    row = previous["rows"].get(key)
    if row is None:
        return None
    definitive = row["outcome"] in ("COMPLETE", "NOT_ENABLED")
    selected = (not previous["services"] or service in previous["services"]) and (
        not previous["regions"] or region in previous["regions"] or region == "global"
    )
    if not definitive and selected:
        return None  # re-attempt
    source = previous["root"]
    for item in row["files"]:
        target = root / item["path"]
        origin = source / item["path"]
        if not origin.is_file() or sha(origin) != item["sha256"]:
            return None  # previous evidence changed; collect again
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
    rec = dict(row)
    rec.update(collection_id=ctx["collection_id"], carried_from=row["collection_id"])
    record(root, rec)
    with FACTS_LOCK:
        ctx["carried"] = ctx.get("carried", 0) + 1
    return rec


def skipped(root, ctx, service, operation, region, reason, status="NOT_COLLECTED", code=None):
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
        "error": {"code": code or status, "message": reason},
        "files": [],
        "sensitivity": "CONFIDENTIAL",
    }
    record(root, rec)
    return rec


def load_pages(root, rec, key):
    for f in rec["files"]:
        data = read_json(root / f["path"])
        for x in data.get(key, []):
            yield x


def account_session(master, account, role, region, duration=3600, config=None):
    """Refreshable assume-role session. botocore refreshes before expiry; a refresh failure
    (hub sign-in expired, role no longer assumable) raises CredentialsExpired."""
    from botocore.credentials import DeferredRefreshableCredentials
    from botocore.session import get_session

    config = config or CONFIG
    sts = master.client("sts", config=config)
    try:
        partition = sts.get_caller_identity()["Arn"].split(":")[1]
    except Exception as exc:
        status, code = classify(exc)
        if status == "CREDENTIALS_EXPIRED":
            raise CredentialsExpired(code) from None
        raise
    role_arn = f"arn:{partition}:iam::{account}:role/{role}"

    def refresh():
        try:
            c = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="csao-evidence", DurationSeconds=duration
            )["Credentials"]
        except Exception as exc:
            status, code = classify(exc)
            if status == "CREDENTIALS_EXPIRED":
                raise CredentialsExpired(code) from None
            raise AssumeRoleFailed(f"ASSUME_ROLE_{status}_{code}"[:128]) from None
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
        with (folder / "execution.log").open("w", encoding="utf-8") as f:
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


def region_outcomes(ops, declared):
    """(succeeded, partial) declared Regions: succeeded when every regional row there is
    COMPLETE or an AWS-defined absence."""
    seen = {r: [] for r in declared}
    for r in ops:
        if r["region"] in seen and r["service"] not in SCANNERS:
            seen[r["region"]].append(r["outcome"])
    succeeded = [
        r for r, values in seen.items() if values and all(v in DEFINITIVE for v in values)
    ]
    return succeeded, [r for r in declared if r not in succeeded]


SCANNERS = {"prowler", "cloudsplaining", "steampipe"}
DEFINITIVE = {"COMPLETE", "NOT_ENABLED"}
MAX_FACT_ENTRIES = 5000


def bounded(entries):
    entries = list(entries or [])
    return entries[:MAX_FACT_ENTRIES], max(0, len(entries) - MAX_FACT_ENTRIES)


def collection_facts(ctx, ops):
    options = ctx.get("options", DEFAULT_OPTIONS)
    retries, retries_dropped = bounded(ctx.get("retries"))
    limits, limits_dropped = bounded(ctx.get("detail_limits_reached"))
    fallbacks, fallbacks_dropped = bounded(ctx.get("dependency_fallbacks"))
    succeeded, partial = region_outcomes(ops, ctx["regions"])
    return {
        "collector_runtime": {
            "python": platform.python_version(),
            "boto3": boto3.__version__,
            "botocore": botocore.__version__,
            "os": platform.system(),
        },
        "encoding": "UTF-8",
        "options": {k: options[k] for k in sorted(DEFAULT_OPTIONS)},
        "retries": {
            "total": len(ctx.get("retries") or []),
            "operations_retried": sum(1 for r in ops if r.get("retried_statuses")),
            "entries": retries,
            "entries_omitted": retries_dropped,
        },
        "detail_limits": {
            "max_pages_per_operation": MAX_PAGES,
            "operation_timeout_seconds": options["operation_timeout"],
            "reached": limits,
            "reached_omitted": limits_dropped,
        },
        "dependency_fallbacks": {"entries": fallbacks, "entries_omitted": fallbacks_dropped},
        "regions_attempted": ctx.get("regions_attempted", ctx["regions"]),
        "regions_succeeded": succeeded,
        "regions_partial": partial,
        "regions_not_enabled": ctx.get("regions_not_enabled", []),
        "region_status_source": ctx.get("region_status_source", "ec2:DescribeRegions"),
        "organization": ctx.get("organization") or {"access": "NOT_ATTEMPTED"},
        "resumed_from": ctx.get("resumed_from"),
        "resumed_at": ctx.get("resumed_at"),
        "carried_operations": ctx.get("carried", 0),
        "credentials_expired": ctx.get("credentials_expired"),
    }


def finalize(root, ctx, allowed_ops):
    ops = [
        json.loads(x)
        for x in (root / "operations.jsonl").read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
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
                or "\\" in p
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
                    "request_parameters": r["request_parameters"],
                }
            )
    write_json(
        root / "retry-requests.json", {"collection_id": ctx["collection_id"], "requests": missing}
    )
    statuses = Counter(r["outcome"] for r in ops)
    total_bytes = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    interrupted = ctx.get("interrupted") or ctx.get("credentials_expired")
    summary = {
        "collection_id": ctx["collection_id"],
        "account_id": ctx["account_id"],
        "status": "FAILED_VALIDATION"
        if bad or duplicates
        else "INTERRUPTED"
        if interrupted
        else "COMPLETE"
        if all(r["outcome"] == "COMPLETE" for r in ops)
        else "PARTIAL",
        "interruption_reason": "CREDENTIALS_EXPIRED"
        if ctx.get("credentials_expired")
        else "OPERATOR"
        if ctx.get("interrupted")
        else None,
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
        "business_group": ctx.get("business_group") or None,
        "analyzer_contract_status": "CLOSEC_ANALYZER_ADAPTER_closec-v030-native-1",
        "collection_facts": collection_facts(ctx, ops),
    }
    write_json(root / "manifest.json", manifest)
    with (root / "checksums.sha256").open("w", encoding="utf-8", newline="\n") as f:
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
    manifest = read_json(root / "manifest.json")
    summary = read_json(root / "collection-summary.json")
    entries = (root / "checksums.sha256").read_text(encoding="utf-8").splitlines()
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
            "\\" in rel
            or not p.is_relative_to(root.resolve())
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
    """Immutable ZIP (forward-slash entry names under AWS-EVIDENCE/) plus a SHA-256 sidecar
    `<name>.zip.sha256` written after the archive is closed."""
    verify(root)
    target = root.parent / (root.name + ".zip")
    sidecar = root.parent / (root.name + ".zip.sha256")
    if target.exists() or sidecar.exists():
        raise FileExistsError(target)
    with zipfile.ZipFile(
        target, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True
    ) as z:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                if p.is_symlink():
                    raise RuntimeError("Symlink not allowed")
                name = "AWS-EVIDENCE/" + p.relative_to(root).as_posix()
                if "\\" in name or ".." in name.split("/"):
                    raise RuntimeError("Unsafe archive entry: " + name)
                z.write(p, arcname=name)
    with sidecar.open("w", encoding="utf-8", newline="\n") as f:
        f.write(f"{sha(target)}  {target.name}\n")
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


def load_config(path):
    config_path = pathlib.Path(path) if path else SCRIPT_DIR / "config.json"
    if not config_path.is_file():
        raise ValueError(f"Configuration not found: {config_path}. Copy config.example.json to config.json")
    cfg = read_json(config_path)
    cfg["_config_dir"] = str(config_path.resolve().parent)
    return cfg


def resolve_options(cfg, overrides=None):
    """DEFAULT_OPTIONS overridden by config `timeouts`/`retries` and explicit overrides."""
    options = dict(DEFAULT_OPTIONS)
    for section in ("timeouts", "retries"):
        for key, value in (cfg.get(section) or {}).items():
            if key in options:
                options[key] = value
    for key, value in (overrides or {}).items():
        if value is not None and key in options:
            options[key] = value
    for key in ("connect_timeout", "read_timeout", "operation_timeout", "session_duration"):
        if not isinstance(options[key], (int, float)) or options[key] <= 0:
            raise ValueError(f"{key} must be a positive number")
    if not isinstance(options["max_attempts"], int) or not 1 <= options["max_attempts"] <= 10:
        raise ValueError("max_attempts must be an integer from 1 to 10")
    if not 900 <= options["session_duration"] <= 43200:
        raise ValueError("session_duration must be 900-43200 seconds")
    return options


def previous_run(path, account):
    """Verified previous run of the same account and collector version, for resume."""
    folder = pathlib.Path(path).expanduser().resolve()
    verify(folder)
    manifest = read_json(folder / "manifest.json")
    if manifest.get("account_id") != account:
        raise ValueError("Resume run belongs to a different account")
    if manifest.get("collector_version") != VERSION:
        raise ValueError(f"Resume needs a {VERSION} run; collect again instead")
    rows = {}
    for line in (folder / "operations.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            key = (
                row["region"],
                row["service"],
                row["operation"],
                json.dumps(row["request_parameters"], sort_keys=True),
            )
            rows[key] = row  # the last attempt of an operation wins
    return folder, manifest, rows


def region_scope(session, selected, config):
    """Enabled requested Regions. Opted-out Regions are journaled, not aborted (0.3.3)."""
    try:
        enabled = session.client("ec2", region_name=selected[0], config=config).describe_regions(
            AllRegions=True
        )["Regions"]
    except Exception as exc:
        status, code = classify(exc)
        if status == "CREDENTIALS_EXPIRED":
            raise CredentialsExpired(code) from None
        # Opt-in state unknown: attempt every requested Region and say so in the manifest.
        return list(selected), [], f"UNAVAILABLE_{status}_{code}"[:128], None
    names = {
        r["RegionName"]
        for r in enabled
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    }
    declared = [r for r in selected if r in names]
    return declared, [r for r in selected if r not in names], "ec2:DescribeRegions", sorted(names)


def collect_account(
    cfg,
    account,
    regions,
    *,
    account_name="",
    business_group=None,
    options=None,
    throttle=None,
    prowler=False,
    make_package=True,
    resume=None,
    resume_services=(),
    resume_regions=(),
    master=None,
    log=print,
):
    """Collect one account into one run directory and (optionally) one ZIP.

    Raises AssumeRoleFailed or CredentialsExpired before any evidence is written when the
    member role cannot be assumed; afterwards credential expiry finalizes the run as
    INTERRUPTED (resume it once signed in again)."""
    options = options or resolve_options(cfg)
    config = client_config(options)
    approved = cfg["approved_regions"]
    selected = list(regions or approved)
    if not selected or any(r not in approved for r in selected):
        raise ValueError("Requested regions outside allowlist")
    if not re.fullmatch(r"\d{12}", account):
        raise ValueError("Account ID must be 12 digits")
    carried = None
    if resume:
        folder, prior, rows = previous_run(resume, account)
        carried = {
            "root": folder,
            "rows": rows,
            "services": set(resume_services or ()),
            "regions": set(resume_regions or ()),
        }
        account_name = account_name or prior.get("account_name") or ""
        business_group = business_group or prior.get("business_group")
    master = master or boto3.Session(region_name=selected[0])
    # Evidence is written next to this script unless the configuration names a folder.
    base = pathlib.Path(cfg.get("output_directory") or SCRIPT_DIR / "evidence").expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    session, role = account_session(
        master,
        account,
        cfg["spoke_role_name"],
        selected[0],
        duration=options["session_duration"],
        config=config,
    )
    try:
        ident = session.client("sts", config=config).get_caller_identity()
    except (AssumeRoleFailed, CredentialsExpired):
        raise
    except Exception as exc:
        status, code = classify(exc)
        if status == "CREDENTIALS_EXPIRED":
            raise CredentialsExpired(code) from None
        raise AssumeRoleFailed(f"ASSUME_ROLE_{status}_{code}"[:128]) from None
    if ident["Account"] != account:
        raise RuntimeError("Assumed identity does not match target account")
    partition = ident["Arn"].split(":")[1]
    declared, not_enabled, region_source, enabled_names = region_scope(session, selected, config)
    if not declared:
        raise NoEnabledRegion("None of the requested Regions is enabled: " + ", ".join(selected))
    stamp =datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{uuid.uuid4().hex[:8]}"
    label = safe_segment(account_name or "account")[:60]
    root = base / f"{label}__{account}__{run_id}"
    root.mkdir(parents=True, exist_ok=False)
    origin = cfg.get("dataset_origin", "TOOL_GENERATED")
    if origin not in ("TOOL_GENERATED", "SYNTHETIC"):
        raise ValueError("dataset_origin must be TOOL_GENERATED or SYNTHETIC")
    ctx = {
        "account_id": account,
        "assessment_id": cfg["assessment_id"],
        "collection_id": run_id,
        "partition": partition,
        "home_region": (declared or selected)[0],
        "regions": declared,
        "regions_attempted": selected,
        "regions_not_enabled": not_enabled,
        "region_status_source": region_source,
        "role_arn": role,
        # A resumed package spans the original run: carried rows keep their timestamps.
        "started_at": prior["started_at"] if carried else UTC(),
        "resumed_at": UTC() if carried else None,
        "dataset_origin": origin,
        "account_name": account_name,
        "business_group": business_group,
        "options": options,
        "config": config,
        "throttle": throttle,
        "carry": carried,
        "resumed_from": carried and prior["collection_id"],
    }
    write_json(root / "accounts" / account / "identity.json", ident)
    write_json(
        root / "accounts" / account / "regions.json",
        {
            "enabled_regions": enabled_names,
            "approved_regions": approved,
            "selected_regions": selected,
            "declared_regions": declared,
            "regions_not_enabled": not_enabled,
            "region_status_source": region_source,
        },
    )
    for region in not_enabled:
        skipped(
            root,
            ctx,
            "collector",
            "region_scope",
            region,
            "Region not enabled (opted out) for this account; no request was made",
            status="REGION_NOT_ENABLED",
        )
    try:
        collect_all(session, root, ctx, account, declared)
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
    except CredentialsExpired as exc:
        ctx["credentials_expired"] = exc.code
        skipped(
            root,
            ctx,
            "collector",
            "remaining_operations",
            "global",
            "Credentials expired; remaining operations not attempted (sign in again and resume)",
            code="CREDENTIALS_EXPIRED",
        )
    if not ctx.get("interrupted") and not ctx.get("credentials_expired"):
        if prowler:
            run_prowler(root, ctx, role, declared, cfg.get("prowler_executable"))
        else:
            skipped(root, ctx, "prowler", "scan", ",".join(declared), "Disabled by operator")
        for tool in ("cloudsplaining", "steampipe"):
            skipped(
                root,
                ctx,
                tool,
                "scan",
                ",".join(declared),
                "Supplementary scanner deferred; native collection continues",
            )
    summary = finalize(root, ctx, GLOBAL)
    result = {"run_directory": str(root), "summary": summary, "zip": None, "zip_sha256": None}
    if make_package and summary["status"] != "FAILED_VALIDATION":
        target = package(root)
        result["zip"] = str(target)
        result["zip_sha256"] = sha(target)
    return result


def collect(args):
    cfg = load_config(args.config)
    try:
        accounts = load_approved_accounts(cfg)
    except (ValueError, OSError):
        if cfg.get("approved_accounts") or cfg.get("approved_accounts_file"):
            raise
        accounts = []  # No allowlist: each selection requires typed authorization.
    selected = args.regions or cfg["approved_regions"]
    if not selected or any(r not in cfg["approved_regions"] for r in selected):
        raise ValueError("Requested regions outside allowlist")
    options = resolve_options(
        cfg,
        {
            "connect_timeout": args.connect_timeout,
            "read_timeout": args.read_timeout,
            "operation_timeout": args.operation_timeout,
            "max_attempts": args.max_attempts,
        },
    )
    master = boto3.Session(region_name=selected[0])
    account_name = ""
    if args.resume and not args.account:
        args.account = read_json(pathlib.Path(args.resume) / "manifest.json")["account_id"]
    if not args.account:
        args.account, account_name = choose_account(master, accounts, args.search)
    if not re.fullmatch(r"\d{12}", args.account):
        raise ValueError("Account ID must be 12 digits")
    if accounts and args.account not in accounts:
        raise ValueError("Account not in approved allowlist")
    result = collect_account(
        cfg,
        args.account,
        selected,
        account_name=account_name,
        options=options,
        prowler=not args.no_prowler,
        make_package=not args.no_package,
        resume=args.resume,
        resume_services=args.services or (),
        resume_regions=args.regions if args.resume else (),
        master=master,
    )
    print(json.dumps({"run_directory": result["run_directory"], "summary": result["summary"]}, indent=2))
    if result["summary"]["status"] == "FAILED_VALIDATION" and not args.no_package:
        raise RuntimeError("Evidence integrity validation failed; ZIP not finalized")
    if result["zip"]:
        print("ZIP:", result["zip"])
        print("ZIP SHA-256:", result["zip_sha256"])


SCP, RCP = "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"
POLICY_FOLDERS = {SCP: "scp", RCP: "rcp"}


def first_page(root, rec):
    if rec and rec["outcome"] == "COMPLETE" and rec["files"]:
        return read_json(root / rec["files"][0]["path"])
    return {}


def organization_scope(session, root, ctx):
    """Organization facts plus the account's SCP and RCP inheritance chain with policy
    content (root included). Member accounts normally receive AccessDenied; that is journaled
    and recorded as missing organization access, never as an absent policy."""
    account = ctx["account_id"]
    base = f"accounts/{account}/global/organizations"
    described = ctx.get("_org_describe")
    org = {
        "access": "NOT_ATTEMPTED",
        "organization_id": None,
        "management_account_id": None,
        "describe_organization": described["outcome"] if described else "NOT_ATTEMPTED",
        "hierarchy_reached_root": False,
        "policy_types": {},
    }
    ctx["organization"] = org
    details = first_page(root, described).get("Organization") or {}
    org["organization_id"] = details.get("Id")
    org["management_account_id"] = details.get("MasterAccountId")
    if described and described["outcome"] == "NOT_ENABLED":
        org["access"] = "NOT_IN_ORGANIZATION"
        return
    roots = [r for r in first_page(root, ctx.get("_org_roots")).get("Roots") or []]
    enabled_types = None
    if roots and isinstance(roots[0].get("PolicyTypes"), list):
        enabled_types = {
            t.get("Type") for t in roots[0]["PolicyTypes"] if t.get("Status") == "ENABLED"
        }
    states = {}
    for ptype in (SCP, RCP):
        if enabled_types is not None and ptype not in enabled_types:
            states[ptype] = {"status": "NOT_ENABLED_AT_ROOT", "targets_listed": 0, "policies_described": 0, "failures": 0}
        else:
            states[ptype] = {"status": None, "targets_listed": 0, "policies_described": 0, "failures": 0}
    described_ids = set()
    node = account
    denied = incomplete = False
    for _depth in range(10):
        for ptype, state in states.items():
            if state["status"] in ("NOT_ENABLED_AT_ROOT", "ACCESS_DENIED"):
                continue
            rec = api(
                session,
                root,
                ctx,
                "organizations",
                "list_policies_for_target",
                "global",
                {"TargetId": node, "Filter": ptype},
                f"{base}/targets/{safe_segment(node)}/{POLICY_FOLDERS[ptype]}/list_policies_for_target",
            )
            if rec["outcome"] == "ACCESS_DENIED":
                state["status"] = "ACCESS_DENIED"
                continue
            if rec["outcome"] != "COMPLETE":
                state["failures"] += 1
                state["status"] = "INCOMPLETE"
                continue
            state["targets_listed"] += 1
            for policy in load_pages(root, rec, "Policies"):
                pid = policy.get("Id")
                if not pid or pid in described_ids:
                    continue
                described_ids.add(pid)
                content = api(
                    session,
                    root,
                    ctx,
                    "organizations",
                    "describe_policy",
                    "global",
                    {"PolicyId": pid},
                    f"{base}/policies/{safe_segment(pid)}/describe_policy",
                )
                if content["outcome"] == "COMPLETE":
                    state["policies_described"] += 1
                else:
                    state["failures"] += 1
                    state["status"] = "INCOMPLETE"
        if node.startswith("r-"):
            org["hierarchy_reached_root"] = True
            break
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
            denied = denied or parents["outcome"] == "ACCESS_DENIED"
            incomplete = True
            break
        found = [p.get("Id") for p in load_pages(root, parents, "Parents")]
        if not found or not found[0]:
            incomplete = True
            break
        node = found[0]
    for state in states.values():
        if state["status"] is None:
            state["status"] = "COLLECTED" if org["hierarchy_reached_root"] else "INCOMPLETE"
    org["policy_types"] = states
    if any(s["status"] == "ACCESS_DENIED" for s in states.values()) or denied:
        org["access"] = "ACCESS_DENIED"
    elif incomplete or any(s["status"] == "INCOMPLETE" for s in states.values()):
        org["access"] = "INCOMPLETE"
    else:
        org["access"] = "COLLECTED"


# Regional listings whose dependent per-resource calls run only after a COMPLETE outcome.
PARENTS = {
    ("kms", "list_keys"),
    ("cloudtrail", "describe_trails"),
    ("guardduty", "list_detectors"),
    ("lambda", "list_functions"),
    ("elbv2", "describe_load_balancers"),
    ("ec2", "describe_transit_gateway_route_tables"),
    ("ecs", "list_clusters"),
    ("eks", "list_clusters"),
    ("dynamodb", "list_tables"),
}


def collect_all(session, root, ctx, account, selected):
    for service, operations in GLOBAL.items():
        for op in operations:
            params = operation_params(service, op, "global", account)
            rec = api(session, root, ctx, service, op, "global", params)
            if service == "organizations":
                ctx["_org_describe" if op == "describe_organization" else "_org_roots"] = rec
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
                        f"accounts/{account}/global/s3/buckets/{safe_segment(name)}/get_bucket_location",
                    )
                    bucket_region = ctx["home_region"]
                    if loc["outcome"] == "COMPLETE" and loc["files"]:
                        location = read_json(root / loc["files"][0]["path"]).get(
                            "LocationConstraint"
                        )
                        bucket_region = (
                            "us-east-1"
                            if location is None
                            else "eu-west-1"
                            if location == "EU"
                            else location
                        )
                    else:
                        # Location unknown: details are requested through the home Region.
                        note(
                            ctx,
                            "dependency_fallbacks",
                            {
                                "dependency": "s3.get_bucket_location",
                                "parent_outcome": loc["outcome"],
                                "fallback": "HOME_REGION_ENDPOINT",
                                "region": bucket_region,
                                "subject": name,
                            },
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
                            f"accounts/{account}/regions/{bucket_region}/s3/buckets/{safe_segment(name)}/{dep}",
                        )
            elif service == "s3" and op == "list_buckets":
                note(
                    ctx,
                    "dependency_fallbacks",
                    {
                        "dependency": "s3.list_buckets",
                        "parent_outcome": rec["outcome"],
                        "fallback": "DEPENDENT_CALLS_NOT_MADE",
                        "region": "global",
                    },
                )
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
                            f"accounts/{account}/global/iam/policy_versions/{safe_segment(arn)}/{safe_segment(ver)}",
                        )
    organization_scope(session, root, ctx)
    for region in selected:
        for service, operations in REGIONAL.items():
            for op in operations:
                params = operation_params(service, op, region, account)
                rec = api(session, root, ctx, service, op, region, params)
                if rec["outcome"] != "COMPLETE":
                    if (service, op) in PARENTS:
                        note(
                            ctx,
                            "dependency_fallbacks",
                            {
                                "dependency": f"{service}.{op}",
                                "parent_outcome": rec["outcome"],
                                "fallback": "DEPENDENT_CALLS_NOT_MADE",
                                "region": region,
                            },
                        )
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
                                f"accounts/{account}/regions/{region}/kms/keys/{k['KeyId']}/{dep}",
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
                                f"accounts/{account}/regions/{region}/cloudtrail/trails/{safe_segment(trail['Name'])}/{dep}",
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
                            f"accounts/{account}/regions/{region}/guardduty/detectors/{safe_segment(detector)}",
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
                                f"accounts/{account}/regions/{region}/lambda/functions/{safe_segment(fn.get('FunctionName', name))}/get_policy",
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
                                    f"accounts/{account}/regions/{region}/elbv2/load_balancers/{safe_segment(arn)}/{dep}",
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
                                                f"accounts/{account}/regions/{region}/elbv2/listeners/{safe_segment(larn)}/describe_rules",
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
                                    f"accounts/{account}/regions/{region}/ec2/tgw_routes/{safe_segment(rtid)}/{dep}",
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
                                f"accounts/{account}/regions/{region}/ec2/tgw_routes/{safe_segment(rtid)}/search_routes",
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
                            f"accounts/{account}/regions/{region}/ecs/clusters/{safe_segment(arn)}/describe_clusters",
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
                            f"accounts/{account}/regions/{region}/eks/clusters/{safe_segment(name)}/describe_cluster",
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
                            f"accounts/{account}/regions/{region}/dynamodb/tables/{safe_segment(name)}/describe_table",
                        )
                # Lambda list_functions includes function configuration metadata; avoid retrieving code or secret payloads.
    # Delegated administration and effective policy evaluation are not enumerated here.
    skipped(
        root,
        ctx,
        "organizations",
        "effective_scp_rcp_hierarchy",
        "global",
        "Effective SCP/RCP evaluation is performed offline by the analyzer; the SCP and RCP "
        "chain with policy content is attempted separately",
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
    c.add_argument(
        "--resume",
        metavar="RUN_DIRECTORY",
        help="re-attempt failed or missing operations of a previous 0.3.3 run into a new run; "
        "COMPLETE evidence is copied after its SHA-256 is re-verified",
    )
    c.add_argument("--services", nargs="+", help="with --resume: only re-attempt these services")
    c.add_argument("--connect-timeout", type=float)
    c.add_argument("--read-timeout", type=float)
    c.add_argument("--operation-timeout", type=float, help="seconds per operation (all pages)")
    c.add_argument("--max-attempts", type=int, help="attempts per operation (1-10)")
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
            json.dumps(
                {"global": GLOBAL, "regional": REGIONAL, "dependent": DEPENDENT, "inline": INLINE},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
