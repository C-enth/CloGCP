"""Adapter for the actual CloSec AWS collector v0.3.x (`closec-provisional-0.3`) output.

The collector (assessment.py) writes `manifest.json`, an `operations.jsonl` journal with
one row per API attempt (`service`, boto3 `operation`, `outcome`, `error{code,message}`,
`files[]` of per-page native responses), `checksums.sha256` and native page JSON under
`accounts/<id>/...`. This adapter maps that journal onto the shared collector contract
(`closec-collector-1`) without relabelling the manifest or guessing directory layouts:

* boto3 method names map to AWS API names through a botocore-generated table;
* multi-page responses are merged into one native-shaped document under
  `.closec-derived/` (original pages stay untouched and their SHA-256s are recorded);
* AWS-defined absence codes journaled as NOT_ENABLED (for example
  NoSuchPublicAccessBlockConfiguration) become an explicitly derived error body;
* residual pagination tokens or PARTIAL outcomes never yield complete coverage.

Every derived artifact is deterministic, so validation and the repeated import validation
produce identical bytes, and the original journal outcome is preserved per operation.
"""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from offline_analyzer.contracts.aws_operation_names import API_OPERATIONS
from offline_analyzer.ingestion.json_input import MAX_BYTES, InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under, sha256_file

SCHEMA = "closec-provisional-0.3"
PROFILE = "closec-v030-native-1"
VERSIONS = {"0.3.0", "0.3.1", "0.3.2", "0.3.3"}
DERIVED = ".closec-derived"
OUTCOMES = {"COMPLETE", "PARTIAL", "API_ERROR", "ACCESS_DENIED", "NOT_ENABLED", "NOT_COLLECTED"}
# 0.3.3 journal outcomes: distinct collection gaps, each FAILED (coverage ERROR) except
# REGION_NOT_ENABLED, where no request was made (SKIPPED, coverage NOT_COLLECTED). Never PASS.
OUTCOMES_033 = {
    "THROTTLED",
    "CREDENTIALS_EXPIRED",
    "TIMEOUT",
    "CONNECTION_ERROR",
    "REGION_NOT_ENABLED",
    "SERVICE_NOT_IN_USE",
}
OUTCOMES = OUTCOMES | OUTCOMES_033
INTERPRETATIONS_033 = {
    "THROTTLED": "AWS_THROTTLED_AFTER_RETRIES",
    "CREDENTIALS_EXPIRED": "AWS_CREDENTIALS_EXPIRED",
    "TIMEOUT": "AWS_TIMEOUT",
    "CONNECTION_ERROR": "AWS_CONNECTION_ERROR",
    "REGION_NOT_ENABLED": "AWS_REGION_NOT_ENABLED",
    "SERVICE_NOT_IN_USE": "AWS_SERVICE_NOT_IN_USE",
}
TOKENS = {
    "NextToken",
    "nextToken",
    "Marker",
    "NextMarker",
    "NextContinuationToken",
    "NextPageToken",
    "PaginationToken",
}
ERROR_CODE = re.compile(r"^[A-Za-z0-9.:_-]{1,128}$")
MANIFEST_REQUIRED = {
    "schema_version",
    "collector_version",
    "collection_id",
    "account_id",
    "partition",
    "started_at",
    "completed_at",
    "regions",
}
ROW_REQUIRED = {
    "account_id",
    "collection_id",
    "region",
    "service",
    "operation",
    "outcome",
    "started_at",
    "completed_at",
    "files",
}
PROWLER_PROFILES = {"5.10.0": "prowler-ocsf-5.10", "5.26.1": "prowler-ocsf-5.26.1"}


def is_native(directory: Path) -> bool:
    path = directory / "manifest.json"
    if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        return False
    try:
        return json.loads(path.read_bytes()).get("schema_version") == SCHEMA
    except (ValueError, AttributeError):
        return False


def pascal(method: str) -> str:
    return "".join(part.capitalize() for part in method.split("_") if part)[:80] or "Unknown"


def canonical(service: str, method: str, api_operation: object = None) -> tuple[str, bool]:
    """Return the shared `service:Operation` identity and whether it is a real AWS API."""
    prefix = "s3api" if service == "s3" else service
    prefix = re.sub(r"[^a-z0-9-]", "-", prefix.lower())[:40] or "unknown"
    name = API_OPERATIONS.get(f"{service}.{method}")
    if isinstance(api_operation, str) and re.fullmatch(r"[A-Z][A-Za-z0-9]{1,79}", api_operation):
        name = name or api_operation
    if name:
        return f"{prefix}:{name}", True
    # Collector-internal markers (for example effective_scp_rcp_hierarchy) are retained.
    return f"{prefix}:{pascal(method)}", False


def error_code(row: dict, fallback: str) -> str:
    error = row.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, str) and ERROR_CODE.fullmatch(code) else fallback


def _write_derived(directory: Path, relative: str, payload: dict) -> tuple[str, str]:
    data = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_BYTES:
        raise InputError("DERIVED_ARTIFACT_BYTE_LIMIT")
    target = resolve_under(directory, relative)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256(data).hexdigest()
    if not target.is_file() or sha256_file(target) != digest:
        staged = target.with_suffix(".partial")
        staged.write_bytes(data)
        staged.replace(target)
    return relative, digest


def _load_page(directory: Path, name: str) -> dict:
    path = resolve_under(directory, name)
    inspect_json(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise InputError("COLLECTOR_PAGE_SHAPE_UNSUPPORTED")
    return value


def residual(page: dict) -> bool:
    return page.get("IsTruncated") is True or any(page.get(k) for k in TOKENS)


def merge_pages(directory: Path, names: list[str]) -> tuple[dict, bool]:
    """boto3 build_full_result semantics: concatenate list members, drop page tokens."""
    merged: dict = {}
    last: dict = {}
    for name in names:
        last = _load_page(directory, name)
        for key, value in last.items():
            if key in TOKENS or key == "IsTruncated":
                continue
            if isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = merged[key] + value
            elif key not in merged:
                merged[key] = value
    return merged, residual(last)


def read_manifest(directory: Path) -> dict:
    path = resolve_under(directory, "manifest.json")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    inspect_json(path)
    value = json.loads(path.read_bytes())
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != SCHEMA
        or value.get("collector_version") not in VERSIONS
    ):
        raise InputError("COLLECTOR_VERSION_PROFILE_UNSUPPORTED")
    if not MANIFEST_REQUIRED <= value.keys():
        raise InputError("COLLECTOR_V030_MANIFEST_FIELDS_MISSING")
    if not re.fullmatch(r"[0-9]{12}", str(value["account_id"])):
        raise InputError("COLLECTOR_ACCOUNT_INVALID")
    return value


BUSINESS_GROUP = re.compile(r"^[A-Za-z0-9 _.&()-]{1,64}$")
FACTS_BYTES = 2 * 1024 * 1024


def collection_facts(manifest: dict) -> dict | None:
    """Validated 0.3.3 `collection_facts`: known keys only, bounded, never evidence."""
    from offline_analyzer.reporting.aws_collection import FACT_CONSUMERS

    facts = manifest.get("collection_facts")
    if manifest["collector_version"] != "0.3.3":
        if facts is not None:
            raise InputError("COLLECTOR_V030_FACTS_UNSUPPORTED")
        return None
    if not isinstance(facts, dict) or not facts.keys() <= FACT_CONSUMERS.keys():
        raise InputError("COLLECTOR_V030_FACTS_INVALID")
    if len(json.dumps(facts)) > FACTS_BYTES or facts.get("encoding") != "UTF-8":
        raise InputError("COLLECTOR_V030_FACTS_INVALID")
    for key in ("regions_attempted", "regions_succeeded", "regions_partial", "regions_not_enabled"):
        value = facts.get(key, [])
        if not isinstance(value, list) or not all(isinstance(r, str) for r in value):
            raise InputError("COLLECTOR_V030_FACTS_INVALID")
    for key in ("retries", "detail_limits", "dependency_fallbacks", "organization", "options"):
        if not isinstance(facts.get(key, {}), dict):
            raise InputError("COLLECTOR_V030_FACTS_INVALID")
    return facts


def business_group(manifest: dict) -> str | None:
    value = manifest.get("business_group")
    if value is None:
        return None
    if not isinstance(value, str) or not BUSINESS_GROUP.fullmatch(value):
        raise InputError("COLLECTOR_BUSINESS_GROUP_INVALID")
    return value


def prowler_profile(row: dict) -> str | None:
    match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", str(row.get("source_tool_version") or ""))
    return PROWLER_PROFILES.get(match[1]) if match else None


def convert(directory: Path, manifest: dict, rows: list[dict], digests: dict[str, str]):
    """Map journal rows to contract operations; returns (operations, provenance rows)."""
    account = manifest["account_id"]
    regions = set(manifest["regions"])
    operations, provenance = [], []
    identity = f"accounts/{account}/identity.json"
    if identity in digests:
        operations.append(
            {
                "operation": "sts:GetCallerIdentity",
                "region": "global",
                "status": "SUCCEEDED",
                "path": identity,
                "sha256": digests[identity],
                "started_at": manifest["started_at"],
                "completed_at": manifest["started_at"],
                "pages": 1,
                "pagination": "NOT_PAGINATED",
            }
        )
        provenance.append(
            {
                "original_outcome": "COMPLETE",
                "original_error_code": None,
                "derivation": "IDENTITY_FILE_BOUND_AS_GET_CALLER_IDENTITY",
                "source_pages": [digests[identity]],
                "records_returned": None,
                "journal_operation": "sts.get_caller_identity",
                "resource_region": None,
            }
        )
    from offline_analyzer.contracts.r0 import GLOBAL_OPERATIONS
    from offline_analyzer.ingestion.coverage import DEFINED_ABSENCE

    # v0.3.0 passed KMS key UUIDs; the same package's ListKeys evidence maps each to its ARN.
    key_arns = {}
    for row in rows:
        if (row.get("service"), row.get("operation"), row.get("outcome")) == (
            "kms",
            "list_keys",
            "COMPLETE",
        ):
            for item in row.get("files") or []:
                for key in _load_page(directory, item["path"]).get("Keys") or []:
                    if isinstance(key, dict) and isinstance(key.get("KeyArn"), str):
                        key_arns[(str(row["region"]), key.get("KeyId"))] = key["KeyArn"]

    for line, row in enumerate(rows, start=1):
        if not ROW_REQUIRED <= row.keys():
            raise InputError("COLLECTOR_V030_JOURNAL_FIELDS_MISSING")
        if row["account_id"] != account or row["collection_id"] != manifest["collection_id"]:
            raise InputError("COLLECTOR_JOURNAL_SCOPE_MISMATCH")
        outcome = row["outcome"]
        if outcome not in OUTCOMES or (
            outcome in OUTCOMES_033 and manifest["collector_version"] != "0.3.3"
        ):
            raise InputError("COLLECTION_OUTCOME_UNSUPPORTED")
        service, method = str(row["service"]), str(row["operation"])
        files = row["files"]
        if not isinstance(files, list):
            raise InputError("OPERATION_ARTIFACT_REFERENCE_INVALID")
        pages = []
        for item in files:
            name = item.get("path") if isinstance(item, dict) else None
            if not isinstance(name, str) or name not in digests:
                raise InputError("OPERATION_ARTIFACT_REFERENCE_INVALID")
            if item.get("sha256") and item["sha256"] != digests[name]:
                raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
            pages.append(name)
        original_code = error_code(row, outcome)
        record = {
            "region": "global",
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "request_parameters": row.get("request_parameters") or {},
        }
        derivation = None
        subject = record["request_parameters"].get("KeyId") if service == "kms" else None
        resolved = key_arns.get((str(row["region"]), subject))
        if isinstance(subject, str) and not subject.startswith("arn:") and resolved:
            record["request_parameters"] = {**record["request_parameters"], "KeyId": resolved}
            derivation = "KMS_KEY_ID_RESOLVED_FROM_LIST_KEYS"
        if service == "prowler":
            profile = prowler_profile(row)
            ocsf = sorted(p for p in pages if p.endswith(".json"))
            supported = bool(profile) and len(ocsf) == 1 and outcome in {"COMPLETE", "PARTIAL"}
            record["operation"] = "prowler:Scan" if supported else "prowler:UnsupportedScanOutput"
            record.pop("request_parameters")
            if supported:
                record.update(
                    format=profile,
                    tool_version=next(k for k, v in PROWLER_PROFILES.items() if v == profile),
                )
            regions_scanned = str(row["region"]).split(",")
            if len(regions_scanned) == 1 and regions_scanned[0] in regions:
                record["region"] = regions_scanned[0]
            if ocsf and outcome in {"COMPLETE", "PARTIAL"}:
                # Prowler exits non-zero when checks FAIL; v0.3.0 journals that as PARTIAL.
                record.update(
                    status="SUCCEEDED",
                    path=ocsf[0],
                    sha256=digests[ocsf[0]],
                    pages=1,
                    pagination="TRUNCATED" if outcome == "PARTIAL" else "NOT_PAGINATED",
                )
            elif outcome == "NOT_COLLECTED":
                record["status"] = "SKIPPED"
            else:
                record.update(status="FAILED", error_code="PROWLER_" + outcome)
        else:
            operation, real = canonical(service, method, row.get("api_operation"))
            record["operation"] = operation
            region = str(row["region"])
            if operation not in GLOBAL_OPERATIONS and region in regions:
                record["region"] = region
            if outcome in {"COMPLETE", "PARTIAL"} and pages:
                if len(pages) == 1:
                    page = _load_page(directory, pages[0])
                    truncated = residual(page) or outcome == "PARTIAL"
                    record.update(path=pages[0], sha256=digests[pages[0]])
                else:
                    merged, tail = merge_pages(directory, pages)
                    key = hashlib.sha256("".join(digests[p] for p in pages).encode()).hexdigest()
                    path, digest = _write_derived(directory, f"{DERIVED}/pages/{key}.json", merged)
                    truncated = tail or outcome == "PARTIAL"
                    record.update(path=path, sha256=digest)
                    derivation = derivation or "PAGES_MERGED_BUILD_FULL_RESULT"
                record.update(
                    status="SUCCEEDED",
                    pages=len(pages),
                    pagination="TRUNCATED"
                    if truncated
                    else "ALL_PAGES_MERGED"
                    if len(pages) > 1
                    else "NOT_PAGINATED",
                )
            elif (
                outcome == "NOT_ENABLED"
                and real
                and DEFINED_ABSENCE.get(operation) == original_code
            ):
                key = hashlib.sha256(f"{line}:{operation}:{original_code}".encode()).hexdigest()
                path, digest = _write_derived(
                    directory,
                    f"{DERIVED}/absence/{key}.json",
                    {"Error": {"Code": original_code}},
                )
                record.update(
                    status="SUCCEEDED",
                    path=path,
                    sha256=digest,
                    pages=1,
                    pagination="NOT_PAGINATED",
                )
                derivation = "AWS_DEFINED_ABSENCE_FROM_JOURNAL_ERROR_CODE"
            elif outcome == "NOT_COLLECTED":
                record["status"] = "SKIPPED"
            elif outcome == "REGION_NOT_ENABLED":
                record.update(status="SKIPPED", error_code="REGION_NOT_ENABLED")
            else:
                fallback = {"ACCESS_DENIED": "AccessDenied"}.get(outcome, outcome)
                code = original_code if original_code != outcome else fallback
                record.update(status="FAILED", error_code=code)
        operations.append(record)
        provenance.append(
            {
                "original_outcome": outcome,
                "original_error_code": original_code if row.get("error") else None,
                "derivation": derivation,
                "source_pages": [digests[p] for p in pages],
                "records_returned": row.get("records_returned"),
                "journal_operation": f"{service}.{method}",
                "resource_region": str(row["region"]),
                "journal_line": line,
            }
        )
    return operations, provenance


def interpretation(operation: str, outcome: str, code: str | None, derivation: str | None) -> str:
    if derivation == "AWS_DEFINED_ABSENCE_FROM_JOURNAL_ERROR_CODE":
        return "AWS_DEFINED_CONFIGURATION_ABSENCE"
    if operation == "cloudtrail:GetEventSelectors" and outcome == "API_ERROR":
        return "EVENT_SELECTOR_COVERAGE_UNKNOWN_RECOLLECT_WITH_COLLECTOR_0_3_1"
    if operation.startswith("prowler:") and outcome == "PARTIAL":
        return "PROWLER_NONZERO_EXIT_FAIL_CHECKS_OR_PARTIAL_SCAN_REVIEW_EXECUTION_LOG"
    if outcome in INTERPRETATIONS_033:
        return INTERPRETATIONS_033[outcome]
    if outcome == "API_ERROR" and code == "TIMEOUT":
        return "AWS_TIMEOUT"  # 0.3.0-0.3.2 journaled timeouts as API_ERROR
    if outcome == "ACCESS_DENIED":
        return "ACCESS_DENIED_FOR_THIS_ATTEMPT_SERVICE_STATE_UNKNOWN"
    if outcome == "NOT_ENABLED":
        return "COLLECTOR_REPORTED_NOT_ENABLED_" + (code or "UNSPECIFIED")[:60]
    if outcome == "NOT_COLLECTED":
        return "NOT_COLLECTED_" + (code or "UNSPECIFIED")[:60]
    return "COLLECTOR_OUTCOME_PRESERVED"


def inspect_native(directory: Path):
    from offline_analyzer.ingestion.collector import CollectorManifest, inspect_manifest
    from offline_analyzer.ingestion.collector_v030 import read_index, verify_checksums

    digests = verify_checksums(directory)
    manifest = read_manifest(directory)
    facts = collection_facts(manifest)
    group = business_group(manifest)
    rows = read_index(directory)
    operations, provenance = convert(directory, manifest, rows, digests)
    try:
        contract = CollectorManifest.model_validate(
            {
                # Internal adapter target, never the collector's own schema identifier.
                "schema": "closec-collector-1",
                "package_id": manifest["collection_id"],
                "collector": {"name": "CloSec-AWS", "version": manifest["collector_version"]},
                "account_id": manifest["account_id"],
                "partition": manifest["partition"],
                "dataset_origin": manifest.get("dataset_origin"),
                "regions": manifest["regions"],
                "started_at": manifest["started_at"],
                "completed_at": manifest["completed_at"],
                "operations": operations,
            }
        )
    except ValueError as exc:
        raise InputError("COLLECTOR_V030_JOURNAL_INVALID") from exc
    package, summary = inspect_manifest(directory, contract)
    summary["schema"] = PROFILE
    summary["collector_schema"] = SCHEMA
    summary["collector_schema_verified"] = True
    summary["collection_status"] = manifest.get("status")
    summary["original_outcomes"] = dict(sorted(Counter(r["outcome"] for r in rows).items()))
    if facts is not None:
        summary["collection_facts"] = facts
    if group:
        summary["business_group"] = group
    summary["transport_digests"] = {
        "manifest": digests["manifest.json"],
        "index": digests["operations.jsonl"],
        "checksum_index": sha256_file(directory / "checksums.sha256"),
    }
    for result, origin in zip(summary["operations"], provenance, strict=True):
        result.update(origin)
        result["interpretation"] = interpretation(
            result["operation"],
            origin["original_outcome"],
            origin["original_error_code"],
            origin["derivation"],
        )
    listed = {p for r in summary["operations"] for p in [r["artifact_path"]] if p}
    pages = {name for row in rows for item in row["files"] for name in [item["path"]]}
    ancillary = {
        "manifest.json",
        "operations.jsonl",
        "checksums.sha256",
        "collection-summary.json",
        "retry-requests.json",
        f"accounts/{manifest['account_id']}/regions.json",
    } | {p for p in digests if p.startswith("scanners/")}
    summary["ancillary_files_verified_not_imported"] = len(ancillary & digests.keys())
    # Pages merged into a derived artifact are accounted for through source_pages.
    summary["unlisted_files"] = sorted(
        p
        for p in set(summary["unlisted_files"]) - ancillary - pages - listed
        if not p.startswith(DERIVED + "/")
    )
    summary["totals"]["unlisted_files"] = len(summary["unlisted_files"])
    summary["totals"]["journal_attempts"] = len(rows)
    summary["totals"]["derived_artifacts"] = sum(bool(r["derivation"]) for r in provenance)
    return package, summary
