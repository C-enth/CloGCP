"""Collector 0.3.0 transport adapter, with an explicit analyzer field profile.

The collector's actual schema ID/layout is not established by this profile. Unknown
layouts fail closed; a local probe returns only allowlisted field presence and outcomes.
Native response paths always come from the journal, never a guessed directory structure.
"""

import json
import re
import tempfile
from collections import Counter
from pathlib import Path

from offline_analyzer.ingestion.json_input import (
    MAX_BYTES,
    MAX_PACKAGE_BYTES,
    MAX_PACKAGE_FILES,
    InputError,
    inspect_json,
)
from offline_analyzer.ingestion.safety import resolve_under, sha256_file, validate_relative_path

PROFILE = "closec-v030-index-1"
OUTCOMES = {"COMPLETE", "PARTIAL", "API_ERROR", "ACCESS_DENIED", "NOT_ENABLED", "NOT_COLLECTED"}
MANIFEST_REQUIRED = {
    "collector_version",
    "collection_id",
    "account_id",
    "started_at",
    "completed_at",
    "regions",
}
ROW_REQUIRED = {"operation", "region", "status", "started_at", "completed_at"}
OPTIONAL = {
    "path",
    "sha256",
    "pages",
    "pagination",
    "request_parameters",
    "error_code",
    "format",
    "tool_version",
    "resource_region",
}
OPERATION = re.compile(r"^[a-z][a-z0-9-]{1,39}:[A-Z][A-Za-z0-9]{1,79}$")
CHECKSUM = re.compile(r"^([0-9a-fA-F]{64}) [ *](.+)$")


def read_index(directory: Path) -> list[dict]:
    path = resolve_under(directory, "operations.jsonl")
    if path.stat().st_size > 64 * 1024 * 1024:
        raise InputError("OPERATION_INDEX_BYTE_LIMIT")
    rows = []
    with tempfile.TemporaryDirectory() as temporary, path.open("rb") as stream:
        local = Path(temporary) / "row.json"
        while line := stream.readline(2 * 1024 * 1024 + 1):
            if len(line) > 2 * 1024 * 1024:
                raise InputError("RECORD_BYTE_LIMIT")
            if not line.strip():
                continue
            if len(rows) >= MAX_PACKAGE_FILES:
                raise InputError("OPERATION_INDEX_RECORD_LIMIT")
            local.write_bytes(line)
            inspect_json(local)
            row = json.loads(line)
            if not isinstance(row, dict):
                raise InputError("OPERATION_INDEX_OBJECT_REQUIRED")
            rows.append(row)
    if not rows:
        raise InputError("OPERATION_INDEX_EMPTY")
    return rows


def read_metadata(directory: Path) -> dict:
    path = resolve_under(directory, "manifest.json")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    inspect_json(path)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("collector_version") != "0.3.0":
        raise InputError("COLLECTOR_VERSION_PROFILE_UNSUPPORTED")
    return value


def probe(directory: Path) -> dict:
    """Safe diagnostics even when required fields for import are absent. No unknown keys."""
    manifest, rows = read_metadata(directory), read_index(directory)
    counts = Counter(
        r.get("status")
        if isinstance(r.get("status"), str) and r.get("status") in OUTCOMES
        else "UNRECOGNIZED"
        for r in rows
    )
    operations = Counter(
        r.get("operation")
        if isinstance(r.get("operation"), str) and OPERATION.fullmatch(r["operation"])
        else "UNRECOGNIZED"
        for r in rows
    )
    return {
        "adapter_profile": PROFILE,
        "collector_version": "0.3.0",
        "collector_schema_verified": False,
        "schema_field_present": "schema" in manifest or "schema_id" in manifest,
        "attempts": len(rows),
        "original_outcomes": dict(sorted(counts.items())),
        "operations": [
            {"operation": op, "attempts": count} for op, count in sorted(operations.items())
        ],
        "missing_manifest_fields": sorted(MANIFEST_REQUIRED - manifest.keys()),
        "index_field_presence": {
            key: sum(key in r for r in rows) for key in sorted(ROW_REQUIRED | OPTIONAL)
        },
        "index_rows_missing_required_fields": sum(not ROW_REQUIRED <= r.keys() for r in rows),
        "real_export_validation": "NOT_ESTABLISHED",
    }


def verify_checksums(directory: Path) -> dict[str, str]:
    from offline_analyzer.ingestion.collector_v030_native import DERIVED
    from offline_analyzer.ingestion.sidecars import metadata_names

    metadata = metadata_names(directory)
    if any(p.is_symlink() for p in directory.rglob("*")):
        raise InputError("SYMLINK_IN_PACKAGE")
    # Adapter-derived artifacts are regenerated from verified inputs; never collector files.
    files = [
        p
        for p in directory.rglob("*")
        if p.is_file() and p.relative_to(directory).parts[0] != DERIVED
    ]
    if len(files) > MAX_PACKAGE_FILES or any(p.stat().st_size > MAX_BYTES for p in files):
        raise InputError("PACKAGE_FILE_LIMIT")
    if sum(p.stat().st_size for p in files) > MAX_PACKAGE_BYTES:
        raise InputError("PACKAGE_BYTE_LIMIT")
    path = resolve_under(directory, "checksums.sha256")
    if path.stat().st_size > 1024 * 1024:
        raise InputError("CHECKSUM_INDEX_BYTE_LIMIT")
    digests = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = CHECKSUM.fullmatch(line)
            if not match:
                raise InputError("CHECKSUM_INDEX_INVALID")
            digest, name = match.groups()
            validate_relative_path(name)
            if name in digests or name == "checksums.sha256" or name.startswith(DERIVED + "/"):
                raise InputError("CHECKSUM_INDEX_DUPLICATE_OR_SELF")
            target = resolve_under(directory, name)
            if not target.is_file() or sha256_file(target) != digest.lower():
                raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
            digests[name] = digest.lower()
    except (UnicodeError, OSError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("CHECKSUM_INDEX_INVALID") from exc
    present = {p.relative_to(directory).as_posix() for p in files} - {"checksums.sha256"}
    if present - metadata != digests.keys() - metadata:
        raise InputError("CHECKSUM_INVENTORY_INCOMPLETE")
    return digests


def interpretation(operation: str, status: str, error: str | None) -> str:
    if (
        operation == "s3api:GetBucketReplication"
        and error == "ReplicationConfigurationNotFoundError"
    ):
        return "REPLICATION_CONFIGURATION_ABSENT_NO_SECURITY_CONTROL_IMPLEMENTED"
    if operation == "organizations:ListRoots" and status != "COMPLETE":
        return "ORGANIZATION_POLICY_INHERITANCE_UNRESOLVED"
    if status == "ACCESS_DENIED":
        return "ACCESS_DENIED_FOR_THIS_ATTEMPT_SERVICE_STATE_UNKNOWN"
    if status == "NOT_ENABLED":
        return "COLLECTOR_REPORTED_NOT_ENABLED_ANALYZER_STATE_UNVERIFIED"
    if operation == "cloudtrail:GetEventSelectors" and status == "API_ERROR":
        return "EVENT_SELECTOR_COVERAGE_UNKNOWN_RECOLLECT_WITH_TRAILNAME"
    return "COLLECTOR_OUTCOME_PRESERVED"


def inspect_v030(directory: Path):
    from offline_analyzer.ingestion.collector import ERROR_CODE, CollectorManifest, inspect_manifest
    from offline_analyzer.ingestion.collector_v030_native import inspect_native, is_native

    if is_native(directory):
        return inspect_native(directory)

    digests = verify_checksums(directory)
    metadata, rows = read_metadata(directory), read_index(directory)
    if not MANIFEST_REQUIRED <= metadata.keys() or any(not ROW_REQUIRED <= r.keys() for r in rows):
        raise InputError("COLLECTOR_V030_FIELD_PROFILE_INCOMPLETE_RUN_PILOT_PROBE")
    operations, originals = [], []
    try:
        for row in rows:
            original = row["status"]
            if not isinstance(original, str) or original not in OUTCOMES:
                raise InputError("COLLECTION_OUTCOME_UNSUPPORTED")
            operation = row["operation"]
            if not isinstance(operation, str) or not OPERATION.fullmatch(operation):
                raise InputError("OPERATION_IDENTIFIER_INVALID")
            if operation.startswith("s3:"):
                operation = "s3api:" + operation.split(":", 1)[1]
            path = row.get("path")
            if path and (
                not isinstance(path, str) or not path.endswith(".json") or path not in digests
            ):
                raise InputError("OPERATION_ARTIFACT_REFERENCE_INVALID")
            if row.get("sha256") and row["sha256"] != digests.get(path):
                raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
            status = (
                "SUCCEEDED"
                if original in {"COMPLETE", "PARTIAL"}
                else "SKIPPED"
                if original == "NOT_COLLECTED"
                else "FAILED"
            )
            pagination = row.get("pagination", "TRUNCATED" if path else "NOT_PAGINATED")
            if original == "PARTIAL":
                pagination = "TRUNCATED"
            error = row.get("error_code")
            if error is not None and (
                not isinstance(error, str) or not ERROR_CODE.fullmatch(error)
            ):
                raise InputError("OPERATION_ERROR_CODE_INVALID")
            if status == "FAILED":
                error = error or ("AccessDenied" if original == "ACCESS_DENIED" else original)
            else:
                error = None  # The original error remains in persisted journal metadata below.
            resource_region = row.get("resource_region")
            outside = bool(
                resource_region
                and resource_region != "global"
                and resource_region not in metadata["regions"]
            )
            # Retain the artifact and attempt but never assess evidence explicitly outside scope.
            if outside:
                status, path, error = "SKIPPED", None, None
            operations.append(
                {
                    "operation": operation,
                    "region": row["region"],
                    "status": status,
                    "path": path,
                    "sha256": digests.get(path),
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                    "pages": row.get("pages", 0),
                    "pagination": pagination,
                    "request_parameters": row.get("request_parameters", {}),
                    "error_code": error,
                    "format": row.get("format", "aws-json-v1"),
                    "tool_version": row.get("tool_version"),
                }
            )
            originals.append((original, row.get("error_code"), outside))
        manifest = CollectorManifest.model_validate(
            {
                # Internal adapter target, never the collector schema ID.
                "schema": "closec-collector-1",
                "package_id": metadata["collection_id"],
                "collector": {"name": "CloSec", "version": "0.3.0"},
                "account_id": metadata["account_id"],
                "partition": metadata.get("partition", "aws"),
                "dataset_origin": metadata.get("dataset_origin"),
                "regions": metadata["regions"],
                "started_at": metadata["started_at"],
                "completed_at": metadata["completed_at"],
                "operations": operations,
            }
        )
    except (ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("COLLECTOR_V030_FIELD_PROFILE_INVALID_RUN_PILOT_PROBE") from exc
    package, summary = inspect_manifest(directory, manifest)
    summary["schema"] = PROFILE
    summary["collector_schema_verified"] = False
    summary["original_outcomes"] = dict(sorted(Counter(r["status"] for r in rows).items()))
    # Bind import identity/provenance to the original manifest, journal and complete inventory.
    summary["transport_digests"] = {
        "manifest": digests["manifest.json"],
        "index": digests["operations.jsonl"],
        "checksum_index": sha256_file(directory / "checksums.sha256"),
    }
    for result, (status, error, outside) in zip(summary["operations"], originals, strict=True):
        result["original_outcome"] = status
        result["original_error_code"] = error
        result["interpretation"] = (
            "RESOURCE_OUTSIDE_APPROVED_REGION_NOT_ASSESSED"
            if outside
            else interpretation(result["operation"], status, error)
        )
    ancillary = {
        "manifest.json",
        "operations.jsonl",
        "checksums.sha256",
        "collection-summary.json",
        "retry-requests.json",
    }
    ancillary |= {p for p in digests if p.startswith("scanners/") and p.endswith((".log", ".csv"))}
    summary["ancillary_files_verified_not_imported"] = len(
        ancillary & (digests.keys() | {"checksums.sha256"})
    )
    summary["unlisted_files"] = sorted(set(summary["unlisted_files"]) - ancillary)
    summary["totals"]["unlisted_files"] = len(summary["unlisted_files"])
    return package, summary
