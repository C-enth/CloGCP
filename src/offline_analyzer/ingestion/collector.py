"""Versioned collector packages (`closec-collector-1`) mapped onto the existing r0.1 package.

A collector writes one immutable package per account/run: native AWS JSON responses plus
`collector-manifest.json` with per-operation metadata. Loading converts it deterministically
into the existing `Package`, so import, verification, run identity and provenance are
unchanged. Operations the analyzer cannot parse and files the manifest does not list are
reported in the collection summary, never silently dropped.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, model_validator

from offline_analyzer.contracts.models import AccountId, Digest, Identifier
from offline_analyzer.contracts.r0 import (
    AWS_OPERATIONS,
    GLOBAL_OPERATIONS,
    NORMALIZATION_VERSION,
    VERSION,
    Package,
    Source,
)
from offline_analyzer.ingestion.json_input import InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under, sha256_file, validate_relative_path

COLLECTOR_MANIFEST = "collector-manifest.json"
COLLECTOR_SCHEMA = "closec-collector-1"
CONTRACT_VERSION = "1.2.0"
PROWLER_VERSION = "5.10.0"
PROWLER_PROFILES = {"prowler-ocsf-5.10": "5.10.0", "prowler-ocsf-5.26.1": "5.26.1"}
MAX_OPERATIONS = 20000
ERROR_CODE = re.compile(r"^[A-Za-z0-9.:_-]{1,128}$")
SUPPORTED = frozenset(AWS_OPERATIONS) | {"prowler:Scan"}


class CollectorContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Collector(CollectorContract):
    name: Identifier
    version: Identifier


class Operation(CollectorContract):
    operation: Annotated[str, Field(pattern=r"^[a-z0-9-]{2,40}:[A-Za-z0-9]{2,80}$")]
    region: Identifier
    status: Literal["SUCCEEDED", "FAILED", "SKIPPED"]
    format: Literal["aws-json-v1", "prowler-ocsf-5.10", "prowler-ocsf-5.26.1"] = "aws-json-v1"
    path: Identifier | None = None
    sha256: Digest | None = None
    started_at: AwareDatetime
    completed_at: AwareDatetime
    pages: Annotated[int, Field(ge=0, le=100000)] = 0
    pagination: Literal["NOT_PAGINATED", "ALL_PAGES_MERGED", "TRUNCATED"] = "NOT_PAGINATED"
    request_parameters: dict[str, JsonValue] = {}
    error_code: Annotated[str, Field(pattern=ERROR_CODE.pattern)] | None = None
    tool_version: Identifier | None = None

    @model_validator(mode="after")
    def consistent(self):
        for stamp in (self.started_at, self.completed_at):
            if stamp.utcoffset().total_seconds() != 0:
                raise ValueError("timestamps must be UTC")
        if self.completed_at < self.started_at:
            raise ValueError("operation completed before it started")
        if self.path:
            validate_relative_path(self.path)
            if not self.sha256:
                raise ValueError("artifact checksum required")
        if self.status == "SUCCEEDED" and not self.path:
            raise ValueError("successful operation requires artifact")
        if self.status == "FAILED" and not self.error_code:
            raise ValueError("failed operation requires error code")
        if self.status == "SUCCEEDED" and self.error_code:
            raise ValueError("successful operation cannot carry error code")
        if self.format.startswith("prowler-") != (self.operation == "prowler:Scan"):
            raise ValueError("operation/format mismatch")
        if self.operation == "prowler:Scan" and self.tool_version not in (
            None,
            PROWLER_PROFILES[self.format],
        ):
            raise ValueError("unsupported Prowler version")
        if self.status == "SUCCEEDED" and self.pages < 1:
            raise ValueError("successful collection requires page count")
        if self.pagination == "NOT_PAGINATED" and self.pages > 1:
            raise ValueError("multiple pages require merged or truncated status")
        if self.status == "SKIPPED" and self.path:
            raise ValueError("skipped operation cannot carry an artifact")
        return self


class CollectorManifest(CollectorContract):
    schema_id: Literal["closec-collector-1"] = Field(alias="schema")
    package_id: Identifier
    collector: Collector
    account_id: AccountId
    partition: Literal["aws", "aws-cn", "aws-us-gov"] = "aws"
    dataset_origin: Literal["SYNTHETIC", "TOOL_GENERATED"] | None = None
    started_at: AwareDatetime
    completed_at: AwareDatetime
    regions: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=64)]
    operations: Annotated[tuple[Operation, ...], Field(min_length=1, max_length=MAX_OPERATIONS)]

    @model_validator(mode="after")
    def consistent(self):
        from offline_analyzer.normalization.adapters import region_partition

        for stamp in (self.started_at, self.completed_at):
            if stamp.utcoffset().total_seconds() != 0:
                raise ValueError("timestamps must be UTC")
        if self.completed_at < self.started_at:
            raise ValueError("package completed before it started")
        if len(set(self.regions)) != len(self.regions):
            raise ValueError("duplicate Regions")
        if any(r != "global" and region_partition(r) != self.partition for r in self.regions):
            raise ValueError("Region does not match declared partition")
        for operation in self.operations:
            if operation.started_at < self.started_at or operation.completed_at > self.completed_at:
                raise ValueError("operation outside collection window")
            if operation.region != "global" and operation.region not in self.regions:
                raise ValueError("operation Region not declared")
        paths = [o.path for o in self.operations if o.path]
        if len(set(paths)) != len(paths):
            raise ValueError("artifact listed twice")
        return self


def has_collector_manifest(directory: Path) -> bool:
    return (
        (directory / COLLECTOR_MANIFEST).is_file() and not (directory / "manifest.json").exists()
    ) or ((directory / "manifest.json").is_file() and (directory / "operations.jsonl").is_file())


def read_manifest(directory: Path) -> CollectorManifest:
    path = resolve_under(directory, COLLECTOR_MANIFEST)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    inspect_json(path)  # Same duplicate-key/depth/size safety as every other input.
    try:
        return CollectorManifest.model_validate_json(path.read_bytes())
    except ValueError as exc:
        raise InputError("COLLECTOR_MANIFEST_INVALID") from exc


def source_for(manifest: CollectorManifest, op: Operation) -> Source:
    coverage = {
        "SUCCEEDED": "PARTIAL" if op.pagination == "TRUNCATED" else "COMPLETE",
        "FAILED": "ERROR",
        "SKIPPED": "NOT_COLLECTED",
    }[op.status]
    return Source(
        path=op.path,
        sha256=op.sha256,
        format=op.format,
        operation=op.operation,
        account_id=manifest.account_id,
        partition=manifest.partition,
        region=op.region,
        collected_at=op.completed_at,
        coverage=coverage,
        errors=(op.error_code,) if op.error_code else (),
        collector_version=f"{manifest.collector.name}/{manifest.collector.version}",
        request_parameters=op.request_parameters if op.format == "aws-json-v1" else None,
    )


def inspect_collector(directory: Path) -> tuple[Package, dict]:
    """Integrity-checked conversion plus an operation-level summary (no evidence values)."""
    if (directory / "operations.jsonl").is_file():
        from offline_analyzer.ingestion.collector_v030 import inspect_v030

        return inspect_v030(directory)
    return inspect_manifest(directory, read_manifest(directory))


def inspect_manifest(directory: Path, manifest: CollectorManifest) -> tuple[Package, dict]:
    """Shared native import contract; adapters supply validated collection metadata."""
    if any(p.is_symlink() for p in directory.rglob("*")):
        raise InputError("SYMLINK_IN_PACKAGE")
    listed = {o.path for o in manifest.operations if o.path}
    present = {
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file() and p.name != COLLECTOR_MANIFEST
    }
    missing = listed - present
    if missing:
        raise InputError("COLLECTOR_ARTIFACT_MISSING")
    total_bytes = sum(resolve_under(directory, p).stat().st_size for p in present)
    if total_bytes > 256 * 1024 * 1024:
        raise InputError("PACKAGE_BYTE_LIMIT")
    for op in manifest.operations:
        if op.path and sha256_file(resolve_under(directory, op.path)) != op.sha256:
            raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
        if op.path and op.operation not in SUPPORTED:
            inspect_json(resolve_under(directory, op.path))
    for op in manifest.operations:
        if op.operation == "sts:GetCallerIdentity" and op.status == "SUCCEEDED":
            inspect_json(resolve_under(directory, op.path))
            identity = json.loads(resolve_under(directory, op.path).read_text())
            arn = str(identity.get("Arn", "")).split(":")
            if (
                identity.get("Account") != manifest.account_id
                or len(arn) < 6
                or (
                    arn[0] != "arn" or arn[1] != manifest.partition or arn[4] != manifest.account_id
                )
            ):
                raise InputError("COLLECTOR_IDENTITY_MISMATCH")
    sources, rows = [], []
    for op in manifest.operations:
        supported = op.operation in SUPPORTED
        source = source_for(manifest, op) if supported else None
        if source:
            sources.append(source)
        rows.append(
            {
                "operation": op.operation,
                "region": op.region,
                "status": op.status,
                "started_at": op.started_at.isoformat(),
                "completed_at": op.completed_at.isoformat(),
                "pages": op.pages,
                "pagination": op.pagination,
                "error_code": op.error_code,
                "artifact_sha256": op.sha256,
                "artifact_path": op.path,
                "declared_coverage": source.coverage if source else None,
                "import_handling": "IMPORTED" if supported else "UNSUPPORTED_OPERATION_RETAINED",
            }
        )
    if not sources:
        raise InputError("NO_SUPPORTED_OPERATIONS")
    try:
        package = Package(
            targets=tuple(
                {"account_id": manifest.account_id, "region": r} for r in manifest.regions
            ),
            sources=tuple(sources),
        )
    except ValueError as exc:
        raise InputError("COLLECTOR_PACKAGE_EXCEEDS_CONTRACT") from exc
    statuses = [r["status"] for r in rows]
    summary = {
        "schema": COLLECTOR_SCHEMA,
        "package_id": manifest.package_id,
        "collector": manifest.collector.model_dump(),
        "account_id": manifest.account_id,
        "partition": manifest.partition,
        "dataset_origin": manifest.dataset_origin,
        "regions": list(manifest.regions),
        "started_at": manifest.started_at.isoformat(),
        "completed_at": manifest.completed_at.isoformat(),
        "operations": rows,
        "totals": {
            "operations": len(rows),
            "succeeded": statuses.count("SUCCEEDED"),
            "failed": statuses.count("FAILED"),
            "skipped": statuses.count("SKIPPED"),
            "truncated": sum(r["pagination"] == "TRUNCATED" for r in rows),
            "imported": len(sources),
            "unsupported_operations": sum(r["import_handling"] != "IMPORTED" for r in rows),
            "unlisted_files": len(present - listed),
        },
        "unlisted_files": sorted(present - listed),
    }
    return package, summary


def store_summary(workspace: Path, run_id: str, summary: dict) -> None:
    """Workspace-local; reimport of the same run must describe the same package."""
    directory = resolve_under(workspace, "collections")
    directory.mkdir(mode=0o700, exist_ok=True)
    path = resolve_under(directory, f"{run_id}.json")
    data = json.dumps(summary, sort_keys=True, indent=1)
    if path.exists():
        if path.read_text(encoding="utf-8") != data:
            raise InputError("COLLECTION_SUMMARY_CONFLICT")
        return
    staged = path.with_suffix(".json.partial")
    try:
        staged.write_text(data, encoding="utf-8")
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)


def retain_unsupported(workspace: Path, directory: Path, summary: dict) -> None:
    """Keep verified bytes of unparsed operations in the content-addressed raw store."""
    raw = resolve_under(workspace, "raw")
    raw.mkdir(mode=0o700, exist_ok=True)
    for row in summary["operations"]:
        if row["import_handling"] == "IMPORTED" or not row["artifact_path"]:
            continue
        destination = resolve_under(raw, f"{row['artifact_sha256']}.json")
        if destination.exists():
            if sha256_file(destination) != row["artifact_sha256"]:
                raise InputError("STORED_RAW_INTEGRITY_FAILURE")
            continue
        data = resolve_under(directory, row["artifact_path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != row["artifact_sha256"]:
            raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
        destination.write_bytes(data)


def stored_summary(workspace: Path, run_id: str) -> dict | None:
    if not re.fullmatch(r"run-[0-9a-f]{64}", run_id):
        return None
    path = workspace / "collections" / f"{run_id}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def sanitized(summary: dict) -> dict:
    """Shareable form: operation metadata and counts, no account, paths or digests."""
    result = {
        "schema": summary["schema"],
        "collector": summary["collector"],
        "partition": summary["partition"],
        "region_count": len(summary["regions"]),
        "totals": summary["totals"],
        "operations": [
            {
                k: r[k]
                for k in (
                    "operation",
                    "status",
                    "pages",
                    "pagination",
                    "error_code",
                    "import_handling",
                )
            }
            for r in summary["operations"]
        ],
    }
    if "original_outcomes" in summary:
        result["original_outcomes"] = summary["original_outcomes"]
        result["collector_schema_verified"] = False
        for public, original in zip(result["operations"], summary["operations"], strict=True):
            public["original_outcome"] = original["original_outcome"]
            public["interpretation"] = original["interpretation"]
    return result


def contract() -> dict:
    """Machine-readable analyzer/collector contract generated from the source registries."""
    from offline_analyzer.ingestion.coverage import DEFINED_ABSENCE, PARAMETERS, SELECTORS
    from offline_analyzer.normalization.adapters import AWS_SHAPES, SINGLETONS
    from offline_analyzer.normalization.enterprise_adapters import PROFILES
    from offline_analyzer.normalization.iam_adapters import LIST_KINDS, ORG_LISTS, SINGLE
    from offline_analyzer.verification import REQUIRED, REQUIRED_AWS

    def structure(operation):
        if operation in AWS_SHAPES:
            top, prefix, children, _, _ = AWS_SHAPES[operation]
            return {"root": top, "record_prefix": prefix, "children": children, "type": "array"}
        if operation in PROFILES:
            top, prefix, _, _, _, _ = PROFILES[operation]
            return {
                "root": top,
                "record_prefix": prefix,
                "type": "array"
                if prefix.endswith(".item")
                else "string"
                if top == "Policy"
                else "object",
            }
        if operation in LIST_KINDS or operation in ORG_LISTS:
            root = (LIST_KINDS.get(operation) or ORG_LISTS.get(operation))[0]
            return {"root": root, "type": "array"}
        if operation in SINGLE:
            return {"root": SINGLE[operation][0] or "$", "type": "object"}
        if operation in SINGLETONS:
            return {
                "root": SINGLETONS[operation][0],
                "type": "array" if operation.endswith("GetBucketAcl") else "object",
            }
        return {"root": "$", "type": "object"}

    operations = []
    for op in AWS_OPERATIONS:
        operations.append(
            {
                "operation": op,
                "boto3_service": "s3" if op.startswith("s3api:") else op.split(":")[0],
                "boto3_method": re.sub(
                    r"([a-z0-9])([A-Z])",
                    lambda match: match[1] + "_" + match[2],
                    re.sub(
                        r"(.)([A-Z][a-z]+)",
                        lambda match: match[1] + "_" + match[2],
                        op.split(":")[1],
                    ),
                ).lower(),
                "native_structure": structure(op),
                "format": "aws-json-v1",
                "scope": "GLOBAL" if op in GLOBAL_OPERATIONS else "REGIONAL",
                "required_response_fields": REQUIRED_AWS.get(op, {}),
                "accepted_request_parameters": sorted(PARAMETERS.get(op, ())),
                "selector_parameters_downgrade_completeness": sorted(SELECTORS.get(op, ())),
                "defined_absence_error_code": DEFINED_ABSENCE.get(op),
            }
        )
    for profile, version in PROWLER_PROFILES.items():
        operations.append(
            {
                "operation": "prowler:Scan",
                "format": profile,
                "scope": "SUPPLEMENTARY",
                "required_response_fields": REQUIRED[profile],
                "tool_version": version,
                "validation": "SOURCE_REVIEWED_SYNTHETIC_TESTED_REAL_EXPORT_NOT_ESTABLISHED",
                "note": (
                    "Scanner output cannot establish inventory completeness or analyst approval."
                ),
            }
        )
    return {
        "contract": "closec-analyzer-collector",
        "contract_version": CONTRACT_VERSION,
        "package_schema": COLLECTOR_SCHEMA,
        "analyzer_package_schema": VERSION,
        "normalizer": NORMALIZATION_VERSION,
        "manifest_file": COLLECTOR_MANIFEST,
        "manifest_json_schema": CollectorManifest.model_json_schema(by_alias=True),
        "collector_v030": {
            "adapter_profile": "closec-v030-index-1",
            "collector_schema_id": None,
            "real_export_validation": "NOT_ESTABLISHED",
            "manifest_file": "manifest.json",
            "operation_index_file": "operations.jsonl",
            "checksum_file": "checksums.sha256",
            "manifest_required_fields": [
                "collector_version",
                "collection_id",
                "account_id",
                "started_at",
                "completed_at",
                "regions",
            ],
            "index_required_fields": [
                "operation",
                "region",
                "status",
                "started_at",
                "completed_at",
            ],
            "artifact_reference": (
                "Explicit path in index; SHA-256 from checksums.sha256. No directory inference."
            ),
            "pagination": (
                "pages and pagination required for COMPLETE/PARTIAL artifacts; "
                "missing pagination never COMPLETE"
            ),
            "outcomes": [
                "COMPLETE",
                "PARTIAL",
                "API_ERROR",
                "ACCESS_DENIED",
                "NOT_ENABLED",
                "NOT_COLLECTED",
            ],
            "limitations": (
                "Field profile is synthetic-tested, not verified against the pilot manifest. "
                "Unknown required layouts fail closed with local diagnostic codes."
            ),
        },
        "package_rules": [
            "One immutable directory per account and collection run; never modify after "
            "writing the manifest.",
            "Every artifact is a native AWS JSON response (or Prowler OCSF array) listed "
            "exactly once with its SHA-256; unlisted files are reported, not imported.",
            "All timestamps are UTC with an explicit offset (Z or +00:00).",
            "Global operations use region 'global'; regional operations use the AWS Region.",
            "Package account_id is the 12-digit account the credentials resolved to.",
            "Unsupported operations may be included; they are retained in the collection "
            "summary as UNSUPPORTED_OPERATION_RETAINED and are not parsed.",
            "At most 256 supported operation records per package (analyzer source limit); "
            "split larger collections into multiple packages for the same account.",
        ],
        "pagination_rules": [
            "Merge all pages into one native-shaped response (boto3 "
            "paginator.paginate().build_full_result()) and record pagination "
            "ALL_PAGES_MERGED with the page count.",
            "Any residual NextToken/Marker/NextMarker or IsTruncated=true downgrades "
            "coverage to PARTIAL.",
            "pagination TRUNCATED is imported as PARTIAL coverage.",
            "Never record a starting NextToken/Marker in request_parameters for a complete "
            "collection; that marks the source as starting mid-listing.",
        ],
        "error_rules": [
            "FAILED requires error_code (the AWS error code, e.g. AccessDenied); imported "
            "as ERROR coverage. Missing evidence never becomes PASS.",
            "SKIPPED is imported as NOT_COLLECTED.",
            "Defined-absence codes (defined_absence_error_code) are configuration states; "
            "store the error response body as the artifact with status SUCCEEDED.",
        ],
        "import_conventions": [
            (
                "GUI: Evidence import -> select collector ZIP or package folder -> Validate "
                "evidence -> Import."
            ),
            "CLI: cli --workspace W import <package> --origin tool-generated.",
            "Assessment workspaces accept only origin tool-generated.",
            "Identical package bytes reimport to the same run; analyst decisions persist.",
        ],
        "source_version_limitations": [
            "Response shapes are validated structurally by the field verifier; real-export "
            "compatibility is established only by running the verifier on actual "
            "tool-generated packages.",
            (
                "Prowler OCSF profiles accept exact versions 5.10.0 and 5.26.1; unknown "
                "versions fail closed."
            ),
            "Per-role IAM Get*/List* calls are supported but GetAccountAuthorizationDetails "
            "is preferred to stay within the per-package source limit.",
        ],
        "supported_operations": operations,
        "known_unsupported_operations": [
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "securityhub:DescribeHub",
            "config:DescribeConfigurationRecorders",
            "config:DescribeConfigurationRecorderStatus",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            "s3api:ListBuckets",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
        ],
        "unsupported_policy": (
            "Operations absent from supported_operations are retained but never "
            "normalized/evaluated."
        ),
        "operation_index": {
            "location": "collector-manifest.json operations[]",
            "separate_index_file_supported": False,
            "pagination_record": ["pages", "pagination"],
            "partial_page_artifacts_supported": False,
        },
        "accepted_structures": (
            "Native AWS response objects with registered root/list fields; no CLI "
            "--query transformations or arbitrary wrappers. Prowler is an OCSF Detection "
            "Finding array, class_uid 2004."
        ),
        "example_package": [
            "collector-manifest.json",
            "responses/identity.json",
            "responses/iam-authorization.json",
            "responses/ec2-us-east-1.json",
            "responses/prowler-ocsf.json",
        ],
        "iam_scope": (
            "Roles, trust, attached and inline documents, default managed versions and "
            "boundaries are parsed; UserDetailList/GroupDetailList are preserved raw but "
            "not evaluated. Missing versions remain unresolved."
        ),
        "version_compatibility": {
            "collector_schema": COLLECTOR_SCHEMA,
            "canonical_schema": VERSION,
            "prior_databases_readable": True,
            "mixed_normalizers_in_one_enterprise_snapshot": False,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Write the analyzer/collector contract")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(contract(), indent=2, sort_keys=True), encoding="utf-8")
    print(
        f"Contract {CONTRACT_VERSION}: {len(contract()['supported_operations'])} operation profiles"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
