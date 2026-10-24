"""Explicit pilot-1.2.2 adapter; local hashes never imply source authentication."""

import json
import re
from pathlib import Path
from typing import get_args

from pydantic import ValidationError

from offline_analyzer.contracts.gcp_expanded import ExpandedManifest, ExpandedManifest22
from offline_analyzer.contracts.gcp_legacy import ManifestDetection, Pilot15Manifest, PilotManifest
from offline_analyzer.contracts.r0 import Package, Source
from offline_analyzer.ingestion.archive import canonical_member
from offline_analyzer.ingestion.json_input import SECRET_VALUE, InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.ingestion.sidecars import metadata_names
from offline_analyzer.normalization.gcp import PROFILES, gcp_records, source_record_count

MANIFEST = "collection_manifest.json"
PROFILE = "gcp-pilot-1.2.2-adapter-1"
ADAPTERS = {
    "pilot-1.2.2": (PilotManifest, PROFILE),
    "pilot-1.5": (Pilot15Manifest, "gcp-pilot-1.5-adapter-1"),
    "assessment-expanded-2.1": (ExpandedManifest, "gcp-expanded-2.1-adapter-1"),
    "assessment-expanded-2.2": (ExpandedManifest22, "gcp-expanded-2.2-adapter-1"),
}
SUCCESS_STATUSES = {"SUCCESS", "EMPTY"}
INTEGRITY = "LOCAL_HASH_ONLY_NO_SOURCE_CHECKSUMS"
# File names are part of this versioned collector profile, not generic heuristics.
OPERATIONS = {
    "inventory/project.json": "gcp:projects.get",
    "inventory/assets.json": "gcp:cloudasset.searchAllResources",
    "inventory/asset_iam_search.json": "gcp:cloudasset.searchAllIamPolicies",
    "api/api_keys.json": "gcp:apikeys.keys.list",
    "api/enabled_services.json": "gcp:serviceusage.services.list",
    "identity/project_iam.json": "gcp:projects.getIamPolicy",
    "identity/service_accounts.json": "gcp:iam.serviceAccounts.list",
    "identity/custom_roles.json": "gcp:iam.roles.list",
    "governance/org_policies.json": "gcp:orgpolicy.policies.list",
    "logging/sinks.json": "gcp:logging.sinks.list",
    "logging/buckets_global.json": "gcp:logging.buckets.list",
    "logging/exclusions.json": "gcp:logging.exclusions.list",
    "monitoring/alert_policies.json": "gcp:monitoring.alertPolicies.list",
    "storage/buckets.json": "gcp:storage.buckets.list",
    "compute/instances.json": "gcp:compute.instances.list",
    "network/firewalls.json": "gcp:compute.firewalls.list",
    "network/networks.json": "gcp:compute.networks.list",
}


def manifest_data(directory: Path) -> dict:
    path = resolve_under(directory, MANIFEST)
    if path.stat().st_size > 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    inspect_json(path)
    data = json.loads(path.read_bytes())
    if not isinstance(data, dict):
        raise InputError("LEGACY_GCP_MANIFEST_INVALID")
    return data


# Collector versions the 2.2 evidence contract accepts (a wrong version is named, not reported
# as a generic contract failure).
GCP_COLLECTOR_VERSIONS_22 = get_args(
    ExpandedManifest22.model_fields["collector_version"].annotation
)


def unsupported_collector_version(data: dict) -> bool:
    """True when a 2.2 package declares a collector version outside the accepted range."""
    return (
        data.get("schema_version") == "assessment-expanded-2.2"
        and data.get("collector_version") not in GCP_COLLECTOR_VERSIONS_22
    )


def manifest_detection(directory: Path) -> dict:
    data = manifest_data(directory)
    version = data.get("schema_version")
    adapter = ADAPTERS.get(version) if isinstance(version, str) else None
    wrong_collector = unsupported_collector_version(data) if adapter else None
    display = (
        version
        if isinstance(version, str)
        and re.fullmatch(r"(?:pilot-|assessment-expanded-)[0-9]+(?:\.[0-9]+){0,3}", version)
        else "MISSING"
        if version is None
        else "UNRECOGNIZED_TOKEN"
    )
    return ManifestDetection(
        detected_version=display,
        selected_adapter=adapter[1] if adapter else "NONE",
        expected_versions=list(ADAPTERS),
        manifest_count=1,
        rejection_condition=(
            "collector_version is outside the accepted range for assessment-expanded-2.2 "
            "(2.2.0 to 2.2.8)"
        )
        if wrong_collector
        else None
        if adapter
        else "root schema_version is missing"
        if version is None
        else "root schema_version is not a supported collector version",
        corrective_action=None
        if adapter and not wrong_collector
        else (
            "Preserve the original package; use a CloSec adapter supporting its exact collector "
            "version. Do not rename or edit the manifest."
        ),
    ).model_dump(mode="json")


def read_manifest(directory: Path) -> PilotManifest | Pilot15Manifest:
    data = manifest_data(directory)
    version = data.get("schema_version")
    adapter = ADAPTERS.get(version) if isinstance(version, str) else None
    if adapter is None:
        raise InputError("UNSUPPORTED_MANIFEST_VERSION")
    if unsupported_collector_version(data):
        raise InputError("GCP_COLLECTOR_VERSION_UNSUPPORTED")
    try:
        return adapter[0].model_validate(data)
    except ValidationError as exc:
        raise InputError("LEGACY_GCP_MANIFEST_INVALID") from exc


def error_category(path: Path | None) -> str:
    if path is None:
        return "COLLECTION_FAILED"
    if path.stat().st_size > 1024 * 1024:
        raise InputError("LEGACY_STDERR_BYTE_LIMIT")
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if SECRET_VALUE.search(text):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    if re.search(r"Invalid choice|unrecognized arguments|invalid command", text, re.I):
        return "COLLECTOR_COMMAND_ERROR"
    if re.search(
        r"PERMISSION[_ ]DENIED|Permission.*denied|insufficient permission|access denied", text, re.I
    ):
        return "COLLECTION_PERMISSION_FAILURE"
    if re.search(r"SERVICE_DISABLED|API.*(?:not enabled|disabled)|has not been used", text, re.I):
        return "API_DISABLED_OR_UNAVAILABLE"
    return "COLLECTION_FAILED"


def inspect_failed_output(path: Path):
    """Failed stdout is retained as bytes, never usable facts or required valid JSON."""
    try:
        inspect_json(path)
    except InputError as exc:
        if str(exc) != "MALFORMED_JSON":
            raise
        # Still reject recognizable credential values without reporting source text.
        tail = ""
        with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
            while chunk := stream.read(65536):
                text = tail + chunk
                if SECRET_VALUE.search(text):
                    raise InputError("CREDENTIAL_MATERIAL_REJECTED") from None
                tail = text[-128:]


def inspect_package(directory: Path) -> tuple[Package, dict]:
    manifest = read_manifest(directory)
    if isinstance(manifest, ExpandedManifest):
        from offline_analyzer.ingestion.gcp_expanded import inspect_expanded

        return inspect_expanded(directory, manifest)
    allowed, referenced = {MANIFEST} | metadata_names(directory), set()
    profile = ADAPTERS[manifest.schema_version][1]
    if isinstance(manifest, Pilot15Manifest):
        asset_types = directory / "discovered_asset_types.json"
        if asset_types.is_file():
            if asset_types.is_symlink():
                raise InputError("UNSAFE_ARCHIVE_MEMBER")
            if asset_types.stat().st_size > 1024 * 1024:
                raise InputError("MANIFEST_BYTE_LIMIT")
            inspect_json(asset_types)
            if json.loads(asset_types.read_bytes()) != [
                row.model_dump() for row in manifest.discovered_asset_types
            ]:
                raise InputError("MANIFEST_FILE_REFERENCE_MISMATCH")
            allowed.add("discovered_asset_types.json")
    paths = []
    for dataset in manifest.datasets:
        row = []
        for value, is_error in ((dataset.file, False), (dataset.error_file, True)):
            name = canonical_member(value) if value else None
            if name:
                if name.casefold() in referenced:
                    raise InputError("MANIFEST_FILE_REFERENCE_MISMATCH")
                referenced.add(name.casefold())
                if (is_error and not name.endswith(".stderr.txt")) or (
                    not is_error and not name.endswith(".json")
                ):
                    raise InputError("UNSUPPORTED_SOURCE_FORMAT")
                path = resolve_under(directory, name)
                if path.is_symlink():
                    raise InputError("UNSAFE_ARCHIVE_MEMBER")
                if path.is_file():
                    allowed.add(name)
                elif dataset.status in SUCCESS_STATUSES:
                    raise InputError("MISSING_DECLARED_EVIDENCE")
                else:
                    name = None
            row.append(name)
        paths.append(row)
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise InputError("UNSAFE_ARCHIVE_MEMBER")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    if actual != allowed:
        raise InputError("MANIFEST_FILE_REFERENCE_MISMATCH")
    number = None
    project = directory / "inventory/project.json"
    project_collected = any(
        dataset.file
        and canonical_member(dataset.file) == "inventory/project.json"
        and dataset.status in SUCCESS_STATUSES
        for dataset in manifest.datasets
    )
    if project_collected and project.is_file():
        inspect_json(project)
        data = json.loads(project.read_bytes())
        if isinstance(data, dict):
            if data.get("projectId") not in {None, manifest.project_id}:
                from offline_analyzer.normalization.gcp_identity import mismatch

                raise mismatch(
                    "inventory/project.json",
                    manifest.project_id,
                    "projectId",
                    data.get("projectId"),
                )
            number = str(data["projectNumber"]) if data.get("projectNumber") is not None else None
            if (
                number is None
                and isinstance(data.get("name"), str)
                and re.fullmatch(r"projects/[0-9]{1,20}", data["name"])
            ):
                number = data["name"].split("/")[1]
    sources, diagnostics = [], []
    for dataset, (file, error_file) in zip(manifest.datasets, paths, strict=True):
        declared_file = canonical_member(dataset.file) if dataset.file else None
        operation_file = declared_file
        if isinstance(manifest, Pilot15Manifest) and not operation_file and error_file:
            operation_file = error_file.removesuffix(".stderr.txt") + ".json"
        operation = OPERATIONS.get(operation_file, "gcp:legacy.unsupported")
        failure = (
            error_category(directory / error_file if error_file else None)
            if dataset.status not in SUCCESS_STATUSES
            else None
        )
        if failure:
            failure = {
                "API_DISABLED": "API_DISABLED_OR_UNAVAILABLE",
                "AUTH_ERROR": "COLLECTION_AUTH_FAILURE",
                "ACCESS_DENIED": "COLLECTION_PERMISSION_FAILURE",
            }.get(dataset.status, failure)
        metadata = {
            "adapter_profile": profile,
            "contract_version": manifest.schema_version,
            "dataset_origin": manifest.dataset_origin,
            "status": dataset.status,
            "domain": dataset.domain,
            "dataset": dataset.dataset,
            "original_file": declared_file,
            "error_file": error_file,
            "local_file_sha256": sha256_file(directory / file) if file else None,
            "local_error_sha256": sha256_file(directory / error_file) if error_file else None,
            "project_display_name": manifest.project_name,
            "expected_projects": [manifest.project_id],
            "provenance": "legacy-unverified",
            "integrity_assurance": INTEGRITY,
            "source_checksum_declared": False,
            "pagination_complete": False,
            "started_at": dataset.started_utc.isoformat(),
            "completed_at": dataset.finished_utc.isoformat(),
            "declared_record_count": dataset.record_count,
            "exit_code": dataset.exit_code,
            "error_category": failure,
            "collection_correction_required": failure == "COLLECTOR_COMMAND_ERROR",
        }
        digest = sha256_file(directory / file) if file else None
        source = Source(
            path=file,
            sha256=digest,
            format="gcp-json-v1",
            operation=operation,
            project_id=manifest.project_id,
            project_number=number,
            region="global",
            collected_at=dataset.finished_utc,
            coverage="ERROR" if failure else "PARTIAL",
            errors=(failure,) if failure else (),
            collector_version=manifest.schema_version,
            request_parameters={},
            gcp_metadata=metadata,
        )
        count = 0
        if file:
            path = directory / file
            if dataset.status in SUCCESS_STATUSES:
                shape = inspect_json(path)
                count = source_record_count(path, source, shape)
                if dataset.status == "EMPTY" and count != 0:
                    raise InputError("LEGACY_EMPTY_RECORD_MISMATCH")
                for _ in gcp_records(path, source, "legacy-preflight", shape):
                    pass
            else:
                # Failed outputs remain raw input but are never parsed as usable facts.
                inspect_failed_output(path)
                source = source.model_copy(update={"path": None, "sha256": None})
        sources.append(source)
        diagnostics.append(
            {
                "operation": operation,
                "profile": profile,
                "parser_accepted": True,
                "parser_supported": operation in PROFILES,
                "effective_coverage": source.coverage,
                "original_status": dataset.status,
                "error_category": failure,
                "normalized_resource_records": count,
                "declared_record_count": dataset.record_count,
                "integrity_assurance": INTEGRITY,
                "source_checksum_verified": False,
            }
        )
    return Package(sources=tuple(sources)), {
        "sources": diagnostics,
        "contract_version": manifest.schema_version,
        "adapter_profile": profile,
        "project_id": manifest.project_id,
        "project_number": number,
        "original_status_totals": {
            s: sum(d.status == s for d in manifest.datasets)
            for s in (
                sorted({d.status for d in manifest.datasets})
                if isinstance(manifest, Pilot15Manifest)
                else ("SUCCESS", "EMPTY", "FAILED")
            )
        },
        "integrity_assurance": INTEGRITY,
        "source_checksum_verified": False,
        "real_export_validation": "NOT_ESTABLISHED",
        "raw_values_included": False,
        "qualification": (
            "Legacy collector has no source checksums; locally hashed bytes "
            "are unauthenticated. Pagination/completeness are unverified; "
            "failures are not empty inventories."
        ),
    }


def integrity_acknowledgment_required(directory: Path) -> bool:
    """Legacy/2.1 GCP packages declare no source checksums; 2.2 packages must verify them."""
    if not (directory / MANIFEST).is_file():
        return False
    try:
        return manifest_data(directory).get("schema_version") != "assessment-expanded-2.2"
    except InputError:
        return True
