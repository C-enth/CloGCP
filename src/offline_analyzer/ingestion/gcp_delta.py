"""Strict offline delta transport adapter; no collection or rule decisions."""

import json
from pathlib import Path

from clogcp_delta.collector import load, semantic, sha
from clogcp_delta.models import Manifest
from offline_analyzer.contracts.r0 import Package, Source
from offline_analyzer.ingestion.json_input import InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under

CATALOGUE = {
    "BUCKET_IAM": ("gcp:storage.buckets.getIamPolicy", "bucket_iam", "GCP::IAMPolicy", "Run"),
    "FOLDER_IAM": ("gcp:folders.getIamPolicy", "folder_iam", "GCP::IAMPolicy", "Run"),
    "FOLDER_METADATA": ("gcp:folders.get", "folder_describe", "GCP::Folder", "Run"),
    "DISCOVERY_ENGINES": (
        "gcp:discoveryengine.engines.list",
        "discovery_engines",
        "GCP::DiscoveryEngine",
        "RestList",
    ),
    "DISCOVERY_DATASTORES": (
        "gcp:discoveryengine.dataStores.list",
        "discovery_datastores",
        "GCP::DiscoveryDataStore",
        "RestList",
    ),
    "DISCOVERY_RESOURCE": (
        "gcp:discoveryengine.resources.get",
        "discovery_resource",
        "GCP::DiscoveryResource",
        "Invoke-RestEvidence",
    ),
    "IAM_RECOMMENDATIONS": (
        "gcp:delta.iamRecommendations",
        "unsupported",
        "GCP::Unsupported",
        "Run",
    ),
}


def inspect_package(directory: Path) -> tuple[Package, dict]:
    try:
        manifest = Manifest.model_validate(load(resolve_under(directory, "manifest.json")))
    except (ValueError, OSError) as exc:
        raise InputError("GCP_DELTA_MANIFEST_INVALID") from exc
    allowed = {"manifest.json", *[r.file for r in manifest.results if r.file]}
    if {
        p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()
    } != allowed:
        raise InputError("GCP_DELTA_UNLISTED_OR_MISSING_ARTIFACT")
    sources, states, diagnostics = [], [], []
    if sum(p.stat().st_size for p in directory.rglob("*") if p.is_file()) > 256 * 1024 * 1024:
        raise InputError("GCP_DELTA_PACKAGE_BYTE_LIMIT")
    for result in manifest.results:
        if result.state == "SKIPPED_ALREADY_COMPLETE":
            continue  # never invent a new collected source for a skipped operation
        operation, family, kind, method = CATALOGUE[result.request.operation]
        coverage = (
            "COMPLETE"
            if result.state in {"COMPLETE", "EMPTY"}
            else "PARTIAL"
            if result.file
            else "ERROR"
            if result.error_code
            else "NOT_COLLECTED"
        )
        if result.file:
            path = resolve_under(directory, result.file)
            if sha(path.read_bytes()) != result.sha256:
                raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
            payload = load(path)
            if isinstance(payload, dict) and "error" in payload:
                raise InputError("GCP_ERROR_RESPONSE_AS_EVIDENCE")
            semantic_hash = sha(
                json.dumps(semantic(payload), sort_keys=True, separators=(",", ":")).encode()
            )
            if semantic_hash != result.semantic_sha256:
                raise InputError("GCP_DELTA_SEMANTIC_HASH_MISMATCH")
            if result.request.operation == "FOLDER_METADATA" and (
                not isinstance(payload, dict) or payload.get("name") != result.request.resource
            ):
                raise InputError("GCP_DELTA_FOLDER_IDENTITY_MISMATCH")
            if result.request.operation.startswith("DISCOVERY_"):

                def resource_name(value, request=result.request):
                    number = request.project_number
                    return (
                        str(value).replace(
                            "projects/" + number + "/",
                            "projects/" + request.project_id + "/",
                            1,
                        )
                        if number
                        else str(value)
                    )

                expected = resource_name(result.request.resource)
                prefix = expected + (
                    "/engines/"
                    if result.request.operation == "DISCOVERY_ENGINES"
                    else "/dataStores/"
                )
                if not isinstance(payload, list) or any(
                    not isinstance(record, dict)
                    or not (
                        resource_name(record.get("name", "")) == expected
                        if result.request.operation == "DISCOVERY_RESOURCE"
                        else resource_name(record.get("name", "")).startswith(prefix)
                    )
                    for record in payload
                ):
                    raise InputError("GCP_DELTA_DISCOVERY_SCOPE_MISMATCH")
        subject = (
            "buckets/" + result.request.resource
            if result.request.operation == "BUCKET_IAM"
            else result.request.resource
        )
        params = (
            {"subject": subject}
            if result.request.operation in {"BUCKET_IAM", "FOLDER_IAM", "FOLDER_METADATA"}
            else {"parent": subject}
        )
        source = Source(
            path=result.file,
            sha256=result.sha256,
            format="gcp-json-v1",
            operation=operation,
            account_id=None,
            project_id=result.request.project_id,
            project_number=result.request.project_number,
            region="global",
            collected_at=result.completed_at,
            coverage=coverage,
            errors=(result.error_code,) if result.error_code else (),
            collector_version=manifest.collector_version,
            request_parameters=params,
            gcp_metadata={
                "contract_version": "gcp-delta-1",
                "dataset_origin": manifest.dataset_origin,
                "dataset": result.request.request_id,
                "status": result.state,
                "approval_sha256": manifest.approval_sha256,
                "redacted_fields": result.redacted_fields,
                "duplicate_of": result.duplicate_of,
                "semantic_sha256": result.semantic_sha256,
                "completed_at": result.completed_at.isoformat(),
                "scope_ancestors": [],  # approvals are not observed hierarchy evidence
                "dataset_contract": {
                    "family": family,
                    "method": method,
                    "resource_type": kind,
                    "analysis_support": "EXISTING_RULES" if "IAM" in kind else "NOT_EVALUATED",
                },
            },
        )
        if result.file:
            from offline_analyzer.normalization.gcp import gcp_records, source_record_count

            if source_record_count(path, source, inspect_json(path)) != result.record_count:
                raise InputError("GCP_DELTA_RECORD_COUNT_MISMATCH")
            for _ in gcp_records(path, source, "delta-preflight", inspect_json(path)):
                pass
        sources.append(source)
        states.append(result.state)
        diagnostics.append(
            {
                "operation": operation,
                "profile": "gcp-delta-1",
                "parser_accepted": True,
                "parser_supported": kind != "GCP::Unsupported",
                "effective_coverage": coverage,
                "original_status": result.state,
                "normalized_resource_records": result.record_count,
                "integrity_unchanged": bool(result.file),
                "provenance": "collector-declared",
            }
        )
    if not sources:
        raise InputError("GCP_DELTA_NO_NEW_SOURCES")
    return Package(sources=tuple(sources)), {
        "contract_version": "gcp-delta-1",
        "states": states,
        "sources": diagnostics,
        "raw_values_included": False,
        "real_export_validation": "NOT_ESTABLISHED",
    }
