"""GCP manifest validation translated to the existing immutable importer."""

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from offline_analyzer.contracts.gcp import GCPDataset, GCPManifest
from offline_analyzer.contracts.r0 import Package, Source
from offline_analyzer.ingestion.json_input import InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.normalization.gcp import PROFILES, gcp_records, source_record_count


def is_gcp(directory: Path) -> bool:
    if resolve_under(directory, "collection_manifest.json").is_file():
        return True
    path = resolve_under(directory, "manifest.json")
    if not path.is_file():
        return False
    if path.stat().st_size > 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    shape = inspect_json(path)
    return shape["fields"].get("contract_version", (None, None))[1] in {
        "closec-gcp-1",
        "gcp-delta-1",
    }


def read_manifest(directory: Path) -> GCPManifest:
    path = resolve_under(directory, "manifest.json")
    if path.stat().st_size > 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    inspect_json(path)
    try:
        manifest = GCPManifest.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        raise InputError("GCP_MANIFEST_INVALID") from exc
    if (
        manifest.collector_version.casefold().startswith("synthetic")
        and manifest.dataset_origin != "synthetic"
    ):
        raise InputError("GCP_SYNTHETIC_ORIGIN_CONFLICT")
    allowed = {"manifest.json", *[d.path for d in manifest.datasets if d.path]}
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    if actual != allowed:
        raise InputError("GCP_UNLISTED_OR_MISSING_ARTIFACT")
    return manifest


def coverage(dataset: GCPDataset, provenance: str) -> str:
    if dataset.status in {"FAILED", "ACCESS_DENIED"}:
        return "ERROR"
    if dataset.status in {"NOT_COLLECTED", "NOT_APPLICABLE", "UNSUPPORTED", "UNKNOWN"}:
        return "NOT_COLLECTED"
    if not dataset.path:
        return "NOT_COLLECTED"
    return (
        "COMPLETE"
        if dataset.status in {"SUCCESS", "EMPTY"} and provenance == "collector-declared"
        else "PARTIAL"
    )


def inspect_package(directory: Path) -> tuple[Package, dict]:
    manifest_path = resolve_under(directory, "manifest.json")
    if manifest_path.is_file():
        shape = inspect_json(manifest_path)
        if shape["fields"].get("contract_version", (None, None))[1] == "gcp-delta-1":
            from offline_analyzer.ingestion.gcp_delta import inspect_package as delta_package

            return delta_package(directory)
    if (directory / "collection_manifest.json").is_file():
        from offline_analyzer.ingestion.gcp_legacy import inspect_package as legacy_package

        return legacy_package(directory)
    manifest = read_manifest(directory)
    sources, diagnostics = [], []
    for dataset in manifest.datasets:
        metadata = {
            **dataset.model_dump(mode="json"),
            "expected_projects": list(manifest.expected_projects),
            "organization_id": manifest.organization_id,
            "folder_id": manifest.folder_id,
            "provenance": manifest.provenance,
            "assessment_id": manifest.assessment_id,
            "dataset_origin": manifest.dataset_origin,
            "max_key_age_days": manifest.max_key_age_days,
        }
        source = Source(
            path=dataset.path,
            sha256=dataset.sha256,
            format="gcp-json-v1",
            operation=dataset.operation,
            account_id=None,
            project_id=dataset.project_id,
            project_number=dataset.project_number,
            region=dataset.location,
            collected_at=dataset.completed_at or datetime(1970, 1, 1, tzinfo=UTC),
            coverage=coverage(dataset, manifest.provenance),
            errors=dataset.errors
            or ((dataset.status,) if dataset.status in {"FAILED", "ACCESS_DENIED"} else ()),
            collector_version=manifest.collector_version,
            request_parameters=dataset.parameters,
            gcp_metadata=metadata,
        )
        count = 0
        if dataset.path:
            path = resolve_under(directory, dataset.path)
            if sha256_file(path) != dataset.sha256:
                raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
            shape = inspect_json(path)
            if shape["root"] == "start_map" and "error" in shape["fields"]:
                raise InputError("GCP_ERROR_RESPONSE_AS_EVIDENCE")
            count = source_record_count(path, source, shape)
            if count != dataset.record_count:
                raise InputError("GCP_RECORD_COUNT_MISMATCH")
            # Check identities and shape before retaining any raw bytes.
            for _ in gcp_records(path, source, "gcp-preflight", shape):
                pass
        sources.append(source)
        diagnostics.append(
            {
                "operation": dataset.operation,
                "profile": dataset.parser_profile,
                "parser_accepted": True,
                "parser_supported": dataset.operation in PROFILES,
                "effective_coverage": source.coverage,
                "original_status": dataset.status,
                "provenance": manifest.provenance,
                "normalized_resource_records": count,
                "integrity_unchanged": bool(dataset.path),
            }
        )
    return Package(sources=tuple(sources)), {
        "sources": diagnostics,
        "real_export_validation": "NOT_ESTABLISHED",
        "raw_values_included": False,
        "contract_version": manifest.contract_version,
        "qualification": "Checksums verify bytes; provenance and completeness remain declarations",
    }


def guided_manifest(directory: Path, names: list[str], settings: dict) -> None:
    """Operator-identified raw JSON: never upgrade manually supplied completeness."""
    if not settings.get("project_id") or not settings.get("operation"):
        raise InputError("GCP_GUIDED_SOURCE_REQUIRED")
    if settings["operation"] not in PROFILES:
        raise InputError("GCP_GUIDED_OPERATION_UNSUPPORTED")
    datasets = []
    for name in names:
        path = resolve_under(directory, name)
        shape = inspect_json(path)
        source = Source(
            path=name,
            sha256=sha256_file(path),
            format="gcp-json-v1",
            operation=settings["operation"],
            project_id=settings["project_id"],
            project_number=settings.get("project_number") or None,
            collected_at=settings.get("collected_at") or datetime(1970, 1, 1, tzinfo=UTC),
            region=settings.get("region") or "global",
            request_parameters=settings.get("request_parameters") or {},
        )
        datasets.append(
            GCPDataset(
                project_id=source.project_id,
                project_number=source.project_number,
                path=name,
                sha256=source.sha256,
                operation=source.operation,
                parameters=source.request_parameters,
                status="PARTIAL",
                dataset_type=settings.get("evidence_category") or "native-json",
                completed_at=settings.get("collected_at") or None,
                record_count=source_record_count(path, source, shape),
            )
        )
    manifest = GCPManifest(
        collector_version="manual",
        assessment_id=settings.get("assessment_id") or "manual",
        expected_projects=settings.get("expected_projects") or [settings["project_id"]],
        collected_projects=[settings["project_id"]],
        dataset_origin=settings.get("origin", "synthetic"),
        provenance="manual-unverified",
        datasets=datasets,
    )
    (directory / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")


def contract() -> dict:
    from offline_analyzer.rules.gcp import GCP_RULES

    return {
        "schema": GCPManifest.model_json_schema(),
        "legacy_profile": "pilot-1.2.2",
        "supported_operations": [
            {
                "operation": op,
                "resource_type": p[0],
                "applicable_rules": [r.rule_id for r in GCP_RULES if r.operation == op],
            }
            for op, p in PROFILES.items()
        ],
        "security": "Metadata only; keyString, tokens, private keys and secrets are rejected",
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(contract(), indent=2), encoding="utf-8")
