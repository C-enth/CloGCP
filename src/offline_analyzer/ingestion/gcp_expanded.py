"""Strict expanded collector adapter; collection failure never means absence."""

import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from offline_analyzer.contracts.gcp_expanded import ExpandedManifest
from offline_analyzer.contracts.gcp_expanded_catalog import dataset_contract
from offline_analyzer.contracts.r0 import Package, Source
from offline_analyzer.ingestion.archive import canonical_member
from offline_analyzer.ingestion.json_input import InputError, inspect_json, records
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.ingestion.sidecars import metadata_names
from offline_analyzer.normalization.gcp import gcp_records, source_record_count

PROFILE = "gcp-expanded-2.1-adapter-1"
PROFILE_22 = "gcp-expanded-2.2-adapter-1"
INTEGRITY = "LOCAL_HASH_ONLY_NO_SOURCE_CHECKSUMS"
INTEGRITY_22 = "SOURCE_CHECKSUMS_VERIFIED_UNAUTHENTICATED"
USABLE = {"SUCCESS", "EMPTY", "TRUNCATED", "PARTIAL"}
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
ERRORS = {
    "FAILED": "COLLECTION_FAILED",
    "API_DISABLED": "API_DISABLED_OR_UNAVAILABLE",
    "ACCESS_DENIED": "COLLECTION_PERMISSION_FAILURE",
    "COMMAND_ERROR": "COLLECTOR_COMMAND_ERROR",
    "AUTH_ERROR": "COLLECTION_AUTH_FAILURE",
    "TRUNCATED": "COLLECTION_TRUNCATED",
    "RATE_LIMITED": "COLLECTION_RATE_LIMITED",
    "NOT_FOUND": "COLLECTION_NOT_FOUND",
    "HTTP_ERROR": "COLLECTION_HTTP_ERROR",
    "SERVER_ERROR": "COLLECTION_SERVER_ERROR",
    "PARTIAL": "COLLECTION_LOCATIONS_UNREACHABLE",
    "TIMEOUT": "COLLECTION_TIMEOUT",
    "QUOTA_PROJECT_DENIED": "COLLECTION_QUOTA_PROJECT_DENIED",
    "UNEXPECTED_SCHEMA": "COLLECTION_UNEXPECTED_RESPONSE_SCHEMA",
    "INVALID_OUTPUT": "COLLECTION_INVALID_OUTPUT",
    "UNSUPPORTED_ENDPOINT": "COLLECTION_UNSUPPORTED_ENDPOINT",
}


# Collector 2.2.6 manifest fields, consumed as per-dataset completeness notes.
DETAIL_FAMILIES = {
    "service_accounts": ("service_accounts", "sa_keys_", "sa_iam_"),
    "buckets": ("buckets", "bucket_iam_", "bucket_details_"),
    "api_keys": ("api_keys", "api_key_detail_"),
    "custom_roles": ("custom_roles", "custom_role_detail_"),
    "kms": ("kms_locations_rest", "kms_keyrings_", "kms_keys_", "kms_versions_"),
}
IAM_TARGETS = {  # IAM family -> (REST target list, gcloud fallback list)
    "run_iam": ("run_services_rest", "cloud_run"),
    "function_iam": ("functions_rest", "functions"),
}


def _family(name: str, members: tuple[str, ...]) -> bool:
    return any(name == m or (m.endswith("_") and name.startswith(m)) for m in members)


def collection_notes(manifest) -> dict[str, list[str]]:
    """Dataset name -> completeness notes from detail limits and IAM target dependencies.

    Notes only explain coverage; they never turn a gap into evidence. A detail limit leaves
    the affected family Partial; an incomplete target list leaves its IAM datasets Partial;
    a failed list with no usable fallback leaves IAM uncollected (UNKNOWN, never PASS).
    """
    names = {d.dataset: d.status for d in manifest.datasets if d.domain != "serverless"}
    serverless = {d.dataset: d.status for d in manifest.datasets if d.domain == "serverless"}
    notes: dict[str, list[str]] = {}
    limits = getattr(manifest, "detail_limits_reached", None)
    for key, members in DETAIL_FAMILIES.items():
        if limits is not None and getattr(limits, key):
            for name in [*names, *serverless]:
                if _family(name, members):
                    notes.setdefault(name, []).append(f"DETAIL_LIMIT_REACHED_{key.upper()}")
    fallbacks = {f.dataset_family: f for f in getattr(manifest, "dependency_fallbacks", [])}
    for family, (rest, gcloud) in IAM_TARGETS.items():
        iam = [n for n in serverless if n.startswith(family + "_")]
        rest_status = serverless.get(rest)
        fallback = fallbacks.get(family)
        if fallback is not None:
            notes.setdefault(rest, []).append("IAM_TARGETS_FALLBACK_USED")
            if fallback.fallback_status in USABLE:
                for name in iam:
                    notes.setdefault(name, []).append("IAM_TARGETS_FROM_GCLOUD_LIST")
            else:
                for name in (rest, gcloud):
                    notes.setdefault(name, []).append("IAM_TARGETS_UNAVAILABLE")
        elif rest_status in {"PARTIAL", "TRUNCATED"}:
            for name in (rest, *iam):
                notes.setdefault(name, []).append("IAM_TARGET_LIST_INCOMPLETE")
        elif rest_status is not None and rest_status not in USABLE | {"API_DISABLED"}:
            # API_DISABLED is its own reason (service not enabled); there is nothing to fall
            # back to (collector 2.2.7 records no fallback for it).
            notes.setdefault(rest, []).append("IAM_TARGETS_UNAVAILABLE")
    return notes


def verify_declared_checksums(directory: Path) -> set[str]:
    """2.2 packages list every evidence file once; any mismatch or omission fails closed."""
    path = resolve_under(directory, "checksums.sha256")
    if path.is_symlink() or not path.is_file():
        raise InputError("SOURCE_CHECKSUMS_REQUIRED")
    if path.stat().st_size > 8 * 1024 * 1024:
        raise InputError("CHECKSUM_INDEX_BYTE_LIMIT")
    declared = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        match = CHECKSUM_LINE.fullmatch(line.strip())
        if not match:
            raise InputError("CHECKSUM_INDEX_INVALID")
        name = canonical_member(match[2])
        if not name or name in declared or name == "checksums.sha256":
            raise InputError("CHECKSUM_INDEX_DUPLICATE_OR_SELF")
        target = resolve_under(directory, name)
        if target.is_symlink() or not target.is_file() or sha256_file(target) != match[1]:
            raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
        declared[name] = match[1]
    present = (
        {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
        - metadata_names(directory)
        - {"checksums.sha256"}
    )
    if present != declared.keys():
        raise InputError("CHECKSUM_INVENTORY_INCOMPLETE")
    return set(declared)


def parameters(dataset, project: str) -> dict:
    """Interpret only known read-only command context; never execute manifest strings."""
    command = dataset.command if isinstance(dataset.command, str) else " ".join(dataset.command)
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise InputError("GCP_SOURCE_CONTEXT_INVALID") from exc
    result = {}
    if dataset.dataset.startswith("gke_node_pools_") and len(tokens) == 2 and tokens[0] == "GET":
        url = urlsplit(tokens[1])
        if url.scheme == "https" and url.netloc == "container.googleapis.com":
            match = re.fullmatch(
                r"/v1/(projects/[^/]+/(?:locations|zones)/[^/]+/clusters/[^/]+)/nodePools", url.path
            )
            if match:
                result["parent"] = match[1]
    if dataset.dataset == "project_iam":
        result["subject"] = f"projects/{project}"
    elif match := re.fullmatch(r"(folder|organization)_([0-9]{1,20})_iam", dataset.dataset):
        result["subject"] = f"{match[1]}s/{match[2]}"
    elif "get-iam-policy" in tokens:
        index = tokens.index("get-iam-policy")
        if index + 1 < len(tokens):
            subject = tokens[index + 1]
            if dataset.dataset.startswith("bucket_iam_"):
                result["subject"] = "buckets/" + subject.removeprefix("gs://").rstrip("/")
            elif dataset.dataset.startswith("sa_iam_"):
                result["subject"] = f"projects/{project}/serviceAccounts/{subject}"
            elif dataset.dataset == "parent_org_iam" and re.fullmatch(r"[0-9]{1,20}", subject):
                result["subject"] = "organizations/" + subject
            elif dataset.dataset == "parent_folder_iam" and re.fullmatch(r"[0-9]{1,20}", subject):
                result["subject"] = "folders/" + subject
            elif dataset.dataset.startswith(("run_iam_", "function_iam_")):
                region = next(
                    (t.split("=", 1)[1] for t in tokens if t.startswith("--region=")), None
                )
                if region:
                    service = "services" if dataset.dataset.startswith("run_") else "functions"
                    result["subject"] = f"projects/{project}/locations/{region}/{service}/{subject}"
    if dataset.dataset.startswith("effective_policy_"):
        result["effective"] = "--effective" in tokens
        if "describe" in tokens and tokens.index("describe") + 1 < len(tokens):
            result["constraint"] = tokens[tokens.index("describe") + 1]
    return result


def inspect_expanded(directory: Path, manifest: ExpandedManifest) -> tuple[Package, dict]:
    from offline_analyzer.ingestion.gcp_legacy import error_category, inspect_failed_output

    v22 = manifest.schema_version == "assessment-expanded-2.2"
    profile = PROFILE_22 if v22 else PROFILE
    integrity = INTEGRITY_22 if v22 else INTEGRITY
    allowed = {"collection_manifest.json"} | metadata_names(directory)
    if v22:
        verify_declared_checksums(directory)
        allowed.add("checksums.sha256")
    interrupted = v22 and manifest.collection_status != "COMPLETE"
    seen = set()
    prepared = []
    identities = set()
    for dataset in manifest.datasets:
        identity = (dataset.domain, dataset.dataset)
        if identity in identities:
            raise InputError("GCP_DUPLICATE_DATASET")
        identities.add(identity)
        paths = []
        for value, error in ((dataset.file, False), (dataset.error_file, True)):
            name = canonical_member(value) if value else None
            if name:
                expected = f"{dataset.domain}/{dataset.dataset}" + (
                    ".stderr.txt" if error else ".json"
                )
                if name != expected or name.casefold() in seen:
                    raise InputError("MANIFEST_FILE_REFERENCE_MISMATCH")
                seen.add(name.casefold())
                path = resolve_under(directory, name)
                if path.is_symlink():
                    raise InputError("UNSAFE_ARCHIVE_MEMBER")
                if not path.is_file():
                    raise InputError("MISSING_DECLARED_EVIDENCE")
                allowed.add(name)
            paths.append(name)
        prepared.append((dataset, *paths))
    for name in ("discovered_asset_types.json", "iam_parent_hierarchy_attempted.json"):
        path = directory / name
        if path.exists():
            if path.is_symlink():
                raise InputError("UNSAFE_ARCHIVE_MEMBER")
            if path.stat().st_size > 1024 * 1024:
                raise InputError("MANIFEST_BYTE_LIMIT")
            # PowerShell may write an empty hierarchy metadata artifact. It is not evidence.
            empty_hierarchy = (
                name.startswith("iam_parent")
                and not path.read_bytes().removeprefix(b"\xef\xbb\xbf").strip()
            )
            if not empty_hierarchy:
                inspect_json(path)
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                if name.startswith("discovered") and value != [
                    r.model_dump() for r in manifest.discovered_asset_types
                ]:
                    raise InputError("MANIFEST_FILE_REFERENCE_MISMATCH")
                if name.startswith("iam_parent") and not isinstance(value, (list, dict)):
                    raise InputError("GCP_HIERARCHY_METADATA_INVALID")
            allowed.add(name)
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise InputError("UNSAFE_ARCHIVE_MEMBER")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    if actual != allowed:
        raise InputError("MANIFEST_FILE_REFERENCE_MISMATCH")
    number = None
    for dataset, name, _ in prepared:
        if dataset.dataset == "project" and dataset.status in USABLE and name:
            path = directory / name
            inspect_json(path)
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(data, dict) or data.get("projectId") != manifest.project_id:
                from offline_analyzer.normalization.gcp_identity import mismatch

                raise mismatch(
                    name,
                    manifest.project_id,
                    "projectId / project object",
                    data.get("projectId") if isinstance(data, dict) else "not an object",
                )
            number = str(data["projectNumber"]) if data.get("projectNumber") is not None else None
    sources, diagnostics = [], []
    notes = collection_notes(manifest)
    # The project's own parent chain, from the collector's per-parent dataset names. Only
    # these scopes (plus the project) may contribute IAM search results (ADR-010).
    ancestors = sorted(
        {
            f"{kind}s/{number}"
            for dataset, _, _ in prepared
            for kind, number in re.findall(r"^(organization|folder)_(\d+)_", dataset.dataset)
        }
    )
    for dataset, name, error_name in prepared:
        contract = dataset_contract(dataset.domain, dataset.dataset, manifest.schema_version)
        operation = contract["operation"] if contract else "gcp:expanded.unsupported"
        failure = ERRORS.get(dataset.status)
        if error_name:
            error_category(
                directory / error_name
            )  # bounded local credential inspection, no raw logging
        metadata = {
            "adapter_profile": profile,
            "scope_ancestors": ancestors,
            "contract_version": manifest.schema_version,
            "dataset_origin": manifest.dataset_origin,
            "expected_projects": [manifest.project_id],
            "status": dataset.status,
            "domain": dataset.domain,
            "dataset": dataset.dataset,
            "dataset_contract": contract or {},
            "original_file": name,
            "error_file": error_name,
            "local_file_sha256": sha256_file(directory / name) if name else None,
            "local_error_sha256": sha256_file(directory / error_name) if error_name else None,
            "provenance": "collector-unverified",
            "integrity_assurance": integrity,
            "source_checksum_declared": v22,
            "pagination_complete": False,  # set below for complete datasets
            "started_at": dataset.started_utc.isoformat(),
            "completed_at": dataset.finished_utc.isoformat(),
            "declared_record_count": dataset.record_count,
            "pages": dataset.pages,
            "error_category": failure,
            "collection_correction_required": dataset.status == "COMMAND_ERROR",
            "required_api": dataset.required_api,
            "collector_limits": {
                "max_detail_items": manifest.max_detail_items,
                "max_api_pages": manifest.max_api_pages,
                "discovery_engine_detail_limit_reached": (
                    manifest.discovery_engine_detail_limit_reached
                ),
                "bigquery_dataset_detail_limit_reached": (
                    manifest.bigquery_dataset_detail_limit_reached
                ),
            },
            "completeness_limitations": ([] if v22 else ["SOURCE_CHECKSUMS_ABSENT"])
            + ["COLLECTOR_PAGINATION_UNVERIFIED"]
            + (["COLLECTION_INTERRUPTED"] if interrupted else [])
            + (["COLLECTION_LOCATIONS_UNREACHABLE"] if dataset.status == "PARTIAL" else [])
            + (
                ["REST_EMPTY_RESPONSE_FIELD_PRESENCE_UNVERIFIED"]
                if contract and contract["method"] != "Run" and dataset.status == "EMPTY"
                else []
            )
            + (["COLLECTION_TRUNCATED"] if dataset.status == "TRUNCATED" else []),
        }
        usable = dataset.status in USABLE
        metadata["completeness_limitations"] += notes.get(dataset.dataset, [])
        if manifest.discovery_engine_detail_limit_reached and dataset.domain == "ai":
            metadata["completeness_limitations"].append("DISCOVERY_DETAIL_COLLECTION_LIMIT_REACHED")
        if manifest.bigquery_dataset_detail_limit_reached and dataset.dataset.startswith(
            ("bigquery", "bq_")
        ):
            metadata["completeness_limitations"].append("BIGQUERY_DETAIL_COLLECTION_LIMIT_REACHED")
        # Collector 2.2 (verified checksums, record counts checked below): SUCCESS and EMPTY
        # mean every page was followed (a page cap is TRUNCATED, unreachable locations PARTIAL),
        # so the dataset is COMPLETE. Interrupted runs, detail limits and 2.1 packages stay
        # PARTIAL; every failure status stays ERROR with its reason.
        complete = (
            v22
            and not interrupted
            and dataset.status in {"SUCCESS", "EMPTY"}
            and not notes.get(dataset.dataset)
            and not any(
                n.endswith("DETAIL_COLLECTION_LIMIT_REACHED")
                for n in metadata["completeness_limitations"]
            )
        )
        if complete:
            metadata["pagination_complete"] = True
            metadata["completeness_limitations"].remove("COLLECTOR_PAGINATION_UNVERIFIED")
        source = Source(
            path=name if usable else None,
            sha256=metadata["local_file_sha256"] if usable else None,
            format="gcp-json-v1",
            operation=operation,
            project_id=manifest.project_id,
            project_number=number,
            region="global",
            collected_at=dataset.finished_utc,
            coverage="COMPLETE" if complete else "PARTIAL" if usable else "ERROR",
            errors=(failure,) if failure else (),
            collector_version=manifest.schema_version,
            request_parameters=parameters(dataset, manifest.project_id),
            gcp_metadata=metadata,
        )
        count = 0
        if name:
            path = directory / name
            if usable:
                shape = inspect_json(path)
                transport_count = sum(
                    1 for _ in records(path, "item" if shape["root"] == "start_array" else "")
                )
                if transport_count != dataset.record_count:
                    raise InputError("GCP_TRANSPORT_RECORD_COUNT_MISMATCH")
                count = source_record_count(path, source, shape)
                for _ in gcp_records(path, source, "expanded-preflight", shape):
                    pass
                if dataset.status == "EMPTY" and count:
                    raise InputError("LEGACY_EMPTY_RECORD_MISMATCH")
            else:
                inspect_failed_output(path)
        sources.append(source)
        diagnostics.append(
            {
                "operation": operation,
                "profile": profile,
                "parser_accepted": True,
                "parser_supported": bool(contract),
                "effective_coverage": source.coverage,
                "original_status": dataset.status,
                "error_category": failure,
                "normalized_resource_records": count,
                "declared_record_count": dataset.record_count,
                "integrity_assurance": integrity,
                "source_checksum_verified": v22,
                "analysis_support": contract["analysis_support"]
                if contract
                else "UNSUPPORTED_PARSER",
            }
        )
    return Package(sources=tuple(sources)), {
        "sources": diagnostics,
        "contract_version": manifest.schema_version,
        "adapter_profile": profile,
        "collection_status": getattr(manifest, "collection_status", None),
        "quota_project_used": bool(getattr(manifest, "quota_project", None)),
        "project_id": manifest.project_id,
        "project_number": number,
        "original_status_totals": {
            s: sum(d.status == s for d in manifest.datasets)
            for s in sorted({d.status for d in manifest.datasets})
        },
        "integrity_assurance": integrity,
        "source_checksum_verified": v22,
        "real_export_validation": "NOT_ESTABLISHED",
        "raw_values_included": False,
        "qualification": (
            "Locally hashed, unauthenticated collector output; truncation, failures "
            "and empty REST responses do not establish complete inventories."
        ),
    }
