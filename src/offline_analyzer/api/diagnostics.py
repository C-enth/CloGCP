"""Positive projection of diagnostics; arbitrary errors/tracebacks are never exported."""

from collections import Counter

from offline_analyzer.contracts.diagnostic import SanitizedDiagnostic
from offline_analyzer.contracts.gcp_expanded_catalog import DATASETS
from offline_analyzer.contracts.r0 import AWS_OPERATIONS
from offline_analyzer.normalization.gcp import PROFILES

SUPPORTED = (
    set(AWS_OPERATIONS) | set(PROFILES) | {row["operation"] for row in DATASETS} | {"prowler:Scan"}
)
PARSERS = {
    "aws-json-v1",
    "gcp-json-v1",
    "prowler-ocsf-5.10",
    "prowler-ocsf-5.26.1",
    "gcp-pilot-1.2.2-adapter-1",
    "gcp-pilot-1.5-adapter-1",
    "gcp-expanded-2.1-adapter-1",
    "gcp-expanded-2.2-adapter-1",
}
STATUSES = {
    "SUCCESS",
    "EMPTY",
    "FAILED",
    "ACCESS_DENIED",
    "PARTIAL",
    "NOT_COLLECTED",
    "NOT_APPLICABLE",
    "UNSUPPORTED",
    "UNKNOWN",
    "COMPLETE",
    "ERROR",
    "API_DISABLED",
    "AUTH_ERROR",
    "COMMAND_ERROR",
    "TRUNCATED",
    "RATE_LIMITED",
    "NOT_FOUND",
    "HTTP_ERROR",
    "SERVER_ERROR",
}


def compatibility_diagnostic(report: dict) -> dict:
    """Export counts and fixed parser vocabulary, never imported identity fields."""
    rows = report.get("sources", [])
    totals = (report.get("collector_package") or {}).get("totals", {})
    return {
        "schema_version": "closec-compatibility-summary-1",
        "real_export_validation": report.get("real_export_validation")
        if report.get("real_export_validation")
        in {
            "NOT_ESTABLISHED",
            "LOCAL_TOOL_GENERATED_INPUT_VERIFIED",
            "STRUCTURE_COMPATIBLE_OPERATOR_DECLARED",
            "INCOMPLETE_OR_INCOMPATIBLE",
        }
        else "NOT_ESTABLISHED",
        "raw_values_included": False,
        "customer_paths_included": False,
        "sources": [
            {
                "profile": row.get("profile") if row.get("profile") in PARSERS else "UNSUPPORTED",
                "operation": row.get("operation")
                if row.get("operation") in SUPPORTED
                else "UNSUPPORTED",
                "parser_accepted": row.get("parser_accepted") is True,
                "effective_coverage": row.get("effective_coverage")
                if row.get("effective_coverage") in STATUSES
                else "UNKNOWN",
            }
            for row in rows
        ],
        "collector_package": {
            "totals": {
                key: value
                for key, value in totals.items()
                if key
                in {
                    "complete",
                    "empty",
                    "partial",
                    "failed",
                    "not_collected",
                    "not_applicable",
                    "unsupported_operations",
                    "operations",
                    "files",
                }
                and type(value) is int
                and value >= 0
            }
        },
    }


def job_diagnostic(runtime, job):
    result = job.get("result") or {}
    report = result.get("diagnostics") or {}
    sources = report.get("sources") or []
    collector_operations = (report.get("collector_package") or {}).get("operations", [])
    retained_unsupported = sum(
        row.get("operation") not in SUPPORTED for row in collector_operations
    )
    supported = sum(
        row.get("operation") in SUPPORTED and row.get("parser_supported", True) for row in sources
    )
    statuses = Counter(
        row.get("original_status") or row.get("effective_coverage") for row in sources
    )
    known_state = report.get("real_export_validation", "NOT_ESTABLISHED")
    # Only fixed verifier classifications are eligible; origin declarations alone prove nothing.
    if known_state not in {
        "NOT_ESTABLISHED",
        "LOCAL_TOOL_GENERATED_INPUT_VERIFIED",
        "STRUCTURE_COMPATIBLE_OPERATOR_DECLARED",
        "INCOMPLETE_OR_INCOMPATIBLE",
    }:
        known_state = "NOT_ESTABLISHED"
    data = {
        **runtime.status(),
        "job_id": job["id"],
        "job_type": job["kind"],
        "job_state": job["state"],
        "job_stage": job["stage"],
        "provider": job["provider"],
        "import_mode": job["import_mode"],
        "detected_manifest_version": job["manifest_version"],
        "manifest_detection": job.get("manifest_detection"),
        "submitted_at": job["submitted_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "duration_seconds": job["duration_seconds"],
        "last_progress_at": job["last_progress_at"],
        "heartbeat_at": job["heartbeat_at"],
        "timings": job["timings"],
        "error_code": job["error"],
        "stack_trace_classification": job["error_class"],
        "recoverable": job["recoverable"],
        "limit": job["limit"],
        "files_total": job["files_total"],
        "supported_dataset_count": supported,
        "unsupported_dataset_count": len(sources) - supported + retained_unsupported,
        "collection_error_count": sum(row.get("effective_coverage") == "ERROR" for row in sources),
        "dataset_status_counts": {key: count for key, count in statuses.items() if key in STATUSES},
        "parser_names": sorted(
            {row.get("profile") for row in sources if row.get("profile") in PARSERS}
        ),
        "failed_supported_operations": sorted(
            {
                row["operation"]
                for row in sources
                if row.get("operation") in SUPPORTED
                and (
                    row.get("effective_coverage") == "ERROR" or row.get("parser_accepted") is False
                )
            }
        ),
        "database_integrity": "TRANSACTION_COMMITTED_AND_SCHEMA_READABLE"
        if job["status"] == "SUCCEEDED" and result.get("run_id")
        else "NOT_CHECKED",
        "real_evidence_compatibility": known_state,
    }
    return SanitizedDiagnostic.model_validate(data).model_dump(mode="json")
