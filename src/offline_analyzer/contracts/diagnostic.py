"""Allowlisted export diagnostics: no source identifiers, values, filenames or paths."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from offline_analyzer.contracts.gcp_legacy import ManifestDetection


class SanitizedDiagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["closec-local-diagnostic-1"] = "closec-local-diagnostic-1"
    product: Literal["CloSec"] = "CloSec"
    application_version: str
    git_revision: str | None
    working_tree_modified: bool | None
    backend_source_hash: str
    frontend_build_id: str | None
    transport_version: str
    compatible: bool
    source_changed_since_startup: bool
    operating_system: str
    operating_system_release: str
    job_id: str
    job_type: str
    job_state: str
    job_stage: str
    provider: str
    import_mode: str
    detected_manifest_version: str | None
    manifest_detection: ManifestDetection | None = None
    submitted_at: float
    started_at: float | None
    finished_at: float | None
    duration_seconds: float
    last_progress_at: str
    heartbeat_at: str
    timings: dict[str, float]
    error_code: str | None
    stack_trace_classification: str | None
    recoverable: bool
    limit: dict[str, int | str] | None
    files_total: int | None
    supported_dataset_count: int
    unsupported_dataset_count: int
    collection_error_count: int
    dataset_status_counts: dict[str, int]
    parser_names: list[str] = Field(max_length=40)
    failed_supported_operations: list[str] = Field(max_length=1024)
    database_integrity: Literal["NOT_CHECKED", "TRANSACTION_COMMITTED_AND_SCHEMA_READABLE"]
    real_evidence_compatibility: str
    raw_values_included: Literal[False] = False
    customer_paths_included: Literal[False] = False
