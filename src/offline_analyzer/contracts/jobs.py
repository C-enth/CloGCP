"""Private local job journal. Sanitized diagnostics project an explicit allowlist."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue

from offline_analyzer.contracts.gcp_legacy import ManifestDetection


class LocalJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["local-job-1"] = "local-job-1"
    id: str = Field(pattern=r"^[0-9a-f]{32}$")
    kind: str = Field(min_length=1, max_length=80)
    workspace_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "INTERRUPTED"]
    state: Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"]
    stage: str = Field(max_length=80)
    provider: Literal["AWS", "GCP", "Consolidated", "UNRESOLVED"] = "UNRESOLVED"
    import_mode: Literal["ZIP", "FOLDER", "GUIDED_JSON", "NONE"] = "NONE"
    submitted_at: float
    stage_started_at: float
    started_at: float | None = None
    finished_at: float | None = None
    updated_at: AwareDatetime
    last_progress_at: AwareDatetime
    heartbeat_at: AwareDatetime
    result: dict[str, JsonValue] | None = None
    error: str | None = Field(default=None, max_length=80)
    error_class: str | None = Field(default=None, max_length=80)
    recoverable: bool = True
    cancel_supported: bool = False
    key: str | None = Field(default=None, max_length=240)
    progress: dict[str, JsonValue] | None = None
    explanation: dict[str, str] | None = None
    timings: dict[str, float] = Field(default_factory=dict)
    files_total: int | None = None
    manifest_version: str | None = Field(default=None, max_length=80)
    manifest_detection: ManifestDetection | None = None
    collection_id: str | None = Field(default=None, max_length=256)
    scopes: list[str] = Field(default_factory=list, max_length=2048)
    limit: dict[str, int | str] | None = None
