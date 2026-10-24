"""Strict observed expanded collector contract, independent of pilot contracts."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from offline_analyzer.contracts.gcp_legacy import Pilot15Dataset, Pilot15Manifest


class ExpandedDataset(Pilot15Dataset):
    record_count: int | None = Field(default=None, ge=0, le=100000, strict=True)
    status: Literal[
        "SUCCESS",
        "EMPTY",
        "FAILED",
        "API_DISABLED",
        "ACCESS_DENIED",
        "COMMAND_ERROR",
        "AUTH_ERROR",
        "TRUNCATED",
        "RATE_LIMITED",
        "NOT_FOUND",
        "HTTP_ERROR",
        "SERVER_ERROR",
    ]

    @model_validator(mode="after")
    def expanded_status(self):
        if self.status == "TRUNCATED" and (not self.file or self.record_count is None):
            raise ValueError("Truncated collection requires retained partial output and count")
        if self.status in {"SUCCESS", "EMPTY"} and self.record_count is None:
            raise ValueError("Successful expanded collection requires a transport record count")
        return self

    @model_validator(mode="after")
    def valid_status(self):
        # REST does not write exit_code; gcloud does. Keep successful-file checks.
        if self.started_utc > self.finished_utc:
            raise ValueError("Invalid collection time window")
        if self.status in {"SUCCESS", "EMPTY"} and (
            self.exit_code not in {None, 0} or not self.file
        ):
            raise ValueError("Successful collection needs output and no command failure")
        if self.status == "EMPTY" and self.record_count != 0:
            raise ValueError("EMPTY count mismatch")
        return self


class ExpandedManifest(Pilot15Manifest):
    schema_version: Literal["assessment-expanded-2.1"]
    datasets: list[ExpandedDataset] = Field(min_length=1, max_length=1024)
    max_detail_items: int = Field(ge=0, le=100000, strict=True)
    max_api_pages: int = Field(ge=0, le=100000, strict=True)
    scope: Literal["project"]
    discovery_engine_detail_limit_reached: bool = Field(strict=True)
    bigquery_dataset_detail_limit_reached: bool = Field(strict=True)


class ExpandedDataset22(ExpandedDataset):
    """Collector 2.2 statuses. Every addition is a collection gap, never a security result."""

    status: Literal[
        "SUCCESS",
        "EMPTY",
        "PARTIAL",
        "FAILED",
        "API_DISABLED",
        "ACCESS_DENIED",
        "QUOTA_PROJECT_DENIED",
        "COMMAND_ERROR",
        "AUTH_ERROR",
        "TRUNCATED",
        "TIMEOUT",
        "RATE_LIMITED",
        "NOT_FOUND",
        "HTTP_ERROR",
        "SERVER_ERROR",
        "UNEXPECTED_SCHEMA",
        "INVALID_OUTPUT",
        "UNSUPPORTED_ENDPOINT",
    ]

    @model_validator(mode="after")
    def partial_output(self):
        if self.status == "PARTIAL" and (not self.file or self.record_count is None):
            raise ValueError("Partial collection requires retained output and count")
        if self.status in {"UNEXPECTED_SCHEMA", "UNSUPPORTED_ENDPOINT", "TIMEOUT"} and self.file:
            raise ValueError("Collection gap cannot carry evidence output")
        return self


class DependencyFallback(BaseModel):
    """Collector 2.2.6: an IAM collection whose REST target list failed used the gcloud list."""

    model_config = ConfigDict(extra="forbid")
    dataset_family: Literal["run_iam", "function_iam"]
    failed_dependency: str = Field(pattern=r"^serverless/[a-z_]{1,60}$")
    failed_status: str = Field(pattern=r"^[A-Z_]{1,40}$")
    fallback_source: str = Field(pattern=r"^serverless/[a-z_]{1,60}$")
    fallback_status: str = Field(pattern=r"^[A-Z_]{1,40}$")
    targets: int = Field(ge=0, le=100000, strict=True)


class DetailLimitsReached(BaseModel):
    """Collector 2.2.6: detail loops stopped by -MaxDetailItems (their remaining items were not
    described). A collection gap, never a security result."""

    model_config = ConfigDict(extra="forbid")
    service_accounts: bool = Field(strict=True)
    buckets: bool = Field(strict=True)
    api_keys: bool = Field(strict=True)
    custom_roles: bool = Field(strict=True)
    kms: bool = Field(strict=True)


class ExpandedManifest22(ExpandedManifest):
    schema_version: Literal["assessment-expanded-2.2"]  # type: ignore[assignment]
    datasets: list[ExpandedDataset22] = Field(min_length=1, max_length=4096)  # type: ignore[assignment]
    # 2.2.1 adds read-only project discovery; 2.2.2 a gcloud sign-in check; 2.2.3 makes
    # folder/organization IAM search opt-in; 2.2.4 omits public images; 2.2.6 records detail
    # limits and dependency fallbacks (optional fields below); 2.2.7 corrects collection
    # (pre-check exemptions, effective-policy names, quota-project classification); 2.2.8
    # describes custom roles by bare role ID with their scope flag. The evidence format is
    # unchanged.
    collector_version: Literal[
        "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8"
    ]
    detail_limits_reached: DetailLimitsReached | None = None
    dependency_fallbacks: list[DependencyFallback] = Field(default_factory=list, max_length=20)
    collection_status: Literal["COMPLETE", "INTERRUPTED"]
    quota_project: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    command_timeout_seconds: int = Field(ge=10, le=3600, strict=True)
    http_max_retries: int = Field(ge=0, le=6, strict=True)
    page_hard_cap: int = Field(ge=1, le=100000, strict=True)
