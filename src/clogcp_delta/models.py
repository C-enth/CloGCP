"""Versioned approvals and evidence metadata. Real identifiers belong in private plans."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

Project = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")]
Operation = Literal[
    "BUCKET_IAM",
    "FOLDER_METADATA",
    "FOLDER_IAM",
    "DISCOVERY_ENGINES",
    "DISCOVERY_DATASTORES",
    "DISCOVERY_RESOURCE",
    "IAM_RECOMMENDATIONS",
]
State = Literal[
    "COMPLETE",
    "EMPTY",
    "PARTIAL",
    "DENIED",
    "MISSING",
    "API_ERROR",
    "API_DISABLED",
    "QUOTA_PROJECT_DENIED",
    "NOT_COLLECTED",
    "SKIPPED_ALREADY_COMPLETE",
    "UNSUPPORTED",
]


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    project_id: Project
    project_number: str | None = Field(default=None, pattern=r"^[0-9]{1,20}$")
    operation: Operation
    resource: str = Field(min_length=1, max_length=1000)
    optional: bool = False

    @model_validator(mode="after")
    def resource_scope(self):
        import re

        if self.operation == "BUCKET_IAM":
            valid = re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", self.resource)
            valid = valid and ".." not in self.resource
        elif self.operation in {"FOLDER_IAM", "FOLDER_METADATA"}:
            valid = re.fullmatch(r"folders/[0-9]{1,20}", self.resource)
        elif self.operation.startswith("DISCOVERY_"):
            tail = (
                r"/(engines|dataStores)/[A-Za-z0-9_-]{1,100}"
                if self.operation == "DISCOVERY_RESOURCE"
                else ""
            )
            valid = re.fullmatch(
                r"projects/"
                + "(?:"
                + re.escape(self.project_id)
                + ("|" + re.escape(self.project_number) if self.project_number else "")
                + ")"
                + r"/locations/(global|us|eu)/collections/[A-Za-z0-9_-]{1,100}"
                + tail,
                self.resource,
            )
        else:
            valid = self.optional and self.resource == f"projects/{self.project_id}"
        if not valid:
            raise ValueError("RESOURCE_OUTSIDE_APPROVED_OPERATION_SCOPE")
        return self


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["gcp-delta-plan-1"] = "gcp-delta-plan-1"
    approved_by: str = Field(min_length=1, max_length=200)
    approved_at: AwareDatetime
    catalogue_reconciled: bool = False
    matrix_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    quota_project: Project | None = None
    concurrency: int = Field(default=2, ge=1, le=4)
    requests_per_second_per_api: float = Field(default=2.0, gt=0, le=10)
    requests: list[Request] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def distinct(self):
        if len({r.request_id for r in self.requests}) != len(self.requests):
            raise ValueError("DUPLICATE_REQUEST_ID")
        return self


class Result(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request: Request
    state: State
    started_at: AwareDatetime
    completed_at: AwareDatetime
    file: str | None = Field(default=None, pattern=r"^evidence/[0-9a-f]{64}\.json$")
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    semantic_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    record_count: int = Field(default=0, ge=0, le=100000)
    duplicate_of: str | None = None
    pagination_complete: bool = False
    redacted_fields: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, pattern=r"^[A-Z0-9_]{1,80}$")

    @model_validator(mode="after")
    def integrity(self):
        if bool(self.file) != bool(self.sha256):
            raise ValueError("FILE_HASH_PAIR_REQUIRED")
        if self.state in {"COMPLETE", "EMPTY", "PARTIAL"} and not self.file:
            raise ValueError("COLLECTED_BYTES_REQUIRED")
        if self.state in {"COMPLETE", "EMPTY"} and not self.pagination_complete:
            raise ValueError("COMPLETE_PAGINATION_REQUIRED")
        if self.started_at > self.completed_at:
            raise ValueError("TIMESTAMP_ORDER")
        return self


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["gcp-delta-1"] = "gcp-delta-1"
    collector_version: Literal["gcp-delta-1.0.0rc1"] = "gcp-delta-1.0.0rc1"
    dataset_origin: Literal["synthetic", "tool-generated"]
    created_at: AwareDatetime
    approval_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalogue_reconciled: bool
    executed: bool
    quota_project: Project | None = None
    results: list[Result] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def execution_consistent(self):
        if len({r.request.request_id for r in self.results}) != len(self.results):
            raise ValueError("DUPLICATE_RESULT_ID")
        if sum(bool(r.file) for r in self.results) > 1024:
            raise ValueError("PACKAGE_FILE_LIMIT")
        if self.executed and not self.catalogue_reconciled:
            raise ValueError("EXECUTED_CATALOGUE_REQUIRED")
        if not self.executed and any(r.file for r in self.results):
            raise ValueError("DRY_RUN_CANNOT_DECLARE_COLLECTED_BYTES")
        return self
