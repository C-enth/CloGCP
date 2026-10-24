"""Versioned native GCP evidence contract; contains metadata, never credentials."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from offline_analyzer.contracts.models import Digest, Identifier
from offline_analyzer.ingestion.safety import validate_relative_path

ProjectId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")]
ProjectNumber = Annotated[str, Field(pattern=r"^[0-9]{1,20}$")]
Status = Literal[
    "SUCCESS",
    "EMPTY",
    "FAILED",
    "PARTIAL",
    "ACCESS_DENIED",
    "NOT_COLLECTED",
    "NOT_APPLICABLE",
    "UNSUPPORTED",
    "UNKNOWN",
]


class GCPDataset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    project_id: ProjectId
    project_number: ProjectNumber | None = None
    operation: Annotated[str, Field(pattern=r"^gcp:[A-Za-z0-9_.]+$", max_length=200)]
    parameters: dict[str, str] = Field(default_factory=dict, max_length=40)
    started_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    dataset_type: Identifier = "native-json"
    location: Identifier = "global"
    status: Status
    record_count: int = Field(ge=0, le=100000)
    path: Identifier | None = None
    sha256: Digest | None = None
    pagination_complete: bool = False
    truncated: bool = False
    errors: tuple[Annotated[str, Field(pattern=r"^[A-Z0-9_]{1,100}$")], ...] = ()
    parser_profile: Literal["gcp-native-1", "unsupported"] = "gcp-native-1"
    normalized_resource_types: tuple[Identifier, ...] = ()
    applicable_rules: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def consistent(self):
        if self.path:
            validate_relative_path(self.path)
            if not self.sha256:
                raise ValueError("GCP checksum required")
        elif self.status in {"SUCCESS", "EMPTY", "PARTIAL"}:
            raise ValueError("GCP successful operation requires bytes")
        if self.status in {"SUCCESS", "EMPTY"} and (
            not self.pagination_complete or self.truncated or self.errors
        ):
            raise ValueError("GCP complete status requires complete pagination without errors")
        if self.status == "EMPTY" and self.record_count != 0:
            raise ValueError("GCP EMPTY requires zero records")
        if self.started_at and self.completed_at and self.started_at > self.completed_at:
            raise ValueError("GCP collection time order")
        return self


class GCPManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["closec-gcp-1"] = "closec-gcp-1"
    collector_version: Identifier
    assessment_id: Identifier
    organization_id: Annotated[str, Field(pattern=r"^[0-9]{1,20}$")] | None = None
    folder_id: Annotated[str, Field(pattern=r"^[0-9]{1,20}$")] | None = None
    expected_projects: tuple[ProjectId, ...] = Field(min_length=1, max_length=4096)
    collected_projects: tuple[ProjectId, ...] = Field(max_length=4096)
    dataset_origin: Literal["synthetic", "tool-generated"]
    provenance: Literal["collector-declared", "manual-unverified"] = "collector-declared"
    max_key_age_days: int = Field(default=90, ge=1, le=3650)
    datasets: tuple[GCPDataset, ...] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def scope(self):
        if len(set(self.expected_projects)) != len(self.expected_projects):
            raise ValueError("GCP duplicate expected projects")
        if len(set(self.collected_projects)) != len(self.collected_projects):
            raise ValueError("GCP duplicate collected projects")
        expected, collected = set(self.expected_projects), set(self.collected_projects)
        if not collected <= expected or any(d.project_id not in expected for d in self.datasets):
            raise ValueError("GCP project scope mismatch")
        if {d.project_id for d in self.datasets if d.path} != collected:
            raise ValueError("GCP collected project mismatch")
        paths = [d.path for d in self.datasets if d.path]
        if len({p.casefold() for p in paths}) != len(paths):
            raise ValueError("GCP duplicate artifact paths")
        if self.provenance == "manual-unverified" and any(
            d.status in {"SUCCESS", "EMPTY"} for d in self.datasets
        ):
            raise ValueError("GCP manual evidence cannot declare complete collection")
        if self.provenance == "collector-declared" and any(
            d.status in {"SUCCESS", "EMPTY"} and (not d.started_at or not d.completed_at)
            for d in self.datasets
        ):
            raise ValueError("Collector success requires collection timestamps")
        return self


class CloudTransition(BaseModel):
    """Static relationships and attack prerequisites remain separate claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["cloud-transition-1"] = "cloud-transition-1"
    provider: Literal["AWS", "GCP"]
    source: Identifier
    destination: Identifier
    relationship: Identifier
    status: Literal["STRUCTURAL_ONLY", "SUPPORTED", "POTENTIAL", "BLOCKED", "UNKNOWN"]
    evidence: tuple[dict[str, str], ...] = ()
    attack_prerequisites: tuple[Identifier, ...] = ()
    missing_evidence: tuple[Identifier, ...] = ()
    blocking_controls: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def supported_requires_evidence(self):
        if self.status == "SUPPORTED" and (
            not self.evidence
            or self.missing_evidence
            or self.blocking_controls
            or self.attack_prerequisites
        ):
            raise ValueError("Supported transition requires resolved context and evidence")
        if self.status == "BLOCKED" and not self.blocking_controls:
            raise ValueError("Blocked transition needs an observed blocking control")
        return self
