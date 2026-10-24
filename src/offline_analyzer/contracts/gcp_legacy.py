"""Observed native collector format; no checksum/completeness assertions added."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, model_validator

from offline_analyzer.contracts.gcp import ProjectId


class PilotDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(max_length=100)
    dataset: str = Field(max_length=200)
    status: Literal["SUCCESS", "EMPTY", "FAILED"]
    record_count: int | None = Field(default=None, ge=0, le=100000)
    exit_code: int
    started_utc: AwareDatetime
    finished_utc: AwareDatetime
    file: str | None = Field(default=None, max_length=500)
    error_file: str | None = Field(default=None, max_length=500)
    command: str | list[str] = Field(max_length=16000)

    @model_validator(mode="after")
    def valid_status(self):
        if self.started_utc > self.finished_utc:
            raise ValueError("Invalid collection time window")
        if self.status in {"SUCCESS", "EMPTY"} and (self.exit_code != 0 or not self.file):
            raise ValueError("Successful collection needs a file and zero exit code")
        if self.status == "EMPTY" and self.record_count not in {None, 0}:
            raise ValueError("EMPTY count mismatch")
        return self


class PilotManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["pilot-1.2.2"]
    collector: str | dict[str, JsonValue]
    project_id: ProjectId
    project_name: str | None = Field(default=None, max_length=300)
    collected_utc: AwareDatetime
    scope: JsonValue
    limitations: JsonValue
    datasets: list[PilotDataset] = Field(min_length=1, max_length=1024)
    # Synthetic fixtures must declare their origin. Real unlabelled legacy collectors
    # default to tool-generated, never auto-converted into demonstrations.
    dataset_origin: Literal["synthetic", "tool-generated"] = "tool-generated"


class Pilot15Dataset(PilotDataset):
    status: Literal["SUCCESS", "EMPTY", "FAILED", "ACCESS_DENIED", "API_DISABLED", "AUTH_ERROR"]
    exit_code: int | None = None
    required_api: str = Field(max_length=400)
    pages: int | None = Field(default=None, ge=0, le=100000, strict=True)


class AssetTypeCount(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_type: str = Field(min_length=1, max_length=400)
    count: int = Field(ge=0, strict=True)


class Pilot15Manifest(PilotManifest):
    schema_version: Literal["pilot-1.5"]
    datasets: list[Pilot15Dataset] = Field(min_length=1, max_length=1024)
    max_detail_items: int = Field(ge=1, le=100000, strict=True)
    max_api_pages: int = Field(ge=1, le=100000, strict=True)
    enabled_api_count: int = Field(ge=0, le=100000, strict=True)
    discovered_asset_types: list[AssetTypeCount] = Field(max_length=4096)


class ManifestDetection(BaseModel):
    """Fixed format vocabulary only; no paths, customer values or raw errors."""

    model_config = ConfigDict(extra="forbid")
    filename: Literal["collection_manifest.json"] = "collection_manifest.json"
    detected_version: str = Field(
        pattern=r"^(?:(?:pilot-|assessment-expanded-)[0-9]+(?:\.[0-9]+){0,3}|MISSING|UNRECOGNIZED_TOKEN)$",
        max_length=80,
    )
    selected_adapter: Literal[
        "gcp-pilot-1.2.2-adapter-1",
        "gcp-pilot-1.5-adapter-1",
        "gcp-expanded-2.1-adapter-1",
        "gcp-expanded-2.2-adapter-1",
        "NONE",
    ]
    expected_versions: list[
        Literal["pilot-1.2.2", "pilot-1.5", "assessment-expanded-2.1", "assessment-expanded-2.2"]
    ]
    manifest_count: int = Field(ge=0, le=1100)
    rejection_condition: (
        Literal[
            "root schema_version is missing",
            "root schema_version is not a supported pilot version",
            "root schema_version is not a supported collector version",
            "collector_version is outside the accepted range for assessment-expanded-2.2 "
            "(2.2.0 to 2.2.8)",
            "manifest root must be an object",
        ]
        | None
    ) = None
    corrective_action: (
        Literal[
            "Preserve the original package; use a CloSec adapter supporting its exact collector "
            "version. Do not rename or edit the manifest."
        ]
        | None
    ) = None
