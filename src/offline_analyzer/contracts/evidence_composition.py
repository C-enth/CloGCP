"""Versioned evidence-composition provenance; source runs and reviews are immutable."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class CompositionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    resource_scope: list[str] = Field(min_length=3, max_length=3)
    previous_observation: str
    previous_artifact: str
    new_artifact: str | None
    previous_collected_at: AwareDatetime
    new_collected_at: AwareDatetime
    status: Literal[
        "SUPERSEDED_BY_LATER_ATTEMPT",
        "SAME_TIME_CONFLICT_REQUIRES_REVIEW",
        "OLDER_DELTA_RETAINED_AS_HISTORY",
        "SEMANTICALLY_EQUIVALENT_BASIS_RETAINED",
    ]
    new_coverage: str


class EvidenceComposition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["gcp-evidence-composition-1"] = "gcp-evidence-composition-1"
    base_run: str
    delta_run: str
    source_runs: list[str] = Field(min_length=2, max_length=2)
    events: list[CompositionEvent]
    collection_timestamps: list[AwareDatetime]
    simultaneous_state_established: Literal[False] = False
    temporally_mixed: bool
    baseline_modified: Literal[False] = False
    analysis_strategy: Literal["EXISTING_EVALUATORS_IN_NEW_RUN"]
    broader_analysis_reason: str
    affected_scopes: list[list[str]]
    security_reviews_copied: Literal[False] = False
    reconciliation: list[dict] = Field(default_factory=list)
    materialized_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
