"""Versioned configuration conclusions; independent of execution and analyst review."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

Classification = Literal[
    "SUPPORTED", "CONDITIONAL", "BLOCKED", "INSUFFICIENT_EVIDENCE", "UNSUPPORTED"
]
PermissionState = Literal["AVAILABLE", "CONTRADICTED", "CONDITIONAL", "UNCOLLECTED", "UNSUPPORTED"]


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    state: PermissionState
    reason: str
    observation_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def requires_evidence(self):
        if self.state in {"AVAILABLE", "CONTRADICTED"} and not self.observation_ids:
            raise ValueError("positive and blocking conclusions require cited observations")
        return self


class PermissionEvidence(Condition):
    permission: str
    principal: str
    resource: str
    allow_state: PermissionState


class DiscoveryLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_nodes: int = Field(default=10000, ge=1, le=100000)
    max_depth: int = Field(default=6, ge=1, le=16)
    max_candidates: int = Field(default=1000, ge=1, le=10000)
    max_bindings: int = Field(default=50000, ge=1, le=200000)


class GCPPathEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["gcp-attack-path-2"] = "gcp-attack-path-2"
    engine_version: Literal["2.0.0", "2.0.1"] = "2.0.1"
    path_id: str
    canonical_key: str
    root_cause_id: str
    family: str
    project_id: str
    root_security_gap: str
    entry_point: str
    target: str
    identity: str
    mechanism: str
    relationships: list[str]
    prerequisites: list[Condition] = Field(min_length=1)
    classification: Classification
    exploitation_verification: Literal["UNVERIFIED"] = "UNVERIFIED"
    exploitation_requirements: list[str] = Field(default_factory=list)
    finding_validation: Literal["NOT_INHERITED"] = "NOT_INHERITED"
    analyst_review: Literal["UNREVIEWED"] = "UNREVIEWED"
    potential_impact: str
    severity: Literal["HIGH", "MEDIUM"]
    severity_rationale: str
    evidence_provenance: list[dict] = Field(default_factory=list)
    original_finding_ids: list[str] = Field(default_factory=list)
    legacy_paths: list[dict] = Field(default_factory=list)
    recommended_remediation: str
    remaining_verification: list[str]

    @model_validator(mode="after")
    def qualified_state(self):
        if self.classification != classify(self.prerequisites):
            raise ValueError("classification disagrees with mandatory configuration prerequisites")
        return self


def classify(conditions: list[Condition]) -> Classification:
    states = {c.state for c in conditions}
    if "CONTRADICTED" in states:
        return "BLOCKED"
    if not states or "UNCOLLECTED" in states:
        return "INSUFFICIENT_EVIDENCE"
    if "UNSUPPORTED" in states:
        return "UNSUPPORTED"
    if "CONDITIONAL" in states:
        return "CONDITIONAL"
    return "SUPPORTED"


class GCPAttackPathRegister(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["gcp-attack-path-register-2"] = "gcp-attack-path-register-2"
    engine_version: Literal["2.0.0", "2.0.1"] = "2.0.1"
    run_id: str
    evaluated_at: AwareDatetime
    paths: list[GCPPathEvaluation]
    active_path_ids: list[str]
    root_cause_groups: dict[str, list[str]]
    limits: DiscoveryLimits
    truncated: bool
    truncation_reasons: list[str]
    elapsed_seconds: float
    visited_nodes: int
    inspected_bindings: int
    limitations: list[str]
