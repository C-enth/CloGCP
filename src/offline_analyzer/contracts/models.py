"""Versioned, conservative boundary contracts; no evaluation engine."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

Identifier = Annotated[str, Field(min_length=1, max_length=512)]
AccountId = Annotated[str, Field(pattern=r"^[0-9]{12}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"


class Artifact(Contract):
    artifact_id: Identifier
    relative_path: Identifier
    sha256: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0)]

    @field_validator("relative_path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        from offline_analyzer.ingestion.safety import validate_relative_path

        validate_relative_path(value)
        return value


class EvidenceRef(Contract):
    artifact_id: Identifier
    locator: Identifier


class Coverage(Contract):
    account_id: AccountId
    region: Identifier  # explicit "global" where applicable
    service: Identifier
    operation: Identifier
    status: Literal["COMPLETE", "PARTIAL", "ERROR", "NOT_COLLECTED"]
    errors: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def validate_error(self):
        if self.status == "ERROR" and not self.errors:
            raise ValueError("ERROR coverage requires error records")
        return self


class Manifest(Contract):
    run_id: Identifier
    source_id: Identifier
    collector: Identifier
    collector_version: Identifier
    collection_started: AwareDatetime
    collection_finished: AwareDatetime
    artifacts: tuple[Artifact, ...]
    coverage: tuple[Coverage, ...]

    @model_validator(mode="after")
    def consistent(self):
        if self.collection_finished < self.collection_started:
            raise ValueError("collection window reversed")
        ids = [a.artifact_id for a in self.artifacts]
        paths = [a.relative_path for a in self.artifacts]
        if len(set(ids)) != len(ids) or len(set(paths)) != len(paths):
            raise ValueError("duplicate artifact identity or path")
        return self


class Resource(Contract):
    resource_id: Identifier
    partition: Identifier
    account_id: AccountId
    region: Identifier
    service: Identifier
    native_id: Identifier


class Observation(Contract):
    observation_id: Identifier
    run_id: Identifier
    source_id: Identifier
    parser_id: Identifier
    parser_version: Identifier
    resource: Resource
    predicate: Identifier
    value: JsonValue
    observed_at: AwareDatetime
    evidence: Annotated[tuple[EvidenceRef, ...], Field(min_length=1)]
    limitations: tuple[Identifier, ...] = ()


class Relationship(Contract):
    relationship_id: Identifier
    run_id: Identifier
    source_resource_id: Identifier
    target_resource_id: Identifier
    kind: Literal["CONTAINS", "ATTACHED_TO", "TRUSTS", "PERMITS", "ROUTES_TO"]
    evidence: Annotated[tuple[EvidenceRef, ...], Field(min_length=1)]
    conditions: tuple[Identifier, ...] = ()
    limitations: tuple[Identifier, ...] = ()


class Outcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    COLLECTION_ERROR = "COLLECTION_ERROR"
    MANUAL_VALIDATION_REQUIRED = "MANUAL_VALIDATION_REQUIRED"


class RuleSpec(Contract):
    control_id: Identifier
    rule_version: Identifier
    methodology_sha256: Digest
    source_location: Identifier
    prerequisites: tuple[Identifier, ...]
    applicability: Identifier
    pass_condition: Identifier
    fail_condition: Identifier
    limitations: tuple[Identifier, ...]
    status: Literal["DRAFT", "APPROVED"] = "DRAFT"


class Evaluation(Contract):
    evaluation_id: Identifier
    run_id: Identifier
    control_id: Identifier
    rule_version: Identifier
    methodology_sha256: Digest
    accounts: tuple[AccountId, ...]
    resource_ids: tuple[Identifier, ...]
    outcome: Outcome
    evidence: tuple[EvidenceRef, ...]
    reasoning: Identifier
    missing_dependencies: tuple[Identifier, ...]
    confidence: Literal["HIGH", "MEDIUM", "LOW", "UNASSESSED"]
    limitations: tuple[Identifier, ...]
    assessed_at: AwareDatetime

    @model_validator(mode="after")
    def defensible_pass(self):
        if self.outcome == Outcome.PASS and (not self.evidence or self.missing_dependencies):
            raise ValueError("PASS requires evidence and satisfied dependencies")
        return self


class PathEvaluation(Contract):
    path_definition_id: Identifier
    definition_version: Identifier
    run_id: Identifier
    state: Literal["SUPPORTED", "BLOCKED", "UNKNOWN", "NOT_APPLICABLE"]
    relationship_ids: tuple[Identifier, ...]
    evidence: tuple[EvidenceRef, ...]
    prerequisites: tuple[Identifier, ...]
    blockers: tuple[Identifier, ...]
    missing_dependencies: tuple[Identifier, ...]
    reasoning: Identifier
    limitations: tuple[Identifier, ...]
    assessed_at: AwareDatetime

    @model_validator(mode="after")
    def supported_requires_proof(self):
        if self.state == "SUPPORTED" and (
            not self.relationship_ids
            or not self.evidence
            or self.missing_dependencies
            or self.blockers
        ):
            raise ValueError("SUPPORTED requires evidenced edges and resolved prerequisites")
        return self
