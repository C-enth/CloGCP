"""Additive enterprise projection contract; observed references are not authorization."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from offline_analyzer.contracts.models import AccountId, EvidenceRef, Identifier

STATUS = Literal["DIRECTLY_OBSERVED", "DERIVED_SUPPORTED", "POTENTIAL", "BLOCKED", "UNKNOWN"]


class Edge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["enterprise-1"] = "enterprise-1"
    relationship_id: Identifier
    run_id: Identifier
    source_account: AccountId | None
    source: Annotated[str, Field(min_length=1, max_length=4096)]
    destination_account: AccountId | None
    destination: Annotated[str, Field(min_length=1, max_length=4096)]
    source_partition: Identifier | None = None
    destination_partition: Identifier | None = None
    relationship_type: Identifier
    service: Identifier
    domain: Literal["IAM", "RESOURCE_ACCESS", "NETWORK", "MONITORING", "ORGANIZATION"]
    region: Identifier
    status: STATUS
    authorization: str | None = None
    evidence: tuple[EvidenceRef, ...]
    observation_ids: tuple[Identifier, ...]
    collected_at: tuple[AwareDatetime, ...]
    assessed_at: AwareDatetime
    missing: tuple[str, ...] = ()
    blocking: tuple[str, ...] = ()
    confidence: Literal["HIGH", "MEDIUM", "LOW", "UNASSESSED"]
    limitations: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    detail: str
    related_findings: tuple[str, ...] = ()
    methodology_ids: tuple[str, ...] = ()
    target_privilege: str | None = None
    outside_registry: bool | None = None

    @model_validator(mode="after")
    def supported(self):
        if (
            self.status in {"DIRECTLY_OBSERVED", "DERIVED_SUPPORTED", "BLOCKED"}
            and not self.evidence
        ):
            raise ValueError("supported or blocked edge requires source evidence")
        if self.status == "DERIVED_SUPPORTED" and (self.missing or self.blocking):
            raise ValueError("supported predicate cannot have unresolved prerequisites")
        if (
            self.source_partition
            and self.destination_partition
            and self.source_partition != self.destination_partition
            and self.status == "DERIVED_SUPPORTED"
        ):
            raise ValueError("cross-partition authorization cannot be supported")
        return self


class EnterpriseSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["enterprise-1"] = "enterprise-1"
    member_runs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=2048)]
    context: dict[str, str | None]
    targets: Annotated[tuple[dict[str, str], ...], Field(max_length=16384)]
