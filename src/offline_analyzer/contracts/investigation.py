"""Evidence-bound additional security observations, distinct from approved findings."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict

from offline_analyzer.contracts.models import AccountId, EvidenceRef, Identifier


class SecurityInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["security-investigation-1"] = "security-investigation-1"
    investigation_id: Identifier
    finding_id: Identifier
    evaluation_id: Identifier
    rule_id: Identifier
    security_domain: Identifier
    account_id: AccountId
    region: Identifier
    affected_resources: tuple[Identifier, ...]
    evidence: tuple[EvidenceRef, ...]
    technical_hypothesis: str
    missing_validation: tuple[Identifier, ...]
    security_implications: str
    assessment_snapshot_time: AwareDatetime
    methodology_id: None = None
    scope: Literal["ADDITIONAL_SECURITY_OBSERVATION_REQUIRING_ANALYST_REVIEW"] = (
        "ADDITIONAL_SECURITY_OBSERVATION_REQUIRING_ANALYST_REVIEW"
    )
