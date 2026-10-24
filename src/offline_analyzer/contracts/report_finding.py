"""Immutable analyst-authored report revisions, separate from automated candidates."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from offline_analyzer.contracts.models import Digest, Identifier

Text = Annotated[str, Field(max_length=16000)]


class ReportSections(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    title: Annotated[str, Field(min_length=1, max_length=500)]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_rationale: Text
    technical_observation: Text
    expected_posture: Text
    risk: Text
    attack_scenario: Text = (
        "Not established. Configuration evidence does not demonstrate exploitation."
    )
    root_cause: Text = "Not established; validate configuration ownership and change history."
    remediation: Text
    # Group-level edit (owner brief 2b): immediate mitigation separate from the permanent fix.
    immediate_mitigation: Text = ""
    considerations: Text
    validation: Text
    references: tuple[Annotated[str, Field(max_length=2000)], ...] = Field(max_length=20)


class ReportEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    analyst: Annotated[str, Field(min_length=1, max_length=200)]
    sections: ReportSections
    # Root-cause group edits may cover up to MAX_BULK member findings.
    member_ids: list[Identifier] = Field(min_length=1, max_length=2000)
    include_in_report: bool = False
    consolidation_basis: Text = ""


class ReportApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=1)
    analyst: Annotated[str, Field(min_length=1, max_length=200)]
    kind: Literal["RECOMMENDATION", "NARRATIVE", "CONSOLIDATION", "RISK_ACCEPTANCE"]
    rationale: Text = ""


class EvidenceSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding_id: Identifier
    fingerprint: Digest
    account_id: Identifier | None
    provider: Literal["AWS", "GCP"] = "AWS"
    project_id: Identifier | None = None
    region: Identifier
    resource_id: Identifier
    native_id: Identifier
    collection_ids: tuple[Identifier, ...] = Field(min_length=1)
    evidence: tuple[dict[str, str], ...] = Field(min_length=1)


class ApprovalStamp(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reviewer: Annotated[str, Field(min_length=1, max_length=200)]
    approved_at: AwareDatetime
    assessment_run: Identifier
    rationale: Text


class ReportRevision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["report-finding-1"] = "report-finding-1"
    report_id: Identifier
    primary_finding: Identifier
    revision: int = Field(ge=1)
    run_id: Identifier
    created_at: AwareDatetime
    author: Identifier
    sections: ReportSections
    snapshots: tuple[EvidenceSnapshot, ...] = Field(min_length=1, max_length=200)
    recommendation_version: Identifier
    include_in_report: bool
    consolidation_basis: Text = ""
    recommendation_approval: ApprovalStamp | None = None
    narrative_approval: ApprovalStamp | None = None
    consolidation_approval: ApprovalStamp | None = None
    risk_acceptance: ApprovalStamp | None = None
    report_text: str
