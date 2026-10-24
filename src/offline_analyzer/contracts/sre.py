"""SRE validation verdicts, recorded independently of analyst decisions (ADR-008)."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from offline_analyzer.contracts.models import Digest, Identifier

Verdict = Literal["SENT_TO_SRE", "GAP_CONFIRMED", "NO_GAP_BAU", "NEEDS_INFO"]
Person = Annotated[str, Field(max_length=200)]


class SreValidation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["sre-validation-1"] = "sre-validation-1"
    finding_id: Identifier
    run_id: Identifier
    verdict: Verdict
    sre_contact: Person = ""
    recorded_by: Annotated[str, Field(min_length=1, max_length=200)]
    reason: Annotated[str, Field(max_length=16000)] = ""
    recorded_at: AwareDatetime
    evidence_fingerprint: Digest

    @model_validator(mode="after")
    def _justified(self):
        # A BAU conclusion removes a finding from the vulnerability path; record why.
        if self.verdict == "NO_GAP_BAU" and not self.reason.strip():
            raise ValueError("NO_GAP_BAU requires the SRE's BAU justification")
        return self
