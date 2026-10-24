"""Analyst exclusion of a finding from client reporting; evidence and evaluation unchanged."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from offline_analyzer.contracts.models import Identifier

# Common reasons offered in the UI; OTHER requires an explanatory note.
Reason = Literal[
    "FALSE_POSITIVE",
    "DUPLICATE",
    "ACCEPTED_RISK",
    "OUT_OF_SCOPE",
    "COMPENSATING_CONTROL",
    "NOT_APPLICABLE",
    "OTHER",
]
Action = Literal["EXCLUDE", "RESTORE"]
Note = Annotated[str, Field(max_length=2000)]


class ExclusionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["finding-exclusion-request-1"] = "finding-exclusion-request-1"
    action: Action
    reason: Reason | None = None
    note: Note = ""
    analyst: Annotated[str, Field(min_length=1, max_length=200)]

    @model_validator(mode="after")
    def _reasoned(self):
        if self.action == "EXCLUDE" and self.reason is None:
            raise ValueError("An exclusion requires a reason")
        if self.reason == "OTHER" and not self.note.strip():
            raise ValueError("Reason OTHER requires a note")
        if self.reason == "FALSE_POSITIVE" and not self.note.strip():
            raise ValueError("A false-positive disposition requires a reason")
        return self


class BulkExclusionRequest(ExclusionRequest):
    """The same disposition for many findings of one run, all-or-nothing."""

    version: Literal["finding-exclusion-request-1"] = "finding-exclusion-request-1"
    finding_ids: Annotated[list[Identifier], Field(min_length=1, max_length=2000)]


class FindingExclusion(BaseModel):
    """Append-only record; the latest record per finding decides whether it is excluded."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["finding-exclusion-1"] = "finding-exclusion-1"
    finding_id: Identifier
    run_id: Identifier
    action: Action
    reason: Reason | None = None
    note: Note = ""
    analyst: Annotated[str, Field(min_length=1, max_length=200)]
    recorded_at: AwareDatetime
    # Analyst state of the finding when the disposition was recorded (restore reverts to it).
    previous_state: Annotated[str, Field(max_length=60)] | None = None
    # Principals named by the finding when recorded; a new import of the same project
    # carries a false-positive disposition over only when they match exactly.
    principals: tuple[Annotated[str, Field(max_length=400)], ...] = ()
    # Set on read (never stored) when a disposition is carried over from another import.
    carried_from: Identifier | None = None
