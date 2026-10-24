"""Versioned immutable assessment edition."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, JsonValue


class FrozenAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["finalized-assessment-1"] = "finalized-assessment-1"
    run_id: str
    created_at: AwareDatetime
    analyst: str
    view: dict[str, JsonValue]
    document: dict[str, JsonValue]
