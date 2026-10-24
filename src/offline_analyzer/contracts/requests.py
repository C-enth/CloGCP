"""Versioned offline request contract; collection scope remains collector-controlled."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from offline_analyzer.contracts.models import AccountId, Identifier
from offline_analyzer.contracts.r0 import AWS_OPERATIONS


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_id: Literal["closec-evidence-request-item-1"] = Field(
        default="closec-evidence-request-item-1", alias="schema"
    )
    request_id: Identifier
    account_id: AccountId
    region: Identifier
    operation: Literal[*AWS_OPERATIONS]
    state: Identifier
    reason: str
    request: str
    request_parameters: dict[str, JsonValue]
    related_investigations: list[str]
    related_controls: list[str]
    priority: Literal["HIGH", "NORMAL"]
    recommended_freshness_hours: int = Field(ge=1, le=168)
    freshness_basis: str
