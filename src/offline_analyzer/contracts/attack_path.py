"""One directed attack-path edge with its justification, STRIDE mapping and evidence."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

EdgeType = Literal[
    "network-reachable",
    "can-invoke-anonymously",
    "can-read-anonymously",
    "can-impersonate",
    "authenticates-as",
    "holds-role",
    "can-access",
    "can-call-api",
    "reads-credentials",
    "can-assume",
    "federates-as",
    "can-escalate",
    "not-blocked-by",
    "stores",
]
Stride = Literal[
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]
Text = Annotated[str, Field(min_length=1, max_length=4000)]


class PathHop(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["path-hop-1"] = "path-hop-1"
    index: int = Field(ge=1)
    source: Text
    target: Text
    edge_type: EdgeType
    direction: Text
    justification: Text
    stride: list[Stride] = Field(min_length=1)
    status: Literal["PROVEN", "HYPOTHESIS", "BLOCKED"]
    rule_ids: list[str] = []
    finding_ids: list[str] = []
    observation_ids: list[str] = []
    evidence_refs: list[dict[str, str]] = []
    missing_evidence: list[Annotated[str, Field(max_length=2000)]] = []
