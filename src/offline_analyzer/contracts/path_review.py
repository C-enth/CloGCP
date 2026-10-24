"""Analyst review of an evidence-backed path interpretation, never exploitation proof."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict


class PathReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["path-review-1"] = "path-review-1"
    run_id: str
    path_id: str
    fingerprint: str
    analyst: str
    reviewed_at: AwareDatetime
    status: Literal["CONFIRMED", "REJECTED"]
