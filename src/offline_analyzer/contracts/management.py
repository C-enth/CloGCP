"""Versioned scope actions; independent exact identity and explicit confirmation."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator


class ScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["scope-action-1"] = "scope-action-1"
    provider: Literal["AWS", "GCP"]
    scope_id: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def exact_identity(self):
        pattern = r"[0-9]{12}" if self.provider == "AWS" else r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
        if not re.fullmatch(pattern, self.scope_id):
            raise ValueError("Canonical scope identifier required")
        return self


class ScopeDelete(ScopeRequest):
    preview_token: str = Field(max_length=200)
    confirmation: str = Field(default="", max_length=100)
    confirmed: StrictBool = False
    # Pre-purge workspace backup; on unless the analyst explicitly unticks it.
    backup: StrictBool = True
    # Explicit override when a finalised edition includes the scope (never the default).
    supersede_frozen: StrictBool = False
    supersede_confirmation: str = Field(default="", max_length=100)
    supersede_reason: str = Field(default="", max_length=2000)


class ScopeReplace(ScopeRequest):
    upload_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    acknowledge_legacy_integrity: StrictBool = False


class FileRequest(BaseModel):
    """One imported file, named by its exact content digest."""

    model_config = ConfigDict(extra="forbid")
    version: Literal["file-action-1"] = "file-action-1"
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FileDelete(FileRequest):
    preview_token: str = Field(max_length=200)
    confirmation: str = Field(default="", max_length=100)
    confirmed: StrictBool = False
    supersede_frozen: StrictBool = False
    supersede_confirmation: str = Field(default="", max_length=100)
    supersede_reason: str = Field(default="", max_length=2000)
