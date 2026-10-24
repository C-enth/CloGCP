"""Private, analyst-approved account registry kept inside the assessment workspace.

Maps real 12-digit account IDs to the approved tracker keys (ACCT-nnn). Every entry must
come from an approved source document; nothing is inferred from row order, names or
evidence. The registry classifies results and keys tracker rows; it never gates analysis:
accounts absent from it are still assessed and reported by their 12-digit ID.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from offline_analyzer.contracts.models import AccountId, Identifier
from offline_analyzer.ingestion.json_input import InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under

REGISTRY_FILE = "account-registry.json"
TRACKER_KEY = r"^(?:ACCT-[0-9]{3,}|[0-9]{12})$"


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    account_id: AccountId
    tracker_key: Annotated[str, Field(pattern=TRACKER_KEY)] | None = None
    in_scope: bool
    environment: Identifier | None = None
    alias: Identifier | None = None
    groups: Annotated[tuple[Identifier, ...], Field(max_length=64)] = ()


class AccountRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["account-registry-1"]
    source: Identifier  # approved inventory document the mapping was taken from
    approved_by: Identifier
    approved_at: AwareDatetime
    entries: Annotated[tuple[Entry, ...], Field(max_length=10000)]

    @model_validator(mode="after")
    def unique(self):
        ids = [e.account_id for e in self.entries]
        keys = [e.tracker_key for e in self.entries if e.tracker_key]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate account ID")
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate tracker key")
        return self

    @property
    def accounts(self) -> dict[str, Entry]:
        return {e.account_id: e for e in self.entries}

    @property
    def in_scope(self) -> list[str]:
        return sorted(e.account_id for e in self.entries if e.in_scope)

    def tracker_keys(self) -> dict[str, str]:
        return {e.account_id: e.tracker_key for e in self.entries if e.tracker_key}

    def fingerprint(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


def parse_registry(path: Path) -> AccountRegistry:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise InputError("ACCOUNT_REGISTRY_FILE_LIMIT")
    inspect_json(path)  # duplicate keys, depth, credential patterns
    try:
        return AccountRegistry.model_validate_json(path.read_bytes())
    except ValueError as exc:
        raise InputError("INVALID_ACCOUNT_REGISTRY") from exc


def install_registry(workspace: Path, path: Path) -> AccountRegistry:
    """Validate and store privately; previous versions are retained, never overwritten."""
    registry = parse_registry(path)
    target = resolve_under(workspace, REGISTRY_FILE)
    history = resolve_under(workspace, "account-registry-history")
    history.mkdir(mode=0o700, exist_ok=True)
    if target.exists():
        previous = target.read_bytes()
        archived = history / f"{hashlib.sha256(previous).hexdigest()}.json"
        if not archived.exists():
            archived.write_bytes(previous)
            os.chmod(archived, 0o600)
    staging = resolve_under(workspace, REGISTRY_FILE + ".tmp")
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(registry.model_dump_json(indent=2))
    staging.replace(target)
    return registry


def workspace_registry(workspace: Path) -> AccountRegistry | None:
    target = resolve_under(workspace, REGISTRY_FILE)
    return parse_registry(target) if target.exists() else None


def legacy_key_map(path: Path) -> dict[str, str]:
    """R1 `--account-keys` JSON (12-digit -> tracker key), still accepted for export."""
    if path.stat().st_size > 1024 * 1024:
        raise InputError("ACCOUNT_KEY_FILE_LIMIT")
    inspect_json(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(k, str)
        and re.fullmatch(r"[0-9]{12}", k)
        and isinstance(v, str)
        and re.fullmatch(TRACKER_KEY, v)
        for k, v in data.items()
    ):
        raise InputError("INVALID_ACCOUNT_KEY_FILE")
    if len(set(data.values())) != len(data):
        raise InputError("DUPLICATE_TRACKER_ACCOUNT_KEY")
    return data
