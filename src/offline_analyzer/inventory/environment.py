"""Workspace environment label and per-run dataset origin.

A workspace is either SYNTHETIC (demonstrations, tests, training) or ASSESSMENT (approved
customer collector exports). The label is set once and never changed. SYNTHETIC workspaces
accept only origin "synthetic" and ASSESSMENT workspaces only "tool-generated", so a
demonstration can never be mixed with, or mistaken for, customer findings. Unlabeled
legacy workspaces remain readable and are flagged as not approved for customer reporting.
"""

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under

ENVIRONMENT_FILE = "workspace-environment.json"
ORIGINS_FILE = "run-origins.json"
ALLOWED_ORIGINS = {"SYNTHETIC": {"synthetic"}, "ASSESSMENT": {"tool-generated"}}


@dataclass(frozen=True)
class Environment:
    label: str
    name: str
    created_at: str


def workspace_environment(workspace: Path) -> Environment | None:
    path = resolve_under(workspace, ENVIRONMENT_FILE)
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("label") not in ALLOWED_ORIGINS:
        raise InputError("INVALID_WORKSPACE_ENVIRONMENT")
    return Environment(data["label"], data.get("name", ""), data.get("created_at", ""))


def set_environment(workspace: Path, label: str, name: str = "") -> Environment:
    """Label once; relabelling an existing workspace is refused."""
    if label not in ALLOWED_ORIGINS:
        raise InputError("INVALID_WORKSPACE_ENVIRONMENT")
    if not re.fullmatch(r"[\w .:-]{0,80}", name):
        raise InputError("INVALID_WORKSPACE_NAME")
    current = workspace_environment(workspace)
    if current:
        if current.label != label:
            raise InputError("WORKSPACE_ENVIRONMENT_IMMUTABLE")
        return current
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment = Environment(label, name, datetime.now(UTC).isoformat())
    path = resolve_under(workspace, ENVIRONMENT_FILE)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(environment.__dict__, stream, indent=2)
    return environment


def check_origin(workspace: Path, origin: str) -> None:
    environment = workspace_environment(workspace)
    if environment and origin not in ALLOWED_ORIGINS[environment.label]:
        raise InputError(
            "SYNTHETIC_WORKSPACE_REJECTS_TOOL_GENERATED"
            if environment.label == "SYNTHETIC"
            else "ASSESSMENT_WORKSPACE_REJECTS_SYNTHETIC"
        )


def run_origins(workspace: Path) -> dict[str, str]:
    path = resolve_under(workspace, ORIGINS_FILE)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def record_run_origin(workspace: Path, run: str, origin: str) -> None:
    """A run keeps its first origin; importing the same run under another origin fails."""
    if origin not in {"synthetic", "tool-generated", "mixed", "unrecorded"}:
        raise InputError("INVALID_ORIGIN")
    origins = run_origins(workspace)
    if origins.get(run, origin) != origin:
        raise InputError("RUN_ORIGIN_CONFLICT")
    origins[run] = origin
    path = resolve_under(workspace, ORIGINS_FILE)
    staging = resolve_under(workspace, ORIGINS_FILE + ".tmp")
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(origins, stream, indent=2, sort_keys=True)
    staging.replace(path)


def dataset_origin(workspace: Path, runs: list[str]) -> str:
    """SYNTHETIC / TOOL_GENERATED / MIXED / UNRECORDED for a set of runs."""
    origins = run_origins(workspace)
    found = {origins.get(run, "unrecorded") for run in runs}
    if found == {"synthetic"}:
        return "SYNTHETIC"
    if found == {"tool-generated"}:
        return "TOOL_GENERATED"
    return "UNRECORDED" if found == {"unrecorded"} else "MIXED"


def enterprise_origin(store, members: list[str] | None) -> str:
    """Origin of an enterprise snapshot's members; ASSESSMENT needs all tool-generated."""
    if members is None:
        snapshots = (
            {r[0] for r in store.db.execute("SELECT run_id FROM enterprise_snapshots").fetchall()}
            if store.db.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_name='enterprise_snapshots'"
            ).fetchone()
            else set()
        )
        members = [
            r[0]
            for r in store.db.execute("SELECT run_id FROM runs").fetchall()
            if r[0] not in snapshots
        ]
    combined = dataset_origin(store.workspace, members)
    environment = workspace_environment(store.workspace)
    if environment and environment.label == "ASSESSMENT" and combined != "TOOL_GENERATED":
        raise InputError("ENTERPRISE_MEMBERS_MUST_BE_TOOL_GENERATED")
    if environment and environment.label == "SYNTHETIC" and combined != "SYNTHETIC":
        raise InputError("ENTERPRISE_MEMBERS_MUST_BE_SYNTHETIC")
    return {"SYNTHETIC": "synthetic", "TOOL_GENERATED": "tool-generated"}.get(
        combined, combined.lower()
    )
