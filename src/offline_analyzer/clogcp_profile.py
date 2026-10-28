"""CloGCP distribution isolation, with the existing launcher and workspace architecture."""

import json
import os
import sys
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError

MARKER = "clogcp-workspace.json"


def configure() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") / "CloGCP"
        config = Path(os.environ.get("APPDATA") or Path.home() / "AppData/Roaming") / "CloGCP"
    elif sys.platform == "darwin":
        base = config = Path.home() / "Library/Application Support/CloGCP"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "clogcp"
        config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "clogcp"
    os.environ["CLOGCP_PROFILE"] = "1"
    os.environ["CLOSEC_CONFIG_DIR"] = os.environ.get("CLOGCP_CONFIG_DIR", str(config))
    # CloSec environment overrides are intentionally not inherited by this distribution.
    os.environ.pop("CLOSEC_WORKSPACE", None)
    if os.environ.get("CLOGCP_WORKSPACE"):
        os.environ["CLOSEC_WORKSPACE"] = os.environ["CLOGCP_WORKSPACE"]
    return base / "workspace"


MARKER_CONTENT = {"schema": "clogcp-workspace-1", "product": "CloGCP"}
# Files the launcher itself may leave in a folder before it becomes a workspace.
LAUNCHER_FILES = {
    ".gui-owner.lock",
    ".gui-owner.pid",
    "application.log",
    "workspace-environment.json",
}
# Fixed refusal codes and their reasons; no path or workspace content is ever included.
REFUSALS = {
    "CLOGCP_REFUSES_EXISTING_CLOSEC_OR_UNMARKED_WORKSPACE": (
        "This folder is not a CloGCP workspace (no clogcp-workspace.json; it may belong to "
        "another application). CloGCP opens only its own workspaces and never adopts another "
        "folder."
    ),
    "CLOGCP_WORKSPACE_MARKER_INVALID": (
        "The CloGCP workspace marker (clogcp-workspace.json) is damaged or not a regular file."
    ),
    "CLOSE_OR_RECOVER_PREVIOUS_APPLICATION_FIRST": (
        "The workspace was not closed cleanly: a database journal (assessment.duckdb.wal) is "
        "present. Close any application using it; if none is running, create a recovered copy "
        "with the verified-copy tool (--recover-journal) and open the copy. The original is "
        "never changed."
    ),
    "EXPLICIT_VERSIONED_WORKSPACE_UPGRADE_REQUIRED": (
        "The workspace uses an older database layout. Create an upgraded copy with the "
        "verified-copy tool (--upgrade-additive) and open the copy."
    ),
    "UNSUPPORTED_DATABASE_VERSION": (
        "This CloGCP does not support the workspace's database version (it may be newer). "
        "Open it with the release that created it; nothing was changed."
    ),
    "EXPLICIT_WORKSPACE_RECOVERY_REQUIRED": (
        "A workspace scope operation was interrupted and needs explicit recovery first."
    ),
    "INCOMPLETE_WORKSPACE_RECOVERY_REFUSED": (
        "This folder is part of an unfinished verified copy. Do not open it; repeat the copy "
        "into a new folder."
    ),
}


def marker_problem(path: Path) -> str | None:
    """Read-only form of the marker rule in ensure_workspace: refusal code or None."""
    path = path.resolve()
    marker = path / MARKER
    if marker.is_file() and not marker.is_symlink():
        try:
            valid = marker.stat().st_size <= 1024 and json.loads(marker.read_bytes()) == (
                MARKER_CONTENT
            )
        except (OSError, ValueError):
            valid = False
        return None if valid else "CLOGCP_WORKSPACE_MARKER_INVALID"
    if marker.exists() or marker.is_symlink():
        return "CLOGCP_WORKSPACE_MARKER_INVALID"
    if path.exists() and any(p.name not in LAUNCHER_FILES for p in path.iterdir()):
        return "CLOGCP_REFUSES_EXISTING_CLOSEC_OR_UNMARKED_WORKSPACE"
    return None


def open_refusal(path: Path) -> str | None:
    """Every check the CloGCP launcher applies before opening, read-only: code or None.

    Shared by the launcher and the Open existing workspace check, so the screen never
    accepts a folder the launcher would then refuse."""
    from offline_analyzer.storage.side_by_side import compatible

    problem = marker_problem(path)
    if problem:
        return problem
    try:
        compatible(path)
    except InputError as exc:
        return str(exc)
    return None


def ensure_workspace(path: Path) -> None:
    path = path.resolve()
    problem = marker_problem(path)
    if problem:
        raise InputError(problem)
    marker = path / MARKER
    if marker.is_file():
        return
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with marker.open("x") as file:
        json.dump(MARKER_CONTENT, file)
    os.chmod(marker, 0o600)
