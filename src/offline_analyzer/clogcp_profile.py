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


def ensure_workspace(path: Path) -> None:
    path = path.resolve()
    marker = path / MARKER
    if marker.is_file() and not marker.is_symlink():
        if marker.stat().st_size > 1024 or json.loads(marker.read_bytes()) != {
            "schema": "clogcp-workspace-1",
            "product": "CloGCP",
        }:
            raise InputError("CLOGCP_WORKSPACE_MARKER_INVALID")
        return
    if marker.exists() or marker.is_symlink():
        raise InputError("CLOGCP_WORKSPACE_MARKER_INVALID")
    if path.exists() and any(
        p.name
        not in {
            ".gui-owner.lock",
            ".gui-owner.pid",
            "application.log",
            "workspace-environment.json",
        }
        for p in path.iterdir()
    ):
        raise InputError("CLOGCP_REFUSES_EXISTING_CLOSEC_OR_UNMARKED_WORKSPACE")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with marker.open("x") as file:
        json.dump({"schema": "clogcp-workspace-1", "product": "CloGCP"}, file)
    os.chmod(marker, 0o600)
