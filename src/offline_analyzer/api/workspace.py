"""Workspace location endpoints: show the active location, check a candidate folder, and
(only after explicit confirmation) open, create, copy-and-switch, back up or return to the
default. The path is returned to the local user only; errors are fixed codes, and audit
lines carry a one-way hash. Switching takes effect on restart; nothing is moved or deleted.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.storage import location as loc

PURPOSES = ("open", "create", "change", "backup")


class LocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: Literal["open", "create", "change", "backup", "default"]
    path: str = Field(default="", max_length=4096)
    confirm: bool = False
    accept_warnings: bool = False


def candidate(path: str) -> Path:
    if not path or "\x00" in path:
        raise InputError("LOCATION_PATH_INVALID")
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise InputError("LOCATION_PATH_INVALID")
    return target


def target_state(target: Path) -> str:
    if not target.exists():
        return "NEW"
    if not target.is_dir():
        return "FILE"
    return "EMPTY" if not any(target.iterdir()) else "NOT_EMPTY"


def folder_bytes(workspace: Path) -> int:
    return sum(p.stat().st_size for p in workspace.rglob("*") if p.is_file())


def register(app: FastAPI, *, workspace: Path, coordinator, location: dict, restart) -> None:
    from offline_analyzer.launcher import lifecycle_log
    from offline_analyzer.storage.store import Store

    def audit(event: str, target: Path) -> None:
        lifecycle_log(workspace, event, loc.path_hash(target.absolute()))

    def check(body: LocationRequest) -> dict:
        target = candidate(body.path)
        checks = loc.location_checks(
            target,
            workspace_bytes=folder_bytes(workspace) if body.purpose in {"change", "backup"} else 0,
        )
        result = {"purpose": body.purpose, "checks": checks, "target_state": target_state(target)}
        if body.purpose == "open":
            result["inspection"] = loc.inspect_workspace(target)
            if result["inspection"]["code"]:
                result["inspection"]["message"] = loc.ERRORS[result["inspection"]["code"]]
        if body.purpose in {"create", "change"} and result["target_state"] in {
            "NOT_EMPTY",
            "FILE",
        }:
            result["refusal"] = {
                "code": "TARGET_NOT_EMPTY",
                "message": loc.ERRORS["TARGET_NOT_EMPTY"],
            }
        if body.purpose == "backup" and result["target_state"] == "FILE":
            result["refusal"] = {
                "code": "NOT_A_DIRECTORY",
                "message": loc.ERRORS["NOT_A_DIRECTORY"],
            }
        return result

    def copy_now(target: Path) -> dict:
        with Store(workspace) as store:
            store.db.execute("CHECKPOINT")
            before = loc.counts(store.db)
        report = loc.copy_tree(workspace, target, before)
        report["counts_before"] = before
        return report

    @app.get("/api/workspace")
    def current():
        status, remembered = loc.read_pointer()
        return {
            "path": str(workspace),
            "source": location.get("source", "COMMAND_LINE"),
            "setup_required": location.get("setup_required", False),
            "default_path": location.get("default_path"),
            "remembered": status,
            "open_report": location.get("open_report"),
            "checks": loc.location_checks(workspace)
            if not location.get("setup_required")
            else None,
            "restart_available": restart is not None,
            "backup_note": "Backups hold client data: handle, store and delete them under the "
            "same rules as the evidence.",
        }

    @app.post("/api/workspace/check")
    def check_location(body: LocationRequest):
        if body.purpose == "default":
            raise InputError("LOCATION_PATH_INVALID")
        return check(body)

    @app.post("/api/workspace/apply")
    async def apply(body: LocationRequest):
        if not body.confirm:
            raise InputError("LOCATION_CONFIRMATION_REQUIRED")
        if body.purpose == "default":
            loc.clear_pointer()
            return {"restart_required": True}
        found = check(body)
        if found["checks"]["blocked"]:
            raise InputError("LOCATION_BLOCKED")
        if found.get("refusal"):
            raise InputError(found["refusal"]["code"])
        if found["checks"]["warnings"] and not body.accept_warnings:
            return JSONResponse(
                {
                    "error": "LOCATION_WARNINGS_NOT_ACCEPTED",
                    "message": "Review the location warnings and accept them explicitly.",
                },
                status_code=409,
            )
        target = candidate(body.path)
        if body.purpose == "open":
            inspection = found["inspection"]
            if inspection["code"]:
                raise InputError("WORKSPACE_" + inspection["code"])
            loc.write_pointer(target.resolve())
            audit("WORKSPACE_SELECTED", target)
            return {"restart_required": True, "inspection": inspection}
        if body.purpose == "create":
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.chmod(0o700)
            loc.write_pointer(target.resolve())
            audit("WORKSPACE_SELECTED", target)
            return {"restart_required": True}
        if body.purpose == "change":
            report = await coordinator.exclusive(lambda: copy_now(target))
            loc.write_pointer(target.resolve())
            audit("WORKSPACE_COPIED", target)
            return {
                "restart_required": True,
                "previous_path": str(workspace),
                "previous_kept": True,
                "files": report["files"],
                "bytes": report["bytes"],
                "counts": report["counts"],
                "counts_match": report["counts"] == report["counts_before"],
            }
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = target / f"closec-backup-{stamp}"
        if destination.exists():
            raise InputError("TARGET_NOT_EMPTY")
        report = await coordinator.exclusive(lambda: copy_now(destination))
        import json

        manifest = {
            "backup": "closec-workspace-copy",
            "created_utc": datetime.now(UTC).isoformat(),
            "counts": report["counts"],
            "files": report["entries"],
        }
        (destination / "closec-backup-manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        audit("WORKSPACE_BACKUP", destination)
        return {
            "destination": str(destination),
            "files": report["files"],
            "bytes": report["bytes"],
            "counts": report["counts"],
            "counts_match": report["counts"] == report["counts_before"],
            "note": "Backups hold client data: handle, store and delete them under the same "
            "rules as the evidence.",
        }

    @app.post("/api/workspace/restart")
    def restart_now():
        if restart is None:
            return {"restarting": False}
        restart()
        return {"restarting": True}
