"""Consistent workspace backup and verified restore (local directories, no archives).

Backup requires that no GUI owns the workspace, checkpoints DuckDB, then copies the
database, raw evidence, reports, registry, environment label and run origins with a
SHA-256 manifest. Restore only targets a new or empty directory, refuses symlinks,
traversal and files not listed in the manifest, verifies every hash, then opens the
restored database and re-verifies stored raw evidence before reporting success.
"""

import hashlib
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under, validate_relative_path

MANIFEST = "backup-manifest.json"
INCLUDED_FILES = (
    "assessment.duckdb",
    "account-registry.json",
    "workspace-environment.json",
    "run-origins.json",
)
INCLUDED_DIRECTORIES = (
    "raw",
    "reports",
    "account-registry-history",
    "uploads",
    "collections",
    "jobs",
)


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            sha.update(chunk)
    return sha.hexdigest()


def owned(workspace: Path):
    """Exclusive ownership: fails while a GUI (or another backup) holds the workspace."""
    from offline_analyzer.launcher import WorkspaceLock

    try:
        return WorkspaceLock(workspace)
    except RuntimeError as exc:
        raise InputError("WORKSPACE_IN_USE_STOP_APPLICATION_FIRST") from exc


def backup_files(workspace: Path) -> list[str]:
    files = [name for name in INCLUDED_FILES if (workspace / name).is_file()]
    for directory in INCLUDED_DIRECTORIES:
        root = workspace / directory
        if root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.is_symlink():
                    raise InputError("SYMLINK_IN_WORKSPACE")
                if path.is_file():
                    files.append(path.relative_to(workspace).as_posix())
    return files


def backup(workspace: Path, output: Path) -> dict:
    workspace, output = workspace.resolve(), output.resolve()
    if output.exists():
        raise InputError("BACKUP_OUTPUT_EXISTS")
    if output.is_relative_to(workspace):
        raise InputError("BACKUP_INSIDE_WORKSPACE")
    if not (workspace / "assessment.duckdb").is_file():
        raise InputError("WORKSPACE_DATABASE_NOT_FOUND")
    lock = owned(workspace)
    try:
        from offline_analyzer.storage.store import Store

        with Store(workspace) as store:
            store.db.execute("CHECKPOINT")
            runs = store.db.execute("SELECT count(*) FROM runs").fetchone()[0]
        return _write(workspace, output, runs)
    finally:
        lock.close()


def backup_open(store, output: Path) -> dict:
    """Backup by the process that already owns the workspace and its single DB writer.

    Used before an in-application purge; the caller holds the scope-operation guard, so
    no other writer runs. The output is restorable with `restore` like any backup.
    """
    workspace, output = store.workspace, output.resolve()
    if output.exists() or output.with_name(output.name + ".partial").exists():
        raise InputError("BACKUP_OUTPUT_EXISTS")
    if output.is_relative_to(workspace):
        raise InputError("BACKUP_INSIDE_WORKSPACE")
    store.db.execute("CHECKPOINT")
    runs = store.db.execute("SELECT count(*) FROM runs").fetchone()[0]
    return _write(workspace, output, runs)


def _write(workspace: Path, output: Path, runs: int) -> dict:
    staging = output.with_name(output.name + ".partial")
    staging.mkdir(parents=True, mode=0o700)
    entries = []
    for relative in backup_files(workspace):
        source, target = workspace / relative, staging / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        entries.append({"path": relative, "bytes": target.stat().st_size, "sha256": digest(target)})
    manifest = {
        "backup_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "runs": runs,
        "files": entries,
    }
    (staging / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    staging.rename(output)
    return {"files": len(entries), "bytes": sum(e["bytes"] for e in entries), "runs": runs}


def restore(source: Path, workspace: Path) -> dict:
    source, workspace = source.resolve(), workspace.resolve()
    if workspace.exists() and any(workspace.iterdir()):
        raise InputError("RESTORE_TARGET_NOT_EMPTY")
    manifest_path = source / MANIFEST
    if not manifest_path.is_file() or manifest_path.stat().st_size > 64 * 1024 * 1024:
        raise InputError("BACKUP_MANIFEST_MISSING")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        listed = {entry["path"]: entry for entry in manifest["files"]}
    except (ValueError, KeyError, TypeError) as exc:
        raise InputError("BACKUP_MANIFEST_INVALID") from exc
    allowed = set(INCLUDED_FILES) | set(INCLUDED_DIRECTORIES)
    present = set()
    for path in source.rglob("*"):
        if path.is_symlink():
            raise InputError("SYMLINK_IN_BACKUP")
        if path.is_file() and path != manifest_path:
            present.add(path.relative_to(source).as_posix())
    if present != set(listed):
        raise InputError("BACKUP_CONTENT_MISMATCH")
    for relative, entry in listed.items():
        try:
            validate_relative_path(relative)
        except ValueError as exc:
            raise InputError("BACKUP_PATH_INVALID") from exc
        if relative.split("/", 1)[0] not in allowed:
            raise InputError("BACKUP_PATH_INVALID")
        path = resolve_under(source, relative)
        if path.stat().st_size != entry["bytes"] or digest(path) != entry["sha256"]:
            raise InputError("BACKUP_INTEGRITY_FAILURE")
    staging = workspace.with_name(workspace.name + ".restoring")
    if staging.exists():
        raise InputError("RESTORE_STAGING_EXISTS")
    staging.mkdir(parents=True, mode=0o700)
    for relative in listed:
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source / relative, target)
        os.chmod(target, 0o600)
    from offline_analyzer.rules.engine import verify_raw
    from offline_analyzer.storage.store import Store

    with Store(staging) as store:
        runs = [r[0] for r in store.db.execute("SELECT run_id FROM runs").fetchall()]
        for run in runs:
            verify_raw(store, run)
    if workspace.exists():
        workspace.rmdir()
    staging.rename(workspace)
    return {"files": len(listed), "runs": len(runs)}
