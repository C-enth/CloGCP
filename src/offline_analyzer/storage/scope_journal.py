"""Recoverable database publication and exact managed-file removal, never broad cleanup."""

import json
import os
import re
from contextlib import contextmanager
from pathlib import Path

import duckdb

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under

JOURNAL = ".scope-journal.json"


def rollback_raw(workspace: Path, directory: Path):
    """Remove only new uncommitted content-addressed bytes named by this stage."""
    marker = checked_file(workspace, str((directory / "marker.json").relative_to(workspace)))
    if not marker.is_file() or marker.stat().st_size > 128 * 1024:
        raise InputError("SCOPE_RECOVERY_REQUIRED")
    data = json.loads(marker.read_text())
    if set(data) - {"scope_stage_version", "event_id", "rollback_raw"} or (
        data.get("scope_stage_version") != 1 or data.get("event_id") != directory.name
    ):
        raise InputError("SCOPE_RECOVERY_REQUIRED")
    digests = data.get("rollback_raw", [])
    if (
        not isinstance(digests, list)
        or len(digests) > 1025
        or any(not isinstance(sha, str) or not re.fullmatch("[0-9a-f]{64}", sha) for sha in digests)
    ):
        raise InputError("SCOPE_RECOVERY_REQUIRED")
    from offline_analyzer.storage.store import CONNECTION_CONFIG

    db = duckdb.connect(str(checked_file(workspace, "assessment.duckdb")), config=CONNECTION_CONFIG)
    try:
        for sha in digests:
            if not db.execute("SELECT 1 FROM artifacts WHERE sha256=? LIMIT 1", [sha]).fetchone():
                checked_file(workspace, "raw/" + sha + ".json").unlink(missing_ok=True)
        working = checked_file(
            workspace, f".scope-staging/{directory.name}/working/assessment.duckdb"
        )
        if working.is_file():
            staged = duckdb.connect(str(working), config=CONNECTION_CONFIG)
            try:
                for (run,) in staged.execute("SELECT run_id FROM runs").fetchall():
                    if not re.fullmatch("run-[0-9a-f]{64}", run):
                        raise InputError("SCOPE_RECOVERY_REQUIRED")
                    if not db.execute("SELECT 1 FROM runs WHERE run_id=?", [run]).fetchone():
                        checked_file(workspace, "collections/" + run + ".json").unlink(
                            missing_ok=True
                        )
            finally:
                staged.close()
    finally:
        db.close()


def checked_file(workspace: Path, relative: str) -> Path:
    path = resolve_under(workspace, relative)
    if any(
        p.is_symlink()
        for p in [workspace / relative, *(workspace / relative).parents]
        if p.is_relative_to(workspace)
    ):
        raise InputError("UNSAFE_MANAGED_FILE")
    return path


@contextmanager
def guard(workspace: Path):
    lock = checked_file(workspace, ".scope-operation.lock")
    stream = lock.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            stream.seek(0)
            stream.write(b"0")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        stream.close()
        raise InputError("SCOPE_OPERATION_IN_PROGRESS") from exc
    try:
        yield
    finally:
        stream.close()


def write_journal(workspace: Path, data: dict):
    temp = checked_file(workspace, JOURNAL + ".tmp")
    with temp.open("w", encoding="utf-8") as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp, 0o600)
    temp.replace(checked_file(workspace, JOURNAL))


def recover_locked(workspace: Path) -> bool:
    path = checked_file(workspace, JOURNAL)
    if not path.exists():
        return False
    if path.stat().st_size > 4 * 1024 * 1024:
        raise InputError("SCOPE_JOURNAL_INVALID")
    try:
        data = json.loads(path.read_text())
        event = data["event_id"]
        if not re.fullmatch(r"[0-9a-f]{32}", event) or data["version"] != 1:
            raise ValueError()
        directory = checked_file(workspace, ".scope-staging/" + event)
        old = directory / "old.duckdb"
        database = checked_file(workspace, "assessment.duckdb")
        committed = False
        if database.is_file():
            db = duckdb.connect(str(database), read_only=True)
            try:
                exists = db.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_name='scope_audit'"
                ).fetchone()
                committed = bool(
                    exists
                    and db.execute("SELECT 1 FROM scope_audit WHERE event_id=?", [event]).fetchone()
                )
            finally:
                db.close()
        if not committed:
            if old.is_file():
                old.replace(database)
            if not database.is_file():
                raise InputError("SCOPE_RECOVERY_DATABASE_MISSING")
            rollback_raw(workspace, directory)
        else:
            if data.get("origins") is not None:
                from offline_analyzer.inventory.environment import ORIGINS_FILE

                staging = checked_file(workspace, ORIGINS_FILE + ".tmp")
                staging.write_text(json.dumps(data["origins"]), encoding="utf-8")
                staging.replace(checked_file(workspace, ORIGINS_FILE))
            for relative in data["files"]:
                if relative.split("/", 1)[0] not in {
                    "raw",
                    "uploads",
                    "collections",
                    "reports",
                    "jobs",
                }:
                    raise InputError("SCOPE_JOURNAL_INVALID")
                checked_file(workspace, relative).unlink(missing_ok=True)
            parents = {
                checked_file(workspace, relative).parent
                for relative in data["files"]
                if relative.startswith("uploads/")
            }
            for parent in sorted(parents, key=lambda p: len(p.parts), reverse=True):
                while parent != workspace / "uploads" and parent.is_relative_to(
                    workspace / "uploads"
                ):
                    if not parent.exists() or any(parent.iterdir()):
                        break
                    parent.rmdir()
                    parent = parent.parent
        # Only exact files created by this operation; never recurse into caller data.
        for name in (
            "marker.json",
            "old.duckdb",
            "new.duckdb",
            "new.duckdb.wal",
            "working/assessment.duckdb",
            "working/assessment.duckdb.wal",
            "compact/assessment.duckdb",
            "compact/assessment.duckdb.wal",
        ):
            checked_file(workspace, f".scope-staging/{event}/{name}").unlink(missing_ok=True)
        for child in ("working", "compact"):
            folder = directory / child
            if folder.exists() and not any(folder.iterdir()):
                folder.rmdir()
        if directory.exists() and not any(directory.iterdir()):
            directory.rmdir()
        path.unlink()
        return committed
    except (KeyError, TypeError, ValueError, OSError, duckdb.Error) as exc:
        raise InputError("SCOPE_RECOVERY_REQUIRED") from exc


def recover(workspace: Path):
    if (workspace / JOURNAL).exists() or (workspace / ".scope-staging").exists():
        with guard(workspace):
            recover_locked(workspace)
            discard_orphans(workspace)


def discard_orphans(workspace: Path):
    root = checked_file(workspace, ".scope-staging")
    if not root.is_dir():
        return
    for directory in root.iterdir():
        if not re.fullmatch("[0-9a-f]{32}", directory.name):
            raise InputError("SCOPE_RECOVERY_REQUIRED")
        checked_file(workspace, ".scope-staging/" + directory.name)
        if (directory / "old.duckdb").exists():
            raise InputError("SCOPE_RECOVERY_REQUIRED")
        rollback_raw(workspace, directory)
        for name in (
            "working/assessment.duckdb",
            "working/assessment.duckdb.wal",
            "compact/assessment.duckdb",
            "compact/assessment.duckdb.wal",
            "marker.json",
        ):
            checked_file(workspace, f".scope-staging/{directory.name}/{name}").unlink(
                missing_ok=True
            )
        for name in ("working", "compact"):
            child = directory / name
            if child.exists() and not any(child.iterdir()):
                child.rmdir()
        if not any(directory.iterdir()):
            directory.rmdir()
        else:
            raise InputError("SCOPE_RECOVERY_REQUIRED")
