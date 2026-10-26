"""User-chosen workspace location: remembered pointer, safety checks, read-only inspection,
safe open (recovery, schema check, pre-migration backup) and verified copy/backup.

Privacy: the workspace path is shown to the local user only. It is never written to logs,
diagnostics, exports, reports or error codes; audit lines carry `path_hash` instead. The
pointer file lives in the OS user-configuration folder, outside every workspace and the
repository, and holds only the path and a timestamp.
"""

import hashlib
import json
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.storage.backup import digest

POINTER = "workspace-location.json"
DATABASE = "assessment.duckdb"
SUPPORTED_SCHEMA = 1
# Files that belong to one running process, never copied or compared.
VOLATILE = {".gui-owner.lock", ".gui-owner.pid", ".scope-operation.lock"}
LOW_FREE_BYTES = 5 * 1024**3
WINDOWS_PATH_BUDGET = 180  # leaves room under MAX_PATH (260) for nested workspace files
SYNC_PARTS = {
    "dropbox",
    "onedrive",
    "google drive",
    "googledrive",
    "my drive",
    "icloud drive",
    "iclouddrive",
    "mobile documents",
    "cloudstorage",
    "box",
    "box sync",
    "pcloud drive",
    "mega",
    "sync",
    "nextcloud",
    "owncloud",
}
MESSAGES = {
    "SOURCE_TREE": "Inside the CloSec source tree. Workspaces must never live in the code "
    "repository.",
    "RELEASE_FOLDER": "Inside a CloSec release or application folder. Updates replace this "
    "folder; workspaces must live elsewhere.",
    "GIT_REPOSITORY": "Inside a git repository: client data could be committed or pushed.",
    "SYNC_FOLDER": "Inside a cloud-synced folder (iCloud Drive, Dropbox, OneDrive, Google "
    "Drive or similar): client data would leave this computer.",
    "NETWORK_OR_REMOVABLE": "On a network share or removable drive: locking and crash "
    "recovery are not reliable there, and the media can be lost.",
    "NOT_WRITABLE": "The folder is not writable by this user.",
    "LOW_FREE_SPACE": "Less than 5 GB (or twice the workspace size) is free on this drive.",
    "PATH_TOO_LONG": "The path is long for Windows; nested workspace files could exceed the "
    "260-character limit.",
    "WORLD_READABLE": "Other users on this computer can read the folder (permissions).",
}
BLOCKING = {"SOURCE_TREE", "RELEASE_FOLDER"}
ERRORS = {
    "NOT_A_DIRECTORY": "The path is not an existing folder.",
    "NOT_A_WORKSPACE": "The folder has no CloSec database (assessment.duckdb). Choose the "
    "workspace folder itself, or use Create new workspace for an empty folder.",
    "WAL_WITHOUT_DATABASE": "A database journal (.wal) exists without its database. Keep both "
    "files together; do not open this folder until the database file is restored.",
    "ENVIRONMENT_UNREADABLE": "workspace-environment.json exists but cannot be read.",
    "IN_USE": "Another CloSec process has this workspace open. Stop it first.",
    "NEWER_SCHEMA": "The workspace was written by a newer CloSec than this one. Open it with "
    "that version; this version never downgrades a workspace.",
    "DATABASE_UNREADABLE": "The database could not be opened read-only for checking.",
    "TARGET_NOT_EMPTY": "The destination must be a new or empty folder.",
    "TARGET_INSIDE_WORKSPACE": "The destination is inside the current workspace.",
    "COPY_VERIFICATION_FAILED": "The copy did not match the original (sizes, hashes or "
    "counts). Nothing was switched; the original is unchanged.",
}


# ---------------------------------------------------------------- pointer
def config_dir() -> Path:
    """OS user-configuration folder (tests set CLOSEC_CONFIG_DIR to a temporary folder)."""
    override = os.environ.get("CLOSEC_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "CloSec"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "CloSec"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "closec"


def path_hash(path: Path | str) -> str:
    """One-way identifier for audit lines; the path itself is never logged."""
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]


def read_pointer() -> tuple[str, Path | None]:
    """("ABSENT" | "VALID" | "INVALID", path). Invalid never raises: the UI asks instead."""
    file = config_dir() / POINTER
    if not file.exists():
        return "ABSENT", None
    try:
        if file.stat().st_size > 16 * 1024:
            return "INVALID", None
        data = json.loads(file.read_text(encoding="utf-8"))
        path = Path(data["path"])
        datetime.fromisoformat(data["updated_utc"])
    except (OSError, ValueError, KeyError, TypeError):
        return "INVALID", None
    if not path.is_absolute() or not path.is_dir():
        return "INVALID", None
    if not (path / DATABASE).is_file() and any(path.iterdir()):
        return "INVALID", None
    return "VALID", path


def write_pointer(path: Path) -> None:
    folder = config_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = folder / (POINTER + ".partial")
    temp.write_text(
        json.dumps({"path": str(path), "updated_utc": datetime.now(UTC).isoformat()}),
        encoding="utf-8",
    )
    os.chmod(temp, 0o600)
    os.replace(temp, folder / POINTER)


def clear_pointer() -> None:
    (config_dir() / POINTER).unlink(missing_ok=True)


# ---------------------------------------------------------------- safety checks
def _pure(path, windows: bool) -> PurePath:
    return PureWindowsPath(str(path)) if windows else PurePosixPath(str(path))


def _existing(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return None


def app_root() -> Path:
    """Folder holding this application's `src/` (developer checkout or installed release)."""
    return Path(__file__).resolve().parents[3]


def location_checks(
    path, *, windows: bool | None = None, workspace_bytes: int = 0, home: Path | None = None
) -> dict:
    """Blocking problems and warnings for a candidate workspace (or backup) folder.

    `windows=True` evaluates a Windows path by text only (used on any OS in tests); the
    filesystem probes run only for paths on this machine.
    """
    windows = sys.platform == "win32" if windows is None else windows
    local = windows == (sys.platform == "win32")
    pure = _pure(path, windows)
    parts = [p.lower() for p in pure.parts]
    blocked, warnings = [], []
    if local:
        target = Path(path).absolute()
        chain = [target, *target.parents]
        root = app_root()
        if any(
            (c / "pyproject.toml").is_file() and (c / "src" / "offline_analyzer").is_dir()
            for c in chain
        ):
            blocked.append("SOURCE_TREE")
        if (
            target == root
            or root in target.parents
            or any(
                (c / name).exists()
                for c in chain
                for name in ("CloSec.command", "CloSec.cmd", "CloSec.zip", "portable-manifest.json")
            )
        ):
            blocked.append("RELEASE_FOLDER")
        if any((c / ".git").exists() for c in chain):
            warnings.append("GIT_REPOSITORY")
    if any(p in SYNC_PARTS or p.startswith(("onedrive -", "dropbox (")) for p in parts):
        warnings.append("SYNC_FOLDER")
    if windows:
        text = str(pure)
        if text.startswith("\\\\") or (local and _windows_drive_remote_or_removable(text)):
            warnings.append("NETWORK_OR_REMOVABLE")
        if len(text) > WINDOWS_PATH_BUDGET:
            warnings.append("PATH_TOO_LONG")
    elif len(parts) > 2 and parts[1] in {"volumes", "media", "mnt"}:
        warnings.append("NETWORK_OR_REMOVABLE")
    if local:
        existing = _existing(Path(path).absolute())
        if existing is not None:
            if not os.access(existing, os.W_OK):
                warnings.append("NOT_WRITABLE")
            free = shutil.disk_usage(existing).free
            if free < max(LOW_FREE_BYTES, 2 * workspace_bytes):
                warnings.append("LOW_FREE_SPACE")
            if not windows and Path(path).is_dir() and Path(path).stat().st_mode & 0o007:
                warnings.append("WORLD_READABLE")
    return {
        "blocked": sorted(set(blocked)),
        "warnings": sorted(set(warnings)),
        "messages": {code: MESSAGES[code] for code in {*blocked, *warnings}},
    }


def _windows_drive_remote_or_removable(text: str) -> bool:
    try:  # Windows only: DRIVE_REMOVABLE = 2, DRIVE_REMOTE = 4
        import ctypes

        return ctypes.windll.kernel32.GetDriveTypeW(text[:3]) in {2, 4}
    except (AttributeError, OSError):
        return False


# ---------------------------------------------------------------- inspection
def expected_tables() -> set[str]:
    from offline_analyzer.storage import store

    statements = (*store.DDL, *store.ENTERPRISE_DDL, *store.REPORT_DDL, *store.MANAGEMENT_DDL)
    return {m for s in statements for m in re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", s)}


def counts(db) -> dict:
    """Counts only (no identifiers): what a reopened or copied workspace must reproduce."""
    tables = {
        r[0] for r in db.execute("SELECT table_name FROM information_schema.tables").fetchall()
    }

    def count(table: str, where: str = "") -> int:
        if table not in tables:
            return 0
        return db.execute(f"SELECT count(*) FROM {table} {where}").fetchone()[0]

    return {
        "runs": count("runs"),
        "sources": count("sources"),
        "findings": count("findings"),
        "analyst_decisions": count("decisions"),
        "confirmations": count(
            "decisions", "WHERE json_extract_string(data,'$.status')='CONFIRMED'"
        ),
        "exclusion_records": count("finding_exclusions"),
        "report_drafts": count("report_revisions"),
        "finalised_editions": count("finalized_assessments"),
        "path_reviews": count("path_reviews"),
    }


def lock_holder(workspace: Path) -> int | None:
    """PID of the CloSec process that owns the workspace lock, or None when it is free."""
    from offline_analyzer.launcher import WorkspaceLock

    if not (workspace / ".gui-owner.lock").exists():
        return None
    try:
        WorkspaceLock(workspace, record_pid=False).close()
        return None
    except RuntimeError:
        try:
            return int((workspace / ".gui-owner.pid").read_text().strip())
        except (OSError, ValueError):
            return 0  # held, owner unknown


def _schema(db) -> tuple[int | None, set[str]]:
    tables = {
        r[0] for r in db.execute("SELECT table_name FROM information_schema.tables").fetchall()
    }
    version = None
    if "schema_info" in tables:
        row = db.execute("SELECT max(version) FROM schema_info").fetchone()
        version = row[0] if row else None
    return version, expected_tables() - tables


def inspect_workspace(path: Path) -> dict:
    """Read-only check of a candidate workspace. Never modifies it (DuckDB replays a leftover
    journal in memory only when opened read-only)."""
    import duckdb

    from offline_analyzer.inventory.environment import workspace_environment

    path = Path(path)
    report = {"ok": False, "code": None, "counts": None, "unclean_shutdown": False}
    if not path.is_dir():
        return {**report, "code": "NOT_A_DIRECTORY"}
    database, journal = path / DATABASE, path / (DATABASE + ".wal")
    if journal.exists() and not database.exists():
        return {**report, "code": "WAL_WITHOUT_DATABASE"}
    if not database.is_file():
        return {**report, "code": "NOT_A_WORKSPACE", "empty": not any(path.iterdir())}
    report["unclean_shutdown"] = journal.exists()
    environment = path / "workspace-environment.json"
    try:
        label = workspace_environment(path)
        report["environment"] = label.label if label else "UNLABELED"
    except Exception:  # noqa: BLE001 - any parse failure is a refusal reason, not a crash
        return {**report, "code": "ENVIRONMENT_UNREADABLE"}
    if not environment.exists():
        report["environment"] = "UNLABELED"
    holder = lock_holder(path)
    if holder is not None:
        return {**report, "code": "IN_USE", "locked_by_pid": holder}
    try:
        db = duckdb.connect(str(database), read_only=True)
    except duckdb.Error as exc:
        pid = re.search(r"PID (\d+)", str(exc))
        if "lock" in str(exc).lower():
            return {**report, "code": "IN_USE", "locked_by_pid": int(pid[1]) if pid else 0}
        return {**report, "code": "DATABASE_UNREADABLE"}
    try:
        version, missing = _schema(db)
        report["schema"] = (
            "NEWER"
            if version is not None and version > SUPPORTED_SCHEMA
            else "OLDER"
            if missing or version is None
            else "CURRENT"
        )
        report["missing_tables"] = len(missing)
        if report["schema"] == "NEWER":
            return {**report, "code": "NEWER_SCHEMA"}
        report["counts"] = counts(db)
    except duckdb.Error:
        return {**report, "code": "DATABASE_UNREADABLE"}
    finally:
        db.close()
    return {**report, "ok": True}


def prepare_open(workspace: Path) -> dict:
    """Run by the launcher (which holds the workspace lock) before the application starts.

    Newer schema: refuse, unchanged. Older schema: verified backup beside the workspace,
    then the additive migration that Store applies. Leftover journal: DuckDB recovers on the
    read-write open; the result is checkpointed and counted. Returns counts only.
    """
    from offline_analyzer.storage.store import Store

    if os.environ.get("CLOGCP_PROFILE") == "1":
        from offline_analyzer.clogcp_profile import ensure_workspace

        ensure_workspace(workspace)
        from offline_analyzer.storage.side_by_side import compatible

        compatible(workspace)
        # The CloGCP profile never checkpoints, recovers or migrates on opening.
        # Additive upgrades require the explicit verified-copy command.
        return {
            "opened": True,
            "recovered": False,
            "migrated": False,
            "backup": None,
            "integrity": "OK",
            "read_only_preflight": True,
        }

    report = {"opened": True, "recovered": False, "migrated": False, "backup": None}
    database = workspace / DATABASE
    if not database.exists():
        report["new_workspace"] = True
        return report
    found = (
        inspect_workspace(workspace) if not _locked_by_us(workspace) else _inspect_owned(workspace)
    )
    if found["code"] == "NEWER_SCHEMA":
        raise InputError("WORKSPACE_NEWER_SCHEMA")
    if found["code"] in {"DATABASE_UNREADABLE", "WAL_WITHOUT_DATABASE", "ENVIRONMENT_UNREADABLE"}:
        raise InputError("WORKSPACE_" + found["code"])
    report["recovered"] = bool(found.get("unclean_shutdown"))
    if found.get("schema") == "OLDER":
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        target = workspace.parent / (workspace.name + "-backups") / f"pre-migration-{stamp}"
        report["backup"] = copy_tree(workspace, target, found["counts"])
        report["migrated"] = True
    with Store(workspace) as store:
        store.db.execute("CHECKPOINT")
        version, missing = _schema(store.db)
        report["integrity"] = "OK" if version == SUPPORTED_SCHEMA and not missing else "FAILED"
        report["counts"] = counts(store.db)
    if report["integrity"] != "OK":
        raise InputError("WORKSPACE_INTEGRITY_FAILED")
    report["journal_remaining"] = (workspace / (DATABASE + ".wal")).exists()
    return report


def _locked_by_us(workspace: Path) -> bool:
    try:
        return int((workspace / ".gui-owner.pid").read_text().strip()) == os.getpid()
    except (OSError, ValueError):
        return False


def _inspect_owned(workspace: Path) -> dict:
    """Inspection when this process already holds the GUI lock (skip the lock probe)."""
    import duckdb

    report = {"code": None, "unclean_shutdown": (workspace / (DATABASE + ".wal")).exists()}
    try:
        db = duckdb.connect(str(workspace / DATABASE), read_only=True)
    except duckdb.Error:
        return {**report, "code": "DATABASE_UNREADABLE"}
    try:
        version, missing = _schema(db)
        if version is not None and version > SUPPORTED_SCHEMA:
            return {**report, "code": "NEWER_SCHEMA"}
        return {
            **report,
            "schema": "OLDER" if missing or version is None else "CURRENT",
            "counts": counts(db),
        }
    finally:
        db.close()


# ---------------------------------------------------------------- verified copy
def workspace_files(workspace: Path) -> list[str]:
    files = []
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            raise InputError("SYMLINK_IN_WORKSPACE")
        relative = path.relative_to(workspace)
        if (
            path.is_file()
            and relative.name not in VOLATILE
            and not relative.name.endswith((".partial", ".tmp"))
        ):
            files.append(relative.as_posix())
    return files


def target_ready(target: Path) -> None:
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise InputError("TARGET_NOT_EMPTY")


def copy_tree(workspace: Path, target: Path, expected_counts: dict | None) -> dict:
    """Copy every workspace file (database and journal included) to a new folder, verify
    sizes, SHA-256 and the counts report, then publish. The source is only read; on any
    failure the partial copy is removed and nothing is published."""
    import duckdb

    workspace, target = workspace.resolve(), target.absolute()
    if target == workspace or workspace in target.parents:
        raise InputError("TARGET_INSIDE_WORKSPACE")
    target_ready(target)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    staging = target.with_name(f"{target.name}.partial-{stamp}")
    entries = []
    try:
        staging.mkdir(parents=True, mode=0o700)
        for relative in workspace_files(workspace):
            source, copy = workspace / relative, staging / relative
            copy.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, copy)
            os.chmod(copy, 0o600)
            original = digest(source)
            if copy.stat().st_size != source.stat().st_size or digest(copy) != original:
                raise InputError("COPY_VERIFICATION_FAILED")
            entries.append({"path": relative, "bytes": copy.stat().st_size, "sha256": original})
        copied = None
        if (staging / DATABASE).exists():
            db = duckdb.connect(str(staging / DATABASE), read_only=True)
            try:
                copied = counts(db)
            finally:
                db.close()
        if expected_counts is not None and copied != expected_counts:
            raise InputError("COPY_VERIFICATION_FAILED")
        if target.exists():
            target.rmdir()  # verified empty by target_ready
        staging.rename(target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "files": len(entries),
        "bytes": sum(e["bytes"] for e in entries),
        "counts": copied,
        "entries": entries,
    }
