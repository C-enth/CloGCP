"""Explicit verified workspace copy; inspecting/opening never upgrades existing records."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.storage.store import (
    CONNECTION_CONFIG,
    CONSOLIDATION_DDL,
    DDL,
    ENTERPRISE_DDL,
    MANAGEMENT_DDL,
    REPORT_DDL,
    Store,
)

HASH_CHUNK_BYTES = 1024 * 1024
INCOMPLETE = ".workspace-recovery-incomplete"


def _stat_no_links(path: Path) -> os.stat_result:
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
        # FILE_ATTRIBUTE_REPARSE_POINT also covers Windows directory junctions.
        raise InputError("WORKSPACE_SYMLINK_OR_REPARSE_POINT_REFUSED")
    return value


def _safe_absolute(path: Path) -> Path:
    if ".." in path.parts:
        raise InputError("WORKSPACE_PATH_TRAVERSAL_REFUSED")
    path = path.absolute()
    for parent in (*reversed(path.parents), path):
        try:
            _stat_no_links(parent)
        except FileNotFoundError:
            continue
    return path


def _reject_incomplete(path: Path) -> None:
    if any((parent / INCOMPLETE).exists() for parent in (path, *path.parents)):
        raise InputError("INCOMPLETE_WORKSPACE_RECOVERY_REFUSED")


def _workspace_files(workspace: Path) -> Iterator[Path]:
    for path in sorted(workspace.iterdir()):
        value = _stat_no_links(path)
        if stat.S_ISDIR(value.st_mode):
            yield from _workspace_files(path)
        elif stat.S_ISREG(value.st_mode):
            yield path
        else:
            raise InputError("WORKSPACE_SPECIAL_FILE_REFUSED")


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def workspace_sha256(path: Path) -> str:
    """Hash every byte in bounded chunks, independently of ingestion size limits."""
    from offline_analyzer.provenance.execution import checkpoint

    path = _safe_absolute(path)
    before = _stat_no_links(path)
    if not stat.S_ISREG(before.st_mode):
        raise InputError("WORKSPACE_REGULAR_FILE_REQUIRED")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest, total = hashlib.sha256(), 0
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        # Windows path/handle APIs can expose different file identities. Compare
        # each API with itself over time, rather than rejecting stable files.
        if opened.st_size != before.st_size:
            raise InputError("WORKSPACE_FILE_CHANGED_DURING_HASH")
        while chunk := stream.read(HASH_CHUNK_BYTES):
            checkpoint()
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (
        total != before.st_size
        or _file_identity(after) != _file_identity(opened)
        or _file_identity(_stat_no_links(path)) != _file_identity(before)
    ):
        raise InputError("WORKSPACE_FILE_CHANGED_DURING_HASH")
    return digest.hexdigest()


def compatible(workspace: Path) -> None:
    """Fail before a writable connection, journal recovery, migration or regeneration."""
    workspace = _safe_absolute(workspace)
    _reject_incomplete(workspace)
    if (workspace / ".scope-journal.json").exists() or (workspace / ".scope-staging").exists():
        raise InputError("EXPLICIT_WORKSPACE_RECOVERY_REQUIRED")
    database = workspace / "assessment.duckdb"
    if not database.exists():
        return  # An explicitly selected empty workspace may be initialized.
    if database.is_symlink() or Path(str(database) + ".wal").exists():
        raise InputError("CLOSE_OR_RECOVER_PREVIOUS_APPLICATION_FIRST")
    expected = {
        m[1]
        for sql in (*DDL, *ENTERPRISE_DDL, *REPORT_DDL, *MANAGEMENT_DDL, *CONSOLIDATION_DDL)
        if (m := re.search(r"CREATE TABLE IF NOT EXISTS (\w+)", sql))
    }
    with Store(workspace, read_only=True) as store:
        actual = {r[0] for r in store.db.execute("SHOW TABLES").fetchall()}
        if not expected <= actual:
            raise InputError("EXPLICIT_VERSIONED_WORKSPACE_UPGRADE_REQUIRED")
        if store.db.execute("SELECT version FROM schema_info").fetchall() != [(1,)]:
            raise InputError("UNSUPPORTED_DATABASE_VERSION")


def file_inventory(workspace: Path) -> dict[str, str]:
    workspace = _safe_absolute(workspace)
    inventory = {}
    for path in _workspace_files(workspace):
        inventory[path.relative_to(workspace).as_posix()] = workspace_sha256(path)
    return inventory


def database_inventory(workspace: Path) -> dict[str, dict]:
    """Hash every row of every table, including all independent review/history tables."""
    result = {}
    with Store(workspace, read_only=True) as store:
        for (table,) in store.db.execute("SHOW TABLES").fetchall():
            if not re.fullmatch(r"[A-Za-z0-9_]+", table):
                raise InputError("UNSUPPORTED_TABLE_IDENTIFIER")
            digest, count = hashlib.sha256(), 0
            # Sort row digests to avoid loading wide customer rows in memory or output.
            hashes = []
            for row in store.rows(f'SELECT * FROM "{table}"'):
                hashes.append(hashlib.sha256(json.dumps(row, default=str).encode()).digest())
                count += 1
            for value in sorted(hashes):
                digest.update(value)
            result[table] = {"rows": count, "sha256": digest.hexdigest()}
    return result


def recover_copy(source: Path, target: Path, *, upgrade_additive: bool = False) -> dict:
    source, target = _safe_absolute(source), _safe_absolute(target)
    _reject_incomplete(source)
    _reject_incomplete(target.parent)
    if target.exists() or source == target or source in target.parents or target in source.parents:
        raise InputError("NEW_SIBLING_WORKSPACE_REQUIRED")
    if upgrade_additive:
        # Only the two known empty additive tables may be absent. Read-only first;
        # no generic migrations, scope recovery or analysis are permitted.
        from offline_analyzer.storage.consolidation_schema import TABLES

        if any(
            (source / name).exists()
            for name in (".scope-journal.json", ".scope-staging", "assessment.duckdb.wal")
        ):
            raise InputError("CLOSE_OR_RECOVER_PREVIOUS_APPLICATION_FIRST")
        with Store(source, read_only=True) as store:
            actual = {r[0] for r in store.db.execute("SHOW TABLES").fetchall()}
            expected = {
                m[1]
                for sql in (*DDL, *ENTERPRISE_DDL, *REPORT_DDL, *MANAGEMENT_DDL)
                if (m := re.search(r"CREATE TABLE IF NOT EXISTS (\w+)", sql))
            }
            if not expected <= actual or store.db.execute(
                "SELECT version FROM schema_info"
            ).fetchall() != [(1,)]:
                raise InputError("UNSUPPORTED_ADDITIVE_WORKSPACE_UPGRADE")
        added = sorted(set(TABLES) - actual)
    else:
        compatible(source)
        added = []
    if not (source / "assessment.duckdb").is_file():
        raise InputError("WORKSPACE_DATABASE_REQUIRED")
    before = file_inventory(source)
    tables = database_inventory(source)
    if not target.parent.is_dir():
        raise InputError("WORKSPACE_TARGET_PARENT_REQUIRED")
    total_bytes = sum(path.stat().st_size for path in _workspace_files(source))
    # Reserve space for the full copy, optional database backup/upgrade, and metadata.
    if shutil.disk_usage(target.parent).free < 2 * total_bytes + 16 * 1024 * 1024:
        raise InputError("INSUFFICIENT_WORKSPACE_COPY_SPACE")
    container = Path(tempfile.mkdtemp(prefix=".clogcp-recovery-", dir=target.parent))
    copied = container / "workspace"
    try:
        (container / INCOMPLETE).write_text("Unverified recovery; do not open.\n")
        # Never dereference links introduced after inventory; verification rejects them.
        shutil.copytree(source, copied, symlinks=True)
        os.chmod(copied, 0o700)
        if before != file_inventory(copied) or tables != database_inventory(copied):
            raise InputError("WORKSPACE_COPY_VERIFICATION_FAILED")
        if before != file_inventory(source):
            raise InputError("SOURCE_WORKSPACE_CHANGED_DURING_COPY")
        if added:
            # Windows denies copying a database held open by DuckDB. Back up the
            # closed staged file first, then add only the known empty tables.
            import duckdb

            directory = copied / "schema-backups"
            directory.mkdir(mode=0o700, exist_ok=True)
            backup = directory / f"assessment-before-recovery-additive-{uuid4().hex}.duckdb"
            shutil.copyfile(copied / "assessment.duckdb", backup)
            if workspace_sha256(backup) != before["assessment.duckdb"]:
                raise InputError("WORKSPACE_BACKUP_VERIFICATION_FAILED")
            db = duckdb.connect(str(copied / "assessment.duckdb"), config=CONNECTION_CONFIG)
            try:
                db.execute("BEGIN TRANSACTION")
                for sql in CONSOLIDATION_DDL:
                    db.execute(sql)
                db.execute("COMMIT")
            finally:
                db.close()  # Also rolls back an interrupted/failed transaction.
        after_tables = database_inventory(copied)
        if any(after_tables.get(name) != value for name, value in tables.items()) or any(
            after_tables[name]["rows"] != 0 for name in added
        ):
            raise InputError("ADDITIVE_WORKSPACE_ROW_PRESERVATION_FAILED")
        after_files = file_inventory(copied)
        manifest_name = "side-by-side-recovery.json"
        if (copied / manifest_name).exists():
            manifest_name = f"side-by-side-recovery-{uuid4().hex}.json"
        manifest = {
            "schema_version": "clogcp-workspace-recovery-1",
            "files": before,
            "tables": tables,
            "destination_files": after_files,
            "destination_tables": after_tables,
            "manifest_file": manifest_name,
            "source_modified": False,
            "records_migrated": False,
            "additive_tables_created_in_copy": added,
            "recovery_verified": True,
        }
        encoded = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_path = copied / manifest_name
        with manifest_path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        final_files = file_inventory(copied)
        if final_files.pop(manifest_name) != hashlib.sha256(encoded).hexdigest() or (
            final_files != after_files
        ):
            raise InputError("WORKSPACE_COPY_VERIFICATION_FAILED")
        if before != file_inventory(source) or tables != database_inventory(source):
            raise InputError("SOURCE_WORKSPACE_CHANGED_DURING_COPY")
        # The verified payload leaves the incomplete-marked container atomically.
        if target.exists() or target.is_symlink():
            raise InputError("NEW_SIBLING_WORKSPACE_REQUIRED")
        copied.rename(target)
    finally:
        # Includes KeyboardInterrupt/cancellation. A hard kill leaves the marked private
        # container; compatible() refuses it and its descendants as a workspace.
        shutil.rmtree(container, ignore_errors=True)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--upgrade-additive", action="store_true")
    args = parser.parse_args()
    try:
        report = recover_copy(args.source, args.target, upgrade_additive=args.upgrade_additive)
    except InputError as exc:
        raise SystemExit(str(exc)) from None
    except (OSError, shutil.Error):
        raise SystemExit("WORKSPACE_COPY_IO_FAILED_CHECK_DISK_SPACE_AND_PERMISSIONS") from None
    print(
        json.dumps(
            {
                "recovery_verified": True,
                "files_verified": len(report["files"]),
                "manifest_file": report["manifest_file"],
            }
        )
    )


if __name__ == "__main__":
    main()
