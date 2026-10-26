"""Explicit verified workspace copy; inspecting/opening never upgrades existing records."""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.storage.store import (
    CONSOLIDATION_DDL,
    DDL,
    ENTERPRISE_DDL,
    MANAGEMENT_DDL,
    REPORT_DDL,
    Store,
)


def compatible(workspace: Path) -> None:
    """Fail before a writable connection, journal recovery, migration or regeneration."""
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
    inventory = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            raise InputError("WORKSPACE_SYMLINK_REFUSED")
        if path.is_file():
            inventory[path.relative_to(workspace).as_posix()] = sha256_file(path)
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
    source, target = source.resolve(), target.resolve()
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
    shutil.copytree(source, target)
    if before != file_inventory(target) or tables != database_inventory(target):
        raise InputError("WORKSPACE_COPY_VERIFICATION_FAILED")
    if before != file_inventory(source):
        raise InputError("SOURCE_WORKSPACE_CHANGED_DURING_COPY")
    if upgrade_additive:
        with Store(target, _recover=False):
            pass
        after = database_inventory(target)
        if any(after.get(name) != value for name, value in tables.items()) or any(
            after[name]["rows"] != 0 for name in added
        ):
            raise InputError("ADDITIVE_WORKSPACE_ROW_PRESERVATION_FAILED")
        if before != file_inventory(source):
            raise InputError("SOURCE_WORKSPACE_CHANGED_DURING_UPGRADE")
        compatible(target)
    manifest = {
        "schema_version": "clogcp-workspace-recovery-1",
        "files": before,
        "tables": tables,
        "source_modified": False,
        "records_migrated": False,
        "additive_tables_created_in_copy": added,
        "recovery_verified": True,
    }
    (target / "side-by-side-recovery.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--upgrade-additive", action="store_true")
    args = parser.parse_args()
    report = recover_copy(args.source, args.target, upgrade_additive=args.upgrade_additive)
    print(json.dumps({"recovery_verified": True, "files_verified": len(report["files"])}))


if __name__ == "__main__":
    main()
