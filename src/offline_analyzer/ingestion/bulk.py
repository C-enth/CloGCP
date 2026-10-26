"""Bulk import of AWS collector packages from one local folder (batch collection output).

Every `*.zip` directly in the folder is one package; nothing is extracted outside the
workspace and every package goes through the normal import (safe unpack, checksums, contract
validation, origin check). Per package one result row is written; a failure never stops the
others. Duplicates per account: the latest collection (manifest `completed_at`, then
collection ID) is imported, older ones are shown as SUPERSEDED (also when the workspace
already holds a newer import of that account). A `.zip.sha256` sidecar, when present, must
match. Progress is persisted after each package in `bulk-imports/<id>.json`, so re-running
the same folder resumes: packages already handled (same SHA-256) are not imported again.

Scope reconciliation against an expected account list reports missing, unexpected and
duplicate accounts. The report carries counts and identifiers only, never evidence values.
"""

import hashlib
import json
import re
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.provenance.execution import checkpoint

MAX_PACKAGES = 2048
MANIFEST_BYTES = 4 * 1024 * 1024
ACCOUNT = re.compile(r"^[0-9]{12}$")
SCHEMA = "closec-bulk-import-1"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def peek(archive: Path) -> dict:
    """Identity of one AWS package from its manifest (bounded read, no extraction)."""
    try:
        with zipfile.ZipFile(archive) as package:
            names = [i for i in package.infolist() if i.filename.endswith("manifest.json")]
            manifest = next(
                (i for i in names if i.filename.replace("\\", "/") == "AWS-EVIDENCE/manifest.json"),
                None,
            )
            if manifest is None or manifest.file_size > MANIFEST_BYTES:
                raise InputError("BULK_AWS_MANIFEST_REQUIRED")
            value = json.loads(package.read(manifest))
    except (zipfile.BadZipFile, ValueError, OSError) as exc:
        raise InputError("BULK_ARCHIVE_UNREADABLE") from exc
    if not isinstance(value, dict) or value.get("schema_version") != "closec-provisional-0.3":
        raise InputError("BULK_AWS_MANIFEST_REQUIRED")
    account = str(value.get("account_id") or "")
    if not ACCOUNT.fullmatch(account):
        raise InputError("COLLECTOR_ACCOUNT_INVALID")
    return {
        "account_id": account,
        "collection_id": str(value.get("collection_id") or ""),
        "completed_at": str(value.get("completed_at") or ""),
        "collector_version": str(value.get("collector_version") or ""),
        "collection_status": str(value.get("status") or ""),
        "business_group": value.get("business_group")
        if isinstance(value.get("business_group"), str)
        else None,
    }


def sidecar_state(archive: Path, digest: str) -> str:
    sidecar = archive.with_name(archive.name + ".sha256")
    if not sidecar.is_file():
        return "ABSENT"
    text = sidecar.read_text(encoding="utf-8", errors="replace").split()
    return (
        "MATCH" if text and text[0].lower() == digest and text[-1] == archive.name else "MISMATCH"
    )


def workspace_latest(store) -> dict[str, tuple[str, str]]:
    """account -> (completed_at, run) of the newest AWS collector import in the workspace."""
    from offline_analyzer.enterprise.snapshot import active_imports
    from offline_analyzer.ingestion.collector import stored_summary

    found: dict[str, tuple[str, str]] = {}
    for run in active_imports(store):
        summary = stored_summary(store.workspace, run) or {}
        account = summary.get("account_id")
        if account and summary.get("schema") == "closec-v030-native-1":
            stamp = str(summary.get("completed_at") or "")
            if account not in found or (stamp, run) > found[account]:
                found[account] = (stamp, run)
    return found


def bulk_id(folder: Path) -> str:
    return hashlib.sha256(str(folder.resolve()).encode()).hexdigest()[:32]


def report_path(store, identifier: str) -> Path:
    directory = resolve_under(store.workspace, "bulk-imports")
    directory.mkdir(mode=0o700, exist_ok=True)
    return resolve_under(directory, f"{identifier}.json")


def _save(path: Path, report: dict) -> None:
    staged = path.with_suffix(".json.partial")
    staged.write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    staged.replace(path)


def load_report(store, identifier: str) -> dict | None:
    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        return None
    path = report_path(store, identifier)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def expected_accounts(text: str) -> tuple[list[str], list[str]]:
    """Expected account IDs from pasted text or CSV (first 12-digit field per line)."""
    accounts, problems, seen = [], [], set()
    for number, line in enumerate(text.splitlines(), start=1):
        item = line.split("#", 1)[0].strip()
        if not item or item.lower().startswith("account_id"):
            continue
        value = item.split(",", 1)[0].strip()
        if not ACCOUNT.fullmatch(value):
            problems.append(f"line {number}: not a 12-digit account ID")
        elif value in seen:
            problems.append(f"line {number}: duplicate account ID")
        else:
            seen.add(value)
            accounts.append(value)
    return accounts, problems


def reconcile(rows: list[dict], expected: list[str] | None, latest: dict) -> dict:
    """Expected versus collected accounts: missing, unexpected, duplicate."""
    packages: dict[str, int] = {}
    for row in rows:
        if row.get("account_id"):
            packages[row["account_id"]] = packages.get(row["account_id"], 0) + 1
    present = {
        r["account_id"]
        for r in rows
        if r["status"] in {"IMPORTED", "ALREADY_IMPORTED", "SUPERSEDED"} and r.get("account_id")
    } | set(latest)
    result = {
        "duplicates": sorted(a for a, n in packages.items() if n > 1),
        "accounts_with_packages": len(packages),
    }
    if expected is not None:
        wanted = set(expected)
        result.update(
            expected=len(wanted),
            missing=sorted(wanted - present),
            unexpected=sorted(present - wanted),
            matched=len(wanted & present),
        )
    return result


def bulk_import(
    store,
    folder: Path,
    *,
    expected: list[str] | None = None,
    analyze: bool = True,
    progress=None,
) -> dict:
    """Import every AWS package ZIP of `folder`; returns (and persists) the bulk report."""
    from offline_analyzer.ingestion.archive import unpack_package
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.rules.engine import assess

    folder = Path(folder).expanduser()
    if folder.is_symlink() or not folder.is_dir():
        raise InputError("BULK_FOLDER_NOT_FOUND")
    archives = sorted(
        p
        for p in folder.iterdir()
        if p.suffix.lower() == ".zip" and p.is_file() and not p.is_symlink()
    )
    if not archives:
        raise InputError("BULK_FOLDER_HAS_NO_PACKAGES")
    if len(archives) > MAX_PACKAGES:
        raise InputError("BULK_PACKAGE_LIMIT")
    identifier = bulk_id(folder)
    path = report_path(store, identifier)
    previous = load_report(store, identifier) or {}
    done = {r["sha256"]: r for r in previous.get("packages", []) if r.get("sha256")}
    rows = []
    identities: dict[str, dict] = {}
    for archive in archives:
        checkpoint()
        digest = sha256_file(archive)
        row = {"file": archive.name, "sha256": digest, "bytes": archive.stat().st_size}
        try:
            row.update(peek(archive))
            row["sidecar"] = sidecar_state(archive, digest)
            if row["sidecar"] == "MISMATCH":
                raise InputError("ZIP_SHA256_SIDECAR_MISMATCH")
            row["status"] = "PENDING"
            identities[digest] = row
        except InputError as exc:
            row.update(status="REJECTED", code=str(exc))
        rows.append(row)
    # Per account the newest valid collection wins; older packages are superseded. When the
    # newest package of an account is invalid, the next newest is imported and the account is
    # flagged, never silently.
    latest = workspace_latest(store)
    candidates: dict[str, list[dict]] = {}
    for row in identities.values():
        candidates.setdefault(row["account_id"], []).append(row)
    for group in candidates.values():
        group.sort(key=lambda r: (r["completed_at"], r["collection_id"], r["sha256"]), reverse=True)
    report = {
        "schema": SCHEMA,
        "bulk_id": identifier,
        "folder": folder.name,
        "started_at": previous.get("started_at") or _now(),
        "packages": rows,
        "analyze": analyze,
        "fallbacks": [],
    }

    def import_one(row) -> bool:
        earlier = done.get(row["sha256"])
        if (
            earlier
            and earlier.get("status") in {"IMPORTED", "ALREADY_IMPORTED"}
            and store.db.execute(
                "SELECT 1 FROM runs WHERE run_id=?", [earlier.get("run_id")]
            ).fetchone()
        ):
            row.update(status="ALREADY_IMPORTED", run_id=earlier["run_id"])
            if (
                analyze
                and not store.db.execute(
                    "SELECT 1 FROM assessments WHERE run_id=?", [earlier["run_id"]]
                ).fetchone()
            ):
                assess(store, earlier["run_id"])
            return True
        try:
            # Unpacked into a private staging folder inside the workspace, then deleted.
            with tempfile.TemporaryDirectory(prefix="bulk-import-", dir=store.workspace) as temp:
                root = Path(temp) / "package"
                root.mkdir(mode=0o700)
                before = store.db.execute("SELECT count(*) FROM runs").fetchone()[0]
                run = import_package(store, unpack_package(folder / row["file"], root))
                after = store.db.execute("SELECT count(*) FROM runs").fetchone()[0]
            from offline_analyzer.inventory.environment import record_run_origin

            origin = "synthetic" if _origin(store, run) == "SYNTHETIC" else "tool-generated"
            record_run_origin(store.workspace, run, origin)
            row.update(status="IMPORTED" if after > before else "ALREADY_IMPORTED", run_id=run)
            if analyze:
                assess(store, run)
                row["analyzed"] = True
            return True
        except InputError as exc:
            row.update(status="REJECTED", code=str(exc))
        except Exception as exc:  # isolation: one package never blocks the others
            row.update(status="REJECTED", code=f"IMPORT_FAILED_{type(exc).__name__}"[:64])
        return False

    # Packages already refused before import (sidecar mismatch) still count as "newer".
    refused = {}
    for row in rows:
        if row["status"] == "REJECTED" and row.get("account_id") and row.get("completed_at"):
            refused.setdefault(row["account_id"], []).append(row)
    total = sum(len(g) for g in candidates.values())
    index = 0
    for account, group in sorted(candidates.items()):
        held = latest.get(account)
        imported = None
        for row in group:
            index += 1
            checkpoint()
            if imported is not None:
                row.update(status="SUPERSEDED", superseded_by="newer package in this folder")
                continue
            if held and held[0] > row["completed_at"]:
                row.update(status="SUPERSEDED", superseded_by=f"newer import {held[1]}")
                continue
            if progress:
                progress(f"Importing {row['file']}", index, total)
            if import_one(row):
                imported = row
            _save(path, report)
        if imported is None:
            continue
        invalid = [
            r
            for r in group + refused.get(account, [])
            if r["status"] == "REJECTED"
            and (r["completed_at"], r["collection_id"])
            > (imported["completed_at"], imported["collection_id"])
        ]
        if invalid:
            imported["fallback"] = "latest package invalid, fell back to older"
            report["fallbacks"].append(
                {
                    "account_id": account,
                    "imported": imported["file"],
                    "invalid": sorted(r["file"] for r in invalid),
                    "codes": sorted({r.get("code", "") for r in invalid}),
                }
            )
        _save(path, report)
    report["reconciliation"] = reconcile(rows, expected, workspace_latest(store))
    report["counts"] = {
        status: sum(r["status"] == status for r in rows)
        for status in ("IMPORTED", "ALREADY_IMPORTED", "SUPERSEDED", "REJECTED")
    }
    report["completed_at"] = _now()
    _save(path, report)
    return report


def _origin(store, run: str) -> str:
    from offline_analyzer.ingestion.collector import stored_summary

    return str((stored_summary(store.workspace, run) or {}).get("dataset_origin") or "")
