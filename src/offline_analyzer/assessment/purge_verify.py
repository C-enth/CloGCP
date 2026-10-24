"""Search every backend store for a purged account/project identifier.

Results carry counts by table and file category, and draft titles with the identifier
redacted; never the identifier, values or file names, so they are safe for job records
and logs. A match is a whole-token occurrence: a project ID must not be part of a longer
project ID, an account ID must not be part of a longer number.

Remaining references are separated: other scopes' own evidence (for example a trust
policy naming the purged account), analyst-written drafts, superseded frozen editions
(kept by decision) and anything else. Only zero remaining references reads as CLEAN.
"""

import json
import re
from pathlib import Path

CHUNK = 1024 * 1024
# Files that the scan itself or the platform owns and that cannot hold evidence.
IGNORED = {".scope-operation.lock", ".gui-owner.lock"}
REDACTED = "[purged identifier]"
# Imported evidence and everything derived from it, per run.
EVIDENCE_TABLES = {
    "sources",
    "artifacts",
    "observations",
    "evidence_refs",
    "evaluations",
    "findings",
    "finding_resources",
    "runs",
    "assessments",
    "enterprise_edges",
    "enterprise_issues",
    "enterprise_projection",
    "enterprise_snapshots",
    "security_investigations",
}
EVIDENCE_FILES = {"raw", "uploads", "collections"}
DATABASE_FILES = "database file"


def token_pattern(identifier: str, provider: str) -> str:
    word = "0-9" if provider == "AWS" else "a-z0-9-"
    return f"(^|[^{word}]){re.escape(identifier)}($|[^{word}])"


def _category(relative: Path) -> str:
    if len(relative.parts) == 1:
        return DATABASE_FILES if relative.name.startswith("assessment.duckdb") else "workspace"
    return relative.parts[0]


def _file_contains(path: Path, searches: list[tuple[bytes, re.Pattern]], overlap: int) -> bool:
    """One read per file. A token match always contains the literal identifier, so the
    regular expression only runs on chunks where the fast literal search already hit."""
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK):
            window = tail + chunk
            if any(literal in window and pattern.search(window) for literal, pattern in searches):
                return True
            tail = chunk[-overlap:]
    return False


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def scan(store, provider: str, identifiers: list[str]) -> dict:
    """Matching rows per table (all text columns), files per category, and drafts."""
    database: dict[str, int] = {}
    files: dict[str, int] = {}
    drafts: dict[str, dict] = {}
    columns = store.db.execute(
        "SELECT table_name,column_name FROM information_schema.columns "
        "WHERE table_schema='main' AND data_type='VARCHAR' ORDER BY table_name,column_name"
    ).fetchall()
    present = [i for i in identifiers if i]
    sql_patterns = [token_pattern(i, provider) for i in present]
    by_table: dict[str, list[str]] = {}
    for table, column in columns:
        by_table.setdefault(table, []).append(column)
    for table, names in by_table.items():
        # One pass per table; each (column, identifier) pair counts as its own query did.
        terms, params = [], []
        for name in names:
            column = _quoted(name)
            for literal, pattern in zip(present, sql_patterns, strict=True):
                terms.append(
                    f"count(*) FILTER (WHERE contains({column}, ?) AND regexp_matches({column}, ?))"
                )
                params += [literal, pattern]
        if not terms:
            continue
        count = sum(
            store.db.execute(f"SELECT {','.join(terms)} FROM {_quoted(table)}", params).fetchone()
        )
        if count:
            database[table] = count
    if "report_revisions" in database:
        compiled = [re.compile(p) for p in sql_patterns]
        for report_id, raw in store.rows(
            "SELECT report_id,data FROM report_revisions ORDER BY report_id,revision"
        ):
            if not any(c.search(raw) for c in compiled):
                continue
            title = json.loads(raw).get("sections", {}).get("title", "Untitled draft")
            for c in compiled:
                title = c.sub(lambda m: m.group(1) + REDACTED + m.group(2), title)
            entry = drafts.setdefault(report_id, {"draft": "", "report_id": report_id})
            entry["draft"] = title
            entry["revisions"] = entry.get("revisions", 0) + 1
    searches = [
        (literal.encode(), re.compile(p.encode()))
        for literal, p in zip(present, sql_patterns, strict=True)
    ]
    overlap = max((len(i.encode()) for i in identifiers), default=0) + 2
    for path in sorted(store.workspace.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.name in IGNORED:
            continue
        if searches and _file_contains(path, searches, overlap):
            key = _category(path.relative_to(store.workspace))
            files[key] = files.get(key, 0) + 1
    return {"database": database, "files": files, "drafts": list(drafts.values())}


def _split(found: dict) -> dict:
    db, files = found["database"], found["files"]
    evidence = {
        "database_rows": {t: n for t, n in db.items() if t in EVIDENCE_TABLES},
        "files": {c: n for c, n in files.items() if c in EVIDENCE_FILES},
    }
    other = {
        "database_rows": {
            t: n
            for t, n in db.items()
            if t not in EVIDENCE_TABLES | {"report_revisions", "finalized_assessments"}
        },
        "files": {c: n for c, n in files.items() if c not in EVIDENCE_FILES | {DATABASE_FILES}},
    }
    return {"evidence": evidence, "other": other}


def _total(group: dict) -> int:
    return sum(group["database_rows"].values()) + sum(group["files"].values())


def verify_purged(store, provider: str, identifiers: list[str], before: dict | None = None) -> dict:
    """Separated report of what the purge removed and what still mentions the identifier.

    `before` is a `scan` taken before the purge; references removed are the differences.
    """
    after = scan(store, provider, identifiers)
    parts = _split(after)
    retained_evidence, other = parts["evidence"], parts["other"]
    draft_revisions = sum(d["revisions"] for d in after["drafts"])
    editions = after["database"].get("finalized_assessments", 0)
    database_files = after["files"].get(DATABASE_FILES, 0)
    remaining = sum(after["database"].values()) + sum(after["files"].values())
    removed = {"database_rows": {}, "files": {}}
    for key, field in (("database", "database_rows"), ("files", "files")):
        for name, count in (before or {}).get(key, {}).items():
            gone = count - after[key].get(name, 0)
            if gone > 0:
                removed[field][name] = gone
    return {
        "status": "CLEAN" if remaining == 0 else "RETAINED_REFERENCES",
        "clean": remaining == 0,
        "references": remaining,
        "references_removed": {**removed, "total": _total(removed)},
        "cross_account_evidence_retained": {
            **retained_evidence,
            "total": _total(retained_evidence),
        },
        "analyst_drafts_mentioning": {"drafts": after["drafts"], "revisions": draft_revisions},
        "superseded_frozen_editions_retained": editions,
        "other_retained": {**other, "total": _total(other)},
        # Database/WAL files hold the retained rows above; matches without rows would be
        # unreferenced pages.
        "database_files_with_matches": database_files,
        "unreferenced_database_pages": database_files if remaining == database_files else 0,
        "identifiers_checked": len([i for i in identifiers if i]),
        "wal_present": (store.workspace / "assessment.duckdb.wal").exists(),
    }
