"""Scoped lifecycle operations through the existing store and engines.

Stage changes in a private DB, fully reassess before publication, then publish with a
recoverable journal. A compact logical DB copy avoids retaining deleted rows in the
new database's free pages. This is not forensic media erasure or backup recall.
"""

import json
import re
import secrets
import shutil
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.enterprise.correlate import correlate
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.ingestion.importer import import_package, load_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import check_origin, run_origins
from offline_analyzer.provenance.execution import checkpoint, committing, report
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.scope_journal import (
    checked_file,
    discard_orphans,
    guard,
    recover_locked,
    write_journal,
)
from offline_analyzer.storage.store import Store

RUN_TABLES = (
    "sources",
    "artifacts",
    "observations",
    "evidence_refs",
    "evaluations",
    "findings",
    "finding_resources",
    "assessments",
    "enterprise_edges",
    "enterprise_issues",
    "enterprise_projection",
    "enterprise_snapshots",
    "security_investigations",
    "scope_uploads",
    "scope_retired_runs",
)
DERIVED = (
    "evaluations",
    "findings",
    "finding_resources",
    "assessments",
    "enterprise_edges",
    "enterprise_issues",
    "enterprise_projection",
    "security_investigations",
)


def identity(provider: str, scope: str):
    pattern = r"[0-9]{12}" if provider == "AWS" else r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
    if provider not in {"AWS", "GCP"} or not re.fullmatch(pattern, scope):
        raise InputError("INVALID_SCOPE_IDENTITY")


def source_scope(source: dict) -> tuple[str, str | None]:
    return (
        ("GCP", source.get("project_id"))
        if source.get("format") == "gcp-json-v1"
        else ("AWS", source.get("account_id"))
    )


def observation_predicate(provider: str) -> str:
    return (
        "tool='gcp' AND json_extract_string(data,'$.project_id')=?"
        if provider == "GCP"
        else "tool<>'gcp' AND account_id=?"
    )


def scopes(store: Store) -> list[dict]:
    from offline_analyzer.attack_paths.gcp import INVESTIGATION_RULES
    from offline_analyzer.inventory.accounts import workspace_registry

    registry = workspace_registry(store.workspace)
    aliases = {e.account_id: e.alias for e in registry.entries} if registry else {}
    found = {}
    for run, raw in store.rows("SELECT run_id,data FROM sources"):
        source = json.loads(raw)
        key = source_scope(source)
        if not key[1]:
            continue
        row = found.setdefault(
            key,
            dict(
                provider=key[0],
                scope_id=key[1],
                project_number=None,
                display_name=None,
                regions=set(),
                datasets=set(),
                snapshots=set(),
                latest_collection=None,
            ),
        )
        row["snapshots"].add(run)
        row["regions"].add(source.get("region") or "global")
        row["datasets"].add(source["operation"])
        meta = source.get("gcp_metadata") or {}
        row["project_number"] = source.get("project_number") or row["project_number"]
        row["display_name"] = meta.get("project_display_name") or row["display_name"]
        stamp = meta.get("completed_at") if key[0] == "GCP" else source.get("collected_at")
        if stamp and (row["latest_collection"] is None or stamp > row["latest_collection"]):
            row["latest_collection"] = stamp
    for (provider, scope), row in found.items():
        if provider == "AWS":
            row["display_name"] = aliases.get(scope)
        pred = observation_predicate(provider)
        row["resources"] = store.db.execute(
            f"SELECT count(DISTINCT resource_id) FROM observations WHERE {pred}", [scope]
        ).fetchone()[0]
        field = "project_id" if provider == "GCP" else "account_id"
        row["findings"] = store.db.execute(
            (
                "SELECT count(DISTINCT finding_id) FROM findings WHERE "
                "coalesce(json_extract_string(data,'$.provider'),'AWS')=? AND "
                "json_extract_string(data,'$."
            )
            + field
            + "')=?",
            [provider, scope],
        ).fetchone()[0]
        row["investigations"] = store.db.execute(
            (
                "SELECT count(DISTINCT investigation_id) FROM "
                "security_investigations WHERE finding_id IN (SELECT finding_id "
                "FROM findings WHERE "
                "coalesce(json_extract_string(data,'$.provider'),'AWS')=? AND "
                "json_extract_string(data,'$."
            )
            + field
            + "')=?)",
            [provider, scope],
        ).fetchone()[0]
        if provider == "GCP":
            placeholders = ",".join("?" for _ in INVESTIGATION_RULES)
            row["investigations"] = store.db.execute(
                "SELECT count(DISTINCT finding_id) FROM findings WHERE "
                "json_extract_string(data,'$.provider')='GCP' AND "
                "json_extract_string(data,'$.project_id')=? AND "
                "json_extract_string(data,'$.rule_id') IN (" + placeholders + ")",
                [scope, *sorted(INVESTIGATION_RULES)],
            ).fetchone()[0]
        if provider == "GCP" and not row["display_name"]:
            for (raw,) in store.rows(
                "SELECT data FROM observations WHERE tool='gcp' AND kind='GCP::Project' "
                "AND json_extract_string(data,'$.project_id')=? ORDER BY run_id",
                [scope],
            ):
                config = json.loads(raw)["configuration"]
                name = config.get("displayName") or config.get("name")
                if isinstance(name, str) and not name.startswith("projects/"):
                    row["display_name"] = name
        for field in ("regions", "datasets", "snapshots"):
            row[field] = sorted(row[field])
        state = store.db.execute(
            "SELECT active_run FROM scope_state WHERE provider=? AND scope_id=?", [provider, scope]
        ).fetchone()
        row["active_snapshot"] = state[0] if state else None
    return sorted(found.values(), key=lambda r: (r["provider"], r["scope_id"]))


def plan(store: Store, provider: str, scope: str) -> dict:
    identity(provider, scope)
    selected = next(
        (s for s in scopes(store) if (s["provider"], s["scope_id"]) == (provider, scope)), None
    )
    if selected is None:
        raise InputError("SCOPE_NOT_FOUND")
    predicate = observation_predicate(provider)
    owned = store.db.execute(
        f"SELECT run_id,observation_id,resource_id FROM observations WHERE {predicate}", [scope]
    ).fetchall()
    affected = {r for r, _, _ in owned}
    resources = {rid for _, _, rid in owned if rid}
    source_ids = set()
    artifacts = set()
    versions = []
    for run, sid, raw in store.rows("SELECT run_id,source_id,data FROM sources"):
        source = json.loads(raw)
        if source_scope(source) == (provider, scope):
            affected.add(run)
            source_ids.add((run, sid))
            versions.append(raw)
            if source.get("artifact_id"):
                artifacts.add((run, source["artifact_id"]))
    # Owned configuration in a shared multi-scope response cannot be safely erased by
    # rewriting evidence. Structural organization account references are not configurations.
    # One set-based query each (a query per artifact/observation took minutes on large
    # projects and timed the preview out).
    structural = "('AWS::Organizations::Account','AWS::OrganizationsAccount')"
    unsafe = False
    if artifacts:
        runs, artifact_ids = zip(*sorted(artifacts), strict=True)
        unsafe |= bool(
            store.db.execute(
                "SELECT 1 FROM observations o JOIN evidence_refs e USING(run_id,observation_id) "
                "JOIN (SELECT unnest(?) AS run_id, unnest(?) AS artifact_id) a "
                "USING(run_id,artifact_id) "
                f"WHERE NOT coalesce(({predicate}),false) AND kind NOT IN {structural} LIMIT 1",
                [list(runs), list(artifact_ids), scope],
            ).fetchone()
        )
    # A target-owned configuration collected through another scope's source must
    # not survive in its raw response after an apparent permanent deletion.
    referenced = store.db.execute(
        "SELECT DISTINCT o.run_id,e.artifact_id FROM observations o "
        "JOIN evidence_refs e USING(run_id,observation_id) "
        f"WHERE {predicate} AND kind NOT IN {structural}",
        [scope],
    ).fetchall()
    unsafe |= any(tuple(ref) not in artifacts for ref in referenced)
    snapshots = list(store.rows("SELECT run_id,members FROM enterprise_snapshots"))
    for run, members in snapshots:
        if set(json.loads(members)) & affected:
            affected.add(run)
    finding_ids = {
        fid
        for fid, raw in store.rows("SELECT finding_id,data FROM findings")
        if source_finding_scope(json.loads(raw)) == (provider, scope)
    }
    files = set()
    upload_ids = set()
    uploads = store.workspace / "uploads"
    if uploads.is_dir():
        for folder in uploads.iterdir():
            if not folder.is_dir() or not re.fullmatch("[0-9a-f]{32}", folder.name):
                continue
            checked_file(store.workspace, "uploads/" + folder.name)
            package = load_package(folder)
            if any(source_scope(s.model_dump()) == (provider, scope) for s in package.sources):
                upload_ids.add(folder.name)
                for path in folder.rglob("*"):
                    if path.is_symlink():
                        raise InputError("UNSAFE_MANAGED_FILE")
                    if path.is_file():
                        files.add(path.relative_to(store.workspace).as_posix())
                for suffix in (".origin", ".zip"):
                    if (uploads / (folder.name + suffix)).is_file():
                        files.add("uploads/" + folder.name + suffix)
    digests = {
        sha
        for run, artifact, sha in store.rows("SELECT run_id,artifact_id,sha256 FROM artifacts")
        if (run, artifact) in artifacts
    }
    unparsed_digests = set()
    # Native AWS collectors can retain unparsed operations outside artifacts.
    # Their checked collection summaries remain the ownership/provenance index.
    summaries = []
    collection_root = store.workspace / "collections"
    if collection_root.is_dir():
        for path in collection_root.glob("*.json"):
            checked_file(store.workspace, path.relative_to(store.workspace).as_posix())
            summaries.append(json.loads(path.read_text()))
    if provider == "AWS":
        for summary in summaries:
            if summary.get("account_id") == scope:
                unparsed_digests.update(
                    row["artifact_sha256"]
                    for row in summary.get("operations", [])
                    if row.get("artifact_sha256") and row.get("import_handling") != "IMPORTED"
                )
        digests.update(unparsed_digests)
    for sha in digests:
        if not re.fullmatch("[0-9a-f]{64}", sha):
            raise InputError("COLLECTION_SUMMARY_INVALID")
        shared_unparsed = any(
            summary.get("account_id") != scope
            and any(row.get("artifact_sha256") == sha for row in summary.get("operations", []))
            for summary in summaries
        )
        unsafe |= sha in unparsed_digests and shared_unparsed
        refs = store.db.execute(
            "SELECT run_id,artifact_id FROM artifacts WHERE sha256=?", [sha]
        ).fetchall()
        if not shared_unparsed and all(tuple(ref) in artifacts for ref in refs):
            files.add("raw/" + sha + ".json")
    reports = 0
    revisions = 0
    review_ids = set()
    edges = 0
    for (fid,) in store.rows(
        "SELECT finding_id FROM decisions UNION SELECT finding_id FROM sre_validations"
    ):
        if fid in finding_ids:
            review_ids.add(fid)
    drafts = {"REMOVE": 0, "STRIP": 0, "INVALIDATE": 0}
    for _, _, _, run, _, raw in store.rows("SELECT * FROM report_revisions"):
        action = draft_action(json.loads(raw), run, provider, scope, affected, artifacts)
        if action != "KEEP":
            revisions += 1
            drafts[action] += 1
    for run, _, src, dst, _, _, _, _raw in store.rows("SELECT * FROM enterprise_edges"):
        if run in affected and provider == "AWS" and scope in {src, dst}:
            edges += 1
    edges_truncated = False
    if provider == "GCP":
        from offline_analyzer.inventory.cloud import relationships

        for run in sorted(affected):
            result = relationships(store, run, project=scope, evidence=False)
            edges += len(result["items"])
            edges_truncated |= result["truncated"]
    for directory in ("reports", "collections"):
        folder = store.workspace / directory
        if not folder.is_dir():
            continue
        for path in folder.iterdir():
            if not path.is_file():
                continue
            if directory == "collections" and path.stem in affected:
                files.add(path.relative_to(store.workspace).as_posix())
            elif directory == "reports" and path.suffix == ".meta":
                meta = json.loads(path.read_text())
                if meta.get("run_id") in affected:
                    reports += 1
                    files.add(path.relative_to(store.workspace).as_posix())
                    for reportfile in folder.glob(path.stem + ".*"):
                        if reportfile.is_file():
                            files.add(reportfile.relative_to(store.workspace).as_posix())
    job_records = referencing_job_records(store.workspace, provider, scope)
    files.update(job_records)
    exclusions = store.db.execute(
        "SELECT count(*) FROM finding_exclusions WHERE finding_id IN (SELECT unnest(?))",
        [sorted(finding_ids)],
    ).fetchone()[0]
    frozen_editions = store.db.execute(
        "SELECT count(*) FROM finalized_assessments WHERE run_id IN (SELECT unnest(?))",
        [sorted(affected)],
    ).fetchone()[0]
    result = dict(
        provider=provider,
        scope_id=scope,
        project_number=selected["project_number"],
        workspace=str(store.workspace),
        snapshots=len(affected),
        resources=len(resources),
        findings=len(finding_ids),
        investigations=selected["investigations"],
        relationship_edges=edges,
        relationship_edges_truncated=edges_truncated,
        analyst_reviews=len(review_ids),
        report_revisions=revisions,
        frozen_editions=frozen_editions,
        path_reviews=store.db.execute(
            "SELECT count(*) FROM path_reviews WHERE run_id IN (SELECT unnest(?))",
            [sorted(affected)],
        ).fetchone()[0],
        managed_exports=reports,
        files=sorted(files),
        shared_raw_blocked=unsafe,
        # Finalised editions are never altered automatically; how a purge treats them
        # is an open owner decision, so the purge is refused while any is affected.
        frozen_decision_required=frozen_editions > 0,
        affected_runs=sorted(affected),
        upload_ids=sorted(upload_ids),
    )
    # What the purge removes, and what it touches but keeps, by category.
    result["removed"] = dict(
        snapshot_rows=len(affected),
        resources=len(resources),
        findings=len(finding_ids),
        analyst_reviews=len(review_ids),
        exclusions=exclusions,
        drafts=drafts["REMOVE"],
        path_reviews=result["path_reviews"],
        scope_labels=store.db.execute(
            "SELECT count(*) FROM scope_labels WHERE provider=? AND scope_id=?", [provider, scope]
        ).fetchone()[0],
        evidence_files=sum(f.startswith(("raw/", "uploads/")) for f in files),
        collection_summaries=sum(f.startswith("collections/") for f in files),
        generated_exports=reports,
        job_records=len(job_records),
    )
    result["retained_affected"] = dict(
        consolidated_drafts_other_scopes=drafts["STRIP"],
        drafts_marked_for_review=drafts["INVALIDATE"],
        snapshots_rebuilt_with_other_scopes=sum(
            1
            for run, members in snapshots
            if run in affected and any(m not in affected for m in json.loads(members))
        ),
        frozen_editions_unchanged=frozen_editions,
    )
    result["preview_token"] = stable_id(
        "scope-preview",
        [
            result,
            sorted(versions),
            store.db.execute("SELECT count(*) FROM decisions").fetchone()[0],
            store.db.execute("SELECT count(*) FROM sre_validations").fetchone()[0],
            store.db.execute("SELECT count(*) FROM report_revisions").fetchone()[0],
            store.db.execute("SELECT count(*) FROM finalized_assessments").fetchone()[0],
            store.db.execute("SELECT count(*) FROM path_reviews").fetchone()[0],
        ],
    )
    if len(result["files"]) > 5000:
        raise InputError("SCOPE_FILE_PLAN_LIMIT")
    result["limitations"] = [
        "Downloaded reports, external original evidence and backups cannot be recalled.",
        "This removes managed logical data, not forensic media remnants.",
        (
            "Shared transport copies are removed; unrelated normalized data "
            "and separately referenced raw files remain."
        ),
        (
            "Affected consolidated conclusions require full reassessment; "
            "historical approvals are not automatic current approval."
        ),
        (
            "Consolidated drafts that also cover other accounts/projects are kept without "
            "this scope's assets and must be reviewed again; analyst-written text is not "
            "rewritten, so the verification lists any identifier it still contains."
        ),
    ]
    if result["frozen_decision_required"]:
        result["limitations"].insert(0, FROZEN_WARNING)
    return result


def draft_action(data: dict, run: str, provider: str, scope: str, affected, artifacts) -> str:
    """REMOVE a draft owned by the scope, STRIP the scope from a consolidated draft that
    also covers other scopes, INVALIDATE drafts of affected snapshots, else KEEP."""
    snapshots = data["snapshots"]
    owned = [source_finding_scope(s) == (provider, scope) for s in snapshots]
    primary_owned = any(
        own and s["finding_id"] == data["primary_finding"]
        for own, s in zip(owned, snapshots, strict=True)
    )
    # A kept snapshot citing the scope's removed raw response cannot stay current.
    lost_evidence = any(
        (run, ref["artifact_id"]) in artifacts
        for own, s in zip(owned, snapshots, strict=True)
        if not own
        for ref in s["evidence"]
    )
    if all(owned) or primary_owned or lost_evidence:
        return "REMOVE"
    if any(owned):
        return "STRIP"
    return "INVALIDATE" if run in affected else "KEEP"


def referencing_job_records(workspace: Path, provider: str, scope: str) -> set[str]:
    """Persisted job sidecars (session diagnostics/results) that name the scope."""
    from offline_analyzer.assessment.purge_verify import token_pattern

    pattern = re.compile(token_pattern(scope, provider).encode())
    found = set()
    folder = workspace / "jobs"
    if folder.is_dir() and not folder.is_symlink():
        for path in folder.glob("*.json"):
            if re.fullmatch(r"[0-9a-f]{32}\.json", path.name) and not path.is_symlink():
                checked_file(workspace, "jobs/" + path.name)
                if pattern.search(path.read_bytes()):
                    found.add("jobs/" + path.name)
    return found


def source_finding_scope(data: dict):
    return (
        data.get("provider", "AWS"),
        data.get("project_id") if data.get("provider") == "GCP" else data.get("account_id"),
    )


def clone_store(store: Store, directory: Path) -> Store:
    store.db.execute("CHECKPOINT")
    directory.mkdir(parents=True)
    marker = directory.parent / "marker.json"
    marker.write_text(json.dumps({"scope_stage_version": 1, "event_id": directory.parent.name}))
    shutil.copyfile(store.workspace / "assessment.duckdb", directory / "assessment.duckdb")
    shadow = Store(directory, _recover=False)
    shadow.workspace = store.workspace  # Read existing immutable raw/registry; DB stays private.
    return shadow


COMPACT_BATCH_ROWS = 2000
COMPACT_BATCH_BYTES = 32 * 1024 * 1024


def compact(shadow: Store, directory: Path):
    """Copy the live rows into a freshly created database, so freed pages holding purged
    data are not carried over. Rows move column-wise (one list parameter per column) in
    bounded batches; the connections keep external access disabled (no ATTACH)."""
    with Store(directory, _recover=False) as target:
        with target.transaction():
            tables = [r[0] for r in shadow.db.execute("SHOW TABLES").fetchall()]
            for name in tables:
                quoted = '"' + name.replace('"', '""') + '"'
                types = dict(
                    target.db.execute(
                        "SELECT column_name,data_type FROM information_schema.columns "
                        "WHERE table_schema='main' AND table_name=?",
                        [name],
                    ).fetchall()
                )
                target.db.execute("DELETE FROM " + quoted)
                cursor = shadow.db.execute("SELECT * FROM " + quoted)
                columns = [d[0] for d in cursor.description]
                missing = [c for c in columns if c not in types]
                if missing:
                    raise InputError("SCOPE_COMPACT_SCHEMA_MISMATCH")
                insert = f"INSERT INTO {quoted} BY NAME SELECT " + ",".join(
                    f'unnest(CAST(? AS {types[c]}[])) AS "{c.replace(chr(34), chr(34) * 2)}"'
                    for c in columns
                )
                for batch in _batches(cursor):
                    target.db.execute(insert, [list(values) for values in zip(*batch, strict=True)])
        target.db.execute("CHECKPOINT")


def _batches(cursor):
    """Row batches bounded by count and by approximate text size (large evidence rows)."""
    batch, size = [], 0
    while rows := cursor.fetchmany(256):
        for row in rows:
            batch.append(row)
            size += sum(len(v) for v in row if isinstance(v, str))
            if len(batch) >= COMPACT_BATCH_ROWS or size >= COMPACT_BATCH_BYTES:
                yield batch
                batch, size = [], 0
    if batch:
        yield batch


def publish(store: Store, directory: Path, event: str, files: list[str], origins: dict):
    compact_path = directory / "compact"
    write_journal(store.workspace, dict(version=1, event_id=event, files=files, origins=origins))
    store.db.close()
    try:
        (store.workspace / "assessment.duckdb").rename(directory / "old.duckdb")
        (compact_path / "assessment.duckdb").rename(store.workspace / "assessment.duckdb")
        recover_locked(store.workspace)
    except BaseException:
        recover_locked(store.workspace)
        raise
    finally:
        if not (store.workspace / ".scope-journal.json").exists():
            connection = Store(store.workspace, _recover=False)
            store.db = connection.db


def purge(shadow: Store, preview: dict, event: str) -> tuple[str | None, dict]:
    provider, scope = preview["provider"], preview["scope_id"]
    predicate = observation_predicate(provider)
    affected = set(preview["affected_runs"])
    supersede_frozen(shadow, preview, event)
    for run in affected:
        shadow.db.execute("DELETE FROM path_reviews WHERE run_id=?", [run])
    removed_findings = set()
    artifacts = set()
    for run, sid, raw in list(shadow.rows("SELECT run_id,source_id,data FROM sources")):
        source = json.loads(raw)
        if source_scope(source) == (provider, scope):
            if source.get("artifact_id"):
                artifacts.add((run, source["artifact_id"]))
            shadow.db.execute("DELETE FROM sources WHERE run_id=? AND source_id=?", [run, sid])
    for _run, fid, raw in list(shadow.rows("SELECT run_id,finding_id,data FROM findings")):
        if source_finding_scope(json.loads(raw)) == (provider, scope):
            removed_findings.add(fid)
    for rid, rev, _, run, _, raw in list(shadow.rows("SELECT * FROM report_revisions")):
        data = json.loads(raw)
        action = draft_action(data, run, provider, scope, affected, artifacts)
        if action == "REMOVE":
            shadow.db.execute(
                "DELETE FROM report_revisions WHERE report_id=? AND revision=?", [rid, rev]
            )
            continue
        if action == "STRIP":
            shadow.db.execute(
                "UPDATE report_revisions SET data=? WHERE report_id=? AND revision=?",
                [without_scope(data, provider, scope), rid, rev],
            )
        if action in {"STRIP", "INVALIDATE"}:
            shadow.db.execute(
                "INSERT INTO scope_invalidated_reports VALUES (?,?) ON CONFLICT DO NOTHING",
                [rid, rev],
            )
    if removed_findings:
        for table in ("decisions", "sre_validations", "finding_exclusions"):
            shadow.db.execute(
                f"DELETE FROM {table} WHERE finding_id IN (SELECT unnest(?))",
                [sorted(removed_findings)],
            )
    shadow.db.execute("DELETE FROM scope_labels WHERE provider=? AND scope_id=?", [provider, scope])
    # Earlier audit events keep their trail under a one-way scope digest.
    shadow.db.execute(
        "UPDATE scope_audit SET scope_id=? WHERE provider=? AND scope_id=?",
        [audit_scope(provider, scope), provider, scope],
    )
    shadow.db.execute(
        "DELETE FROM scope_invalidated_reports WHERE (report_id,revision) NOT IN "
        "(SELECT report_id,revision FROM report_revisions)"
    )
    shadow.db.execute(
        "DELETE FROM evidence_refs WHERE (run_id,observation_id) IN "
        f"(SELECT run_id,observation_id FROM observations WHERE {predicate})",
        [scope],
    )
    shadow.db.execute(f"DELETE FROM observations WHERE {predicate}", [scope])
    for run, artifact in artifacts:
        shadow.db.execute(
            "DELETE FROM evidence_refs WHERE run_id=? AND artifact_id=?", [run, artifact]
        )
        shadow.db.execute("DELETE FROM artifacts WHERE run_id=? AND artifact_id=?", [run, artifact])
    renamed, emptied = rebuild_runs(
        shadow,
        affected,
        event,
        keep_source=lambda _run, s: source_scope(s) != (provider, scope),
        keep_target=lambda t: not (provider == "AWS" and t["account_id"] == scope),
    )
    shadow.db.execute("DELETE FROM scope_state WHERE provider=? AND scope_id=?", [provider, scope])
    for upload in preview["upload_ids"]:
        shadow.db.execute("DELETE FROM scope_uploads WHERE upload_id=?", [upload])
    return reassess_runs(shadow, renamed, emptied, scope if provider == "AWS" else None)


def without_scope(data: dict, provider: str, scope: str) -> str:
    """A consolidated draft revision minus one scope's snapshots, text re-rendered."""
    from offline_analyzer.contracts.report_finding import ReportRevision
    from offline_analyzer.findings.report_ready import render_text

    data = {
        **data,
        "snapshots": [s for s in data["snapshots"] if source_finding_scope(s) != (provider, scope)],
    }
    revision = ReportRevision.model_validate(data)
    return revision.model_copy(
        update={"report_text": render_text(revision.sections, revision.snapshots)}
    ).model_dump_json()


def audit_scope(provider: str, scope: str) -> str:
    return stable_id("purged-scope", [provider, scope])


def rebuild_runs(
    shadow: Store, affected: set[str], event: str, keep_source, keep_target
) -> tuple[dict, set]:
    """Drop emptied runs; give partially purged runs new IDs so nothing stale survives."""
    renamed = {}
    emptied = set()
    for run in sorted(affected):
        for table in DERIVED:
            shadow.db.execute(f"DELETE FROM {table} WHERE run_id=?", [run])
        row = shadow.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()
        if not row:
            continue
        package = json.loads(row[0])
        package["targets"] = [t for t in package.get("targets", []) if keep_target(t)]
        if "sources" in package:
            package["sources"] = [s for s in package["sources"] if keep_source(run, s)]
        if not shadow.db.execute("SELECT 1 FROM sources WHERE run_id=?", [run]).fetchone():
            emptied.add(run)
            for table in RUN_TABLES:
                shadow.db.execute(f"DELETE FROM {table} WHERE run_id=?", [run])
            shadow.db.execute("DELETE FROM runs WHERE run_id=?", [run])
        else:
            new = stable_id("run", ["scope-purge-1", run, event])
            renamed[run] = new
            for table in RUN_TABLES:
                shadow.db.execute(f"UPDATE {table} SET run_id=? WHERE run_id=?", [new, run])
            shadow.db.execute(
                "UPDATE runs SET run_id=?,package=? WHERE run_id=?", [new, json.dumps(package), run]
            )
            for rid, rev, raw in list(
                shadow.rows(
                    "SELECT report_id,revision,data FROM report_revisions WHERE run_id=?", [run]
                )
            ):
                data = json.loads(raw)
                data["run_id"] = new
                shadow.db.execute(
                    "UPDATE report_revisions SET run_id=?,data=? WHERE report_id=? AND revision=?",
                    [new, json.dumps(data), rid, rev],
                )
    for run, members in list(shadow.rows("SELECT run_id,members FROM enterprise_snapshots")):
        members = [renamed.get(m, m) for m in json.loads(members) if m not in emptied]
        shadow.db.execute(
            "UPDATE enterprise_snapshots SET members=? WHERE run_id=?", [json.dumps(members), run]
        )
        raw = json.loads(
            shadow.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()[0]
        )
        raw["member_runs"] = members
        shadow.db.execute("UPDATE runs SET package=? WHERE run_id=?", [json.dumps(raw), run])
    for old, new in renamed.items():
        shadow.db.execute("UPDATE scope_state SET active_run=? WHERE active_run=?", [new, old])
    return renamed, emptied


def reassess_runs(
    shadow: Store, renamed: dict, emptied: set, removed_account: str | None
) -> tuple[str | None, dict]:
    for index, run in enumerate(renamed.values()):
        checkpoint("SCOPE_REASSESS", index, len(renamed))
        assess(shadow, run)
        if shadow.db.execute("SELECT 1 FROM enterprise_snapshots WHERE run_id=?", [run]).fetchone():
            correlate(shadow, run)
            if removed_account:
                shadow.db.execute(
                    (
                        "DELETE FROM enterprise_edges WHERE run_id=? AND "
                        "(source_account=? OR destination_account=?)"
                    ),
                    [run, removed_account, removed_account],
                )
    candidate = shadow.db.execute(
        "SELECT r.run_id FROM runs r LEFT JOIN enterprise_snapshots e "
        "USING(run_id) ORDER BY (e.run_id IS NOT NULL) DESC,r.created_at "
        "DESC LIMIT 1"
    ).fetchone()
    origins = run_origins(shadow.workspace)
    for old, new in renamed.items():
        origins[new] = origins.pop(old, "unrecorded")
    for old in emptied:
        origins.pop(old, None)
    return (candidate[0] if candidate else None), origins


def delete_scope(
    store: Store,
    provider: str,
    scope: str,
    token: str,
    confirmation: str,
    confirmed: bool,
    backup: bool = True,
    supersede: bool = False,
    supersede_confirmation: str = "",
    supersede_reason: str = "",
) -> dict:
    """Purge one account/project everywhere in the backend, then verify what remains.

    A finalised edition including the scope blocks the purge unless the explicit
    "purge and mark edition superseded" override is given. The result names no
    identifier: it is persisted as a job record and must not become a reference itself.
    """
    from offline_analyzer.assessment.purge_verify import scan, verify_purged

    identity(provider, scope)
    if confirmation != scope or confirmed is not True:
        raise InputError("SCOPE_CONFIRMATION_REQUIRED")
    identifiers = [scope]
    with guard(store.workspace):
        discard_orphans(store.workspace)
        preview = plan(store, provider, scope)
        if token != preview["preview_token"]:
            raise InputError("SCOPE_PREVIEW_STALE")
        if preview["shared_raw_blocked"]:
            raise InputError("SHARED_RAW_SCOPE_DELETION_UNSUPPORTED")
        override = frozen_override(
            store, preview, supersede, supersede_confirmation, [scope], supersede_reason, backup
        )
        identifiers += [preview["project_number"]] if preview["project_number"] else []
        counts = {
            k: preview[k]
            for k in (
                "snapshots",
                "resources",
                "findings",
                "relationship_edges",
                "analyst_reviews",
                "report_revisions",
            )
        }
        checkpoint("SCOPE_BACKUP")
        saved = pre_purge_backup(store) if backup else None
        digest = audit_scope(provider, scope)
        action = attach_override(store, preview, override, saved, digest, "DELETE")
        counts["superseded_editions"] = len(override["runs"]) if override else 0
        checkpoint("SCOPE_VERIFY_BEFORE")
        before = scan(store, provider, identifiers)
        result = staged_delete(store, preview, purge, action, provider, digest, counts)
    report("SCOPE_VERIFY_AFTER")
    return dict(
        result,
        removed=preview["removed"],
        retained_affected=preview["retained_affected"],
        superseded_editions=counts["superseded_editions"],
        removed_job_records=sorted(
            f.split("/")[1][:-5] for f in preview["files"] if f.startswith("jobs/")
        ),
        backup=saved,
        verification=verify_purged(store, provider, identifiers, before),
    )


FROZEN_WARNING = (
    "A finalised (frozen) edition includes this data. It is never altered or deleted "
    'automatically: removal is blocked unless you choose "Purge and mark edition '
    'superseded", which keeps the edition record, marks it superseded and requires the '
    "pre-purge backup."
)


def frozen_runs(store: Store, runs) -> list[str]:
    return [
        r
        for (r,) in store.db.execute(
            "SELECT run_id FROM finalized_assessments WHERE run_id IN (SELECT unnest(?)) "
            "ORDER BY run_id",
            [sorted(runs)],
        ).fetchall()
    ]


def frozen_override(
    store: Store,
    preview: dict,
    requested: bool,
    typed: str,
    identifiers: list[str],
    reason: str,
    backup: bool,
) -> dict | None:
    """Validate the explicit supersede override before anything is written."""
    from offline_analyzer.ingestion.json_input import SECRET_VALUE

    if not preview["frozen_decision_required"]:
        return None
    if requested is not True:
        raise InputError("FROZEN_EDITION_DECISION_REQUIRED")
    if typed not in identifiers:
        raise InputError("SUPERSEDE_CONFIRMATION_REQUIRED")
    reason = reason.strip()
    if not 10 <= len(reason) <= 2000 or any(ord(c) < 32 and c not in "\n\t" for c in reason):
        raise InputError("SUPERSEDE_REASON_REQUIRED")
    if SECRET_VALUE.search(reason):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    if backup is not True:
        raise InputError("SUPERSEDE_REQUIRES_BACKUP")
    return dict(runs=frozen_runs(store, preview["affected_runs"]), reason=reason)


def attach_override(
    store: Store, preview: dict, override: dict | None, saved: dict | None, digest: str, action
) -> str:
    """Confirm the backup holds every edition, then hand the override to the purge."""
    if override is None:
        return action
    import duckdb

    from offline_analyzer.storage.backup import MANIFEST
    from offline_analyzer.storage.backup import digest as file_digest
    from offline_analyzer.storage.store import CONNECTION_CONFIG

    root = Path(saved["path"])
    copy = root / "assessment.duckdb"
    listed = {
        e["path"]: e["sha256"]
        for e in json.loads((root / MANIFEST).read_text(encoding="utf-8"))["files"]
    }
    if not copy.is_file() or listed.get("assessment.duckdb") != file_digest(copy):
        raise InputError("SUPERSEDE_BACKUP_UNVERIFIED")
    current = dict(
        store.db.execute(
            "SELECT run_id,data FROM finalized_assessments WHERE run_id IN (SELECT unnest(?))",
            [override["runs"]],
        ).fetchall()
    )
    db = duckdb.connect(str(copy), read_only=True, config=CONNECTION_CONFIG)
    try:
        held = dict(
            db.execute(
                "SELECT run_id,data FROM finalized_assessments WHERE run_id IN (SELECT unnest(?))",
                [override["runs"]],
            ).fetchall()
        )
    finally:
        db.close()
    if not override["runs"] or held != current or set(held) != set(override["runs"]):
        raise InputError("SUPERSEDE_BACKUP_UNVERIFIED")
    preview["supersede"] = dict(override, scope_digest=digest, action=action, backup=saved["path"])
    return action + "_SUPERSEDE"


def supersede_frozen(shadow: Store, preview: dict, event: str) -> None:
    """Editions are kept; with the verified override each is marked superseded."""
    runs = frozen_runs(shadow, preview["affected_runs"])
    override = preview.get("supersede")
    if not runs:
        return
    if not override or set(runs) != set(override["runs"]):
        raise InputError("FROZEN_EDITION_DECISION_REQUIRED")
    now = datetime.now(UTC).isoformat()
    for run in runs:
        shadow.db.execute(
            "INSERT INTO finalized_supersessions VALUES (?,?,?,?)",
            [
                run,
                event,
                now,
                json.dumps(
                    {
                        "status": "SUPERSEDED",
                        "superseded_at": now,
                        "reason": override["reason"],
                        "action": override["action"],
                        "scope_digest": override["scope_digest"],
                        "backup": override["backup"],
                    }
                ),
            ],
        )


def pre_purge_backup(store: Store) -> dict:
    """Restorable copy beside (never inside) the workspace, taken before anything changes."""
    from offline_analyzer.storage.backup import backup_open

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = store.workspace.parent / (store.workspace.name + "-backups") / f"pre-purge-{stamp}"
    summary = backup_open(store, target)
    return dict(path=str(target), files=summary["files"], bytes=summary["bytes"])


def staged_delete(
    store: Store, preview: dict, apply, action: str, provider: str, scope: str, counts: dict
) -> dict:
    """Purge a private DB copy, audit, compact and publish with the recoverable journal."""
    event = secrets.token_hex(16)
    directory = checked_file(store.workspace, ".scope-staging/" + event)
    checkpoint("SCOPE_STAGING")
    shadow = clone_store(store, directory / "working")
    try:
        checkpoint("SCOPE_PURGE")
        run, origins = apply(shadow, preview, event)
        shadow.db.execute(
            "INSERT INTO scope_audit VALUES (?,?,?,?,?,?)",
            [event, provider, scope, action, datetime.now(UTC).isoformat(), json.dumps(counts)],
        )
        checkpoint("SCOPE_COMPACT")
        compact(shadow, directory / "compact")
    finally:
        shadow.db.close()
    committing("SCOPE_PUBLISH")
    publish(store, directory, event, preview["files"], origins)
    return dict(
        run_id=run,
        event_id=event,
        action=action,
        removed=counts,
        external_backups_and_exports="NOT_ERASED",
        forensic_media_erasure="NOT_CLAIMED",
    )


def files(store: Store, provider: str, scope: str) -> list[dict]:
    """Imported evidence files of one exact scope, by content digest."""
    identity(provider, scope)
    digests = dict(store.rows("SELECT run_id || '/' || artifact_id,sha256 FROM artifacts"))
    found: dict[str, dict] = {}
    for run, raw in store.rows("SELECT run_id,data FROM sources"):
        source = json.loads(raw)
        sha = digests.get(f"{run}/{source.get('artifact_id')}")
        if source_scope(source) != (provider, scope) or not sha:
            continue
        row = found.setdefault(
            sha,
            dict(sha256=sha, paths=set(), operations=set(), regions=set(), snapshots=set()),
        )
        row["paths"].add(source.get("path") or "unrecorded")
        row["operations"].add(source["operation"])
        row["regions"].add(source.get("region") or "global")
        row["snapshots"].add(run)
    if len(found) > 5000:
        raise InputError("SCOPE_FILE_PLAN_LIMIT")
    for row in found.values():
        for field in ("paths", "operations", "regions"):
            row[field] = sorted(row[field])
        row["snapshots"] = len(row["snapshots"])
    return sorted(found.values(), key=lambda r: (r["paths"], r["sha256"]))


def file_refs(store: Store, sha: str) -> set[tuple[str, str]]:
    if not re.fullmatch("[0-9a-f]{64}", sha):
        raise InputError("INVALID_FILE_DIGEST")
    return {
        (run, artifact)
        for run, artifact in store.rows(
            "SELECT run_id,artifact_id FROM artifacts WHERE sha256=?", [sha]
        )
    }


def citing_findings(store: Store, refs: set[tuple[str, str]]) -> set[str]:
    runs = sorted({run for run, _ in refs})
    return {
        fid
        for run, fid, raw in store.rows(
            "SELECT run_id,finding_id,data FROM findings WHERE run_id IN (SELECT unnest(?))",
            [runs],
        )
        if any((run, ref.get("artifact_id")) in refs for ref in json.loads(raw).get("evidence", []))
    }


FILE_OBSERVATIONS = (
    "SELECT DISTINCT o.run_id,o.observation_id,o.resource_id FROM observations o "
    "JOIN evidence_refs e USING(run_id,observation_id) JOIN artifacts a "
    "ON a.run_id=e.run_id AND a.artifact_id=e.artifact_id WHERE a.sha256=?"
)


def file_plan(store: Store, sha: str) -> dict:
    """Preview removing one imported file (every copy of its exact bytes) and its data."""
    refs = file_refs(store, sha)
    if not refs:
        raise InputError("FILE_NOT_FOUND")
    affected = {run for run, _ in refs}
    owned = store.db.execute(FILE_OBSERVATIONS, [sha]).fetchall()
    scope_keys = set()
    paths = set()
    for run, raw in store.rows("SELECT run_id,data FROM sources"):
        source = json.loads(raw)
        if (run, source.get("artifact_id")) in refs:
            scope_keys.add(source_scope(source))
            paths.add(source.get("path") or "unrecorded")
    for run, members in list(store.rows("SELECT run_id,members FROM enterprise_snapshots")):
        if set(json.loads(members)) & affected:
            affected.add(run)
    cited = citing_findings(store, refs)
    files = {"raw/" + sha + ".json"}
    uploads = store.workspace / "uploads"
    if uploads.is_dir():
        from offline_analyzer.ingestion.safety import sha256_file

        for folder in uploads.iterdir():
            if not folder.is_dir() or not re.fullmatch("[0-9a-f]{32}", folder.name):
                continue
            checked_file(store.workspace, "uploads/" + folder.name)
            package = load_package(folder)
            for source in package.sources:
                if source.sha256 != sha or not source.path:
                    continue
                path = checked_file(store.workspace, f"uploads/{folder.name}/{source.path}")
                if path.is_file() and sha256_file(path) == sha:
                    files.add(path.relative_to(store.workspace).as_posix())
                    # The transport ZIP holds the same bytes; it cannot be partially kept.
                    if (uploads / (folder.name + ".zip")).is_file():
                        files.add("uploads/" + folder.name + ".zip")
    reports = 0
    for directory in ("reports", "collections"):
        folder = store.workspace / directory
        if not folder.is_dir():
            continue
        for path in folder.iterdir():
            if not path.is_file():
                continue
            if directory == "collections" and path.stem in affected:
                files.add(path.relative_to(store.workspace).as_posix())
            elif directory == "reports" and path.suffix == ".meta":
                if json.loads(path.read_text()).get("run_id") in affected:
                    reports += 1
                    for reportfile in folder.glob(path.stem + ".*"):
                        if reportfile.is_file():
                            files.add(reportfile.relative_to(store.workspace).as_posix())
    revisions = 0
    for _, _, _, run, _, raw in store.rows("SELECT * FROM report_revisions"):
        snaps = json.loads(raw)["snapshots"]
        if run in affected or any(s["finding_id"] in cited for s in snaps):
            revisions += 1
    reviewed = {
        fid
        for (fid,) in store.rows(
            "SELECT finding_id FROM decisions UNION SELECT finding_id FROM sre_validations"
        )
        if fid in cited
    }
    result = dict(
        sha256=sha,
        paths=sorted(paths),
        scopes=[dict(provider=p, scope_id=s) for p, s in sorted(scope_keys, key=str)],
        workspace=str(store.workspace),
        snapshots=len(affected),
        observations=len(owned),
        resources=len({rid for _, _, rid in owned if rid}),
        findings=len(cited),
        analyst_reviews=len(reviewed),
        report_revisions=revisions,
        frozen_editions=store.db.execute(
            "SELECT count(*) FROM finalized_assessments WHERE run_id IN (SELECT unnest(?))",
            [sorted(affected)],
        ).fetchone()[0],
        path_reviews=store.db.execute(
            "SELECT count(*) FROM path_reviews WHERE run_id IN (SELECT unnest(?))",
            [sorted(affected)],
        ).fetchone()[0],
        managed_exports=reports,
        files=sorted(files),
        affected_runs=sorted(affected),
    )
    result["frozen_decision_required"] = result["frozen_editions"] > 0
    result["preview_token"] = stable_id(
        "file-preview",
        [
            result,
            store.db.execute("SELECT count(*) FROM decisions").fetchone()[0],
            store.db.execute("SELECT count(*) FROM sre_validations").fetchone()[0],
            store.db.execute("SELECT count(*) FROM report_revisions").fetchone()[0],
        ],
    )
    if len(result["files"]) > 5000:
        raise InputError("SCOPE_FILE_PLAN_LIMIT")
    result["limitations"] = [
        "Every imported copy of these exact bytes is removed, in all snapshots and scopes.",
        "Affected snapshots are fully reassessed; conclusions may change or disappear.",
        "A retained transport ZIP containing the file is removed in full.",
        "Downloaded reports, external original evidence and backups cannot be recalled.",
        "This removes managed logical data, not forensic media remnants.",
    ]
    if result["frozen_decision_required"]:
        result["limitations"].insert(0, FROZEN_WARNING)
    return result


def purge_file(shadow: Store, preview: dict, event: str) -> tuple[str | None, dict]:
    sha = preview["sha256"]
    refs = file_refs(shadow, sha)
    affected = set(preview["affected_runs"])
    cited = citing_findings(shadow, refs)
    supersede_frozen(shadow, preview, event)
    for run in affected:
        shadow.db.execute("DELETE FROM path_reviews WHERE run_id=?", [run])
    for run, sid, raw in list(shadow.rows("SELECT run_id,source_id,data FROM sources")):
        if (run, json.loads(raw).get("artifact_id")) in refs:
            shadow.db.execute("DELETE FROM sources WHERE run_id=? AND source_id=?", [run, sid])
    for rid, rev, _, run, _, raw in list(shadow.rows("SELECT * FROM report_revisions")):
        snaps = json.loads(raw)["snapshots"]
        if any(
            s["finding_id"] in cited or any((run, r["artifact_id"]) in refs for r in s["evidence"])
            for s in snaps
        ):
            shadow.db.execute(
                "DELETE FROM report_revisions WHERE report_id=? AND revision=?", [rid, rev]
            )
        elif run in affected:
            shadow.db.execute(
                "INSERT INTO scope_invalidated_reports VALUES (?,?) ON CONFLICT DO NOTHING",
                [rid, rev],
            )
    shadow.db.execute(
        "DELETE FROM scope_invalidated_reports WHERE (report_id,revision) NOT IN "
        "(SELECT report_id,revision FROM report_revisions)"
    )
    owned = shadow.db.execute(FILE_OBSERVATIONS, [sha]).fetchall()
    if owned:
        keys = [[run for run, _, _ in owned], [observation for _, observation, _ in owned]]
        for table in ("evidence_refs", "observations"):
            shadow.db.execute(
                f"DELETE FROM {table} WHERE (run_id,observation_id) IN "
                "(SELECT unnest(?), unnest(?))",
                keys,
            )
    for run, artifact in refs:
        shadow.db.execute(
            "DELETE FROM evidence_refs WHERE run_id=? AND artifact_id=?", [run, artifact]
        )
        shadow.db.execute("DELETE FROM artifacts WHERE run_id=? AND artifact_id=?", [run, artifact])
    renamed, emptied = rebuild_runs(
        shadow,
        affected,
        event,
        keep_source=lambda run, s: (run, s.get("artifact_id")) not in refs,
        keep_target=lambda _t: True,
    )
    for run in emptied:
        shadow.db.execute("DELETE FROM scope_state WHERE active_run=?", [run])
    result = reassess_runs(shadow, renamed, emptied, None)
    # Reviews of conclusions that no longer exist anywhere must not outlive their evidence;
    # surviving findings keep reviews, which go stale through their evidence fingerprint.
    remaining = {fid for (fid,) in shadow.rows("SELECT DISTINCT finding_id FROM findings")}
    for fid in cited - remaining:
        shadow.db.execute("DELETE FROM decisions WHERE finding_id=?", [fid])
        shadow.db.execute("DELETE FROM sre_validations WHERE finding_id=?", [fid])
    return result


def delete_file(
    store: Store,
    sha: str,
    token: str,
    confirmation: str,
    confirmed: bool,
    supersede: bool = False,
    supersede_confirmation: str = "",
    supersede_reason: str = "",
) -> dict:
    """Remove one imported file; finalised editions follow the same block/override rule."""
    file_refs(store, sha)
    if confirmation != sha[:12] or confirmed is not True:
        raise InputError("FILE_CONFIRMATION_REQUIRED")
    with guard(store.workspace):
        discard_orphans(store.workspace)
        preview = file_plan(store, sha)
        if token != preview["preview_token"]:
            raise InputError("FILE_PREVIEW_STALE")
        scope_ids = [s["scope_id"] for s in preview["scopes"] if s["scope_id"]]
        override = frozen_override(
            store, preview, supersede, supersede_confirmation, scope_ids, supersede_reason, True
        )
        keys = ("snapshots", "observations", "findings", "analyst_reviews", "report_revisions")
        counts = {k: preview[k] for k in keys}
        first = preview["scopes"][0] if preview["scopes"] else dict(provider="", scope_id="")
        digest = audit_scope(first["provider"], first["scope_id"]) if first["scope_id"] else ""
        saved = pre_purge_backup(store) if override else None
        action = attach_override(store, preview, override, saved, digest, "DELETE_FILE")
        counts["superseded_editions"] = len(override["runs"]) if override else 0
        result = staged_delete(
            store, preview, purge_file, action, first["provider"], digest, counts
        )
        return dict(result, backup=saved, superseded_editions=counts["superseded_editions"])


def projected_member(store: Store, run: str, provider: str, scope: str) -> str | None:
    sources = list(store.source_data(run))
    kept = [s for s in sources if source_scope(s) != (provider, scope)]
    if len(kept) == len(sources):
        return run
    if not kept:
        return None
    new = stable_id("run", ["scope-projection-1", run, provider, scope])
    if store.db.execute("SELECT 1 FROM runs WHERE run_id=?", [new]).fetchone():
        return new
    package = json.loads(
        store.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()[0]
    )
    package["sources"] = [s for s in package["sources"] if source_scope(s) != (provider, scope)]
    package["targets"] = [
        t
        for t in package.get("targets", [])
        if not (provider == "AWS" and t["account_id"] == scope)
    ]
    with store.transaction():
        store.db.execute(
            "INSERT INTO runs VALUES (?,?,?)",
            [new, datetime.now(UTC).isoformat(), json.dumps(package)],
        )
        for sid, raw in store.rows("SELECT source_id,data FROM sources WHERE run_id=?", [run]):
            if source_scope(json.loads(raw)) != (provider, scope):
                store.db.execute("INSERT INTO sources VALUES (?,?,?)", [new, sid, raw])
        retained_artifacts = {s.get("artifact_id") for s in kept}
        for aid, sha, size in store.rows(
            "SELECT artifact_id,sha256,size_bytes FROM artifacts WHERE run_id=?", [run]
        ):
            if aid in retained_artifacts:
                store.db.execute("INSERT INTO artifacts VALUES (?,?,?,?)", [new, aid, sha, size])
        pred = observation_predicate(provider)
        store.db.execute(
            "INSERT INTO observations SELECT ?,observation_id,resource_id,account_id,"
            "region,tool,check_id,kind,data FROM observations WHERE run_id=? "
            f"AND NOT coalesce(({pred}),false) "
            "AND json_extract_string(data,'$.evidence.artifact_id') "
            "IN (SELECT artifact_id FROM artifacts WHERE run_id=?)",
            [new, run, scope, new],
        )
        store.db.execute(
            (
                "INSERT INTO evidence_refs SELECT "
                "?,observation_id,artifact_id,locator FROM evidence_refs WHERE "
                "run_id=? AND observation_id IN (SELECT observation_id FROM "
                "observations WHERE run_id=?) AND artifact_id IN (SELECT "
                "artifact_id FROM artifacts WHERE run_id=?)"
            ),
            [new, run, new, new],
        )
    return new


def replace_scope(
    store: Store,
    provider: str,
    scope: str,
    directory: Path,
    origin: str,
    *,
    upload_id: str | None = None,
) -> dict:
    identity(provider, scope)
    if upload_id is not None and not re.fullmatch("[0-9a-f]{32}", upload_id):
        raise InputError("UPLOAD_NOT_FOUND")
    check_origin(store.workspace, origin)
    package = load_package(directory)
    if {source_scope(s.model_dump()) for s in package.sources} != {(provider, scope)}:
        raise InputError("REPLACEMENT_SCOPE_MISMATCH")
    known = next(
        (
            s["project_number"]
            for s in scopes(store)
            if s["provider"] == provider and s["scope_id"] == scope
        ),
        None,
    )
    incoming_numbers = {s.project_number for s in package.sources if s.project_number}
    if provider == "GCP" and known and incoming_numbers and incoming_numbers != {known}:
        raise InputError("REPLACEMENT_PROJECT_NUMBER_MISMATCH")
    event = secrets.token_hex(16)
    staging = checked_file(store.workspace, ".scope-staging/" + event)
    with guard(store.workspace):
        discard_orphans(store.workspace)
        shadow = clone_store(store, staging / "working")
        try:
            # Record newly publishable bytes before import, so a failed or interrupted
            # replacement can discard them without touching existing raw snapshots.
            from offline_analyzer.ingestion.safety import sha256_file

            rollback_raw = sorted(
                {
                    sha256_file(path)
                    for path in directory.rglob("*.json")
                    if path.is_file() and not path.is_symlink()
                }
            )
            rollback_raw = [
                sha
                for sha in rollback_raw
                if not (store.workspace / "raw" / (sha + ".json")).exists()
            ]
            marker = staging / "marker.json"
            marker.write_text(
                json.dumps(
                    {
                        "scope_stage_version": 1,
                        "event_id": event,
                        "rollback_raw": rollback_raw,
                    }
                )
            )
            origins = run_origins(store.workspace)
            incoming = import_package(shadow, directory)
            if upload_id:
                shadow.db.execute(
                    "INSERT INTO scope_uploads VALUES (?,?) ON CONFLICT DO NOTHING",
                    [incoming, upload_id],
                )
            if origins.get(incoming, origin) != origin:
                raise InputError("RUN_ORIGIN_CONFLICT")
            origins[incoming] = origin
            assess(shadow, incoming)
            selected = []
            original = [
                r
                for (r,) in shadow.rows(
                    "SELECT run_id FROM runs WHERE run_id NOT IN (SELECT run_id FROM "
                    "enterprise_snapshots) AND run_id NOT IN (SELECT run_id FROM "
                    "scope_retired_runs)"
                )
            ]
            current = shadow.db.execute(
                "SELECT active_run FROM scope_state WHERE provider=? AND scope_id=?",
                [provider, scope],
            ).fetchone()
            baseline = (
                shadow.db.execute(
                    "SELECT members FROM enterprise_snapshots WHERE run_id=?", [current[0]]
                ).fetchone()
                if current
                else None
            )
            if baseline:
                original = json.loads(baseline[0])
            for old in original:
                if old == incoming:
                    continue
                projected = projected_member(shadow, old, provider, scope)
                if projected:
                    selected.append(projected)
                    origins[projected] = origins.get(old, "unrecorded")
                if projected != old:
                    shadow.db.execute(
                        "INSERT INTO scope_retired_runs VALUES (?) ON CONFLICT DO NOTHING", [old]
                    )
            run = assess_enterprise(shadow, [*selected, incoming])
            from offline_analyzer.inventory.environment import workspace_environment

            if workspace_environment(store.workspace) and any(
                origins.get(member) != origin for member in selected
            ):
                raise InputError("REPLACEMENT_ORIGIN_CONFLICT")
            origins[run] = origin
            for current in scopes(shadow):
                shadow.db.execute(
                    (
                        "INSERT INTO scope_state VALUES (?,?,?) ON "
                        "CONFLICT(provider,scope_id) DO UPDATE SET "
                        "active_run=excluded.active_run"
                    ),
                    [current["provider"], current["scope_id"], run],
                )
            shadow.db.execute(
                "INSERT INTO scope_audit VALUES (?,?,?,?,?,?)",
                [
                    event,
                    provider,
                    scope,
                    "REPLACE",
                    datetime.now(UTC).isoformat(),
                    json.dumps({"members": len(selected) + 1}),
                ],
            )
            compact(shadow, staging / "compact")
        finally:
            shadow.db.close()
        publish(store, staging, event, [], origins)
        # The journal atomically published the desired origin map and upload linkage.
        return dict(
            run_id=run,
            import_run=incoming,
            event_id=event,
            action="REPLACE",
            old_evidence_retained=True,
            mode="SAFE_FULL_REASSESSMENT",
        )
