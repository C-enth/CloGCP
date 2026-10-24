"""Immutable union of explicitly selected imports, preserving original evidence and history."""

import json
from datetime import UTC, datetime

from offline_analyzer.contracts.enterprise import EnterpriseSnapshot
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.accounts import workspace_registry
from offline_analyzer.provenance.execution import checkpoint, committing
from offline_analyzer.rules.engine import ENGINE_VERSION, assess, verify_raw

VERSION = "enterprise-1"


def active_imports(store) -> list[str]:
    """Every original import that is not a snapshot and not retired."""
    return [
        r
        for (r,) in store.rows(
            "SELECT run_id FROM runs WHERE run_id NOT IN "
            "(SELECT run_id FROM enterprise_snapshots) "
            "AND run_id NOT IN (SELECT run_id FROM scope_retired_runs) ORDER BY run_id"
        )
    ]


def import_scopes(store) -> dict[str, dict]:
    """run -> {"scopes": provider-neutral scope keys, "collected": newest collection time}."""
    from offline_analyzer.enterprise.refresh import import_scope_key as scope_key

    found: dict[str, dict] = {}
    for run in active_imports(store):
        scopes, times = set(), []
        for source in store.source_data(run):
            key = scope_key(source)
            if key:
                scopes.add(key)
            if source.get("collected_at"):
                times.append(str(source["collected_at"]))
        created = store.db.execute("SELECT created_at FROM runs WHERE run_id=?", [run]).fetchone()
        found[run] = {"scopes": scopes, "collected": max(times) if times else str(created[0])}
    return found


def superseded_imports(store) -> dict[str, list[str]]:
    """Active imports that are not the newest for any of their scopes -> the newer imports.

    Newest = latest collection time per scope (GCP project, AWS account); ties by run ID.
    Superseded imports are not snapshot members by default but can be selected explicitly.
    """
    runs = import_scopes(store)
    newest: dict[str, str] = {}
    for run, info in sorted(runs.items(), key=lambda item: (item[1]["collected"], item[0])):
        for scope in info["scopes"]:
            newest[scope] = run
    return {
        run: sorted({newest[scope] for scope in info["scopes"]})
        for run, info in runs.items()
        if info["scopes"] and not any(newest[scope] == run for scope in info["scopes"])
    }


def members(store) -> list[str]:
    """Default snapshot membership: the latest active import per scope (owner brief 1c)."""
    superseded = superseded_imports(store)
    return [run for run in active_imports(store) if run not in superseded]


def build_snapshot(store, selected: list[str] | None = None) -> str:
    selected = sorted(set(selected if selected is not None else members(store)))
    if not selected or len(selected) > 2048:
        raise InputError("INVALID_ENTERPRISE_MEMBERS")
    for member in selected:
        checkpoint("SOURCE_INTEGRITY")
        store.require_run(member)
        if store.db.execute("SELECT 1 FROM scope_retired_runs WHERE run_id=?", [member]).fetchone():
            raise InputError("RETIRED_ENTERPRISE_MEMBER")
        if store.db.execute(
            "SELECT 1 FROM enterprise_snapshots WHERE run_id=?", [member]
        ).fetchone():
            raise InputError("NESTED_ENTERPRISE_SNAPSHOT")
        verify_raw(store, member)
    marks = ",".join("?" for _ in selected)
    versions = store.db.execute(
        f"SELECT DISTINCT json_extract_string(data,'$.normalization_version') FROM observations "
        f"WHERE run_id IN ({marks})",
        selected,
    ).fetchall()
    if len(versions) > 1:
        raise InputError("ENTERPRISE_NORMALIZER_VERSION_CONFLICT")
    gcp_versions = store.db.execute(
        f"SELECT DISTINCT coalesce(json_extract_string(data,'$.source_details.parser_profile'),"
        f"'UNRECORDED') FROM observations WHERE run_id IN ({marks}) AND tool='gcp'",
        selected,
    ).fetchall()
    if len(gcp_versions) > 1:
        raise InputError("ENTERPRISE_GCP_PARSER_VERSION_CONFLICT")
    for identity, other in (("project_id", "project_number"), ("project_number", "project_id")):
        conflicts = store.db.execute(
            f"SELECT 1 FROM sources WHERE run_id IN ({marks}) AND "
            f"json_extract_string(data,'$.format')='gcp-json-v1' AND "
            f"json_extract_string(data,'$.{identity}') IS NOT NULL "
            f"GROUP BY json_extract_string(data,'$.{identity}') HAVING "
            f"count(DISTINCT json_extract_string(data,'$.{other}'))>1 LIMIT 1",
            selected,
        ).fetchone()
        if conflicts:
            raise InputError("ENTERPRISE_GCP_PROJECT_IDENTITY_CONFLICT")
    count = store.db.execute(
        f"SELECT count(*) FROM observations WHERE run_id IN ({marks})", selected
    ).fetchone()[0]
    if count > 250000:
        raise InputError("ENTERPRISE_OBSERVATION_LIMIT")
    registry = workspace_registry(store.workspace)
    context = {"registry": registry.fingerprint() if registry else None, "engine": ENGINE_VERSION}
    run = stable_id("run", [VERSION, selected, context])
    if store.db.execute("SELECT 1 FROM runs WHERE run_id=?", [run]).fetchone():
        verify_raw(store, run)
        from offline_analyzer.enterprise.validation import validate_snapshot

        if validate_snapshot(store, run)["status"] == "ERROR":
            raise InputError("ENTERPRISE_RECONCILIATION_FAILED")
        return run
    targets = set()
    for (data,) in store.rows(f"SELECT package FROM runs WHERE run_id IN ({marks})", selected):
        targets.update((t["account_id"], t["region"]) for t in json.loads(data).get("targets", []))
    package = EnterpriseSnapshot(
        member_runs=tuple(selected),
        context=context,
        targets=tuple({"account_id": a, "region": r} for a, r in sorted(targets)),
    ).model_dump_json()
    with store.transaction():
        store.db.execute(
            "INSERT INTO runs VALUES (?,?,?)", [run, datetime.now(UTC).isoformat(), package]
        )
        for table, key, columns in (
            ("sources", "source_id", "source_id,data"),
            ("artifacts", "artifact_id", "artifact_id,sha256,size_bytes"),
            (
                "observations",
                "observation_id",
                "observation_id,resource_id,account_id,region,tool,check_id,kind,data",
            ),
            ("evidence_refs", "artifact_id,locator", "observation_id,artifact_id,locator"),
        ):
            checkpoint("SNAPSHOT_NORMALIZATION")
            # Same canonical ID selects its original first provenance deterministically; all
            # occurrence refs remain. Conflicting facts have different IDs and both survive.
            store.db.execute(
                f"INSERT INTO {table} SELECT ?,{columns} FROM {table} "
                f"WHERE run_id IN ({marks}) QUALIFY row_number() OVER "
                f"(PARTITION BY {key} ORDER BY run_id)=1",
                [run, *selected],
            )
        store.db.execute(
            "INSERT INTO enterprise_snapshots VALUES (?,?,?)", [run, json.dumps(selected), VERSION]
        )
        from offline_analyzer.enterprise.validation import validate_snapshot

        if validate_snapshot(store, run)["status"] == "ERROR":
            raise InputError("ENTERPRISE_RECONCILIATION_FAILED")
        committing("SNAPSHOT_COMMIT")
    return run


def assess_enterprise(store, selected: list[str] | None = None) -> str:
    from offline_analyzer.enterprise.correlate import correlate

    run = build_snapshot(store, selected)
    if not store.db.execute("SELECT 1 FROM assessments WHERE run_id=?", [run]).fetchone():
        assess(store, run)
    checkpoint("CORRELATION")
    correlate(store, run)
    return run
