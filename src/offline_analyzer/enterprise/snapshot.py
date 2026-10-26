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
# Snapshot caps (fail closed). enterprise/shards.py plans business-group snapshots below them.
MAX_MEMBERS = 2048
MAX_OBSERVATIONS = 250000


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
    """run -> {"scopes": provider-neutral scope keys, "collected": newest collection time,
    "times": newest collection time per scope}. AWS scopes (partition, account, Region or
    global) are dated by their own sources, so a multi-account import is compared per account;
    GCP scopes keep the import's newest time (unchanged)."""
    from offline_analyzer.enterprise.refresh import import_scope_key as scope_key

    found: dict[str, dict] = {}
    for run in active_imports(store):
        scopes, times, per_scope = set(), [], {}
        for source in store.source_data(run):
            key = scope_key(source)
            if key:
                scopes.add(key)
            if source.get("collected_at"):
                times.append(str(source["collected_at"]))
                if key and key.startswith("AWS:"):
                    per_scope[key] = max(per_scope.get(key, ""), str(source["collected_at"]))
        created = store.db.execute("SELECT created_at FROM runs WHERE run_id=?", [run]).fetchone()
        collected = max(times) if times else str(created[0])
        found[run] = {
            "scopes": scopes,
            "collected": collected,
            "times": {s: per_scope.get(s, collected) for s in scopes},
        }
    return found


def newest_by_scope(runs: dict[str, dict]) -> dict[str, str]:
    """scope -> newest run (latest collection time for that scope; ties by run ID)."""
    newest: dict[str, tuple[str, str]] = {}
    for run, info in runs.items():
        for scope in info["scopes"]:
            candidate = (info["times"][scope], run)
            if scope not in newest or candidate > newest[scope]:
                newest[scope] = candidate
    return {scope: run for scope, (_, run) in newest.items()}


def superseded_imports(store) -> dict[str, list[str]]:
    """Active imports that are not the newest for any of their scopes -> the newer imports.

    Newest = latest collection time per scope (GCP project, AWS partition/account/Region);
    ties by run ID. Superseded imports are not snapshot members by default but can be
    selected explicitly.
    """
    runs = import_scopes(store)
    newest = newest_by_scope(runs)
    return {
        run: sorted({newest[scope] for scope in info["scopes"]})
        for run, info in runs.items()
        if info["scopes"] and not any(newest[scope] == run for scope in info["scopes"])
    }


def partially_superseded(store) -> dict[str, dict[str, str]]:
    """Default members some of whose AWS datasets a newer default member also collected:
    run -> {"<account> <Region> <operation>": newer run}. The snapshot leaves those datasets
    out (scope_plan); the import's other datasets are included."""
    selected = members(store)
    keyed, newest, plan = _dataset_plan(store, selected)
    found = {}
    for member, lost in plan.items():
        dropped = set(lost)
        labels = {}
        for sid, key, _ in keyed[member]:
            if sid in dropped:
                scope, operation, _params = key.split("|", 2)
                label = " ".join(scope.split(":")[2:]).strip() + " " + operation
                labels[label] = newest[key][1]
        found[member] = dict(sorted(labels.items()))
    return found


def members(store) -> list[str]:
    """Default snapshot membership: the latest active import per scope (owner brief 1c)."""
    superseded = superseded_imports(store)
    return [run for run in active_imports(store) if run not in superseded]


def dataset_key(source: dict) -> str | None:
    """AWS dataset identity for the snapshot plan: partition, account, Region, operation and
    request parameters (per-resource calls keep their subject). None for GCP sources."""
    from offline_analyzer.enterprise.refresh import import_scope_key as scope_key

    scope = scope_key(source)
    if not scope or not scope.startswith("AWS:"):
        return None
    parameters = json.dumps(source.get("request_parameters") or {}, sort_keys=True)
    return f"{scope}|{source.get('operation')}|{parameters}"


def scope_plan(store, selected: list[str]) -> dict[str, list[str]]:
    """member -> source IDs left out of the union because a newer selected member collected
    the same AWS dataset (partition, account, Region, operation, request parameters) with a
    strictly later collection time.

    The newer collection replaces the older one, so a stale snapshot of one account in a
    multi-account import never conflicts with (or downgrades) the newer import, while
    complementary per-Region or per-service imports merge. A member that would lose every
    one of its sources was selected explicitly as history (the default membership excludes
    it); it is kept whole and conflicting facts surface as UNKNOWN, as before. GCP sources are
    never filtered. Deterministic from the members' sources: the builder and
    validate_snapshot compute the same plan."""
    return _dataset_plan(store, selected)[2]


def _dataset_plan(store, selected: list[str]):
    """(member -> [(source ID, dataset key, collected)], dataset key -> (time, newest member),
    plan) for scope_plan and partially_superseded."""
    keyed: dict[str, list[tuple[str, str, str]]] = {}
    for member in selected:
        # Writer connection: also used before the snapshot commit.
        for source_id, raw in store.db.execute(
            "SELECT source_id, data FROM sources WHERE run_id=?", [member]
        ).fetchall():
            source = json.loads(raw)
            key = dataset_key(source)
            keyed.setdefault(member, [])
            if key:
                when = str(source.get("collected_at") or "")
                keyed[member].append((source_id, key, when))
    newest: dict[str, tuple[str, str]] = {}
    for member, items in keyed.items():
        for _, key, when in items:
            if key not in newest or (when, member) > newest[key]:
                newest[key] = (when, member)
    totals = {
        m: store.db.execute("SELECT count(*) FROM sources WHERE run_id=?", [m]).fetchone()[0]
        for m in keyed
    }
    plan = {}
    for member, items in sorted(keyed.items()):
        # Only a strictly newer collection replaces a dataset: equal collection times are not
        # ordered, so both are kept (conflicts surface as UNKNOWN, as before).
        lost = sorted(sid for sid, key, when in items if when < newest[key][0])
        if lost and len(lost) < totals[member]:
            plan[member] = lost
    return keyed, newest, plan


def _plan_tables(store, plan: dict[str, list[str]]) -> None:
    """Temporary tables of the (member, source) pairs and (member, artifact) pairs to leave
    out. An artifact is left out only when no kept source of the same member uses it."""
    store.db.execute(
        "CREATE OR REPLACE TEMP TABLE snapshot_drop_sources(run_id VARCHAR, id VARCHAR)"
    )
    store.db.execute(
        "CREATE OR REPLACE TEMP TABLE snapshot_drop_artifacts(run_id VARCHAR, id VARCHAR)"
    )
    for member, ids in plan.items():
        store.db.executemany(
            "INSERT INTO snapshot_drop_sources VALUES (?,?)", [[member, i] for i in ids]
        )
    store.db.execute(
        "INSERT INTO snapshot_drop_artifacts SELECT DISTINCT s.run_id, "
        "json_extract_string(s.data,'$.artifact_id') FROM sources s JOIN snapshot_drop_sources d "
        "ON s.run_id=d.run_id AND s.source_id=d.id "
        "WHERE json_extract_string(s.data,'$.artifact_id') IS NOT NULL AND NOT EXISTS ("
        "SELECT 1 FROM sources k WHERE k.run_id=s.run_id "
        "AND json_extract_string(k.data,'$.artifact_id')="
        "json_extract_string(s.data,'$.artifact_id') "
        "AND NOT EXISTS (SELECT 1 FROM snapshot_drop_sources x "
        "WHERE x.run_id=k.run_id AND x.id=k.source_id))"
    )


def drop_plan_tables(store) -> None:
    """Temporary plan tables never outlive their statement (compaction copies every table)."""
    store.db.execute("DROP TABLE IF EXISTS snapshot_drop_sources")
    store.db.execute("DROP TABLE IF EXISTS snapshot_drop_artifacts")


# Per-table predicate (alias t) leaving out the planned rows; empty plan = exact union.
PLAN_FILTERS = {
    "sources": "NOT EXISTS (SELECT 1 FROM snapshot_drop_sources d "
    "WHERE d.run_id=t.run_id AND d.id=t.source_id)",
    "artifacts": "NOT EXISTS (SELECT 1 FROM snapshot_drop_artifacts d "
    "WHERE d.run_id=t.run_id AND d.id=t.artifact_id)",
    "evidence_refs": "NOT EXISTS (SELECT 1 FROM snapshot_drop_artifacts d "
    "WHERE d.run_id=t.run_id AND d.id=t.artifact_id)",
    # An observation is left out only when every reference of it in that member points to
    # left-out evidence (it then has no kept provenance in that member).
    "observations": "NOT (EXISTS (SELECT 1 FROM evidence_refs e WHERE e.run_id=t.run_id "
    "AND e.observation_id=t.observation_id) AND NOT EXISTS (SELECT 1 FROM evidence_refs e "
    "WHERE e.run_id=t.run_id AND e.observation_id=t.observation_id AND NOT EXISTS ("
    "SELECT 1 FROM snapshot_drop_artifacts d WHERE d.run_id=e.run_id "
    "AND d.id=e.artifact_id)))",
}


def build_snapshot(store, selected: list[str] | None = None) -> str:
    selected = sorted(set(selected if selected is not None else members(store)))
    if not selected or len(selected) > MAX_MEMBERS:
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
    if count > MAX_OBSERVATIONS:
        raise InputError("ENTERPRISE_OBSERVATION_LIMIT")
    registry = workspace_registry(store.workspace)
    context = {"registry": registry.fingerprint() if registry else None, "engine": ENGINE_VERSION}
    plan = scope_plan(store, selected)
    # The plan joins the identity only when it filters something: unfiltered snapshots keep
    # their historical run IDs.
    run = stable_id("run", [VERSION, selected, context] + ([{"superseded": plan}] if plan else []))
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
        _plan_tables(store, plan)
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
                f"INSERT INTO {table} SELECT ?,{columns} FROM {table} t "
                f"WHERE run_id IN ({marks}) AND {PLAN_FILTERS[table]} QUALIFY row_number() OVER "
                f"(PARTITION BY {key} ORDER BY run_id)=1",
                [run, *selected],
            )
        store.db.execute(
            "INSERT INTO enterprise_snapshots VALUES (?,?,?)", [run, json.dumps(selected), VERSION]
        )
        from offline_analyzer.enterprise.validation import validate_snapshot

        if validate_snapshot(store, run)["status"] == "ERROR":
            raise InputError("ENTERPRISE_RECONCILIATION_FAILED")
        drop_plan_tables(store)
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
