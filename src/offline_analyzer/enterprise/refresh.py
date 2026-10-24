"""Explicit account collection replacement with immutable history and full recomputation."""

import json

from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import enterprise_origin, record_run_origin


def scope_key(source: dict) -> str | None:
    """Provider-neutral scope of a source: "GCP:<project>" or "AWS:<account>"."""
    if source.get("format") == "gcp-json-v1" and source.get("project_id"):
        return "GCP:" + source["project_id"]
    if source.get("account_id"):
        return "AWS:" + source["account_id"]
    return None


def import_scope_key(source: dict) -> str | None:
    """Finest scope one import covers, for "latest import" selection: a GCP project, or an AWS
    partition + account + region (complementary regional or partition packages never
    supersede each other)."""
    if source.get("format") == "gcp-json-v1" and source.get("project_id"):
        return "GCP:" + source["project_id"]
    if source.get("account_id"):
        return ":".join(
            [
                "AWS",
                source.get("partition") or "aws",
                source["account_id"],
                source.get("region") or "",
            ]
        )
    return None


def accounts_for(store, run: str) -> set[str]:
    """Scope keys (AWS accounts and GCP projects) a run's evidence covers."""
    store.require_run(run)
    return {key for s in store.source_data(run) if (key := scope_key(s))}


def _split(keys) -> tuple[list[str], list[str]]:
    aws = sorted(k.split(":", 1)[1] for k in keys if k.startswith("AWS:"))
    gcp = sorted(k.split(":", 1)[1] for k in keys if k.startswith("GCP:"))
    return aws, gcp


def refresh_plan(store, baseline: str, replacements: list[str]) -> dict:
    row = store.db.execute(
        "SELECT members FROM enterprise_snapshots WHERE run_id=?", [baseline]
    ).fetchone()
    if not row or not replacements or len(replacements) > 2048:
        raise InputError("INVALID_ENTERPRISE_REFRESH")
    old = json.loads(row[0])
    updated = set()
    for run in replacements:
        if store.db.execute("SELECT 1 FROM enterprise_snapshots WHERE run_id=?", [run]).fetchone():
            raise InputError("NESTED_ENTERPRISE_SNAPSHOT")
        updated.update(accounts_for(store, run))
    if not updated:
        raise InputError("REFRESH_ACCOUNT_UNRESOLVED")
    retained, removed = [], []
    for run in old:
        accounts = accounts_for(store, run)
        if accounts & updated:
            if not accounts <= updated:
                raise InputError("PARTIAL_MULTIACCOUNT_REPLACEMENT")
            removed.append(run)
        else:
            retained.append(run)
    selected = sorted(set(retained + replacements))
    origin = enterprise_origin(store, selected)
    aws, gcp = _split(updated)
    in_scope = (
        "(account_id IN (SELECT unnest(?)) OR "
        "json_extract_string(data,'$.project_id') IN (SELECT unnest(?)))"
    )
    affected = store.db.execute(
        "SELECT count(DISTINCT resource_id) FROM observations WHERE run_id=? AND " + in_scope,
        [baseline, aws, gcp],
    ).fetchone()[0]
    relationships = store.db.execute(
        "SELECT count(*) FROM enterprise_edges WHERE run_id=? AND "
        "(source_account IN (SELECT unnest(?)) OR destination_account IN (SELECT unnest(?)))",
        [baseline, aws, aws],
    ).fetchone()[0]
    marks = ",".join("?" for _ in replacements)
    # Compare normalized security facts, excluding timestamps/provenance, to detect changes.
    fingerprint = (
        "string_agg(DISTINCT json_extract(data,'$.configuration') || "
        "coalesce(json_extract_string(data,'$.source_status'),'') || "
        "coalesce(json_extract_string(data,'$.source_check_id'),''), '|' ORDER BY "
        "json_extract(data,'$.configuration') || "
        "coalesce(json_extract_string(data,'$.source_status'),'') || "
        "coalesce(json_extract_string(data,'$.source_check_id'),''))"
    )
    changed = store.db.execute(
        f"WITH old AS (SELECT resource_id,{fingerprint} fact FROM observations "
        "WHERE run_id=? AND " + in_scope + " AND resource_id IS NOT NULL "
        "GROUP BY resource_id), new AS (SELECT resource_id,"
        + fingerprint
        + f" fact FROM observations WHERE run_id IN ({marks}) AND resource_id IS NOT NULL "
        "GROUP BY resource_id) SELECT count(*) FROM old FULL JOIN new USING(resource_id) "
        "WHERE old.fact IS DISTINCT FROM new.fact",
        [baseline, aws, gcp, *replacements],
    ).fetchone()[0]
    evaluations = store.db.execute(
        "SELECT count(*) FROM evaluations WHERE run_id=? AND "
        "(json_extract_string(data,'$.account_id') IN (SELECT unnest(?)) OR "
        "json_extract_string(data,'$.project_id') IN (SELECT unnest(?)))",
        [baseline, aws, gcp],
    ).fetchone()[0]
    return {
        "baseline": baseline,
        "members": selected,
        "replaced_members": removed,
        "retained_members": retained,
        "affected_accounts": sorted(updated),
        "previous_affected_resources": affected,
        "changed_resource_facts": changed,
        "previous_affected_evaluations": evaluations,
        "relationships_requiring_reevaluation": relationships,
        "mode": "SAFE_FULL_RECOMPUTATION",
        "origin": origin,
        "limitation": (
            "Replacement imports define the new account evidence window. Supply all "
            "desired account packages; older account collections remain in historical "
            "runs."
        ),
    }


def refresh_enterprise(store, baseline: str, replacements: list[str]) -> dict:
    plan = refresh_plan(store, baseline, replacements)
    run = assess_enterprise(store, plan["members"])
    record_run_origin(store.workspace, run, plan["origin"])
    return {**plan, "run_id": run}
