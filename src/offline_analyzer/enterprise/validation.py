"""Read-only reconciliation of an enterprise union against its selected imports."""

import json


def validate_snapshot(store, run: str) -> dict:
    store.require_run(run)
    row = store.db.execute(
        "SELECT members FROM enterprise_snapshots WHERE run_id=?", [run]
    ).fetchone()
    if not row:
        from offline_analyzer.evidence.composition import validate_composition

        return validate_composition(store, run)
    selected = json.loads(row[0])
    marks = ",".join("?" for _ in selected)
    from offline_analyzer.enterprise.snapshot import (
        PLAN_FILTERS,
        _plan_tables,
        drop_plan_tables,
        scope_plan,
    )

    # Older scopes of a member that a newer member also covers are left out by design
    # (snapshot.scope_plan); the expected union applies the same deterministic plan.
    plan = scope_plan(store, selected)
    if plan:
        _plan_tables(store, plan)
    checks = []
    for table, keys in (
        ("sources", "source_id"),
        ("artifacts", "artifact_id"),
        ("observations", "observation_id"),
        ("evidence_refs", "artifact_id,locator"),
    ):
        kept = f" AND {PLAN_FILTERS[table]}" if plan else ""
        union = f"SELECT DISTINCT {keys} FROM {table} t WHERE run_id IN ({marks}){kept}"
        actual = f"SELECT {keys} FROM {table} WHERE run_id=?"
        expected = store.db.execute(f"SELECT count(*) FROM ({union})", selected).fetchone()[0]
        observed = store.db.execute(f"SELECT count(*) FROM ({actual})", [run]).fetchone()[0]
        missing = store.db.execute(
            f"SELECT count(*) FROM (({union}) EXCEPT ({actual}))", [*selected, run]
        ).fetchone()[0]
        unexpected = store.db.execute(
            f"SELECT count(*) FROM (({actual}) EXCEPT ({union}))", [run, *selected]
        ).fetchone()[0]
        occurrences = store.db.execute(
            f"SELECT count(*) FROM {table} t WHERE run_id IN ({marks}){kept}", selected
        ).fetchone()[0]
        checks.append(
            {
                "stage": table,
                "expected": expected,
                "actual": observed,
                "missing": missing,
                "unexpected": unexpected,
                "deduplicated_occurrences": occurrences - expected,
                "status": "PASS"
                if not missing and not unexpected and expected == observed
                else "ERROR",
            }
        )

    if plan:
        drop_plan_tables(store)

    def scopes(runs):
        found = {"AWS": set(), "GCP": set()}
        for member in runs:
            # Use the writer connection: this also runs before snapshot COMMIT.
            # Store.rows uses an independent read cursor and cannot see this union yet.
            for (raw,) in store.db.execute(
                "SELECT data FROM sources WHERE run_id=?", [member]
            ).fetchall():
                source = json.loads(raw)
                provider = "GCP" if source["format"] == "gcp-json-v1" else "AWS"
                identity = source.get("project_id") or source.get("account_id")
                if identity:
                    found[provider].add(identity)
        return found

    expected_scopes, actual_scopes = scopes(selected), scopes([run])
    scope_check = {
        p: {
            "expected": sorted(expected_scopes[p]),
            "actual": sorted(actual_scopes[p]),
            "missing": sorted(expected_scopes[p] - actual_scopes[p]),
            "unexpected": sorted(actual_scopes[p] - expected_scopes[p]),
        }
        for p in ("AWS", "GCP")
    }
    from offline_analyzer.enterprise.snapshot import members

    omitted = sorted(set(members(store)) - set(selected))
    errors = any(c["status"] == "ERROR" for c in checks) or expected_scopes != actual_scopes
    result = {
        "status": "ERROR" if errors else "WARNING" if omitted else "PASS",
        "checks": checks,
        "scopes": scope_check,
        "member_count": len(selected),
        "missing_imports": omitted,
        "qualification": "Exact union of selected imports; identical canonical records "
        "deduplicate. "
        "PASS verifies the union, not collection completeness or security posture. "
        "Other available imports are listed for analyst review.",
    }
    if plan:
        result["superseded_sources"] = {m: len(ids) for m, ids in plan.items()}
        result["qualification"] += (
            " Sources of an AWS account/Region that a newer selected import also covers are "
            "left out (superseded_sources); the newer import's evidence is used."
        )
    return result
