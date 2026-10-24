"""Semantically distinct counts shared by CLI and Excel; no aggregate PASS claim."""

import json
from collections import Counter

from offline_analyzer.correlation.prowler import MAPPINGS
from offline_analyzer.inventory.accounts import workspace_registry


def assessment_metrics(store, run_id: str) -> dict:
    from offline_analyzer.findings.exclusions import excluded_ids

    store.require_run(run_id)

    def count(sql: str) -> int:
        return store.db.execute(sql, [run_id]).fetchone()[0]

    sources = list(store.source_data(run_id))
    observed_scopes = set(
        store.rows(
            "SELECT DISTINCT account_id,region FROM observations WHERE run_id=? "
            "AND account_id IS NOT NULL AND region IS NOT NULL",
            [run_id],
        )
    )
    collected_scopes = {
        (s["account_id"], s["region"]) for s in sources if s["account_id"] and s["region"]
    }
    represented = observed_scopes | collected_scopes
    all_outcomes, resource_outcomes, scope_outcomes = Counter(), Counter(), Counter()
    missing_evaluations = 0
    dependencies = set()
    for result in store.results(run_id):
        all_outcomes[str(result.outcome)] += 1
        (scope_outcomes if result.evaluation_scope == "COLLECTION_SCOPE" else resource_outcomes)[
            str(result.outcome)
        ] += 1
        if result.missing_dependencies:
            missing_evaluations += 1
            dependencies.update(result.missing_dependencies)
    unsupported = sum(
        obs.source_tool == "prowler" and obs.source_check_id not in MAPPINGS
        for obs in store.observations(run_id)
    )
    targets = json.loads(
        store.db.execute("SELECT package FROM runs WHERE run_id=?", [run_id]).fetchone()[0]
    )["targets"]
    return {
        "run_id": run_id,
        "assessed": bool(
            store.db.execute("SELECT 1 FROM assessments WHERE run_id=?", [run_id]).fetchone()
        ),
        "evidence_files": count("SELECT count(*) FROM artifacts WHERE run_id=?"),
        "source_descriptors": len(sources),
        "represented_scopes": [{"account": a, "region": r} for a, r in sorted(represented)],
        "unique_accounts": len(
            {s["account_id"] for s in sources if s["account_id"]}
            | {
                a
                for (a,) in store.rows(
                    "SELECT DISTINCT account_id FROM observations WHERE run_id=? "
                    "AND account_id IS NOT NULL",
                    [run_id],
                )
            }
        ),
        # "global" labels non-Regional resources (IAM, account settings); not a Region.
        "unique_regions": len(
            {s["region"] for s in sources if s["region"]}
            | {
                r
                for (r,) in store.rows(
                    "SELECT DISTINCT region FROM observations WHERE run_id=? "
                    "AND region IS NOT NULL AND region <> 'global'",
                    [run_id],
                )
            }
        ),
        "observed_owner_accounts": count(
            "SELECT count(DISTINCT account_id) FROM observations WHERE run_id=?"
        ),
        "observed_resource_regions": count(
            "SELECT count(DISTINCT region) FROM observations WHERE run_id=? AND region <> 'global'"
        ),
        "declared_target_scopes": len({(t["account_id"], t["region"]) for t in targets}),
        "unique_identified_resources": count(
            "SELECT count(DISTINCT resource_id) FROM observations WHERE run_id=?"
        ),
        "resources_evaluated": count(
            "SELECT count(DISTINCT resource_id) FROM evaluations WHERE run_id=?"
        ),
        "normalized_observations": count("SELECT count(*) FROM observations WHERE run_id=?"),
        "raw_observation_occurrences": count("SELECT count(*) FROM evidence_refs WHERE run_id=?"),
        "control_evaluation_records": sum(all_outcomes.values()),
        "outcomes": dict(sorted(all_outcomes.items())),
        "resource_evaluation_outcomes": dict(sorted(resource_outcomes.items())),
        "collection_scope_outcomes": dict(sorted(scope_outcomes.items())),
        # Excluded findings (any reason) are reported separately, never as candidates.
        "candidate_findings": count("SELECT count(*) FROM findings WHERE run_id=?")
        - len(excluded_ids(store, run_id)),
        "source_collections_with_errors": sum(
            bool(s["errors"]) or s["effective_coverage"] == "ERROR" for s in sources
        ),
        "collection_error_records": sum(len(s["errors"]) for s in sources),
        "unresolved_collection_gaps": scope_outcomes["UNKNOWN"]
        + scope_outcomes["COLLECTION_ERROR"],
        "evaluations_missing_evidence": missing_evaluations,
        "unique_missing_dependencies": len(dependencies),
        "unsupported_scanner_observations": unsupported,
        **registry_metrics(store, sources),
        **dataset_labels(store, run_id),
    }


def dataset_labels(store, run_id: str) -> dict:
    """Explicit environment/origin labels so a demonstration is never read as findings."""
    from offline_analyzer.inventory.environment import dataset_origin, workspace_environment

    environment = workspace_environment(store.workspace)
    label = environment.label if environment else "UNLABELED"
    origin = dataset_origin(store.workspace, [run_id])
    return {
        "workspace_environment": label,
        "dataset_origin": origin,
        "customer_findings_eligible": label == "ASSESSMENT" and origin == "TOOL_GENERATED",
    }


def registry_metrics(store, sources) -> dict:
    """Coverage against the approved registry; never implies unassessed accounts passed."""
    registry = workspace_registry(store.workspace)
    if not registry:
        return {"account_registry": "NOT_LOADED"}
    evidence = {s["account_id"] for s in sources if s["account_id"]}
    in_scope = set(registry.in_scope)
    return {
        "account_registry": registry.fingerprint(),
        "registry_in_scope_accounts": len(in_scope),
        "registry_accounts_with_evidence": len(in_scope & evidence),
        "registry_accounts_without_evidence": len(in_scope - evidence),
        "evidence_accounts_not_in_registry": len(evidence - set(registry.accounts)),
    }
