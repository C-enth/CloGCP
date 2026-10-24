"""Deterministic finding readiness. Never an analyst decision or exploitation proof."""

from offline_analyzer.findings.explanations import explain


def finding_quality(finding, evaluation, artifacts: set[str]) -> dict:
    guidance = explain(finding)
    missing = [
        field
        for field in (
            "title",
            "technical_observation",
            "severity_rationale",
            "remediation",
            "suggested_severity",
            "native_id",
        )
        if not str(getattr(finding, field, "") or "").strip()
    ]
    missing += [
        key
        for key in ("why_flagged", "impact", "recommendation", "misuse")
        if not guidance.get(key, "").strip()
    ]
    if not finding.evidence or any(ref.artifact_id not in artifacts for ref in finding.evidence):
        missing.append("evidence_references")
    if evaluation is None or str(evaluation.outcome) != "FAIL":
        missing.append("supporting_fail_evaluation")
    blockers = list(finding.missing_evidence)
    blockers.extend(finding.contradictory_observations)
    if finding.evidence_confidence in {"LOW", "UNASSESSED"}:
        blockers.append("evidence_confidence_requires_validation")
    if evaluation is not None:
        blockers.extend(evaluation.missing_dependencies)
        if evaluation.contradictory_observations:
            blockers.append("contradictory_observations")
    ready = not missing and not blockers
    return {
        "state": "READY_FOR_CONFIRMATION" if ready else "NEEDS_VALIDATION",
        "missing_fields": sorted(set(missing)),
        "unresolved": sorted(set(blockers)),
        "qualification": "Content and evidence consistency checks only. Severity, confidence "
        "and analyst approval remain independent. Exploitation is not verified.",
    }


def run_quality(store, run: str) -> dict:
    artifacts = {
        a for (a,) in store.rows("SELECT artifact_id FROM artifacts WHERE run_id=?", [run])
    }
    results = {(r.rule_id, r.resource_id): r for r in store.results(run)}
    from offline_analyzer.findings.exclusions import excluded

    hidden = excluded(store, run)  # excluded findings are not counted for readiness
    items = {
        f.finding_id: finding_quality(f, results.get((f.rule_id, f.resource_id)), artifacts)
        for f in store.candidates(run)
        if f.finding_id not in hidden
    }
    return {
        "items": items,
        "ready": sum(r["state"] == "READY_FOR_CONFIRMATION" for r in items.values()),
        "needs_validation": sum(r["state"] != "READY_FOR_CONFIRMATION" for r in items.values()),
    }
