"""Deterministic candidates and separate, evidence-bound analyst decisions."""

import hashlib
from datetime import UTC, datetime

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Candidate, Decision, Result, stable_id
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.registry import BY_ID


def candidate(result: Result) -> Candidate | None:
    if result.outcome != Outcome.FAIL or not all(
        (
            result.resource_id,
            result.project_id if result.provider == "GCP" else result.account_id,
            result.region,
            result.native_id,
        )
    ):
        return None
    rule = BY_ID[result.rule_id]
    link = rule.methodology
    return Candidate(
        finding_id=stable_id("finding", [rule.rule_id, result.resource_id]),
        title=rule.title,
        security_domain=rule.domain,
        rule_id=rule.rule_id,
        rule_version=rule.version,
        methodology_id=result.methodology_id,
        mapping_status=result.mapping_status,
        methodology_criteria=result.methodology_criteria,
        methodology_sha256=result.methodology_sha256,
        attack_paths=link.attack_paths if link else (),
        stride_category=link.stride_category if link else None,
        methodology_inherent_severity=link.inherent_severity if link else None,
        finding_class=result.finding_class or rule.finding_class,
        exposure_status=result.exposure_status,
        compensating_controls=result.compensating_controls,
        provider=result.provider,
        project_id=result.project_id,
        project_number=result.project_number,
        organization_id=result.organization_id,
        folder_id=result.folder_id,
        account_id=result.account_id,
        region=result.region,
        resource_id=result.resource_id,
        native_id=result.native_id,
        technical_observation=result.reasoning,
        security_risk=rule.risk,
        evidence=result.evidence,
        contradictory_observations=result.contradictory_observations,
        missing_evidence=result.missing_dependencies + result.evidence_needed,
        suggested_severity=result.suggested_severity or rule.severity,
        severity_rationale=rule.severity_rationale,
        evidence_confidence=result.confidence,
        remediation=rule.remediation,
        validation_requirements=rule.follow_up
        + (
            ("Reconcile contradictory scanner timestamps and resource scope",)
            if result.contradictory_observations
            else ()
        )
        + ("Recollect configuration after remediation; assess collection gaps separately",),
    )


def fingerprint(finding: Candidate) -> str:
    return hashlib.sha256(finding.model_dump_json().encode()).hexdigest()


def validation_status(
    store, finding: Candidate, latest: dict | None = None
) -> tuple[str, Decision | None]:
    """`latest` is an optional preloaded Store.latest_decisions() map for bulk reports."""
    decision = (
        latest.get(finding.finding_id)
        if latest is not None
        else store.latest_decision(finding.finding_id)
    )
    if not decision:
        return "CANDIDATE", None
    if decision.evidence_fingerprint != fingerprint(finding):
        return "NEEDS_REVALIDATION", decision
    return decision.status, decision


def record_decision(
    store, run_id: str, finding_id: str, status: str, analyst: str, note: str
) -> str:
    store.require_run(run_id)
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run_id)
    row = store.db.execute(
        "SELECT data FROM findings WHERE run_id=? AND finding_id=?", [run_id, finding_id]
    ).fetchone()
    if not row:
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    from offline_analyzer.ingestion.json_input import SECRET_VALUE

    if SECRET_VALUE.search(note) or SECRET_VALUE.search(analyst):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    finding = Candidate.model_validate_json(row[0])
    decision = Decision(
        finding_id=finding_id,
        status=status,
        analyst=analyst,
        note=note,
        decided_at=datetime.now(UTC),
        run_id=run_id,
        evidence_fingerprint=fingerprint(finding),
    )
    decision_id = stable_id("decision", decision.model_dump(mode="json"))
    with store.transaction():
        store.db.execute(
            "INSERT INTO decisions VALUES (?, ?, ?, ?)",
            [decision_id, finding_id, decision.decided_at.isoformat(), decision.model_dump_json()],
        )
    return decision_id


def record_decisions(
    store, run_id: str, finding_ids: list[str], status: str, analyst: str, note: str
) -> list[str]:
    """The same decision for many findings, all-or-nothing (bulk marking in the workbench)."""
    store.require_run(run_id)
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run_id)
    if not finding_ids or len(finding_ids) > 2000 or len(set(finding_ids)) != len(finding_ids):
        raise InputError("INVALID_REVIEW_SELECTION")
    from offline_analyzer.ingestion.json_input import SECRET_VALUE

    if SECRET_VALUE.search(note) or SECRET_VALUE.search(analyst):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    found = {
        fid: Candidate.model_validate_json(raw)
        for fid, raw in store.rows(
            "SELECT finding_id,data FROM findings WHERE run_id=? AND "
            "finding_id IN (SELECT unnest(?))",
            [run_id, finding_ids],
        )
    }
    if len(found) != len(finding_ids):
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    now = datetime.now(UTC)
    rows = []
    for fid in finding_ids:
        decision = Decision(
            finding_id=fid,
            status=status,
            analyst=analyst,
            note=note,
            decided_at=now,
            run_id=run_id,
            evidence_fingerprint=fingerprint(found[fid]),
        )
        decision_id = stable_id("decision", decision.model_dump(mode="json"))
        rows.append([decision_id, fid, now.isoformat(), decision.model_dump_json()])
    with store.transaction():
        for row in rows:
            store.db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?)", row)
    return [row[0] for row in rows]
