"""Persist rule-origin investigations in the existing assessment transaction."""

from offline_analyzer.contracts.investigation import SecurityInvestigation
from offline_analyzer.contracts.r0 import Candidate, Result, stable_id
from offline_analyzer.storage.store import Store


def persist(store: Store, run: str, finding: Candidate, result: Result) -> None:
    store.db.execute(
        "INSERT INTO security_investigations VALUES (?,?,?,?)",
        investigation_row(run, finding, result),
    )


def investigation_row(run: str, finding: Candidate, result: Result) -> list:
    """The security_investigations row for a SEC- finding (shared by batched writes)."""
    investigation = SecurityInvestigation(
        investigation_id=stable_id("security-investigation", finding.finding_id),
        finding_id=finding.finding_id,
        evaluation_id=result.evaluation_id,
        rule_id=finding.rule_id,
        security_domain=finding.security_domain,
        account_id=finding.account_id,
        region=finding.region,
        affected_resources=(finding.resource_id,),
        evidence=finding.evidence,
        technical_hypothesis=finding.technical_observation,
        missing_validation=finding.missing_evidence,
        security_implications=finding.security_risk,
        assessment_snapshot_time=result.assessed_at,
    )
    return [
        run,
        investigation.investigation_id,
        finding.finding_id,
        investigation.model_dump_json(),
    ]
