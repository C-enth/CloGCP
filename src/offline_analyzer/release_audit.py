"""Read-only release audit of a workspace: relationship and candidate-finding invariants.

Opens the database read-only and prints counts and invariant violations only: no account
IDs, resource names, policy text or evidence values, so the summary can be shared after
review. Usage:
    python -m offline_analyzer.release_audit --workspace <dir> [--run <run-id>] [--output f.json]
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import duckdb

from offline_analyzer.contracts.investigation import SecurityInvestigation
from offline_analyzer.contracts.r0 import Candidate, stable_id
from offline_analyzer.contracts.report_finding import ReportRevision
from offline_analyzer.enterprise.queries import STRUCTURAL_KINDS as STRUCTURAL  # noqa: E402
from offline_analyzer.findings.generate import fingerprint
from offline_analyzer.findings.report_ready import render_text
from offline_analyzer.inventory.environment import workspace_environment

CLASSES = {"BASELINE_DEVIATION", "POTENTIAL_EXPOSURE", "SUPPORTED_SECURITY_GAP"}


def connect(workspace: Path):
    path = workspace / "assessment.duckdb"
    if not path.is_file():
        raise FileNotFoundError("assessment.duckdb not found in workspace")
    return duckdb.connect(
        str(path),
        read_only=True,
        config={"enable_external_access": "false", "autoload_known_extensions": "false"},
    )


def tables(db) -> set[str]:
    return {r[0] for r in db.execute("SELECT table_name FROM information_schema.tables").fetchall()}


def relationship_audit(db, run: str) -> dict:
    if "enterprise_edges" not in tables(db):
        return {"present": False}
    rows = db.execute(
        "SELECT kind, status, source_account, destination_account, data FROM enterprise_edges "
        "WHERE run_id=?",
        [run],
    ).fetchall()
    observed = {
        r[0]
        for r in db.execute(
            "SELECT observation_id FROM observations WHERE run_id=?", [run]
        ).fetchall()
    }
    by_kind, endpoints, violations = Counter(), Counter(), Counter()
    cross = Counter()
    for kind, status, source, destination, data in rows:
        edge = json.loads(data)
        by_kind[(kind, status)] += 1
        endpoints[(edge.get("source"), edge.get("destination"), kind)] += 1
        if source and destination and source != destination:
            cross[status] += 1
        if edge.get("source") == edge.get("destination"):
            violations["self_loop"] += 1
        if status == "DERIVED_SUPPORTED" and edge.get("missing"):
            violations["supported_with_missing_dependencies"] += 1
        if status == "DERIVED_SUPPORTED" and edge.get("blocking"):
            violations["supported_with_blockers"] += 1
        if status == "BLOCKED" and not edge.get("blocking"):
            violations["blocked_without_blocker"] += 1
        missing_obs = [o for o in edge.get("observation_ids") or [] if o not in observed]
        if missing_obs:
            violations["edge_observation_not_found"] += 1
        if status == "DIRECTLY_OBSERVED" and not edge.get("observation_ids"):
            violations["observed_edge_without_observation"] += 1
    violations["duplicate_endpoints"] = sum(n - 1 for n in endpoints.values() if n > 1)
    structural = sum(n for (k, _), n in by_kind.items() if k in STRUCTURAL)
    return {
        "present": True,
        "total": len(rows),
        "structural_configuration_references": structural,
        "authorization_or_exposure_relationships": len(rows) - structural,
        "by_kind_and_status": {f"{k}/{s}": n for (k, s), n in sorted(by_kind.items())},
        "cross_account_by_status": dict(sorted(cross.items())),
        "violations": {k: v for k, v in sorted(violations.items()) if v},
    }


def finding_audit(db, run: str) -> dict:
    investigations = {}
    if "security_investigations" in tables(db):
        investigations = {
            fid: SecurityInvestigation.model_validate_json(raw)
            for fid, raw in db.execute(
                "SELECT finding_id,data FROM security_investigations WHERE run_id=?", [run]
            ).fetchall()
        }
    evaluations = {
        r[0]: r[1]
        for r in db.execute(
            "SELECT evaluation_id, outcome FROM evaluations WHERE run_id=?", [run]
        ).fetchall()
    }
    artifacts = {r[0] for r in db.execute("SELECT DISTINCT artifact_id FROM artifacts").fetchall()}
    resources = {
        (r[0], r[1])
        for r in db.execute(
            "SELECT finding_id, account_id FROM finding_resources WHERE run_id=?", [run]
        ).fetchall()
    }
    decided = Counter(
        json.loads(r[0])["status"]
        for r in db.execute(
            "SELECT d.data FROM decisions d JOIN findings f ON d.finding_id=f.finding_id "
            "AND f.run_id=?",
            [run],
        ).fetchall()
    )
    violations, classes, severity, mapping = Counter(), Counter(), Counter(), Counter()
    total = 0
    for (data,) in db.execute("SELECT data FROM findings WHERE run_id=?", [run]).fetchall():
        total += 1
        finding = Candidate.model_validate_json(data)
        classes[finding.finding_class or "UNCLASSIFIED"] += 1
        severity[finding.suggested_severity] += 1
        mapping[finding.mapping_status] += 1
        evaluation = stable_id(
            "evaluation", [finding.rule_id, finding.rule_version, finding.resource_id]
        )
        if evaluations.get(evaluation) != "FAIL":
            violations["candidate_without_failed_evaluation"] += 1
        if not finding.evidence:
            violations["candidate_without_evidence"] += 1
        if any(ref.artifact_id not in artifacts for ref in finding.evidence):
            violations["evidence_artifact_not_found"] += 1
        if (finding.finding_id, finding.account_id) not in resources:
            violations["affected_account_mismatch"] += 1
        if finding.mapping_status == "PROPOSED" and not finding.methodology_criteria:
            violations["proposed_mapping_without_criteria"] += 1
        if finding.rule_id.startswith("SEC-"):
            origin = investigations.get(finding.finding_id)
            if (
                not origin
                or origin.rule_id != finding.rule_id
                or origin.evaluation_id != evaluation
                or origin.evidence != finding.evidence
            ):
                violations["additional_observation_without_traceable_investigation"] += 1
        if finding.finding_class and finding.finding_class not in CLASSES:
            violations["unknown_finding_class"] += 1
        if (
            finding.suggested_severity == "CRITICAL"
            and finding.finding_class != "SUPPORTED_SECURITY_GAP"
        ):
            violations["critical_without_supported_gap"] += 1
        if finding.review_status != "CANDIDATE":
            violations["candidate_not_in_candidate_state"] += 1
        if finding.finding_class in {"SUPPORTED_SECURITY_GAP", "POTENTIAL_EXPOSURE"} and not (
            finding.exposure_status
        ):
            violations["exposure_class_without_exposure_statement"] += 1
    return {
        "candidates": total,
        "by_finding_class": dict(sorted(classes.items())),
        "by_suggested_severity": dict(sorted(severity.items())),
        "by_mapping_status": dict(sorted(mapping.items())),
        "analyst_decisions_by_status": dict(sorted(decided.items())),
        "confirmed_only_by_analyst_decision": True,
        "violations": {k: v for k, v in sorted(violations.items()) if v},
    }


def report_audit(db) -> dict:
    """Audit frozen revisions against historical evidence, not later analyst decisions."""
    if "report_revisions" not in tables(db):
        return {"present": False, "violations": {}}
    if not db.execute("SELECT 1 FROM report_revisions LIMIT 1").fetchone():
        return {"present": True, "revisions": 0, "approvals": {}, "violations": {}}
    violations, approvals = Counter(), Counter()
    artifacts = {
        (r, a): digest
        for r, a, digest in db.execute("SELECT run_id,artifact_id,sha256 FROM artifacts").fetchall()
    }
    sources = {(r, s) for r, s in db.execute("SELECT run_id,source_id FROM sources").fetchall()}
    fingerprints = {
        (r, f): fingerprint(Candidate.model_validate_json(raw))
        for r, f, raw in db.execute("SELECT run_id,finding_id,data FROM findings").fetchall()
    }
    count = 0
    for (raw,) in db.execute("SELECT data FROM report_revisions").fetchall():
        count += 1
        try:
            revision = ReportRevision.model_validate_json(raw)
        except ValueError:
            violations["invalid_report_revision"] += 1
            continue
        if revision.report_text != render_text(revision.sections, revision.snapshots):
            violations["report_text_snapshot_mismatch"] += 1
        for snapshot in revision.snapshots:
            # Rerunning an upgraded engine can change historical evaluation fingerprints;
            # the frozen snapshot is retained, but export will require current review.
            if (revision.run_id, snapshot.finding_id) not in fingerprints:
                approvals["historical_finding_no_longer_evaluated"] += 1
            for ref in snapshot.evidence:
                if artifacts.get((revision.run_id, ref["artifact_id"])) != ref["sha256"]:
                    violations["report_evidence_digest_mismatch"] += 1
                if (revision.run_id, ref["collection_id"]) not in sources:
                    violations["report_collection_not_found"] += 1
        for key in (
            "recommendation_approval",
            "narrative_approval",
            "consolidation_approval",
            "risk_acceptance",
        ):
            approval = getattr(revision, key)
            if approval:
                approvals[key] += 1
                if not approval.reviewer.strip() or not approval.approved_at:
                    violations["report_approval_not_traceable"] += 1
        if revision.consolidation_approval and (
            len(revision.snapshots) < 2 or len(revision.consolidation_basis.strip()) < 20
        ):
            violations["consolidation_without_scope_rationale"] += 1
    return {
        "present": True,
        "revisions": count,
        "approvals": dict(approvals),
        "violations": dict(violations),
    }


def audit(workspace: Path, run: str | None = None) -> dict:
    db = connect(workspace)
    try:
        runs = [
            r[0]
            for r in db.execute("SELECT run_id FROM assessments ORDER BY assessed_at").fetchall()
        ]
        if run is None:
            if not runs:
                raise ValueError("no assessed run in workspace")
            if "enterprise_snapshots" in tables(db):
                snapshots = {
                    r[0] for r in db.execute("SELECT run_id FROM enterprise_snapshots").fetchall()
                }
                run = next((r for r in reversed(runs) if r in snapshots), runs[-1])
            else:
                run = runs[-1]
        relationships = relationship_audit(db, run)
        findings = finding_audit(db, run)
        reports = report_audit(db)
    finally:
        db.close()
    environment = workspace_environment(workspace)
    violations = (
        sum(relationships.get("violations", {}).values())
        + sum(findings["violations"].values())
        + sum(reports["violations"].values())
    )
    return {
        "audit_version": "1.1.0",
        "workspace_environment": environment.label if environment else "UNLABELED",
        "run_id": run,
        "relationships": relationships,
        "findings": findings,
        "report_revisions": reports,
        "invariant_violations": violations,
        "result": "PASS" if violations == 0 else "FAIL",
        "contains_customer_values": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--run")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.workspace.resolve(), args.run)
    except Exception as exc:  # noqa: BLE001 -- never print workspace contents
        print(f"Audit failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    text = json.dumps(report, indent=2)
    if args.output:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
    print(text)
    return 0 if report["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
