"""Append-only client narrative editing/approvals with current-evidence export gates."""

import json
from datetime import UTC, datetime

from offline_analyzer.contracts.r0 import Candidate, Decision, stable_id
from offline_analyzer.contracts.report_finding import (
    EvidenceSnapshot,
    ReportApproval,
    ReportEdit,
    ReportRevision,
    ReportSections,
)
from offline_analyzer.findings.explanations import explain
from offline_analyzer.findings.generate import fingerprint, validation_status
from offline_analyzer.findings.recommendations import recommendation
from offline_analyzer.ingestion.json_input import SECRET_VALUE, InputError
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.storage.store import Store


def current_findings(store: Store, run: str, ids: list[str] | None = None) -> dict[str, Candidate]:
    store.require_run(run)
    clause = " AND finding_id IN (SELECT unnest(?))" if ids is not None else ""
    params = [run, ids] if ids is not None else [run]
    return {
        c.finding_id: c
        for (raw,) in store.rows("SELECT data FROM findings WHERE run_id=?" + clause, params)
        if (c := Candidate.model_validate_json(raw))
    }


def latest_revision(store: Store, primary: str) -> ReportRevision | None:
    row = store.db.execute(
        "SELECT data FROM report_revisions WHERE primary_finding=? ORDER BY revision DESC LIMIT 1",
        [primary],
    ).fetchone()
    return ReportRevision.model_validate_json(row[0]) if row else None


def sections_for(finding: Candidate, detail: dict | None = None) -> ReportSections:
    """Pre-filled draft; `detail` (findings.detail) adds actual configuration and commands."""
    rec = recommendation(finding.rule_id)
    explanation = explain(finding)
    observation = finding.technical_observation
    root_cause = "Not established; validate configuration ownership and change history."
    remediation = (
        "\n\n".join(
            f"{title}: {rec[key]}"
            for title, key in (
                ("Recommended action", "recommended_action"),
                ("Immediate mitigation", "immediate_mitigation"),
                ("Permanent remediation", "permanent_remediation"),
                ("Implementation guidance", "implementation_guidance"),
            )
            if rec.get(key)
        )
        or f"Recommended action: {finding.remediation}"
    )
    validation = rec.get("validation_procedure", "Analyst-authored validation required.")
    if detail:
        params = detail["observed"]["parameters"]
        if params:
            observation += "\n\nActual configuration:\n" + "\n".join(
                f"- {p['field']}: {p['actual']} (expected: {p['expected']})" for p in params
            )
        refs = [f"- {e['operation']} {e['file']} {e['locator']}" for e in detail["evidence"]]
        if refs:
            observation += "\n\nEvidence:\n" + "\n".join(refs)
        gap = detail["gap"]
        root_cause = (
            f"Technical gap: {gap['weakness']}; {gap['what_is_wrong']} "
            f"(principle: {gap['principle_violated']}). Organizational root cause: Not "
            "established (ownership, change history); the analyst confirms it."
        )
        if detail["remediation"]["command"]:
            remediation += (
                "\n\nCommand for review (not executed by CloSec): "
                + detail["remediation"]["command"]
            )
        if detail["validation"]["command"]:
            validation += "\n\nRead-only verification: " + detail["validation"]["command"]
    return ReportSections(
        title=finding.title,
        severity=finding.suggested_severity,
        severity_rationale=finding.severity_rationale,
        technical_observation=observation[:16000],
        expected_posture=rec.get("expected_posture", "Analyst-authored expected posture required."),
        risk=explanation["impact"],
        attack_scenario=explanation["misuse"]
        + " Exploitation is not established; the analyst confirms or revises this scenario.",
        root_cause=root_cause,
        remediation=remediation[:16000],
        considerations=rec.get("operational_considerations", "Analyst review required.")
        + "\n\nPossible compensating controls (not presumed deployed): "
        + rec.get("compensating_controls", "No validated alternatives identified."),
        validation=validation[:16000],
        references=rec["references"],
    )


def snapshots_for(
    store: Store, run: str, findings: list[Candidate]
) -> tuple[EvidenceSnapshot, ...]:
    artifacts = dict(store.rows("SELECT artifact_id,sha256 FROM artifacts WHERE run_id=?", [run]))
    collections = {}
    for sid, raw in store.rows("SELECT source_id,data FROM sources WHERE run_id=?", [run]):
        source = json.loads(raw)
        if source.get("artifact_id"):
            collections.setdefault(source["artifact_id"], []).append(
                (
                    sid,
                    (
                        source.get("gcp_metadata", {}).get("completed_at")
                        if source.get("format") == "gcp-json-v1"
                        else source.get("collected_at")
                    )
                    or "Unrecorded",
                )
            )
    snapshots = []
    for finding in findings:
        evidence = []
        for ref in finding.evidence:
            if ref.artifact_id not in artifacts:
                raise InputError("EVIDENCE_ARTIFACT_MISSING")
            if ref.artifact_id not in collections:
                raise InputError("REPORT_COLLECTION_PROVENANCE_MISSING")
            for sid, stamp in sorted(collections[ref.artifact_id]):
                evidence.append(
                    {
                        "artifact_id": ref.artifact_id,
                        "locator": ref.locator,
                        "sha256": artifacts[ref.artifact_id],
                        "collection_id": sid,
                        "collected_at": stamp,
                    }
                )
        snapshots.append(
            EvidenceSnapshot(
                finding_id=finding.finding_id,
                fingerprint=fingerprint(finding),
                account_id=finding.account_id,
                provider=finding.provider,
                project_id=finding.project_id,
                region=finding.region,
                resource_id=finding.resource_id,
                native_id=finding.native_id,
                collection_ids=tuple(sorted({e["collection_id"] for e in evidence})),
                evidence=tuple(evidence),
            )
        )
    return tuple(snapshots)


def render_text(sections: ReportSections, snapshots: tuple[EvidenceSnapshot, ...]) -> str:
    assets = "\n".join(
        f"{s.project_id or s.account_id} | {s.region} | {s.native_id} | {s.resource_id}"
        for s in snapshots
    )
    evidence = "\n".join(
        sorted(
            {
                f"{s.project_id or s.account_id}: {e['artifact_id']} {e['locator']} "
                f"SHA-256 {e['sha256']} collected {e['collected_at']}"
                for s in snapshots
                for e in s.evidence
            }
        )
    )
    parts = (
        ("Finding Title", sections.title),
        ("Approved Severity", sections.severity + " — " + sections.severity_rationale),
        (
            "Affected Scopes and Assets"
            if any(s.provider == "GCP" for s in snapshots)
            else "Affected Accounts and Assets",
            assets,
        ),
        ("Technical Observation", sections.technical_observation),
        ("Expected Security Posture", sections.expected_posture),
        ("Security Risk and Potential Impact", sections.risk),
        ("Attack Scenario", sections.attack_scenario),
        ("Root Cause", sections.root_cause),
        ("Recommended Remediation", sections.remediation),
        ("Implementation Considerations", sections.considerations),
        ("Remediation Validation", sections.validation),
        ("Supporting Evidence", evidence),
        ("Applicable References", "\n".join(sections.references)),
    )
    return "\n\n".join(f"{i}. {title}\n{value}" for i, (title, value) in enumerate(parts, 1))


def validate_text(edit: ReportEdit) -> None:
    if SECRET_VALUE.search(edit.model_dump_json()):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    values = [
        edit.analyst,
        edit.consolidation_basis,
        *edit.sections.references,
        *[v for v in edit.sections.model_dump().values() if isinstance(v, str)],
    ]
    if any(
        (ord(c) < 32 and c not in "\n\r\t")
        or c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        for v in values
        for c in v
    ):
        raise InputError("REPORT_CONTROL_CHARACTERS_REJECTED")
    for value in (
        edit.analyst,
        edit.sections.title,
        edit.sections.severity_rationale,
        edit.sections.technical_observation,
        edit.sections.expected_posture,
        edit.sections.risk,
        edit.sections.remediation,
        edit.sections.considerations,
        edit.sections.validation,
        edit.sections.attack_scenario,
        edit.sections.root_cause,
    ):
        if not value.strip():
            raise InputError("REPORT_SECTION_REQUIRED")
    if any(
        not url.startswith(
            (
                "https://docs.aws.amazon.com/",
                "https://docs.cloud.google.com/",
                "https://cloud.google.com/",
            )
        )
        for url in edit.sections.references
    ):
        raise InputError("REPORT_REFERENCE_NOT_APPROVED")


def insert_revision(store: Store, revision: ReportRevision) -> ReportRevision:
    store.db.execute(
        "INSERT INTO report_revisions VALUES (?,?,?,?,?,?)",
        [
            revision.report_id,
            revision.revision,
            revision.primary_finding,
            revision.run_id,
            revision.created_at.isoformat(),
            revision.model_dump_json(),
        ],
    )
    return revision


def save_revision(store: Store, run: str, primary: str, edit: ReportEdit) -> ReportRevision:
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run)
    validate_text(edit)
    ids = sorted(set(edit.member_ids))
    if primary not in ids:
        raise InputError("REPORT_PRIMARY_NOT_SELECTED")
    findings = current_findings(store, run, ids)
    if set(findings) != set(ids):
        raise InputError("REPORT_MEMBER_NOT_IN_RUN")
    snapshots = snapshots_for(store, run, [findings[f] for f in ids])
    with store.transaction():
        latest = latest_revision(store, primary)
        if edit.expected_revision != (latest.revision if latest else 0):
            raise InputError("REPORT_REVISION_CONFLICT")
        revision = ReportRevision(
            report_id=stable_id("report-finding", primary),
            primary_finding=primary,
            revision=edit.expected_revision + 1,
            run_id=run,
            created_at=datetime.now(UTC),
            author=edit.analyst,
            sections=edit.sections,
            snapshots=snapshots,
            recommendation_version=recommendation(findings[primary].rule_id)["version"],
            include_in_report=edit.include_in_report,
            consolidation_basis=edit.consolidation_basis,
            report_text=render_text(edit.sections, snapshots),
        )
        return insert_revision(store, revision)


def validity(
    revision: ReportRevision,
    findings: dict[str, Candidate],
    decisions: dict[str, Decision],
    store: Store | None = None,
) -> dict:
    state = "CURRENT"
    confirmed = True
    # Per member (owner brief 2b): a member whose evidence changed is NEEDS_REVIEW on its own;
    # the text still applies to the members whose fingerprints are unchanged.
    members: dict[str, str] = {}
    for snapshot in revision.snapshots:
        finding = findings.get(snapshot.finding_id)
        if finding is None:
            state, confirmed = "SUPERSEDED_OR_OUTSIDE_RUN", False
            members[snapshot.finding_id] = "SUPERSEDED_OR_OUTSIDE_RUN"
            continue
        members[snapshot.finding_id] = "CURRENT"
        if fingerprint(finding) != snapshot.fingerprint:
            members[snapshot.finding_id] = "NEEDS_REVIEW"
            if state == "CURRENT":
                state = "NEEDS_REVIEW"
            confirmed = False
        if validation_status(None, finding, decisions)[0] != "CONFIRMED":
            confirmed = False
    approvals = bool(revision.recommendation_approval and revision.narrative_approval)
    consolidated = len(revision.snapshots) == 1 or bool(revision.consolidation_approval)
    if (
        store
        and store.db.execute(
            "SELECT 1 FROM scope_invalidated_reports WHERE report_id=? AND revision=?",
            [revision.report_id, revision.revision],
        ).fetchone()
    ):
        state, confirmed = "NEEDS_REVIEW", False
        members = {k: "NEEDS_REVIEW" for k in members}
    return {
        "evidence_state": state,
        "member_states": members,
        "technical_confirmed": confirmed,
        "eligible": state == "CURRENT"
        and confirmed
        and approvals
        and consolidated
        and revision.include_in_report,
    }


def approve_revision(
    store: Store, run: str, primary: str, approval: ReportApproval
) -> ReportRevision:
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run)
    if SECRET_VALUE.search(approval.model_dump_json()) or not approval.analyst.strip():
        raise InputError("REPORT_REVIEWER_INVALID")
    with store.transaction():
        old = latest_revision(store, primary)
        if not old or old.revision != approval.expected_revision:
            raise InputError("REPORT_REVISION_CONFLICT")
        findings = current_findings(store, run, [s.finding_id for s in old.snapshots])
        state = validity(old, findings, store.latest_decisions(run), store)
        if state["evidence_state"] != "CURRENT":
            raise InputError("REPORT_EVIDENCE_REQUIRES_REVIEW")
        if approval.kind in {"NARRATIVE", "RISK_ACCEPTANCE"} and not state["technical_confirmed"]:
            raise InputError("REPORT_TECHNICAL_CONFIRMATION_REQUIRED")
        if approval.kind == "CONSOLIDATION" and (
            len(old.snapshots) < 2 or len(old.consolidation_basis.strip()) < 20
        ):
            raise InputError("REPORT_CONSOLIDATION_BASIS_REQUIRED")
        if approval.kind == "RISK_ACCEPTANCE" and len(approval.rationale.strip()) < 20:
            raise InputError("RISK_ACCEPTANCE_RATIONALE_REQUIRED")
        key = {
            "NARRATIVE": "narrative_approval",
            "RECOMMENDATION": "recommendation_approval",
            "CONSOLIDATION": "consolidation_approval",
            "RISK_ACCEPTANCE": "risk_acceptance",
        }[approval.kind]
        data = old.model_dump()
        data.update(
            revision=old.revision + 1,
            created_at=datetime.now(UTC),
            author=approval.analyst,
        )
        data[key] = {
            "reviewer": approval.analyst,
            "approved_at": datetime.now(UTC).isoformat(),
            "assessment_run": run,
            "rationale": approval.rationale,
        }
        return insert_revision(store, ReportRevision.model_validate(data))


def report_detail(store: Store, run: str, primary: str) -> dict:
    from offline_analyzer.findings.detail import finding_detail

    findings = current_findings(store, run, [primary])
    old = latest_revision(store, primary)
    from offline_analyzer.findings.finalisation import frozen

    location = {
        "storage": str(store.workspace / "assessment.duckdb") + " / report_revisions",
        "frozen": frozen(store, run) is not None,
        "draft_key": primary,
    }
    history = [
        json.loads(raw)
        for (raw,) in store.rows(
            "SELECT data FROM report_revisions "
            "WHERE primary_finding=? ORDER BY revision DESC LIMIT 100",
            [primary],
        )
    ]
    if old:
        members = current_findings(store, run, [s.finding_id for s in old.snapshots])
        return {
            **location,
            "revision": old.model_dump(mode="json"),
            **validity(old, members, store.latest_decisions(run), store),
            "history": history,
            "recommendation": recommendation(findings[primary].rule_id)
            if primary in findings
            else None,
        }
    if primary not in findings:
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    return {
        **location,
        "revision": None,
        "sections": sections_for(
            findings[primary], finding_detail(store, run, primary)
        ).model_dump(),
        "recommendation": recommendation(findings[primary].rule_id),
        "history": [],
        "eligible": False,
    }


def approved_revisions(
    store: Store, run: str, selected: list[str] | None = None
) -> list[ReportRevision]:
    from offline_analyzer.findings.exclusions import excluded

    findings, decisions = current_findings(store, run), store.latest_decisions(run)
    hidden = excluded(store, run)
    rows = store.rows(
        "SELECT data FROM report_revisions QUALIFY "
        "row_number() OVER (PARTITION BY report_id ORDER BY revision DESC)=1 ORDER BY report_id"
    )
    result = []
    for (raw,) in rows:
        revision = ReportRevision.model_validate_json(raw)
        if selected is not None and revision.primary_finding not in selected:
            continue
        if revision.primary_finding in hidden:
            continue  # Excluded from client reporting; the draft itself is kept for Undo.
        if validity(revision, findings, decisions, store)["eligible"]:
            result.append(revision)
    if selected is not None and set(selected) != {r.primary_finding for r in result}:
        raise InputError("SELECTED_REPORT_FINDINGS_NOT_APPROVED")
    included = set()
    for revision in result:
        ids = {s.finding_id for s in revision.snapshots}
        if ids & included:
            raise InputError("REPORT_OVERLAPPING_CONSOLIDATION_SCOPE")
        included.update(ids)
    return result


def verify_snapshots(store: Store, revisions: list[ReportRevision]) -> None:
    checked = set()
    for revision in revisions:
        for snapshot in revision.snapshots:
            for ref in snapshot.evidence:
                digest = ref["sha256"]
                if digest in checked:
                    continue
                row = store.db.execute(
                    "SELECT sha256 FROM artifacts WHERE run_id=? AND artifact_id=?",
                    [revision.run_id, ref["artifact_id"]],
                ).fetchone()
                try:
                    intact = (
                        sha256_file(resolve_under(store.workspace, f"raw/{digest}.json")) == digest
                    )
                except OSError:
                    intact = False
                if not row or row[0] != digest or not intact:
                    raise InputError("REPORT_EVIDENCE_INTEGRITY_FAILURE")
                checked.add(digest)


def register(store: Store, run: str) -> list[dict]:
    from offline_analyzer.findings.exclusions import excluded

    findings, decisions = current_findings(store, run), store.latest_decisions(run)
    hidden = excluded(store, run)
    result = []
    for (raw,) in store.rows(
        "SELECT data FROM report_revisions QUALIFY "
        "row_number() OVER (PARTITION BY report_id ORDER BY revision DESC)=1 ORDER BY report_id"
    ):
        revision = ReportRevision.model_validate_json(raw)
        if revision.primary_finding not in findings or revision.primary_finding in hidden:
            continue
        result.append(
            {
                "primary_finding": revision.primary_finding,
                "report_id": revision.report_id,
                "revision": revision.revision,
                "title": revision.sections.title,
                "severity": revision.sections.severity,
                "members": len(revision.snapshots),
                "include_in_report": revision.include_in_report,
                "recommendation_approved": bool(revision.recommendation_approval),
                "narrative_approved": bool(revision.narrative_approval),
                **validity(revision, findings, decisions, store),
            }
        )
    return result
