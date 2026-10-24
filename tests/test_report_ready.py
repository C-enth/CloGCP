"""Synthetic golden tests for immutable client narratives and approval integrity."""

import threading
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from offline_analyzer.api.app import create_app
from offline_analyzer.api.services import Views
from offline_analyzer.contracts.report_finding import ReportApproval, ReportEdit
from offline_analyzer.enterprise.refresh import refresh_enterprise
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.findings.recommendations import TEMPLATES, recommendation
from offline_analyzer.findings.report_ready import (
    approve_revision,
    approved_revisions,
    current_findings,
    latest_revision,
    report_detail,
    save_revision,
    verify_snapshots,
)
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import record_run_origin, set_environment
from offline_analyzer.release_audit import audit
from offline_analyzer.reporting.approved import rtf_escape
from offline_analyzer.reporting.capabilities import coverage, matrix
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.registry import ALL_RULES
from offline_analyzer.storage.backup import backup, restore
from offline_analyzer.storage.store import Store
from tests.test_api import ORIGIN, TOKEN, authenticated, await_job
from tests.test_enterprise import package as make_package
from tools.fixtures.r12_demo import build


@pytest.fixture
def work(tmp_path):
    package, workspace = tmp_path / "package", tmp_path / "work"
    build(package)
    set_environment(workspace, "SYNTHETIC")
    with Store(workspace) as store:
        run = import_package(store, package)
        record_run_origin(workspace, run, "synthetic")
        assess(store, run)
        yield store, run, list(current_findings(store, run).values())


def edit_for(store, run, finding, **updates):
    data = {
        "expected_revision": 0,
        "analyst": "synthetic-reviewer",
        "sections": report_detail(store, run, finding.finding_id)["sections"],
        "member_ids": [finding.finding_id],
        "include_in_report": True,
    }
    data.update(updates)
    return ReportEdit.model_validate(data)


def approve(store, run, fid, kind, rationale=""):
    old = latest_revision(store, fid)
    return approve_revision(
        store,
        run,
        fid,
        ReportApproval(
            expected_revision=old.revision,
            analyst="synthetic-reviewer",
            kind=kind,
            rationale=rationale,
        ),
    )


def finalize(store, run, finding):
    save_revision(store, run, finding.finding_id, edit_for(store, run, finding))
    record_decision(
        store, run, finding.finding_id, "CONFIRMED", "synthetic-reviewer", "Evidence reviewed"
    )
    approve(store, run, finding.finding_id, "RECOMMENDATION")
    return approve(store, run, finding.finding_id, "NARRATIVE")


def test_all_executable_rules_have_specific_versioned_remediation():
    assert set(TEMPLATES) == {r.rule_id for r in ALL_RULES}
    for rule in ALL_RULES:
        rec = recommendation(rule.rule_id)
        for field in (
            "recommended_action",
            "immediate_mitigation",
            "permanent_remediation",
            "implementation_guidance",
            "operational_considerations",
            "validation_procedure",
        ):
            assert len(rec[field]) > 30
        assert rec["references"] and rec["status"] == "TEMPLATE_REQUIRES_ANALYST_APPROVAL"
    assert "container" in recommendation("R0-EC2-IMDSV2")["operational_considerations"].lower()
    assert recommendation("unknown")["status"] == "ANALYST_AUTHORED_REMEDIATION_REQUIRED"


def test_candidate_rejected_and_independent_approval_gates(work):
    store, run, findings = work
    f = findings[0]
    save_revision(store, run, f.finding_id, edit_for(store, run, f))
    approve(store, run, f.finding_id, "RECOMMENDATION")
    with pytest.raises(InputError, match="TECHNICAL_CONFIRMATION_REQUIRED"):
        approve(store, run, f.finding_id, "NARRATIVE")
    assert not approved_revisions(store, run)
    record_decision(store, run, f.finding_id, "CONFIRMED", "reviewer", "Reviewed")
    assert not approved_revisions(store, run)
    approve(store, run, f.finding_id, "NARRATIVE")
    assert len(approved_revisions(store, run)) == 1
    record_decision(store, run, f.finding_id, "REJECTED", "reviewer", "False positive")
    assert not approved_revisions(store, run)
    assert latest_revision(store, f.finding_id).narrative_approval


def test_revision_copy_is_stable_and_edit_invalidates_approval(work):
    store, run, findings = work
    f = findings[0]
    old = finalize(store, run, f)
    assert "1. Finding Title\n" in old.report_text
    assert "13. Applicable References\n" in old.report_text
    assert f.account_id in old.report_text and f.resource_id in old.report_text
    assert "Not established" in old.report_text
    assert old.snapshots[0].collection_ids and old.snapshots[0].evidence[0]["sha256"]
    approve(
        store,
        run,
        f.finding_id,
        "RISK_ACCEPTANCE",
        "Time-bound risk approved by the synthetic owner.",
    )
    assert latest_revision(store, f.finding_id).report_text == old.report_text
    with pytest.raises(InputError, match="REVISION_CONFLICT"):
        save_revision(
            store, run, f.finding_id, edit_for(store, run, findings[1], member_ids=[f.finding_id])
        )
    updated = old.sections.model_copy(update={"title": "Analyst-approved client title"})
    saved = save_revision(
        store,
        run,
        f.finding_id,
        ReportEdit(
            expected_revision=4,
            analyst="reviewer",
            sections=updated,
            member_ids=[f.finding_id],
            include_in_report=True,
        ),
    )
    assert not saved.recommendation_approval and not saved.narrative_approval
    assert not approved_revisions(store, run)
    assert report_detail(store, run, f.finding_id)["history"][-1]["report_text"] == old.report_text


def test_evidence_refresh_flags_review_retains_approved_text(work):
    store, run, findings = work
    f = findings[0]
    old = finalize(store, run, f)
    changed = f.model_copy(update={"technical_observation": "Changed collection conclusion"})
    store.db.execute(
        "UPDATE findings SET data=? WHERE run_id=? AND finding_id=?",
        [changed.model_dump_json(), run, f.finding_id],
    )
    detail = report_detail(store, run, f.finding_id)
    assert detail["evidence_state"] == "NEEDS_REVIEW" and not detail["eligible"]
    assert detail["revision"]["report_text"] == old.report_text
    with pytest.raises(InputError, match="EVIDENCE_REQUIRES_REVIEW"):
        approve(store, run, f.finding_id, "NARRATIVE")
    store.db.execute("DELETE FROM findings WHERE run_id=? AND finding_id=?", [run, f.finding_id])
    assert report_detail(store, run, f.finding_id)["evidence_state"] == "SUPERSEDED_OR_OUTSIDE_RUN"


def test_consolidated_scope_needs_explicit_approval_and_all_members_confirmed(work):
    store, run, findings = work
    extra = make_package(
        store.workspace.parent / "other-account",
        [
            (
                "rds:DescribeDBInstances",
                {
                    "DBInstances": [
                        {
                            "DBInstanceArn": "arn:aws:rds:us-east-1:222222222222:db:additional",
                            "Engine": "postgres",
                            "StorageEncrypted": False,
                            "PubliclyAccessible": False,
                        }
                    ]
                },
                {},
            )
        ],
        "222222222222",
    )
    extra_run = import_package(store, extra)
    run = assess_enterprise(store, [run, extra_run])
    findings = list(current_findings(store, run).values())
    first = findings[0]
    second = next(f for f in findings if f.account_id != first.account_id)
    # Analyst authors a combined observation; a shared rule ID alone never consolidates.
    save_revision(
        store,
        run,
        first.finding_id,
        edit_for(
            store,
            run,
            first,
            member_ids=[first.finding_id, second.finding_id],
            consolidation_basis=(
                "Shared rollout configuration and accountable remediation "
                "owner verified by analyst."
            ),
        ),
    )
    for f in (first, second):
        record_decision(store, run, f.finding_id, "CONFIRMED", "reviewer", "Scope verified")
    approve(store, run, first.finding_id, "RECOMMENDATION")
    approve(store, run, first.finding_id, "NARRATIVE")
    assert not approved_revisions(store, run)
    revision = approve(store, run, first.finding_id, "CONSOLIDATION")
    assert len(approved_revisions(store, run)) == 1
    assert len({s.account_id for s in revision.snapshots}) == 2
    finalize(store, run, second)
    with pytest.raises(InputError, match="OVERLAPPING_CONSOLIDATION_SCOPE"):
        approved_revisions(store, run)
    assert len(approved_revisions(store, run, [first.finding_id])) == 1


def test_selected_bulk_export_and_integrity_reconciliation(work):
    store, run, findings = work
    old = finalize(store, run, findings[0])
    views = Views(store.workspace)
    report = views.export(store, run, "approved-text")
    text = (store.workspace / "reports" / (report["id"] + ".txt")).read_text()
    assert old.report_text in text and "SYNTHETIC" in text
    rtf = views.export(store, run, "approved-rtf", selected=[findings[0].finding_id])
    assert (store.workspace / "reports" / (rtf["id"] + ".rtf")).read_text().startswith("{\\rtf1")
    with pytest.raises(InputError, match="NOT_APPROVED"):
        views.export(store, run, "approved-rtf", selected=[findings[1].finding_id])
    assert not list((store.workspace / "reports").glob("*.partial"))
    digest = old.snapshots[0].evidence[0]["sha256"]
    (store.workspace / "raw" / f"{digest}.json").write_text("{}")
    with pytest.raises(InputError, match="INTEGRITY_FAILURE"):
        verify_snapshots(store, [old])


@pytest.mark.parametrize("text", ["a{\\field evil}b", "Unicode: Ω 😀", "<script>alert(1)</script>"])
def test_word_export_escapes_literal_text(text):
    result = rtf_escape(text)
    assert "{\\field" not in result
    if "Ω" in text:
        assert "\\u937?" in result and "\\u-10179?" in result
    if "script" in text:
        assert result == text  # plain RTF text; never rendered as HTML


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("title", "  ", "SECTION_REQUIRED"),
        ("technical_observation", "bad\x00text", "CONTROL_CHARACTERS"),
        ("risk", "reverse\u202etext", "CONTROL_CHARACTERS"),
        ("references", ["https://unapproved.example/doc"], "REFERENCE_NOT_APPROVED"),
    ],
)
def test_invalid_report_content_rejected(work, field, value, error):
    store, run, findings = work
    body = edit_for(store, run, findings[0]).model_dump()
    body["sections"][field] = value
    with pytest.raises(InputError, match=error):
        save_revision(store, run, findings[0].finding_id, ReportEdit.model_validate(body))


def test_coverage_distinguishes_import_checks_and_confirmation(work):
    store, run, findings = work
    capabilities = matrix()
    assert capabilities["summary"]["aws_operations_accepted"] == 58
    assert capabilities["summary"]["deterministic_rules"] == 19
    assert all(
        r["actual_export_compatibility"] == "NOT_ESTABLISHED" for r in capabilities["operations"]
    )
    data = coverage(store, run)
    assert sum(s.get("findings_generated", 0) for s in data["services"]) == len(findings)
    assert sum(s.get("analyst_validated", 0) for s in data["services"]) == 0
    finalize(store, run, findings[0])
    assert sum(s.get("analyst_validated", 0) for s in coverage(store, run)["services"]) == 1


def test_report_revisions_survive_backup_restore_and_reopen(tmp_path):
    package, workspace = tmp_path / "package", tmp_path / "work"
    build(package)
    with Store(workspace) as store:
        run = import_package(store, package)
        assess(store, run)
        finding = list(current_findings(store, run).values())[0]
        old = finalize(store, run, finding)
    backup(workspace, tmp_path / "backup")
    restore(tmp_path / "backup", tmp_path / "restored")
    with Store(tmp_path / "restored") as store:
        assert approved_revisions(store, run)[0].model_dump() == old.model_dump()
        verify_snapshots(store, [old])


def test_report_api_copy_export_and_conflict(tmp_path):
    package, workspace = tmp_path / "package", tmp_path / "work"
    build(package)
    with Store(workspace) as store:
        run = import_package(store, package)
        assess(store, run)
        finding = list(current_findings(store, run).values())[0]
        finalize(store, run, finding)
    with TestClient(
        create_app(workspace, origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN
    ) as client:
        headers = authenticated(client)
        path = f"/api/runs/{run}/report-findings/{finding.finding_id}"
        assert client.get(path + "/copy").json()["text"].startswith("1. Finding Title")
        assert client.get(f"/api/runs/{run}/security-coverage").status_code == 200
        assert client.get(f"/api/runs/{run}/report-findings").json()[0]["eligible"]
        export = await_job(
            client,
            client.post(
                f"/api/runs/{run}/reports",
                headers=headers,
                json={"kind": "approved-rtf", "selected": [finding.finding_id]},
            ),
        )
        assert client.get(f"/api/reports/{export['id']}/download").content.startswith(b"{\\rtf1")
        response = client.post(
            path + "/approve",
            headers=headers,
            json={"expected_revision": 1, "analyst": "reviewer", "kind": "NARRATIVE"},
        )
        assert response.json()["error"] == "REPORT_REVISION_CONFLICT"
        invalid = client.post(
            f"/api/runs/{run}/reports",
            headers=headers,
            json={"kind": "excel", "selected": [finding.finding_id]},
        )
        assert invalid.json()["error"] == "SELECTED_SCOPE_ONLY_FOR_APPROVED_REPORTS"


def test_report_jobs_deduplicate_identical_scope_and_keep_distinct_selections(
    tmp_path, monkeypatch
):
    entered, release = threading.Event(), threading.Event()

    def slow_export(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return {"selected": kwargs["selected"]}

    monkeypatch.setattr(Views, "export", slow_export)
    with TestClient(
        create_app(tmp_path / "work", origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN
    ) as client:
        headers = authenticated(client)
        path = "/api/runs/synthetic-job-scope/reports"
        first = client.post(
            path, headers=headers, json={"kind": "approved-rtf", "selected": ["a"]}
        ).json()
        assert entered.wait(5)
        try:
            duplicate = client.post(
                path, headers=headers, json={"kind": "approved-rtf", "selected": ["a"]}
            ).json()
            second = client.post(
                path, headers=headers, json={"kind": "approved-rtf", "selected": ["b"]}
            ).json()
            assert duplicate["id"] == first["id"] and duplicate["deduplicated"]
            assert second["id"] != first["id"]
        finally:
            release.set()


def test_real_import_refresh_preserves_unrelated_approved_text(tmp_path):
    def rds(account, encrypted):
        return [
            (
                "rds:DescribeDBInstances",
                {
                    "DBInstances": [
                        {
                            "DBInstanceArn": f"arn:aws:rds:us-east-1:{account}:db:application",
                            "Engine": "postgres",
                            "StorageEncrypted": encrypted,
                            "PubliclyAccessible": False,
                        }
                    ]
                },
                {},
            )
        ]

    with Store(tmp_path / "work") as store:
        a = import_package(
            store, make_package(tmp_path / "a", rds("111111111111", False), "111111111111")
        )
        b = import_package(
            store, make_package(tmp_path / "b", rds("222222222222", False), "222222222222")
        )
        run = assess_enterprise(store, [a, b])
        originals = {f.account_id: f for f in current_findings(store, run).values()}
        old_a = finalize(store, run, originals["111111111111"])
        old_b = finalize(store, run, originals["222222222222"])
        new_a = import_package(
            store, make_package(tmp_path / "a-new", rds("111111111111", True), "111111111111")
        )
        refreshed = refresh_enterprise(store, run, [new_a])
        new_run = refreshed["run_id"]
        assert (
            report_detail(store, new_run, old_a.primary_finding)["evidence_state"]
            == "SUPERSEDED_OR_OUTSIDE_RUN"
        )
        assert latest_revision(store, old_a.primary_finding).report_text == old_a.report_text
        assert approved_revisions(store, new_run)[0].report_text == old_b.report_text
        assert import_package(store, tmp_path / "a-new") == new_a
        approve(store, new_run, old_b.primary_finding, "NARRATIVE")
        assert latest_revision(store, old_b.primary_finding).run_id == run
    assert audit(tmp_path / "work", new_run)["result"] == "PASS"


def test_every_rule_has_a_specific_misuse_and_impact_explanation():
    from offline_analyzer.findings.explanations import IMPACT, MISUSE, explain
    from offline_analyzer.rules.registry import PROVIDER_RULES

    rules = {r.rule_id: r for r in PROVIDER_RULES}
    assert set(MISUSE) == set(rules)
    assert set(IMPACT) <= set(rules)
    generic = Counter(r.risk for r in PROVIDER_RULES)
    for rule_id, rule in rules.items():
        explanation = explain(
            {
                "rule_id": rule_id,
                "technical_observation": "observed",
                "security_risk": rule.risk,
                "remediation": rule.remediation,
            }
        )
        assert explanation["why_flagged"] == "observed"
        assert explanation["misuse"].endswith("not demonstrated by configuration evidence.)")
        assert explanation["recommendation"], rule_id
        # A risk sentence shared by several rules is replaced by rule-specific impact.
        assert generic[explanation["impact"]] <= 1, rule_id
