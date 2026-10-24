"""Full collector-shaped synthetic import, analysis and linked report execution."""

import argparse
import hashlib
import json
from zipfile import ZipFile

from openpyxl import load_workbook

from offline_analyzer.clogcp import analyze
from offline_analyzer.reporting.gcp_register import COLUMNS
from offline_analyzer.storage.store import Store
from tools.fixtures.clogcp import build


def test_complete_synthetic_workflow_preserves_inputs_and_exports_actual_evidence(tmp_path):
    packages = [build(tmp_path / "secure", 0, secure=True), build(tmp_path / "insecure", 1)]
    before = {
        str(f): hashlib.sha256(f.read_bytes()).hexdigest()
        for p in packages
        for f in p.rglob("*")
        if f.is_file()
    }
    args = argparse.Namespace(
        packages=packages,
        workspace=tmp_path / "work",
        output=tmp_path / "reports",
        history=None,
        synthetic=True,
    )
    result = analyze(args)
    assert result["projects"] == 2 and result["historical_approvals_applied"] == 0
    assert {
        str(f): hashlib.sha256(f.read_bytes()).hexdigest()
        for p in packages
        for f in p.rglob("*")
        if f.is_file()
    } == before
    with Store(args.workspace) as store:
        findings = list(store.candidates(result["run"]))
        insecure = {f.rule_id for f in findings if f.project_id == "synth-clogcp-01"}
        assert {
            "GCP-GKE-LEGACY-ABAC",
            "GCP-RUN-PUBLIC",
            "GCP-FUNCTION-PUBLIC",
            "GCP-BQ-PUBLIC-DATA",
            "GCP-SQL-EXPLICIT-FLAGS",
            "GCP-DNS-DNSSEC",
            "GCP-LB-TLS",
            "GCP-KMS-ROTATION",
            "GCP-NET-FIREWALL-POLICY",
        } <= insecure
        secure = {f.rule_id for f in findings if f.project_id == "synth-clogcp-00"}
        assert not {
            "GCP-GKE-LEGACY-ABAC",
            "GCP-RUN-PUBLIC",
            "GCP-FUNCTION-PUBLIC",
            "GCP-BQ-PUBLIC-DATA",
            "GCP-SQL-EXPLICIT-FLAGS",
            "GCP-DNS-DNSSEC",
            "GCP-LB-TLS",
            "GCP-KMS-ROTATION",
        }.intersection(secure)
        from offline_analyzer.findings.detail import finding_detail
        from offline_analyzer.findings.explanations import explain
        from offline_analyzer.rules.gcp_domains import SPECS

        for finding in findings:
            if finding.rule_id in SPECS:
                detail = finding_detail(store, result["run"], finding.finding_id)
                assert detail["overview"]["finding_id"] == finding.finding_id
                assert detail["evidence"]
                assert detail["remediation"]["recommended_action"]
                assert explain(finding)["why_flagged"]
        artifacts = {
            s["artifact_id"] for s in store.source_data(result["run"]) if s.get("artifact_id")
        }
        assert all(
            f.evidence and all(e.artifact_id in artifacts for e in f.evidence) for f in findings
        )
        assert len({(f.project_id, f.resource_id, f.rule_id) for f in findings}) == len(findings)
    book = load_workbook(args.output / "CloGCP_Assessment.xlsx", read_only=True)
    assert tuple(next(book["GCP_Observation_Register"].values)) == COLUMNS
    assert len(list(book["GCP_Evidence_Index"].values)) > 1
    assert len(list(book["GCP_Evidence_Details"].values)) > 1
    details = list(book["GCP_Evidence_Details"].values)
    assert any("legacyAbac" in str(row) for row in details)
    book.close()
    assurance = json.loads((args.output / "CloGCP_Analysis_Assurance.json").read_text())
    assert assurance["Dataset Coverage"]
    assert assurance["Unassessed Families"]
    assert any(r["evaluator_executions"] for r in assurance["Dataset Coverage"])
    assert all(r["current_approval"] == "PENDING" for r in assurance["Finding Comparison"])
    with ZipFile(args.output / "CloGCP_Assessment_Report.zip") as archive:
        assert archive.testzip() is None


def test_coverage_context_consumers_reference_registered_rules():
    from offline_analyzer.reporting.clogcp_assurance import CONTEXT_RULES, coverage_matrix
    from offline_analyzer.rules.registry import BY_ID

    assert len(coverage_matrix()) == 118
    assert all(r in BY_ID for rules in CONTEXT_RULES.values() for r in rules)
    assert all(r["limitation"] and r["analysis_status"] for r in coverage_matrix())
