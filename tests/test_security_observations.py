"""Additional technical observations retain incomplete authorization dependencies."""

import json

import pytest

from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.findings.report_ready import current_findings
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.release_audit import audit
from offline_analyzer.reporting.collection import collection_readiness
from offline_analyzer.storage.store import Store
from tests.test_enterprise import A, B, package
from tools.fixtures.r12_demo import allow, deny, doc, gaad_role, trust


@pytest.mark.parametrize(
    "principal,condition,action,expected",
    [
        ("*", None, "kms:Decrypt", "FAIL"),
        ({"AWS": "*"}, None, "kms:*", "FAIL"),
        ("*", {"StringEquals": {"kms:CallerAccount": A}}, "kms:Decrypt", "PASS"),
        ({"AWS": f"arn:aws:iam::{B}:role/external"}, None, "kms:Decrypt", "PASS"),
        ("*", None, "s3:GetObject", "PASS"),
        (None, None, "kms:Decrypt", "UNKNOWN"),
    ],
)
def test_kms_wildcard_principal_pattern_not_effective_decryption(
    tmp_path, principal, condition, action, expected
):
    statement = {"Effect": "Allow", "Action": action, "Resource": "*", "Principal": principal}
    if condition is not None:
        statement["Condition"] = condition
    key = f"arn:aws:kms:us-east-1:{A}:key/12345678-1234-1234-1234-123456789012"
    folder = package(
        tmp_path / "input",
        [
            (
                "kms:GetKeyPolicy",
                {"Policy": json.dumps(doc(statement))},
                {"KeyId": key, "PolicyName": "default"},
            )
        ],
        A,
    )
    with Store(tmp_path / "work") as store:
        run = import_package(store, folder)
        run = assess_enterprise(store, [run])
        result = next(r for r in store.results(run) if r.rule_id == "SEC-KMS-WILDCARD-PRINCIPAL")
        assert str(result.outcome) == expected
        findings = [
            f for f in current_findings(store, run).values() if f.rule_id.startswith("SEC-")
        ]
        if expected == "FAIL":
            finding = findings[0]
            assert (
                finding.methodology_id == "AWS-12" and finding.finding_class == "POTENTIAL_EXPOSURE"
            )
            assert finding.mapping_status == "PROPOSED"
            assert "not established" in finding.exposure_status
            assert "Data classification" in " ".join(finding.missing_evidence)
            assert (
                store.db.execute(
                    "SELECT count(*) FROM security_investigations WHERE run_id=?", [run]
                ).fetchone()[0]
                == 1
            )
            request = collection_readiness(store, run)["evidence_requests"]
            assert any(r["operation"] == "kms:ListGrants" for r in request)
        else:
            assert not findings


@pytest.mark.parametrize(
    "policy,attached,expected",
    [
        (doc(allow("*")), [], "FAIL"),
        (doc(allow("*"), deny("*")), [], "FAIL"),  # observed broad grant, not effective access
        (doc(allow("s3:GetObject")), [], "PASS"),
        (doc(allow("s3:GetObject")), [f"arn:aws:iam::{A}:policy/missing"], "UNKNOWN"),
    ],
)
def test_role_wildcard_preserves_restrictions_and_missing_policy_versions(
    tmp_path, policy, attached, expected
):
    role = gaad_role(
        A,
        "application",
        trust({"Service": "lambda.amazonaws.com"}),
        inline={"application": policy},
        attached=attached,
    )
    folder = package(
        tmp_path / "input",
        [
            (
                "iam:GetAccountAuthorizationDetails",
                {"RoleDetailList": [role], "Policies": [], "IsTruncated": False},
                {},
            )
        ],
        A,
    )
    with Store(tmp_path / "work") as store:
        run = import_package(store, folder)
        run = assess_enterprise(store, [run])
        result = next(r for r in store.results(run) if r.rule_id == "SEC-IAM-ROLE-WILDCARD")
        assert str(result.outcome) == expected
        if expected == "FAIL":
            assert "not established" in result.exposure_status
            assert result.evidence_needed and result.evidence
    report = audit(tmp_path / "work", run)
    assert report["result"] == "PASS", report


def test_additional_investigation_origin_required_by_release_audit(tmp_path):
    role = gaad_role(
        A,
        "application",
        trust({"Service": "lambda.amazonaws.com"}),
        inline={"application": doc(allow("*"))},
    )
    folder = package(
        tmp_path / "input",
        [
            (
                "iam:GetAccountAuthorizationDetails",
                {"RoleDetailList": [role], "Policies": [], "IsTruncated": False},
                {},
            )
        ],
        A,
    )
    with Store(tmp_path / "work") as store:
        run = import_package(store, folder)
        run = assess_enterprise(store, [run])
        finding = next(f for f in store.candidates(run) if f.rule_id.startswith("SEC-"))
        record_decision(
            store, run, finding.finding_id, "CONFIRMED", "synthetic-reviewer", "Evidence reviewed"
        )
    assert audit(tmp_path / "work", run)["result"] == "PASS"
    with Store(tmp_path / "work") as store:
        store.db.execute("DELETE FROM security_investigations")
    report = audit(tmp_path / "work", run)
    assert report["result"] == "FAIL"
    assert (
        report["findings"]["violations"]["additional_observation_without_traceable_investigation"]
        == 1
    )
