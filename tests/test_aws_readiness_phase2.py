"""AWS readiness phase 2: platform-managed identity classification, trust conditions,
organization-control awareness, AP-06 prerequisites and workload-identity context.
Synthetic data only (documented synthetic account IDs)."""

import pytest

from offline_analyzer.attack_paths.feasibility import attack_paths
from offline_analyzer.attack_paths.prerequisites import iam_escalation
from offline_analyzer.contracts.exclusion import ExclusionRequest
from offline_analyzer.findings.exclusions import listing, record
from offline_analyzer.iam.analysis import IamAnalysis
from offline_analyzer.iam.policy import parse_policy
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.reporting.assessment_report import model
from offline_analyzer.rules import aws_identity as identity
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.registry import AWS_IDENTITY_ENRICHED, AWS_PRINCIPAL_CONTEXT_RULES
from offline_analyzer.storage.store import Store
from tools.fixtures.aws_readiness import (
    A,
    B,
    iam,
    organization,
    platform_policies,
    platform_roles,
    workload,
    write,
)
from tools.fixtures.r12_demo import allow, doc

WHEN = "2026-10-01T00:00:00+00:00"
PREFIX = f"arn:aws:iam::{A}:role/"
ROLE = PREFIX + "OrganizationAccountAccessRole"
SCOPE = identity.Scope(
    collected=frozenset({A}),
    registered=frozenset({"222222222222"}),
    organization_members=frozenset({B, "555555555555"}),
    management=frozenset({B}),
    management_evidence={B: "DescribeOrganization o-synthetic01"},
)


@pytest.mark.parametrize(
    ("principal", "kind", "role", "expected"),
    [
        ("lambda.amazonaws.com", "Service", ROLE, identity.PLATFORM_MANAGED),
        ("not a service", "Service", ROLE, identity.UNKNOWN),
        ("*", "AWS", ROLE, identity.EXTERNAL_OR_UNKNOWN),
        (f"arn:aws:iam::{A}:role/x", "AWS", ROLE, identity.SAME_ACCOUNT),
        (f"arn:aws:iam::{B}:root", "AWS", ROLE, identity.PLATFORM_MANAGED),
        # The management account trusting an ordinary role is not platform-managed.
        (
            f"arn:aws:iam::{B}:root",
            "AWS",
            f"arn:aws:iam::{A}:role/app",
            identity.IN_ORG_NOT_ASSESSED,
        ),
        ("222222222222", "AWS", ROLE, identity.IN_SCOPE_OTHER_ACCOUNT),
        ("arn:aws:iam::555555555555:root", "AWS", ROLE, identity.IN_ORG_NOT_ASSESSED),
        ("arn:aws:iam::333333333333:root", "AWS", ROLE, identity.EXTERNAL_OR_UNKNOWN),
        ("AROAEXAMPLEUNIQUEID01", "AWS", ROLE, identity.UNKNOWN),  # deleted principal
        ("arn:aws:iam::saml-provider/x", "Federated", ROLE, identity.UNKNOWN),
    ],
)
def test_trust_classes(principal, kind, role, expected):
    found = identity.classify(principal, kind, role, SCOPE)
    assert found.trust == expected and found.evidence


def test_management_account_needs_organization_evidence():
    # Same role name, no DescribeOrganization evidence: never platform-managed by name alone.
    bare = identity.Scope(collected=frozenset({A}))
    assert identity.classify(f"arn:aws:iam::{B}:root", "AWS", ROLE, bare).trust == (
        identity.EXTERNAL_OR_UNKNOWN
    )


@pytest.mark.parametrize(
    ("arn", "expected"),
    [
        (f"{PREFIX}aws-service-role/x.amazonaws.com/AWSServiceRoleForX", "SERVICE_LINKED"),
        (f"{PREFIX}aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_1", "IDENTITY_CENTER"),
        (ROLE, "ORGANIZATION_ACCESS"),
        (f"arn:aws:iam::{A}:role/AWSControlTowerExecution", "ORGANIZATION_ACCESS"),
        (f"arn:aws:iam::{A}:role/app", "CUSTOMER"),
    ],
)  # fmt: skip
def test_role_classes(arn, expected):
    assert identity.role_class(arn)[0] == expected


def test_conditions_render_binding_keys_and_never_the_external_id():
    statement = parse_policy(
        doc(
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "secret-ish",
                        "aws:PrincipalOrgID": "o-synthetic01",
                        "aws:SourceAccount": A,
                    },
                    "ArnLike": {"aws:SourceArn": f"arn:aws:s3:::bucket-{A}"},
                    "Bool": {"aws:MultiFactorAuthPresent": "true"},
                },
            }
        ),
        "t",
    ).statements[0]
    text = identity.render_conditions(statement)
    assert "secret-ish" not in text and "sts:ExternalId (value set, not shown)" in text
    assert "aws:PrincipalOrgID=o-synthetic01" in text and f"aws:SourceAccount={A}" in text
    assert f"aws:SourceArn=arn:aws:s3:::bucket-{A}" in text
    assert "other conditions: Bool aws:MultiFactorAuthPresent" in text
    assert identity.render_conditions(parse_policy(doc(allow("*")), "x").statements[0]) == (
        "no Condition"
    )


def test_long_text_is_split_not_dropped():
    text = "; ".join(f"part-{i:03d}-" + "x" * 40 for i in range(40))
    parts = identity.chunks(text)
    assert all(len(p) <= 512 for p in parts) and len(parts) > 1
    joined = parts[0] + "; " + "; ".join(p.removeprefix("(continued) ") for p in parts[1:])
    assert joined == text


def test_registry_opt_in():
    assert AWS_IDENTITY_ENRICHED == {
        "R1-IAM-ROLE-TRUST-CONDITIONS",
        "R1-IAM-INSTANCE-ROLE-PRIVILEGE",
        "SEC-IAM-ROLE-WILDCARD",
    }
    assert AWS_PRINCIPAL_CONTEXT_RULES == {"R1-EC2-SG-SENSITIVE-INGRESS"}


def platform(tmp_path, with_organization=True):
    items = iam(A, B, roles=platform_roles(A, B), policies=platform_policies())
    if with_organization:
        items += organization(A, B)
    store = Store(tmp_path / "work")
    run = import_package(store, write(tmp_path / "p", items, WHEN))
    assess(store, run)
    return store, run


def result(store, run, rule, name):
    return next(
        r
        for r in store.results(run)
        if r.rule_id == rule
        and r.evaluation_scope == "RESOURCE"
        and (r.native_id or "").endswith("/" + name)
    )


def test_organization_access_role_reclassified_with_evidence(tmp_path):
    store, run = platform(tmp_path)
    try:
        for name in ("OrganizationAccountAccessRole", "AWSControlTowerExecution"):
            r = result(store, run, "R1-IAM-ROLE-TRUST-CONDITIONS", name)
            assert str(r.outcome) == "FAIL"  # the source clause still fails
            assert (r.finding_class, r.suggested_severity) == ("BASELINE_DEVIATION", "MEDIUM")
            assert r.exposure_status.startswith(
                "Reclassified from POTENTIAL_EXPOSURE/HIGH to BASELINE_DEVIATION/MEDIUM"
            )
            assert "UNCONDITIONED EXTERNAL TRUST" in r.exposure_status
            assert any(
                line.startswith("Platform-managed reclassification evidence:")
                and "DescribeOrganization o-synthetic01" in line
                for line in r.limitations
            )
            exposure = "Exposure: Trust allows sts:AssumeRole"
            assert any(line.startswith(exposure) for line in r.limitations)
    finally:
        store.__exit__()


def test_without_organization_evidence_nothing_is_lowered(tmp_path):
    store, run = platform(tmp_path, with_organization=False)
    try:
        r = result(store, run, "R1-IAM-ROLE-TRUST-CONDITIONS", "OrganizationAccountAccessRole")
        assert (r.finding_class, r.suggested_severity) == ("POTENTIAL_EXPOSURE", "HIGH")
        assert "EXTERNAL_OR_UNKNOWN" in r.exposure_status
        assert any("Organization controls not assessed" in line for line in r.limitations)
    finally:
        store.__exit__()


def test_trust_conditions_and_service_principals_are_rendered(tmp_path):
    store, run = platform(tmp_path)
    try:
        vendor = result(store, run, "R1-IAM-ROLE-TRUST-CONDITIONS", "vendor-external-id")
        assert str(vendor.outcome) == "PASS"
        assert any("sts:ExternalId (value set, not shown)" in line for line in vendor.limitations)
        assert not any("synthetic-shared-value" in line for line in vendor.limitations)
        config = result(store, run, "R1-IAM-ROLE-TRUST-CONDITIONS", "svc-config-bound")
        assert str(config.outcome) == "NOT_APPLICABLE"
        assert any(f"aws:SourceAccount={A}" in line for line in config.limitations)
        service = "trust PLATFORM_MANAGED: AWS service principal"
        assert any(service in line for line in config.limitations)
    finally:
        store.__exit__()


def test_scp_awareness_keeps_severity_and_states_the_gap(tmp_path):
    store, run = platform(tmp_path)
    try:
        sso = result(
            store,
            run,
            "SEC-IAM-ROLE-WILDCARD",
            "AWSReservedSSO_AdministratorAccess_0123456789abcdef",
        )
        assert (sso.finding_class, sso.suggested_severity) == ("POTENTIAL_EXPOSURE", "MEDIUM")
        assert any(line.startswith("Role class IDENTITY_CENTER") for line in sso.limitations)
        assert any("Organization controls not fully assessed" in line for line in sso.limitations)
        analysis = IamAnalysis(store, run, list(store.source_data(run)))
        records = {r.principal.rsplit("/", 1)[-1]: r for r in analysis.passrole()}
        for name in ("OrganizationAccountAccessRole", "svc-lambda-admin"):
            role = analysis.inventory.by_arn[records[name].principal]
            level, notes = analysis.privilege(role)
            assert level == "POTENTIALLY_PRIVILEGED"  # unchanged: SCPs are not assessed
            assert any("organization controls (SCP) are not assessed" in n for n in notes)
            assert records[name].classification == "NOT_AN_ESCALATION"
            assert "Organization controls (SCP) are not assessed" in records[name].reasoning
        slr = records["AWSServiceRoleForAutoScaling"]
        assert slr.classification == "NOT_AN_ESCALATION" and "Service-linked" in slr.reasoning
        notes = [n for n in model(store, run, "all")["coverage_notes"] if n["scope"] == A]
        assert any(n["code"] == "ORGANIZATION_CONTROLS_NOT_ASSESSED" for n in notes)
    finally:
        store.__exit__()


def test_ap06_links_findings_maps_stride_and_honours_exclusion(tmp_path):
    store, run = platform(tmp_path)
    try:
        paths = [p for p in attack_paths(store, run)["items"] if p["attack_path"] == "AP-06"]
        anchors = {p["anchor"].rsplit("/", 1)[-1] for p in paths}
        # Admin and service-linked PassRole principals are not escalation candidates; the
        # organization access roles are reached through cross-account trust (P2).
        assert anchors == {"OrganizationAccountAccessRole", "AWSControlTowerExecution"}
        for path in paths:
            assert path["prerequisites"]["AP-06.P2"] == "VERIFIED"
            assert path["finding_ids"] and path["stride"] == ["Elevation of Privilege"]
            assert path["proof_status"] == "HYPOTHESIS" and path["missing_evidence_named"]
            assert path["feasibility"] == "INSUFFICIENT_EVIDENCE"
            assert path["hops"][0]["status"] == "PROVEN"
        target = paths[0]
        trust_finding = next(
            f for f in store.candidates(run)
            if f.finding_id in target["finding_ids"] and f.rule_id == "R1-IAM-ROLE-TRUST-CONDITIONS"
        )  # fmt: skip
        preset = "AWS Organizations / Control Tower management access role (platform-managed)"
        assert preset in listing(store, run)["false_positive_presets"]
        record(
            store,
            run,
            trust_finding.finding_id,
            ExclusionRequest(action="EXCLUDE", reason="FALSE_POSITIVE", note=preset,
                             analyst="synthetic"),
        )  # fmt: skip
        after = {p["path_id"]: p for p in attack_paths(store, run)["items"]}
        assert after[target["path_id"]]["false_positive_dependency"]["finding_ids"] == [
            trust_finding.finding_id
        ]
    finally:
        store.__exit__()


def test_ap06_p2_is_declared_unverifiable_without_trust_results(tmp_path):
    store, run = platform(tmp_path)
    try:
        analysis = IamAnalysis(store, run, list(store.source_data(run)))
        assert iam_escalation(analysis) == []  # no candidates without the trust results
        results = list(store.results(run))
        records = iam_escalation(analysis, results)
        assert records and all(r.prerequisites["AP-06.P2"] == "VERIFIED" for r in records)
        trust_free = [r for r in results if r.rule_id != "R1-IAM-ROLE-TRUST-CONDITIONS"]
        assert iam_escalation(analysis, trust_free) == []
    finally:
        store.__exit__()


def workload_run(tmp_path, name, document, management=True, routes=False):
    items = workload(A, name, document, routes)
    if management:
        items += organization(A, A)  # SCPs never apply to the management account
    store = Store(tmp_path / "work")
    run = import_package(store, write(tmp_path / "p", items, WHEN))
    assess(store, run)
    sg = next(
        r for r in store.results(run)
        if r.rule_id == "R1-EC2-SG-SENSITIVE-INGRESS" and r.evaluation_scope == "RESOURCE"
    )  # fmt: skip
    return store, sg


def test_privileged_instance_role_raises_exposure(tmp_path):
    store, sg = workload_run(tmp_path, "app-admin", doc(allow("*")))
    try:
        assert str(sg.outcome) == "FAIL" and sg.finding_class == "POTENTIAL_EXPOSURE"
        assert sg.suggested_severity == "HIGH"  # route evidence missing: base MEDIUM
        assert sg.exposure_status.startswith("Raised from MEDIUM to HIGH")
        assert any("ADMIN_EQUIVALENT (supported by evidence)" in line for line in sg.limitations)
    finally:
        store.__exit__()


def test_least_privilege_instance_role_is_labelled_not_lowered(tmp_path):
    store, sg = workload_run(tmp_path, "app-read", doc(allow("s3:GetObject")))
    try:
        assert sg.suggested_severity == "MEDIUM"
        assert any("least privilege for the evaluated probes" in line for line in sg.limitations)
    finally:
        store.__exit__()


def test_unresolved_instance_role_is_never_narrowed(tmp_path):
    store, sg = workload_run(tmp_path, "missing", None, management=False)
    try:
        assert sg.suggested_severity == "MEDIUM"
        assert any("UNRESOLVED" in line for line in sg.limitations)
        assert not any("least privilege" in line for line in sg.limitations)
    finally:
        store.__exit__()
