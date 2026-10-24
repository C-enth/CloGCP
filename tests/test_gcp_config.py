"""Synthetic GCP configuration regression: missing data, correlation and review lifecycle."""

import hashlib
import json
from datetime import UTC, datetime

import pytest

from offline_analyzer.contracts.models import EvidenceRef
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.findings.detail import finding_detail
from offline_analyzer.findings.explanations import explain
from offline_analyzer.findings.generate import record_decision, validation_status
from offline_analyzer.findings.recommendations import recommendation
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.methodology.cloud_checklist import matrix
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.gcp import evaluate
from offline_analyzer.rules.gcp_config import DEFINITIONS, DETAIL, FULL_SCOPE
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import PROJECT, expanded22

NETWORK = f"projects/{PROJECT}/global/networks/shared"
SA = "123456789012-compute@developer.gserviceaccount.com"
FIREWALL = {
    "network": NETWORK,
    "direction": "INGRESS",
    "sourceRanges": ["0.0.0.0/0"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    "priority": 1000,
}


def observation(rule, config, identity="sample", **changes):
    kind, operation = DEFINITIONS[rule][:2]
    return Normalized(
        observation_id=identity,
        provider="GCP",
        project_id=PROJECT,
        resource_id=f"gcp://{PROJECT}/{kind}/{identity}",
        native_id=identity,
        account_id=None,
        region="global",
        resource_type=kind,
        partition=None,
        source_tool="gcp",
        source_version="synthetic",
        source_check_id=operation,
        source_status="SUCCESS",
        source_severity=None,
        collected_at=datetime(2026, 10, 16, tzinfo=UTC),
        operation=operation,
        configuration=config,
        evidence=EvidenceRef(artifact_id="synthetic", locator="/0"),
        integrity_sha256="0" * 64,
    ).model_copy(update=changes)


# Explicit good/bad values for every executable configuration criterion that can fail.
CASES = [
    ("GCP-NET-FW-ADMIN-INTERNET", {**FIREWALL, "sourceRanges": ["10.0.0.0/8"]}, FIREWALL),
    (
        "GCP-NET-FW-DB-INTERNET",
        FIREWALL,
        {**FIREWALL, "allowed": [{"IPProtocol": "tcp", "ports": ["5432"]}]},
    ),
    ("GCP-NET-FW-ANY-INTERNET", FIREWALL, {**FIREWALL, "allowed": [{"IPProtocol": "all"}]}),
    ("GCP-NET-DEFAULT-NETWORK", {"name": "private"}, {"name": "default"}),
    ("GCP-NET-FLOW-LOGS", {"logConfig": {"enable": True}}, {"enableFlowLogs": False}),
    (
        "GCP-NET-PRIVATE-GOOGLE-ACCESS",
        {"privateIpGoogleAccess": True},
        {"privateIpGoogleAccess": False},
    ),
    (
        "GCP-VM-EXTERNAL-IP",
        {"networkInterfaces": [{"accessConfigs": []}]},
        {"networkInterfaces": [{"accessConfigs": [{"natIP": "192.0.2.1"}]}]},
    ),
    ("GCP-VM-DEFAULT-SA", {"serviceAccounts": []}, {"serviceAccounts": [{"email": SA}]}),
    (
        "GCP-VM-FULL-API-SCOPE",
        {"serviceAccounts": [{"email": SA, "scopes": []}]},
        {"serviceAccounts": [{"email": SA, "scopes": [FULL_SCOPE]}]},
    ),
    (
        "GCP-VM-SERIAL-PORT",
        {"metadata": {"items": [{"key": "serial-port-enable", "value": "false"}]}},
        {"metadata": {"items": [{"key": "serial-port-enable", "value": "true"}]}},
    ),
    (
        "GCP-VM-OSLOGIN",
        {"metadata": {"items": [{"key": "enable-oslogin", "value": "true"}]}},
        {"metadata": {"items": [{"key": "enable-oslogin", "value": "false"}]}},
    ),
    (
        "GCP-VM-PROJECT-SSH-KEYS",
        {"metadata": {"items": [{"key": "enable-oslogin", "value": "true"}]}},
        {
            "metadata": {
                "items": [
                    {"key": "enable-oslogin", "value": "false"},
                    {"key": "block-project-ssh-keys", "value": "false"},
                ]
            }
        },
    ),
    (
        "GCP-VM-SHIELDED",
        {
            "shieldedInstanceConfig": {
                "enableSecureBoot": True,
                "enableVtpm": True,
                "enableIntegrityMonitoring": True,
            }
        },
        {"shieldedInstanceConfig": {"enableSecureBoot": False}},
    ),
    ("GCP-VM-IP-FORWARD", {"canIpForward": False}, {"canIpForward": True}),
    (
        "GCP-STORAGE-UBLA",
        {"uniform_bucket_level_access": True},
        {"uniform_bucket_level_access": False},
    ),
    ("GCP-STORAGE-VERSIONING", {"versioning": {"enabled": True}}, {"versioning_enabled": False}),
    (
        "GCP-SQL-OPEN-NETWORK",
        {"settings": {"ipConfiguration": {"ipv4Enabled": False}}},
        {
            "settings": {
                "ipConfiguration": {
                    "ipv4Enabled": True,
                    "authorizedNetworks": [{"value": "0.0.0.0/0"}],
                }
            }
        },
    ),
    (
        "GCP-SQL-PUBLIC-IP",
        {"settings": {"ipConfiguration": {"ipv4Enabled": False}}},
        {"settings": {"ipConfiguration": {"ipv4Enabled": True}}},
    ),
    (
        "GCP-SQL-TLS",
        {"settings": {"ipConfiguration": {"sslMode": "ENCRYPTED_ONLY"}}},
        {"settings": {"ipConfiguration": {"requireSsl": False}}},
    ),
    (
        "GCP-SQL-BACKUP",
        {"settings": {"backupConfiguration": {"enabled": True}}},
        {"settings": {"backupConfiguration": {"enabled": False}}},
    ),
    (
        "GCP-KMS-ROTATION",
        {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s"},
        {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000.1s"},
    ),
]


@pytest.mark.parametrize("rule,good,bad", CASES, ids=[r[0] for r in CASES])
def test_explicit_positive_and_negative(rule, good, bad):
    assert evaluate(rule, observation(rule, good)).outcome == "PASS"
    assert evaluate(rule, observation(rule, bad)).outcome == "FAIL"


@pytest.mark.parametrize("rule", DEFINITIONS)
def test_missing_fields_never_establish_pass_or_finding(rule):
    answer = evaluate(rule, observation(rule, {}))
    assert answer.outcome == "UNKNOWN" and answer.missing
    advice = recommendation(rule)
    assert advice["validation_procedure"] and advice["recommended_action"]
    assert DETAIL[rule][5] in advice["validation_procedure"]
    assert explain({"rule_id": rule, "technical_observation": "synthetic"})["misuse"]


@pytest.mark.parametrize("rule", DEFINITIONS)
def test_malformed_metadata_is_bounded_and_not_a_pass(rule):
    fields = {
        key: 42
        for key in (
            "metadata",
            "serviceAccounts",
            "networkInterfaces",
            "settings",
            "logConfig",
            "iamConfiguration",
            "versioning",
            "name",
            "allowed",
            "denied",
        )
    }
    assert evaluate(rule, observation(rule, fields)).outcome == "UNKNOWN"


def test_policy_inheritance_and_objectives_remain_unresolved():
    rule = "GCP-STORAGE-PAP"
    assert (
        evaluate(rule, observation(rule, {"public_access_prevention": "enforced"})).outcome
        == "PASS"
    )
    inherited = observation(rule, {"public_access_prevention": "inherited"})
    org = observation(
        rule,
        {
            "constraint": "storage.publicAccessPrevention",
            "spec": {"rules": [{"enforce": True, "condition": {"expression": "false"}}]},
        },
    )
    assert evaluate(rule, inherited, [org]).outcome == "UNKNOWN"
    rule = "GCP-LOG-RETENTION"
    answer = evaluate(rule, observation(rule, {"retentionDays": 30}))
    assert answer.outcome == "MANUAL_VALIDATION_REQUIRED" and answer.evidence_needed
    assert evaluate(rule, observation(rule, {"name": "_Required"})).outcome == "NOT_APPLICABLE"


@pytest.mark.parametrize(
    "rule,config",
    [
        ("GCP-NET-FW-ADMIN-INTERNET", {**FIREWALL, "disabled": True}),
        ("GCP-NET-FW-DB-INTERNET", {**FIREWALL, "direction": "EGRESS"}),
        ("GCP-NET-FLOW-LOGS", {"purpose": "REGIONAL_MANAGED_PROXY"}),
        ("GCP-SQL-BACKUP", {"instanceType": "READ_REPLICA_INSTANCE"}),
        ("GCP-KMS-ROTATION", {"purpose": "ASYMMETRIC_SIGN"}),
    ],
)
def test_explicit_inapplicability(rule, config):
    assert evaluate(rule, observation(rule, config)).outcome == "NOT_APPLICABLE"


def test_firewall_deduplication_and_protocols():
    for protocol in ("all", "tcp", "6", "udp", "17"):
        config = {**FIREWALL, "allowed": [{"IPProtocol": protocol}]}
        assert (
            evaluate(
                "GCP-NET-FW-ADMIN-INTERNET", observation("GCP-NET-FW-ADMIN-INTERNET", config)
            ).outcome
            == "NOT_APPLICABLE"
        )
        assert (
            evaluate(
                "GCP-NET-FW-ANY-INTERNET", observation("GCP-NET-FW-ANY-INTERNET", config)
            ).outcome
            == "FAIL"
        )
    config = {**FIREWALL, "allowed": [{"IPProtocol": "icmp"}]}
    assert (
        evaluate(
            "GCP-NET-FW-ADMIN-INTERNET", observation("GCP-NET-FW-ADMIN-INTERNET", config)
        ).outcome
        == "PASS"
    )
    assert (
        evaluate("GCP-NET-FW-ANY-INTERNET", observation("GCP-NET-FW-ANY-INTERNET", config)).outcome
        == "PASS"
    )


def test_deny_priority_family_and_complete_range():
    rule = "GCP-NET-FW-ADMIN-INTERNET"
    allow = observation(rule, FIREWALL)
    deny = observation(
        rule,
        {**FIREWALL, "allowed": [], "denied": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        "deny",
    )
    assert evaluate(rule, allow, [deny]).outcome == "PASS"  # same priority: deny wins
    for update in (
        {"priority": 2000},
        {"sourceRanges": ["::/0"]},
        {"network": "projects/other/global/networks/shared"},
        {"targetTags": ["private"]},
    ):
        narrow = deny.model_copy(update={"configuration": {**deny.configuration, **update}})
        assert evaluate(rule, allow, [narrow]).outcome == "FAIL"
    assert (
        evaluate(rule, allow, [deny.model_copy(update={"source_status": "TRUNCATED"})]).outcome
        == "FAIL"
    )
    rule = "GCP-NET-FW-ANY-INTERNET"
    allow = observation(rule, {**FIREWALL, "allowed": [{"IPProtocol": "all"}]})
    assert evaluate(rule, allow, [deny]).outcome == "FAIL"
    # Denying TCP cannot establish all-protocol coverage.
    deny = deny.model_copy(
        update={"configuration": {**deny.configuration, "denied": [{"IPProtocol": "tcp"}]}}
    )
    assert evaluate(rule, allow, [deny]).outcome == "FAIL"


def test_target_matching_uses_all_interfaces_and_exact_network_and_family():
    rule = "GCP-NET-FW-ADMIN-INTERNET"
    allow = observation(rule, {**FIREWALL, "targetTags": ["web"]})
    vm = observation(
        "GCP-VM-EXTERNAL-IP",
        {
            "status": "RUNNING",
            "tags": {"items": ["web"]},
            "networkInterfaces": [
                {
                    "network": "projects/other/global/networks/shared",
                    "accessConfigs": [{"natIP": "192.0.2.1"}],
                },
                {"network": NETWORK, "accessConfigs": [{"natIP": "192.0.2.2"}]},
            ],
        },
        "vm",
    )
    answer = evaluate(rule, allow, [vm])
    assert answer.finding_class == "POTENTIAL_EXPOSURE" and answer.severity == "HIGH"
    assert answer.related == ("vm",) and answer.limitations
    assert "ACTIVE" not in answer.exposure
    for update in (
        {"tags": {"items": ["other"]}},
        {"networkInterfaces": [vm.configuration["networkInterfaces"][0]]},
        {
            "networkInterfaces": [
                {"network": NETWORK, "ipv6AccessConfigs": [{"externalIpv6": "2001:db8::1"}]}
            ]
        },
    ):
        other = vm.model_copy(update={"configuration": {**vm.configuration, **update}})
        assert evaluate(rule, allow, [other]).finding_class == "BASELINE_DEVIATION"
    ipv6 = observation(rule, {**allow.configuration, "sourceRanges": ["::/0"]})
    assert evaluate(rule, ipv6, [other]).finding_class == "POTENTIAL_EXPOSURE"


def test_default_source_and_invalid_metadata():
    rule = "GCP-NET-FW-ADMIN-INTERNET"
    config = {k: v for k, v in FIREWALL.items() if k != "sourceRanges"}
    assert evaluate(rule, observation(rule, config)).outcome == "FAIL"
    for update in (
        {"priority": "invalid"},
        {"network": "shared"},
        {"sourceRanges": ["invalid"]},
        {"allowed": [{"IPProtocol": "tcp", "ports": ["65536"]}]},
    ):
        assert evaluate(rule, observation(rule, {**config, **update})).outcome == "UNKNOWN"


def rewrite_package(package, replacements):
    path = package / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    for item in manifest["datasets"]:
        if item["dataset"] not in replacements:
            continue
        payload = replacements[item["dataset"]]
        (package / item["file"]).write_text(json.dumps(payload))
        item["record_count"] = len(payload) if isinstance(payload, list) else 1
    path.write_text(json.dumps(manifest))
    checksum = package / "checksums.sha256"
    checksum.write_text(
        "\n".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(package).as_posix()}"
            for p in sorted(package.rglob("*"))
            if p.is_file() and p != checksum
        )
        + "\n"
    )


def test_native_import_risk_context_guidance_review_and_reimport(tmp_path):
    package = expanded22(tmp_path / "package")
    rewrite_package(
        package,
        {
            "firewall_rules": [
                {"name": "public-ssh", **FIREWALL},
                {"name": "unmatched-ssh", **FIREWALL, "targetTags": ["no-matching-vm"]},
            ],
            "instances": [
                {
                    "name": "web",
                    "status": "RUNNING",
                    "zone": f"projects/{PROJECT}/zones/us-central1-a",
                    "networkInterfaces": [
                        {"network": NETWORK, "accessConfigs": [{"natIP": "192.0.2.1"}]}
                    ],
                }
            ],
        },
    )
    before = {
        p.relative_to(package): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in package.rglob("*")
        if p.is_file()
    }
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        finding = next(
            c
            for c in store.candidates(run)
            if c.rule_id == "GCP-NET-FW-ADMIN-INTERNET" and c.native_id.endswith("/public-ssh")
        )
        assert (
            finding.finding_class == "POTENTIAL_EXPOSURE" and finding.suggested_severity == "HIGH"
        )
        assert finding.exposure_status.startswith("POTENTIAL") and len(finding.evidence) == 2
        latent = next(c for c in store.candidates(run) if c.native_id.endswith("/unmatched-ssh"))
        assert (
            latent.suggested_severity == "MEDIUM" and latent.finding_class == "BASELINE_DEVIATION"
        )
        result = next(
            r
            for r in store.results(run)
            if r.rule_id == finding.rule_id and r.resource_id == finding.resource_id
        )
        assert any("Hierarchical" in text for text in result.limitations)
        detail = finding_detail(store, run, finding.finding_id)
        assert detail["evidence"] and detail["validation"] and detail["completeness"]
        assert "firewall-rules describe" in detail["technical_finding"]
        record_decision(
            store, run, finding.finding_id, "CONFIRMED", "synthetic-analyst", "Reviewed metadata"
        )
        assert import_package(store, package) == run
        assess(store, run)
        again = next(c for c in store.candidates(run) if c.finding_id == finding.finding_id)
        assert validation_status(store, again)[0] == "CONFIRMED"
        coverage = matrix(store.results(run), assessed={"GCP"})
        assert not any(row["gcp"]["outcome"] == "PASS" for row in coverage)
        from offline_analyzer.reporting.assessment_report import model
        from offline_analyzer.reporting.report_document import write_excel, write_rtf

        report = model(store, run, include="confirmed")
        assert {f["id"] for f in report["findings"]} == {finding.finding_id}
        word_path = tmp_path / "reviewed.rtf"
        write_rtf(report, word_path)
        word = word_path.read_text()
        assert "Unrestricted" in word and "firewall-rules describe" in word
        from openpyxl import load_workbook

        book_path = tmp_path / "reviewed.xlsx"
        write_excel(report, book_path)
        book = load_workbook(book_path, read_only=True)
        rows = list(book["Technical Findings"].values)
        assert len(rows) == 2 and rows[1][0] == finding.finding_id
        book.close()
    assert before == {
        p.relative_to(package): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in package.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize("enforced,outcome", [(True, "PASS"), (False, "FAIL")])
def test_pap_requires_project_effective_evidence(enforced, outcome):
    rule = "GCP-STORAGE-PAP"
    bucket = observation(rule, {"public_access_prevention": "inherited"})
    policy = observation(
        rule,
        {
            "constraint": "constraints/storage.publicAccessPrevention",
            "_parameters": {"effective": "true"},
            "booleanPolicy": {"enforced": enforced},
        },
        "policy",
        resource_type="GCP::OrgPolicy",
    )
    result = evaluate(rule, bucket, [policy])
    assert result.outcome == outcome and result.related == ("policy",)
    assert (
        evaluate(rule, bucket, [policy.model_copy(update={"project_id": "other-project"})]).outcome
        == "UNKNOWN"
    )
    opposite = policy.model_copy(
        update={
            "configuration": {
                **policy.configuration,
                "booleanPolicy": {"enforced": not enforced},
            }
        }
    )
    assert evaluate(rule, bucket, [policy, opposite]).outcome == "UNKNOWN"


def test_configuration_coverage_spec_matches_executable_mappings():
    from offline_analyzer.methodology.coverage_spec import GCP_CONFIG_COVERAGE
    from offline_analyzer.rules.methodology_links import LINKS

    assert {rule for c in GCP_CONFIG_COVERAGE for rule in c.rules} == set(DEFINITIONS)
    for control in GCP_CONFIG_COVERAGE:
        assert all(LINKS[rule].control_id == control.control_id for rule in control.rules)
    rows = matrix([], assessed={"GCP"})
    assert len(rows) == 204
    assert all(row["gcp"]["implementation_status"] for row in rows)
    sql_tls = next(row for row in rows if row["control_id"] == "1.4.4")
    assert "gcp:expanded.cloud_sql" in sql_tls["gcp_evidence"]


def test_manual_and_inapplicable_subcriteria_do_not_hide_missing_controls():
    from collections import Counter

    from offline_analyzer.methodology.cloud_checklist import control_outcome

    assert (
        control_outcome("8.4.1", "GCP", Counter({"MANUAL VALIDATION": 1}))[0] == "MANUAL VALIDATION"
    )
    assert control_outcome("6.1.2", "GCP", Counter({"NOT APPLICABLE": 4}))[0] == "MANUAL VALIDATION"
    assert (
        control_outcome(
            "8.4.1", "GCP", Counter({"MANUAL VALIDATION": 1, "INSUFFICIENT EVIDENCE": 1})
        )[0]
        == "INSUFFICIENT EVIDENCE"
    )


def test_disabled_api_does_not_prove_new_service_resources_absent(tmp_path):
    package = expanded22(tmp_path / "package")
    manifest_path = package / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    selected = {"instances", "cloud_sql", "kms_keys_1_1", "subnets"}
    for dataset in manifest["datasets"]:
        if dataset["dataset"] not in selected:
            continue
        (package / dataset["file"]).unlink()
        dataset.update(file=None, status="API_DISABLED", record_count=None, exit_code=None)
    manifest_path.write_text(json.dumps(manifest))
    rewrite_package(package, {})
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, package)
        assess(store, run)
        for rule in ("GCP-VM-EXTERNAL-IP", "GCP-SQL-TLS", "GCP-KMS-ROTATION", "GCP-NET-FLOW-LOGS"):
            scopes = [
                r
                for r in store.results(run)
                if r.rule_id == rule and r.evaluation_scope == "COLLECTION_SCOPE"
            ]
            assert scopes and all(r.outcome == "UNKNOWN" for r in scopes)


@pytest.mark.parametrize("sources", [[], ["0.0.0.0/1", "128.0.0.0/1"], ["::/1", "8000::/1"]])
def test_empty_default_and_combined_sources_cover_internet(sources):
    rule = "GCP-NET-FW-ADMIN-INTERNET"
    assert (
        evaluate(rule, observation(rule, {**FIREWALL, "sourceRanges": sources})).outcome == "FAIL"
    )


@pytest.mark.parametrize(
    "nic",
    [
        {},
        {"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]},
        {"accessConfigs": "malformed"},
        {"ipv6AccessConfigs": {}},
    ],
)
def test_external_access_without_an_address_is_not_a_clean_pass(nic):
    rule = "GCP-VM-EXTERNAL-IP"
    assert evaluate(rule, observation(rule, {"networkInterfaces": [nic]})).outcome == "UNKNOWN"
