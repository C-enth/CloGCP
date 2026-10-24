"""Positive, negative and ambiguous synthetic evidence for every additional criterion."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from offline_analyzer.contracts.models import EvidenceRef
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.gcp import evaluate
from offline_analyzer.rules.gcp_context import GCPContext
from offline_analyzer.rules.gcp_domains import SPECS

PROJECT = "synth-clogcp"
NUMBER = "900000000001"
ROLE = f"projects/{PROJECT}/roles/readData"
SERVICE = f"projects/{PROJECT}/locations/us-central1/services/api"
NETWORK = f"projects/{PROJECT}/global/networks/shared"


def obs(kind, config, native="sample", operation="synthetic", project=PROJECT, oid=None):
    return Normalized(
        observation_id=oid or kind + "-" + native,
        provider="GCP",
        project_id=project,
        project_number=NUMBER,
        account_id=None,
        region="us-central1",
        resource_id=f"gcp://{project}/{kind}/{native}",
        native_id=native,
        resource_type="GCP::" + kind,
        partition="gcp",
        source_tool="gcp",
        source_version="synthetic",
        source_check_id=operation,
        source_status="SUCCESS",
        source_severity=None,
        collected_at=datetime(2026, 10, 23, tzinfo=UTC),
        operation=operation,
        configuration=deepcopy(config),
        evidence=EvidenceRef(artifact_id="synthetic", locator="/0"),
        integrity_sha256="0" * 64,
    )


def run(rid, config, related=(), *, native="sample", coverage="COMPLETE"):
    spec = SPECS[rid]
    o = obs(spec.kind.removeprefix("GCP::"), config, native, spec.operation)
    ctx = GCPContext(
        [o, *related], [{"artifact_id": "synthetic", "effective_coverage": coverage}], PROJECT
    )
    return evaluate(rid, o, ctx)


CASES = {}


def case(
    suffix,
    good,
    bad,
    ambiguous=None,
    *,
    good_status="PASS",
    bad_status="FAIL",
    related=(),
    native="sample",
):
    CASES["GCP-" + suffix] = (good, bad, ambiguous or {}, good_status, bad_status, related, native)


def path_config(path, value):
    data = {"autopilot": {"enabled": False}}
    target = data
    parts = path.split(".")
    for p in parts[:-1]:
        target = target.setdefault(p, {})
    target[parts[-1]] = value
    return data


for suffix, path, bad in [
    ("LEGACY-ABAC", "legacyAbac.enabled", True),
    ("PRIVATE-NODES", "privateClusterConfig.enablePrivateNodes", False),
    ("SHIELDED-NODES", "shieldedNodes.enabled", False),
    ("CLIENT-CERT", "masterAuth.clientCertificateConfig.issueClientCertificate", True),
    ("NETWORK-POLICY", "networkPolicy.enabled", False),
]:
    case("GKE-" + suffix, path_config(path, not bad), path_config(path, bad))
case(
    "GKE-ENDPOINT",
    {"privateClusterConfig": {"enablePrivateEndpoint": True}},
    {
        "privateClusterConfig": {"enablePrivateEndpoint": False},
        "masterAuthorizedNetworksConfig": {"enabled": False},
    },
)
case(
    "GKE-WORKLOAD-IDENTITY",
    {"workloadIdentityConfig": {"workloadPool": PROJECT + ".svc.id.goog"}},
    {"autopilot": {"enabled": False}, "workloadIdentityConfig": {}},
)
case(
    "GKE-SECRETS-ENCRYPTION",
    {"databaseEncryption": {"state": "ENCRYPTED"}},
    {"databaseEncryption": {"state": "DECRYPTED"}},
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
POLICY = obs(
    "IAMPolicy", {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}, SERVICE
)
PRIVILEGED = obs(
    "IAMBinding",
    {
        "role": "roles/editor",
        "members": ["serviceAccount:runtime@" + PROJECT + ".iam.gserviceaccount.com"],
    },
)
for kind in ("RUN", "FUNCTION"):
    public = {"invokerIamDisabled": True, "ingress": "INGRESS_TRAFFIC_ALL"}
    private = {"invokerIamDisabled": True, "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}
    case(kind + "-PUBLIC", private, public, good_status="MANUAL_VALIDATION_REQUIRED")
    identity = (
        {"template": {"serviceAccount": "runtime@" + PROJECT + ".iam.gserviceaccount.com"}}
        if kind == "RUN"
        else {
            "serviceConfig": {
                "serviceAccountEmail": "runtime@" + PROJECT + ".iam.gserviceaccount.com"
            }
        }
    )
    case(
        kind + "-RUNTIME-PRIVILEGE",
        (
            {"template": {"serviceAccount": "narrow@" + PROJECT + ".iam.gserviceaccount.com"}}
            if kind == "RUN"
            else {
                "serviceConfig": {
                    "serviceAccountEmail": "narrow@" + PROJECT + ".iam.gserviceaccount.com"
                }
            }
        ),
        identity,
        good_status="MANUAL_VALIDATION_REQUIRED",
        related=[PRIVILEGED],
    )
case(
    "GKE-NODE-PRIVILEGE",
    {"config": {"serviceAccount": "narrow@" + PROJECT + ".iam.gserviceaccount.com"}},
    {"config": {"serviceAccount": "runtime@" + PROJECT + ".iam.gserviceaccount.com"}},
    good_status="MANUAL_VALIDATION_REQUIRED",
    related=[PRIVILEGED],
)
case(
    "BQ-PUBLIC-DATA",
    {"access": [{"role": "roles/bigquery.metadataViewer", "iamMember": "allUsers"}]},
    {"access": [{"role": "READER", "specialGroup": "allUsers"}]},
)
case(
    "SQL-EXPLICIT-FLAGS",
    {
        "databaseVersion": "MYSQL_8_0",
        "settings": {"databaseFlags": [{"name": "local_infile", "value": "off"}]},
    },
    {
        "databaseVersion": "MYSQL_8_0",
        "settings": {"databaseFlags": [{"name": "local_infile", "value": "on"}]},
    },
)
case(
    "DNS-DNSSEC",
    {"visibility": "public", "dnssecConfig": {"state": "on"}},
    {"visibility": "public", "dnssecConfig": {"state": "off"}},
)
SSL = f"projects/{PROJECT}/global/sslPolicies/policy"
PROXY = f"projects/{PROJECT}/global/targetHttpsProxies/proxy"
ASSET = obs(
    "AssetResourceSnapshot",
    {
        "assetType": "compute.googleapis.com/TargetHttpsProxy",
        "resource": {"data": {"selfLink": PROXY, "sslPolicy": SSL}},
    },
    PROXY,
)
FORWARD = obs("ForwardingRule", {"loadBalancingScheme": "EXTERNAL_MANAGED", "target": PROXY})
case(
    "LB-TLS",
    {"minTlsVersion": "TLS_1_2"},
    {"minTlsVersion": "TLS_1_0"},
    related=[ASSET, FORWARD],
    native=SSL,
)
case(
    "LB-ARMOR",
    {"loadBalancingScheme": "EXTERNAL", "protocol": "HTTPS", "securityPolicy": "policy"},
    {"loadBalancingScheme": "EXTERNAL", "protocol": "HTTPS"},
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
case(
    "LB-LOGGING",
    {"loadBalancingScheme": "EXTERNAL", "protocol": "HTTP", "logConfig": {"enable": True}},
    {"loadBalancingScheme": "EXTERNAL", "protocol": "HTTP", "logConfig": {"enable": False}},
)
case(
    "NET-FIREWALL-POLICY",
    {"rules": []},
    {
        "rules": [
            {
                "action": "allow",
                "direction": "INGRESS",
                "priority": 1000,
                "match": {
                    "srcIpRanges": ["0.0.0.0/0"],
                    "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}],
                },
            }
        ]
    },
)
case(
    "GOV-GUARDRAIL",
    {
        "constraint": "compute.requireOsLogin",
        "booleanPolicy": {"enforced": True},
        "_parameters": {"effective": True},
    },
    {
        "constraint": "compute.requireOsLogin",
        "booleanPolicy": {"enforced": False},
        "_parameters": {"effective": True},
    },
)
case(
    "LOG-AUDIT-COVERAGE",
    {
        "auditConfigs": [
            {
                "service": "allServices",
                "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}],
            }
        ]
    },
    {"auditConfigs": []},
    bad_status="UNKNOWN",
)
case("MONITOR-ALERT-DISABLED", {"enabled": True}, {"enabled": False})
case(
    "SECRET-LIFECYCLE",
    {"rotation": {"rotationPeriod": "7776000s"}},
    {},
    good_status="MANUAL_VALIDATION_REQUIRED",
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
case(
    "ARTIFACT-TAGS",
    {"format": "DOCKER", "dockerConfig": {"immutableTags": True}},
    {"format": "DOCKER", "dockerConfig": {"immutableTags": False}},
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
case(
    "BUILD-APPROVAL",
    {"approvalConfig": {"approvalRequired": True}},
    {"approvalConfig": {"approvalRequired": False}},
    good_status="MANUAL_VALIDATION_REQUIRED",
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
case(
    "PUBSUB-PUSH-AUTH",
    {
        "pushConfig": {
            "pushEndpoint": "https://example.com",
            "oidcToken": {"serviceAccountEmail": "push@example.com"},
        }
    },
    {"pushConfig": {"pushEndpoint": "https://example.com"}},
    good_status="MANUAL_VALIDATION_REQUIRED",
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
ROLE_OBS = obs("CustomRole", {"includedPermissions": ["bigquery.tables.getData"]}, ROLE)
case(
    "IAM-CUSTOM-PUBLIC",
    {"members": ["user:owner@example.com"], "role": ROLE},
    {"members": ["allUsers"], "role": ROLE},
    good_status="NOT_APPLICABLE",
    related=[ROLE_OBS],
)
case(
    "WIF-SHARED-ISSUER",
    {
        "disabled": False,
        "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
        "attributeCondition": "assertion.repository_owner_id=='123'",
    },
    {
        "disabled": False,
        "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
        "attributeCondition": "",
    },
    good_status="MANUAL_VALIDATION_REQUIRED",
)


def test_all_additional_rules_have_three_scenarios():
    assert set(CASES) == set(SPECS)


@pytest.mark.parametrize("rid", sorted(CASES))
@pytest.mark.parametrize("scenario", ["good", "bad", "ambiguous"])
def test_each_criterion(rid, scenario):
    good, bad, ambiguous, gs, bs, related, native = CASES[rid]
    cfg = {"good": good, "bad": bad, "ambiguous": ambiguous}[scenario]
    value = run(rid, cfg, related, native=native)
    if scenario == "ambiguous":
        assert value.outcome != "PASS"
        assert value.outcome != "FAIL"
    else:
        assert value.outcome == (gs if scenario == "good" else bs), value
    assert value.reasoning
    if value.outcome == "FAIL":
        assert SPECS[rid].risk and SPECS[rid].remediation and SPECS[rid].reference
        assert value.finding_class in {"POTENTIAL_EXPOSURE", "BASELINE_DEVIATION"}
    assert not any("verified exploitation" in x.lower() for x in value.limitations)


def test_serverless_invoker_and_internal_ingress():
    value = run("GCP-RUN-PUBLIC", {"ingress": "INGRESS_TRAFFIC_ALL"}, [POLICY], native=SERVICE)
    assert value.outcome == "FAIL" and POLICY.observation_id in value.related
    internal = run(
        "GCP-RUN-PUBLIC", {"ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}, [POLICY], native=SERVICE
    )
    assert internal.outcome == "MANUAL_VALIDATION_REQUIRED"
    conditional = POLICY.model_copy(
        update={
            "configuration": {
                "bindings": [
                    {
                        "role": "roles/run.invoker",
                        "members": ["allUsers"],
                        "condition": {"expression": "false"},
                    }
                ]
            }
        }
    )
    assert run("GCP-RUN-PUBLIC", {}, [conditional], native=SERVICE).outcome == "UNKNOWN"


def test_autopilot_and_dataplane_v2():
    for suffix in ("LEGACY-ABAC", "SHIELDED-NODES", "CLIENT-CERT", "WORKLOAD-IDENTITY"):
        assert (
            run("GCP-GKE-" + suffix, {"autopilot": {"enabled": True}}).outcome == "NOT_APPLICABLE"
        )
    assert (
        run(
            "GCP-GKE-NETWORK-POLICY", {"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}}
        ).outcome
        == "PASS"
    )
    assert (
        run(
            "GCP-GKE-PRIVATE-NODES",
            {"autopilot": {"enabled": True}, "privateClusterConfig": {"enablePrivateNodes": False}},
        ).outcome
        == "FAIL"
    )


def test_unset_sql_flag_and_unused_ssl_policy_are_not_findings():
    assert (
        run(
            "GCP-SQL-EXPLICIT-FLAGS",
            {"databaseVersion": "MYSQL_8_0", "settings": {"databaseFlags": []}},
        ).outcome
        == "MANUAL_VALIDATION_REQUIRED"
    )
    assert (
        run("GCP-LB-TLS", {"minTlsVersion": "TLS_1_0"}, native=SSL).outcome
        == "MANUAL_VALIDATION_REQUIRED"
    )
    assert (
        run("GCP-LB-TLS", {"minTlsVersion": "TLS_1_2"}, [ASSET, FORWARD], native=SSL).outcome
        == "PASS"
    )


def test_custom_bigquery_permission_is_resolved():
    a = {"access": [{"iamMember": "allUsers", "role": ROLE}]}
    assert run("GCP-BQ-PUBLIC-DATA", a).outcome == "UNKNOWN"
    assert run("GCP-BQ-PUBLIC-DATA", a, [ROLE_OBS]).outcome == "FAIL"
    metadata = ROLE_OBS.model_copy(
        update={"configuration": {"includedPermissions": ["bigquery.datasets.get"]}}
    )
    assert run("GCP-BQ-PUBLIC-DATA", a, [metadata]).outcome == "PASS"


# Gen 1 functions require their own invoker role; Cloud Run-only flags are not function evidence.
FUNCTION = f"projects/{PROJECT}/locations/us-central1/functions/api"
FUNCTION_POLICY = obs(
    "IAMPolicy",
    {"bindings": [{"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}]},
    FUNCTION,
)
CASES["GCP-FUNCTION-PUBLIC"] = (
    {"environment": "GEN_1", "ingressSettings": "ALLOW_INTERNAL_ONLY"},
    {"environment": "GEN_1", "ingressSettings": "ALLOW_ALL"},
    {},
    "MANUAL_VALIDATION_REQUIRED",
    "FAIL",
    [FUNCTION_POLICY],
    FUNCTION,
)


def test_function_generation_and_underlying_run_relationship():
    legacy = {"environment": "GEN_2", "serviceConfig": {"service": SERVICE}}
    assert run("GCP-FUNCTION-PUBLIC", legacy, [FUNCTION_POLICY], native=FUNCTION).outcome != "FAIL"
    assert run("GCP-FUNCTION-PUBLIC", legacy, [POLICY], native=FUNCTION).outcome == "FAIL"
    svc = obs("RunService", {"ingress": "INGRESS_TRAFFIC_ALL", "invokerIamDisabled": True}, SERVICE)
    assert (
        run("GCP-FUNCTION-PUBLIC", legacy, [svc, POLICY], native=FUNCTION).outcome
        == "MANUAL_VALIDATION_REQUIRED"
    )
    assert (
        run("GCP-FUNCTION-PUBLIC", {"invokerIamDisabled": True}, native=FUNCTION).outcome
        == "UNKNOWN"
    )
