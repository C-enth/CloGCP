"""Regression cases for concrete false-positive/false-negative and identity defects."""

from copy import deepcopy

import pytest

from offline_analyzer.rules.gcp import binding_rule, evaluate
from offline_analyzer.rules.gcp_context import GCPContext
from offline_analyzer.rules.gcp_identity import Scope, principal_kind
from offline_analyzer.rules.gcp_org import matches, providers
from tests.test_clogcp_domains import NETWORK, NUMBER, PROJECT, obs, run

SCOPE = Scope(PROJECT, NUMBER, {PROJECT: NUMBER})


def binding(member, role="roles/editor", **extra):
    return obs(
        "IAMBinding", {"role": role, "members": [member], "subject": "projects/" + PROJECT, **extra}
    )


@pytest.mark.parametrize(
    "member,kind,status",
    [
        (
            "serviceAccount:" + NUMBER + "@cloudservices.gserviceaccount.com",
            "GOOGLE_APIS_AGENT",
            "NOT_APPLICABLE",
        ),
        (
            "serviceAccount:" + NUMBER + "-compute@developer.gserviceaccount.com",
            "COMPUTE_DEFAULT",
            "FAIL",
        ),
        (
            "serviceAccount:" + PROJECT + "@appspot.gserviceaccount.com",
            "APP_ENGINE_DEFAULT",
            "FAIL",
        ),
        ("serviceAccount:worker@" + PROJECT + ".iam.gserviceaccount.com", "USER_MANAGED", "FAIL"),
        ("user:admin@example.com", "HUMAN", "FAIL"),
        ("group:admins@example.com", "GROUP", "FAIL"),
        ("domain:example.com", "DOMAIN", "FAIL"),
        (
            "principalSet://iam.googleapis.com/projects/"
            + NUMBER
            + "/locations/global/workloadIdentityPools/pool/*",
            "FEDERATED",
            "FAIL",
        ),
        ("deleted:user:old@example.com?uid=123", "DELETED", "MANUAL_VALIDATION_REQUIRED"),
        ("unrecognized-principal", "UNRESOLVED", "UNKNOWN"),
    ],
)
def test_identity_type_does_not_create_a_blanket_exception(member, kind, status):
    assert principal_kind(member, SCOPE) == kind
    value = binding_rule(binding(member), "basic", SCOPE)
    assert str(value.outcome) == status


def test_expected_agent_grant_is_narrow_and_requires_ownership():
    agent = "serviceAccount:" + NUMBER + "@cloudservices.gserviceaccount.com"
    assert binding_rule(binding(agent, "roles/owner"), "basic", SCOPE).outcome == "FAIL"
    assert binding_rule(binding(agent), "basic", Scope(PROJECT, None)).outcome == "UNKNOWN"
    service = "serviceAccount:service-" + NUMBER + "@gcp-sa-pubsub.iam.gserviceaccount.com"
    assert binding_rule(binding(service), "basic", SCOPE).outcome == "FAIL"
    assert (
        binding_rule(
            binding(service, "roles/iam.serviceAccountTokenCreator"), "impersonation", SCOPE
        ).outcome
        == "FAIL"
    )
    conditional = binding(
        agent, condition={"expression": 'request.time < timestamp("2027-01-01T00:00:00Z")'}
    )
    assert binding_rule(conditional, "basic", SCOPE).outcome == "UNKNOWN"


def test_same_project_unusual_agent_grant_is_not_cross_project():
    service = "serviceAccount:service-" + NUMBER + "@gcp-sa-pubsub.iam.gserviceaccount.com"
    config = {
        "resource": "//cloudresourcemanager.googleapis.com/projects/" + PROJECT,
        "assetType": "cloudresourcemanager.googleapis.com/Project",
        "policy": {"bindings": [{"role": "roles/editor", "members": [service]}]},
    }
    assert matches("GCP-ORG-SA-PRIVILEGED", config, PROJECT, SCOPE)
    assert not matches("GCP-ORG-CROSSPROJECT-SA", config, PROJECT, SCOPE)


def test_vpc_matching_is_running_scoped_and_shared_vpc_uses_explicit_network():
    fw = obs(
        "Firewall",
        {
            "network": NETWORK,
            "direction": "INGRESS",
            "sourceRanges": ["0.0.0.0/0"],
            "targetTags": ["admin"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        },
    )
    vm = obs(
        "ComputeInstance",
        {
            "status": "RUNNING",
            "tags": {"items": ["admin"]},
            "networkInterfaces": [{"network": NETWORK, "accessConfigs": [{"natIP": "192.0.2.1"}]}],
        },
        project="synth-service-project",
    )
    ctx = GCPContext([fw, vm], [], PROJECT)
    value = evaluate("GCP-NET-FW-ADMIN-INTERNET", fw, ctx)
    assert (
        value.outcome == "FAIL" and value.severity == "HIGH" and vm.observation_id in value.related
    )
    stopped = vm.model_copy(update={"configuration": {**vm.configuration, "status": "TERMINATED"}})
    value = evaluate("GCP-NET-FW-ADMIN-INTERNET", fw, GCPContext([fw, stopped], [], PROJECT))
    assert value.severity == "MEDIUM" and "no matching external endpoint" in value.reasoning
    deny = obs(
        "Firewall",
        {
            "network": NETWORK,
            "direction": "INGRESS",
            "priority": 10,
            "sourceRanges": ["0.0.0.0/0"],
            "denied": [{"IPProtocol": "tcp", "ports": ["22"]}],
        },
        native="deny",
    )
    assert evaluate("GCP-NET-FW-ADMIN-INTERNET", fw, [vm, deny]).outcome == "PASS"


def test_network_policy_higher_priority_deny():
    allow = {
        "action": "allow",
        "direction": "INGRESS",
        "priority": 1000,
        "match": {
            "srcIpRanges": ["0.0.0.0/0"],
            "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}],
        },
    }
    deny = {**deepcopy(allow), "action": "deny", "priority": 10}
    assert run("GCP-NET-FIREWALL-POLICY", {"rules": [allow, deny]}).outcome == "PASS"
    deny["priority"] = 2000
    assert run("GCP-NET-FIREWALL-POLICY", {"rules": [allow, deny]}).outcome == "FAIL"


def test_metadata_inheritance_override_and_windows_applicability():
    project = obs(
        "AssetResourceSnapshot",
        {
            "assetType": "compute.googleapis.com/Project",
            "resource": {
                "data": {
                    "commonInstanceMetadata": {
                        "items": [{"key": "enable-oslogin", "value": "true"}]
                    }
                }
            },
        },
    )
    vm = obs("ComputeInstance", {"metadata": {"items": []}})
    result = evaluate("GCP-VM-OSLOGIN", vm, [project])
    assert result.outcome == "PASS" and project.observation_id in result.related
    override = vm.model_copy(
        update={
            "configuration": {"metadata": {"items": [{"key": "enable-oslogin", "value": "false"}]}}
        }
    )
    assert evaluate("GCP-VM-OSLOGIN", override, [project]).outcome == "FAIL"
    windows = vm.model_copy(
        update={
            "configuration": {
                "disks": [
                    {
                        "licenses": [
                            (
                                "https://www.googleapis.com/compute/v1/projects/windows-cloud/global"
                                "/licenses/windows-server-2022-dc"
                            )
                        ]
                    }
                ],
                "metadata": {"items": [{"key": "enable-oslogin", "value": "false"}]},
            }
        }
    )
    assert evaluate("GCP-VM-OSLOGIN", windows, [project]).outcome == "NOT_APPLICABLE"
    assert evaluate("GCP-VM-PROJECT-SSH-KEYS", windows, [project]).outcome == "NOT_APPLICABLE"


@pytest.mark.parametrize("enforce,status", [(False, "FAIL"), (True, "PASS")])
def test_bucket_list_detail_aliases_and_v2_effective_pap(enforce, status):
    bucket = obs("Bucket", {"iamConfiguration": {"publicAccessPrevention": "inherited"}}, "bucket")
    detail = bucket.model_copy(
        update={"observation_id": "detail", "operation": "gcp:storage.buckets.get"}
    )
    policy = obs(
        "OrgPolicy",
        {
            "name": "projects/" + PROJECT + "/policies/storage.publicAccessPrevention",
            "spec": {"rules": [{"enforce": enforce}]},
            "_parameters": {"effective": True},
        },
    )
    grant = obs(
        "IAMBinding",
        {
            "subject": "buckets/bucket",
            "role": "roles/storage.objectViewer",
            "members": ["allUsers"],
        },
    )
    value = evaluate("GCP-STORAGE-PUBLIC", grant, [bucket, detail, policy])
    assert value.outcome == status
    assert {"detail", policy.observation_id} <= set(value.related)
    assert evaluate("GCP-STORAGE-PAP", bucket, [policy]).outcome == status


def test_public_bigquery_metadata_role_is_not_data_access():
    record = {
        "resource": "//bigquery.googleapis.com/projects/" + PROJECT + "/datasets/data",
        "assetType": "bigquery.googleapis.com/Dataset",
        "policy": {
            "bindings": [{"role": "roles/bigquery.metadataViewer", "members": ["allUsers"]}]
        },
    }
    assert not matches("GCP-ORG-PUBLIC-DATA", record, PROJECT)


def test_provider_project_id_number_alias_is_not_silently_unassessed():
    p = obs(
        "WorkloadIdentityProvider",
        {
            "name": "projects/"
            + PROJECT
            + ("/locations/global/workloadIdentityPools/pool/providers/id")
        },
        native="provider",
    )
    index = providers([p], [{"artifact_id": "synthetic", "effective_coverage": "COMPLETE"}])
    assert index[PROJECT, "pool"] is index[NUMBER, "pool"]


def test_soft_delete_is_reviewed_as_a_recovery_control():
    bucket = obs(
        "Bucket",
        {
            "versioning": {"enabled": False},
            "softDeletePolicy": {"retentionDurationSeconds": "604800"},
        },
    )
    value = evaluate("GCP-STORAGE-VERSIONING", bucket)
    assert value.outcome == "MANUAL_VALIDATION_REQUIRED" and "604800" in value.reasoning


@pytest.mark.parametrize("disabled,outcome", [(True, "NOT_APPLICABLE"), (False, "FAIL")])
def test_federation_parent_pool_is_a_real_applicability_control(disabled, outcome):
    from offline_analyzer.rules.gcp_org import provider_state

    parent = f"projects/{PROJECT}/locations/global/workloadIdentityPools/pool"
    p = obs(
        "WorkloadIdentityProvider",
        {
            "name": parent + "/providers/provider",
            "disabled": False,
            "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
        },
    )
    pool = obs("WorkloadIdentityPool", {"name": parent, "disabled": disabled}, parent)
    sources = [{"artifact_id": "synthetic", "effective_coverage": "COMPLETE"}]
    ctx = GCPContext([p, pool], sources, PROJECT)
    assert str(evaluate("GCP-WIF-SHARED-ISSUER", p, ctx).outcome) == outcome
    index = providers([p, pool], sources)
    result, _, refs = provider_state([{"attribute": "*"}], index[(NUMBER, "pool")])
    assert str(result) == outcome
    assert pool.observation_id in refs


def test_federation_pool_conflicts_and_partial_evidence_are_unknown():
    from offline_analyzer.rules.gcp_org import provider_state

    parent = f"projects/{PROJECT}/locations/global/workloadIdentityPools/pool"
    p = obs(
        "WorkloadIdentityProvider",
        {
            "name": parent + "/providers/provider",
            "disabled": False,
            "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
        },
    )
    disabled = obs("WorkloadIdentityPool", {"name": parent, "disabled": True}, parent)
    enabled = disabled.model_copy(
        update={
            "observation_id": "other-pool-snapshot",
            "configuration": {"name": parent, "disabled": False},
        }
    )
    for pools, coverage in [([disabled, enabled], "COMPLETE"), ([disabled], "PARTIAL")]:
        sources = [{"artifact_id": "synthetic", "effective_coverage": coverage}]
        ctx = GCPContext([p, *pools], sources, PROJECT)
        assert str(evaluate("GCP-WIF-SHARED-ISSUER", p, ctx).outcome) == "UNKNOWN"
        index = providers([p, *pools], sources)
        assert str(provider_state([{"attribute": "*"}], index[(NUMBER, "pool")])[0]) == "UNKNOWN"
