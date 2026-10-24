"""CAI observations retain resource context and do not duplicate native exposures."""

from datetime import timedelta

from offline_analyzer.rules.gcp_context import GCPContext
from offline_analyzer.rules.gcp_public_context import public_context
from tests.test_clogcp_domains import PROJECT, SERVICE, obs


def context(*items):
    return GCPContext(
        list(items), [{"artifact_id": "synthetic", "effective_coverage": "COMPLETE"}], PROJECT
    )


def policy(kind, resource, role):
    return obs(
        "AssetIAMSearchResult",
        {
            "assetType": kind,
            "resource": resource,
            "policy": {"bindings": [{"role": role, "members": ["allUsers"]}]},
        },
    )


def test_bucket_public_grant_blocked_by_collected_pap():
    p = policy(
        "storage.googleapis.com/Bucket",
        "//storage.googleapis.com/buckets/bucket",
        "roles/storage.objectViewer",
    )
    b = obs(
        "Bucket",
        {"name": "bucket", "iamConfiguration": {"publicAccessPrevention": "enforced"}},
        "bucket",
    )
    v = public_context("GCP-ORG-PUBLIC-DATA", p, context(p, b), {})
    assert str(v.outcome) == "NOT_APPLICABLE"
    assert b.observation_id in v.related
    assert str(public_context("GCP-ORG-PUBLIC-DATA", p, context(p), {}).outcome) == "UNKNOWN"


def test_run_internal_ingress_and_native_equivalence():
    p = policy("run.googleapis.com/Service", "//run.googleapis.com/" + SERVICE, "roles/run.invoker")
    internal = obs("RunService", {"ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}, SERVICE)
    assert (
        str(public_context("GCP-ORG-PUBLIC-SERVERLESS", p, context(p, internal), {}).outcome)
        == "MANUAL_VALIDATION_REQUIRED"
    )
    external = internal.model_copy(update={"configuration": {"ingress": "INGRESS_TRAFFIC_ALL"}})
    v = public_context("GCP-ORG-PUBLIC-SERVERLESS", p, context(p, external), {})
    assert str(v.outcome) == "FAIL"
    v = public_context(
        "GCP-ORG-PUBLIC-SERVERLESS",
        p,
        context(p, external),
        {("GCP-RUN-PUBLIC", external.resource_id): "synthetic-finding"},
    )
    assert str(v.outcome) == "MANUAL_VALIDATION_REQUIRED"
    assert "synthetic-finding" in v.reasoning
    assert external.observation_id in v.related


def test_stale_conflicting_or_missing_service_context_is_unknown():
    p = policy("run.googleapis.com/Service", "//run.googleapis.com/" + SERVICE, "roles/run.invoker")
    service = obs("RunService", {"ingress": "INGRESS_TRAFFIC_ALL"}, SERVICE)
    stale = service.model_copy(update={"collected_at": service.collected_at - timedelta(days=2)})
    private = service.model_copy(
        update={
            "observation_id": "private",
            "configuration": {"ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"},
        }
    )
    for items in [(p,), (p, stale), (p, service, private)]:
        assert (
            str(public_context("GCP-ORG-PUBLIC-SERVERLESS", p, context(*items), {}).outcome)
            == "UNKNOWN"
        )
