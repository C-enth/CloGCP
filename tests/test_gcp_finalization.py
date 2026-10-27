"""GCP finalization: claim consistency, presentation identity, register columns and QA.

Positive, negative and ambiguous synthetic fixtures for each change. Every change is display
or export text: stored findings, IDs, fingerprints, decisions and editions are compared
before and after all exports.
"""

import pytest

from offline_analyzer.findings.explanations import MISUSE_QUALIFIER, explain
from offline_analyzer.findings.gcp_recommendations import EXPECTED
from offline_analyzer.findings.location import display_region
from offline_analyzer.findings.recommendations import recommendation
from offline_analyzer.rules.gcp_domains import SPECS
from offline_analyzer.rules.gcp_org import ORG_RULES
from tests.test_clogcp_domains import POLICY, SERVICE, run

GENERIC = (
    "applicability and required security posture reviewed",
    "Secure baseline",
    "Analyst to define expected state",
)


# ---------------------------------------------------------------- Cloud Run semantics


@pytest.mark.parametrize(
    ("config", "policies", "outcome"),
    [
        # Positive: an open service with a public binding, or the IAM check explicitly off.
        ({"ingress": "INGRESS_TRAFFIC_ALL"}, [POLICY], "FAIL"),
        ({"invokerIamDisabled": True, "ingress": "INGRESS_TRAFFIC_ALL"}, [], "FAIL"),
        ({"invokerIamDisabled": "true", "ingress": "INGRESS_TRAFFIC_ALL"}, [], "FAIL"),
        (
            {
                "metadata": {"annotations": {"run.googleapis.com/invoker-iam-disabled": "true"}},
                "ingress": "INGRESS_TRAFFIC_ALL",
            },
            [],
            "FAIL",
        ),
        # Negative: None / False never mean "disabled"; internal ingress limits the claim.
        ({"invokerIamDisabled": None, "ingress": "INGRESS_TRAFFIC_ALL"}, [], "MANUAL"),
        ({"invokerIamDisabled": False, "ingress": "INGRESS_TRAFFIC_ALL"}, [], "MANUAL"),
        ({"ingress": "INGRESS_TRAFFIC_ALL"}, [], "MANUAL"),
        ({"invokerIamDisabled": True, "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}, [], "MANUAL"),
        (
            {"invokerIamDisabled": None, "ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"},
            [POLICY],
            "MANUAL",
        ),
        # Ambiguous: a non-boolean flag is never interpreted.
        ({"invokerIamDisabled": "yes", "ingress": "INGRESS_TRAFFIC_ALL"}, [POLICY], "UNKNOWN"),
        ({"invokerIamDisabled": 1, "ingress": "INGRESS_TRAFFIC_ALL"}, [], "UNKNOWN"),
    ],
)
def test_invoker_iam_disabled_semantics(config, policies, outcome):
    value = run("GCP-RUN-PUBLIC", config, policies, native=SERVICE)
    expected = "MANUAL_VALIDATION_REQUIRED" if outcome == "MANUAL" else outcome
    assert value.outcome == expected, value.reasoning
    if outcome == "FAIL":
        # The reasoning records the observed values the claim rests on.
        assert "invokerIamDisabled=" in value.reasoning and "ingress=" in value.reasoning


# ------------------------------------------------------- narrative and claim consistency


def test_misuse_never_repeats_impact_for_any_domain_rule():
    for rule, spec in SPECS.items():
        text = explain({"rule_id": rule, "technical_observation": "synthetic"})
        assert text["misuse"].endswith(f"({MISUSE_QUALIFIER})"), rule
        assert spec.risk not in text["misuse"], rule
        assert text["impact"] == spec.risk


def test_org_public_serverless_claims_match_its_unresolved_evidence():
    text = explain({"rule_id": "GCP-ORG-PUBLIC-SERVERLESS"})
    risk = next(r for r in ORG_RULES if r.rule_id == "GCP-ORG-PUBLIC-SERVERLESS").risk
    assert "unresolved" in risk
    # Positive: the scenario is conditional on ingress; negative: no unconditional claims.
    assert "If ingress" in text["misuse"]
    for claim in ("Anyone on the internet can call", "run up cost", "without authentication"):
        assert claim not in text["misuse"]
    assert "Cloud Armor" not in text["recommendation"]
    assert "approved public endpoint" in text["recommendation"]


def test_every_gcp_domain_and_org_rule_has_a_checkable_expected_state():
    rules = [*SPECS, *(r.rule_id for r in ORG_RULES)]
    for rule in rules:
        posture = recommendation(rule).get("expected_posture") or ""
        assert rule in EXPECTED and posture == EXPECTED[rule], rule
        assert not any(g in posture for g in GENERIC), rule
    # Ambiguous: an unknown rule keeps the explicit analyst-authored status, never a guess.
    assert recommendation("GCP-NOT-A-RULE")["status"] == "ANALYST_AUTHORED_REMEDIATION_REQUIRED"


# --------------------------------------------------------------- presentation identity


@pytest.mark.parametrize(
    ("stored", "shown"),
    [
        (
            "https://www.googleapis.com/compute/v1/projects/synth/zones/us-central1-a",
            "us-central1-a",
        ),
        ("projects/synth/regions/europe-west1", "europe-west1"),
        ("us-central1", "us-central1"),
        ("global", "global"),
        ("US", "US"),
        ("https://example.invalid/not-a-location", "unrecorded"),
        ("projects/synth/zones/", "unrecorded"),
        ("", "unrecorded"),
        (None, "unrecorded"),
        ("zone with spaces", "unrecorded"),
    ],
)
def test_display_region_uses_only_explicit_location_segments(stored, shown):
    assert display_region(stored) == shown
