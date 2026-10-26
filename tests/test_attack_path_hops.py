"""Attack-path hop model: evidence rules, status propagation and direction justification."""

from types import SimpleNamespace

import pytest
from test_assessment_sprint import estate  # noqa: F401  (synthetic AWS + GCP fixture)
from test_cloud_checklist import org_run  # noqa: F401  (synthetic GCP org-search fixture)
from test_r1 import r1  # noqa: F401  (synthetic AWS R1 fixture)

from offline_analyzer.attack_paths.feasibility import attack_paths
from offline_analyzer.attack_paths.model import (
    BLOCKED,
    EDGE_STRIDE,
    HOP_KEYS,
    HYPOTHESIS,
    PROVEN,
    aws_assumptions,
    aws_hops,
    hop,
    summarize,
)
from offline_analyzer.attack_paths.review import attach, fingerprint
from offline_analyzer.attack_paths.review import record as review_path
from offline_analyzer.attack_paths.specs import BY_PATH
from offline_analyzer.contracts.attack_path import PathHop

REF = {"artifact_id": "artifact-synthetic", "locator": "records[0]"}


def edge(status, **kwargs):
    return hop(
        1, "source", "target", "holds-role", "Because the binding grants it.", status, **kwargs
    )


def test_no_proven_hop_without_a_source_record():
    # A rule ID alone is not a source record.
    demoted = edge(PROVEN, rule_ids=["GCP-ORG-SA-PRIVILEGED"])
    assert demoted["status"] == HYPOTHESIS
    assert any("cited source record" in m for m in demoted["missing_evidence"])
    assert edge(PROVEN, observation_ids=[None])["status"] == HYPOTHESIS
    assert edge(PROVEN, observation_ids=["observation-1"])["status"] == PROVEN
    assert edge(PROVEN, refs=[REF])["status"] == PROVEN


def test_any_blocked_hop_blocks_the_path():
    hops = [edge(PROVEN, refs=[REF]), edge(BLOCKED), edge(HYPOTHESIS, missing=["x"])]
    assert summarize({}, hops, "a", "b", "c")["proof_status"] == BLOCKED


def test_any_non_proven_hop_makes_the_path_a_hypothesis_naming_missing_evidence():
    hops = [edge(PROVEN, refs=[REF]), edge(HYPOTHESIS, missing=["deny policies for p-1"])]
    path = summarize({}, hops, "a", "b", "c")
    assert path["proof_status"] == HYPOTHESIS
    assert "deny policies for p-1" in path["missing_evidence_named"]
    # A hypothesis without a stated gap still names what is missing.
    assert edge(HYPOTHESIS)["missing_evidence"] == ["evidence establishing this edge"]
    proven = summarize({}, [edge(PROVEN, refs=[REF])], "a", "b", "c")
    assert proven["proof_status"] == PROVEN and proven["missing_evidence_named"] == []
    empty = summarize({}, [], "a", "b", "c")
    assert empty["proof_status"] == HYPOTHESIS and empty["missing_evidence_named"]


def test_contract_requires_direction_justification_and_stride():
    valid = edge(PROVEN, refs=[REF])
    with pytest.raises(ValueError):
        PathHop.model_validate({**valid, "justification": ""})
    with pytest.raises(ValueError):
        PathHop.model_validate({**valid, "stride": []})
    assert set(EDGE_STRIDE) == set(PathHop.model_fields["edge_type"].annotation.__args__)


def record(path_id, statuses):
    return SimpleNamespace(path_id=path_id, anchor="synthetic-anchor", prerequisites=statuses)


def evidence(key):
    return (["R-SYNTHETIC"], [], [f"observation-{key}"], [])


def test_aws_alternatives_any_blocked_and_attacker_assumptions():
    # AP-06: P1 OR P2 establishes the escalation hop; P4 unknown keeps the path a hypothesis.
    ap06 = aws_hops(
        record("AP-06", {"AP-06.P1": "VERIFIED", "AP-06.P4": "UNKNOWN"}),
        BY_PATH["AP-06"],
        evidence,
    )
    assert [h["status"] for h in ap06] == [PROVEN, HYPOTHESIS]
    assert ap06[0]["observation_ids"] == ["observation-AP-06.P1"]
    assert any("AP-06.P4" in m for m in ap06[1]["missing_evidence"])
    # AP-05: account-level Block Public Access verified (P1 absent) blocks the entry hop.
    ap05 = aws_hops(record("AP-05", {"AP-05.P1": "NOT_PRESENT"}), BY_PATH["AP-05"], evidence)
    assert ap05[0]["status"] == BLOCKED and "verified absent" in ap05[0]["justification"]
    assert summarize({}, ap05, "a", "b", "c")["proof_status"] == BLOCKED
    # Data classification is never verified from configuration.
    assert ap05[1]["status"] == HYPOTHESIS
    # Exploitation is an assumption, never an edge.
    assumptions = aws_assumptions(BY_PATH["AP-04"])
    assert any(a.startswith("AP-04.P3") for a in assumptions)
    edges = aws_hops(
        record("AP-04", {k: "VERIFIED" for k in ("AP-04.P1", "AP-04.P2", "AP-04.P4")}),
        BY_PATH["AP-04"],
        evidence,
    )
    assert not any("AP-04.P3" in str(h) for h in edges)


def check_paths(store, paths):
    observations = {o for (o,) in store.rows("SELECT observation_id FROM observations")}
    for path in paths:
        assert HOP_KEYS <= set(path), path["path_id"]
        hops = path["hops"]
        for index, h in enumerate(hops, 1):
            PathHop.model_validate(h)
            assert h["index"] == index
            assert h["justification"].strip() and "→" in h["direction"]
            assert h["stride"] == list(EDGE_STRIDE[h["edge_type"]])
            if h["status"] == PROVEN:
                assert h["observation_ids"] or h["evidence_refs"]
            else:
                assert h["missing_evidence"] or h["status"] == BLOCKED
            assert set(h["observation_ids"]) <= observations
            assert h["source"] != "Hypothetical attacker"
        for left, right in zip(hops, hops[1:], strict=False):
            assert left["target"] == right["source"], path["attack_path"]
        statuses = {h["status"] for h in hops}
        expected = (
            BLOCKED
            if BLOCKED in statuses
            else PROVEN
            if hops and statuses == {PROVEN}
            else HYPOTHESIS
        )
        assert path["proof_status"] == expected
        if expected == HYPOTHESIS:
            assert path["missing_evidence_named"]


def test_gcp_org_paths_carry_justified_hops(org_run):  # noqa: F811
    store, run = org_run
    paths = attack_paths(store, run)["items"]
    kinds = {p.get("attack_path") for p in paths}
    assert {"XP-01", "XP-03"} <= kinds
    check_paths(store, paths)
    xp01 = next(p for p in paths if p.get("attack_path") == "XP-01")
    # Deny policies and access boundaries are not verified empty in the fixture.
    assert xp01["proof_status"] == HYPOTHESIS
    assert any("deny policies" in m for m in xp01["missing_evidence_named"])


def test_aws_and_gcp_investigation_paths_carry_justified_hops(r1, estate):  # noqa: F811
    store, run, _directory = r1
    aws = attack_paths(store, run)["items"]
    assert any(p["provider"] == "AWS" and p["hops"] for p in aws)
    check_paths(store, aws)
    store, run, _aws, _gcp = estate
    paths = attack_paths(store, run)["items"]
    investigations = [p for p in paths if p["provider"] == "GCP" and "transitions" in p]
    assert investigations and all(p["hops"] for p in investigations)
    assert all(
        "possession" in " ".join(p["assumptions"]).lower()
        or "control" in " ".join(p["assumptions"]).lower()
        for p in investigations
    )
    check_paths(store, paths)


def test_reviews_recorded_before_the_hop_model_stay_valid(estate):  # noqa: F811
    store, run, _aws, _gcp = estate
    path = attack_paths(store, run)["items"][0]
    legacy = {k: v for k, v in path.items() if k not in HOP_KEYS}
    assert fingerprint(path) == fingerprint(legacy)
    review_path(store, run, path["path_id"], "CONFIRMED", "Synthetic analyst")
    attach(store, run, [legacy])
    assert legacy["analyst_review"] == "CONFIRMED"
