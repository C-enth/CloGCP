"""Phase F: AWS rule correctness on collector 0.3.3 output (fake cloud, synthetic data only).

* Every AWS rule reaches PASS on complete, compliant evidence (docs/AWS_CONTROL_AUTOMATION_AUDIT
  question b) and complete evidence leaves no collection-scope UNKNOWN row.
* Identity enrichment (platform-managed classes, trust conditions, SCP awareness, workload
  pairing) never lowers a finding's severity.
"""

from collections import defaultdict
from pathlib import Path

import pytest

from offline_analyzer.cli import private_copy
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules.registry import ALL_RULES
from offline_analyzer.storage.store import Store
from tools.fixtures import aws_fake_cloud as fake

RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def assessed(tmp_path, *, compliant=False, enrich=True):
    import offline_analyzer.rules.engine as engine

    cloud = fake.fleet(1, size=2)
    cloud.accounts[fake.fleet_account(0)].compliant = compliant
    with fake.installed(cloud) as collector:
        cfg = fake.config(tmp_path / "evidence", regions=("ap-south-1",))
        result = collector.collect_account(cfg, fake.fleet_account(0), None)
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    with private_copy(store.workspace, Path(result["zip"])) as root:
        run = import_package(store, root)
    original = engine.enrich
    if not enrich:
        engine.enrich = lambda rule_id, obs, verdict, context: verdict
    try:
        engine.assess(store, run)
    finally:
        engine.enrich = original
    return store, run


def test_every_aws_rule_reaches_pass_on_complete_compliant_evidence(tmp_path):
    store, run = assessed(tmp_path, compliant=True)
    outcomes = defaultdict(set)
    scope_rows = []
    for rule, scope, outcome in store.rows(
        "SELECT json_extract_string(data,'$.rule_id'), json_extract_string(data,"
        "'$.evaluation_scope'), outcome FROM evaluations WHERE run_id=?",
        [run],
    ):
        outcomes[rule].add(outcome)
        if scope == "COLLECTION_SCOPE":
            scope_rows.append((rule, outcome))
    assert {r.rule_id for r in ALL_RULES} <= outcomes.keys()
    never_pass = sorted(r.rule_id for r in ALL_RULES if "PASS" not in outcomes[r.rule_id])
    assert never_pass == []
    assert scope_rows == []  # complete evidence: per-resource rows suffice
    assert (
        store.db.execute("SELECT count(*) FROM findings WHERE run_id=?", [run]).fetchone()[0] == 0
    )


@pytest.fixture(scope="module")
def severities(tmp_path_factory):
    result = {}
    for enrich in (False, True):
        store, run = assessed(tmp_path_factory.mktemp(f"enrich-{enrich}"), enrich=enrich)
        result[enrich] = {
            fid: (rule, severity, exposure or "")
            for fid, rule, severity, exposure in store.rows(
                "SELECT finding_id, json_extract_string(data,'$.rule_id'), "
                "json_extract_string(data,'$.suggested_severity'), "
                "json_extract_string(data,'$.exposure_status') FROM findings WHERE run_id=?",
                [run],
            )
        }
    return result


def test_identity_enrichment_never_lowers_severity_silently(severities):
    """A lower severity is allowed only as an explicit, evidenced reclassification that
    names the previous class and severity (rules/aws_identity.py); otherwise never."""
    base, enriched = severities[False], severities[True]
    assert base and base.keys() == enriched.keys()  # enrichment never drops a finding
    lowered = [fid for fid in base if RANK[enriched[fid][1]] < RANK[base[fid][1]]]
    silent = [
        fid
        for fid in lowered
        if not enriched[fid][2].startswith("Reclassified from ") or f"/{base[fid][1]} to " not in
        enriched[fid][2]
    ]  # fmt: skip
    assert silent == []
    # The one reclassification in this estate: the organization access role trusted by the
    # evidenced management account (AWS-created; trust is platform-managed).
    assert all("evidenced organization management account" in enriched[f][2] for f in lowered)
    # The enriched rules are the ones whose findings exist in this estate.
    rules = {rule for rule, _severity, _exposure in enriched.values()}
    assert {"R1-IAM-ROLE-TRUST-CONDITIONS", "R1-EC2-SG-SENSITIVE-INGRESS"} <= rules
