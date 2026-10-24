"""Service-account ownership classes and GCP-GOV-KEYS correctness (owner brief 2026-10-18).
All projects, numbers, identities and policies are synthetic."""

import json
from collections import Counter

import pytest

from offline_analyzer.findings.detail import finding_detail
from offline_analyzer.rules.gcp_identity import (
    DEFAULT_SA,
    PLATFORM_AGENT,
    USER_MANAGED,
    Scope,
    account_class,
)

PROJECT, NUMBER = "demo-alpha", "111111111111"
SA = "serviceAccount:"
CLOUDSERVICES = SA + f"{NUMBER}@cloudservices.gserviceaccount.com"
AGENT = SA + f"service-{NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com"
SAME_COMPUTE = SA + f"{NUMBER}-compute@developer.gserviceaccount.com"
OTHER_COMPUTE = SA + "444444444444-compute@developer.gserviceaccount.com"
FOREIGN = SA + "worker@ext-foreign.iam.gserviceaccount.com"
CONDITIONAL = SA + "temp@ext-other.iam.gserviceaccount.com"


def test_classes_owner_and_documented_forms():
    scope = Scope(PROJECT, NUMBER, {PROJECT: NUMBER}, {})
    expected = {
        CLOUDSERVICES: (PLATFORM_AGENT, PROJECT, NUMBER),
        AGENT: (PLATFORM_AGENT, PROJECT, NUMBER),
        SA + "service-999@gs-project-accounts.iam.gserviceaccount.com": (
            PLATFORM_AGENT,
            None,
            "999",
        ),
        SA + "robot@system.gserviceaccount.com": ("UNKNOWN", None, None),
        SAME_COMPUTE: (DEFAULT_SA, PROJECT, NUMBER),
        SA + f"{PROJECT}@appspot.gserviceaccount.com": (DEFAULT_SA, PROJECT, NUMBER),
        SA + f"{NUMBER}@cloudbuild.gserviceaccount.com": (DEFAULT_SA, PROJECT, NUMBER),
        OTHER_COMPUTE: (DEFAULT_SA, None, "444444444444"),
        FOREIGN: (USER_MANAGED, "ext-foreign", None),
        # A customer-created account named like an agent in a known project is user-managed.
        SA + f"service-{NUMBER}@{PROJECT}.iam.gserviceaccount.com": (USER_MANAGED, PROJECT, NUMBER),
    }
    for member, (cls, owner_id, owner_number) in expected.items():
        account = account_class(member, scope)
        assert (account.account_class, account.owner_project_id, account.owner_project_number) == (
            cls,
            owner_id,
            owner_number,
        ), member
    assert account_class("user:a@example.invalid", scope) is None
    # Unresolvable owner comparison is UNKNOWN, never assumed.
    assert account_class(OTHER_COMPUTE, Scope(PROJECT, None)).relation == "UNKNOWN"


@pytest.fixture(scope="module")
def assessed(tmp_path_factory):
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.ingestion.safety import sha256_file
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.gcp_fixture import build

    root = tmp_path_factory.mktemp("ownership")
    package = build(root / "pkg", PROJECT, NUMBER)
    manifest = json.loads((package / "manifest.json").read_text())
    for dataset in manifest["datasets"]:
        if dataset["operation"] == "gcp:projects.getIamPolicy":
            path = package / dataset["path"]
            policy = json.loads(path.read_text())
            policy["bindings"] = [
                {"role": "roles/editor", "members": [CLOUDSERVICES, AGENT]},
                {"role": "roles/owner", "members": [SAME_COMPUTE, OTHER_COMPUTE, FOREIGN]},
                {
                    "role": "roles/editor",
                    "members": [CONDITIONAL],
                    "condition": {"title": "synthetic window", "expression": "true"},
                },
            ]
            path.write_text(json.dumps(policy))
            dataset["sha256"] = sha256_file(path)
    (package / "manifest.json").write_text(json.dumps(manifest))
    set_environment(root / "work", "SYNTHETIC")
    store = Store(root / "work")
    store.__enter__()
    run = import_package(store, package)
    assess(store, run)
    yield store, run
    store.__exit__(None, None, None)


def bindings_by_role(store, run, rule_id):
    found = {}
    for result in store.results(run):
        if result.rule_id != rule_id or not result.supporting_observations:
            continue
        (obs,) = store.observations(run, observation_id=result.supporting_observations[0])
        key = (obs.configuration["role"], bool(obs.configuration.get("condition")))
        found[key] = result
    return found


def test_unexpected_agent_grants_and_default_accounts_remain_assessable(assessed):
    store, run = assessed
    basic = bindings_by_role(store, run, "GCP-IAM-BASIC")
    cross = bindings_by_role(store, run, "GCP-IAM-CROSSPROJECT")
    agents = basic["roles/editor", False]
    assert str(agents.outcome) == "FAIL"
    assert AGENT in agents.reasoning and "Not counted" in agents.reasoning
    assert str(cross["roles/editor", False].outcome) == "PASS"
    # Same-project default compute account still fails the basic-role rule.
    assert str(basic["roles/owner", False].outcome) == "FAIL"
    assert SAME_COMPUTE in basic["roles/owner", False].reasoning
    # Cross-project: the other project's default account and the foreign account only.
    owner = cross["roles/owner", False]
    assert str(owner.outcome) == "FAIL"
    assert OTHER_COMPUTE in owner.reasoning and FOREIGN in owner.reasoning
    assert SAME_COMPUTE not in owner.reasoning
    assert str(cross["roles/editor", True].outcome) == "UNKNOWN"
    findings = [f for f in store.candidates(run) if f.rule_id.startswith("GCP-IAM-")]
    text = " ".join(f.model_dump_json() for f in findings)
    assert AGENT.split(":")[1] in text
    # The expected APIs agent appears in the qualification, not as the risk principal.
    assert CLOUDSERVICES not in agents.reasoning.split("Not counted")[0]


def test_actual_configuration_shows_member_class_owner_role_condition(assessed):
    store, run = assessed
    finding = next(
        f
        for f in store.candidates(run)
        if f.rule_id == "GCP-IAM-CROSSPROJECT" and "roles/owner" in f.model_dump_json()
    )
    rows = finding_detail(store, run, finding.finding_id)["observed"]["parameters"]
    actual = {row["actual"].split(";")[0]: row["actual"] for row in rows}
    assert actual[SAME_COMPUTE] == (
        f"{SAME_COMPUTE}; account class DEFAULT_SA; owner project {PROJECT}; "
        "role roles/owner; condition none"
    )
    assert "account class DEFAULT_SA; owner project number 444444444444" in actual[OTHER_COMPUTE]
    assert "account class USER_MANAGED; owner project ext-foreign" in actual[FOREIGN]
    # A conditional binding renders its condition.
    from offline_analyzer.findings.detail import identity_parameters

    conditional = next(
        o
        for o in store.observations(run, provider="GCP")
        if o.resource_type == "GCP::IAMBinding" and o.configuration.get("condition")
    )
    rows = identity_parameters(
        store, run, finding, {"supporting_observations": [conditional.observation_id]}, ()
    )
    assert rows[0]["actual"].endswith("role roles/editor; condition synthetic window")


def test_principal_view_labels_platform_agents(assessed):
    from offline_analyzer.iam.gcp_principals import lookup

    store, run = assessed
    (row,) = lookup(store, run, CLOUDSERVICES)["bindings"]
    assert row["account_class"] == PLATFORM_AGENT and row["trust"] == "PLATFORM_MANAGED"
    (row,) = lookup(store, run, SAME_COMPUTE)["bindings"]
    assert row["account_class"] == DEFAULT_SA and row["trust"] == "SAME_PROJECT"


# ------------------------------------------------------------------ GCP-GOV-KEYS
CREATION, UPLOAD = "iam.disableServiceAccountKeyCreation", "iam.disableServiceAccountKeyUpload"
MANAGED = "iam.managed.disableServiceAccountKeyCreation"


def governance_run(tmp_path, monkeypatch, policies):
    import test_gcp_collector_227 as c227

    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store

    monkeypatch.setattr(c227, "POLICIES", policies)
    package = c227.package_227(tmp_path / "pkg")
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    store.__enter__()
    run = import_package(store, package)
    assess(store, run)
    return store, run


def keys_results(store, run):
    return [r for r in store.results(run) if r.rule_id == "GCP-GOV-KEYS"]


def test_two_unenforced_constraints_each_name_their_own(tmp_path, monkeypatch):
    unenforced = {"spec": {"rules": [{"enforce": False}]}}
    store, run = governance_run(tmp_path, monkeypatch, {CREATION: unenforced, UPLOAD: unenforced})
    try:
        findings = [f for f in store.candidates(run) if f.rule_id == "GCP-GOV-KEYS"]
        assert len(findings) == 2
        # Missing managed constraints (and an unrelated denied policy dataset) never make the
        # rule UNKNOWN; "Managed constraint not observed" is a completeness note only.
        assert Counter(str(r.outcome) for r in keys_results(store, run)) == {"FAIL": 2}
        for finding in findings:
            name = CREATION if CREATION in finding.native_id else UPLOAD
            other = UPLOAD if name == CREATION else CREATION
            detail = finding_detail(store, run, finding.finding_id)
            rows = {r["field"]: r for r in detail["observed"]["parameters"]}
            assert rows["constraint"]["actual"] == name
            assert rows["effective enforcement"]["actual"] == "rules: enforce: false"
            assert rows["managed constraint"]["actual"] == "not observed"
            assert name in detail["gap"]["what_is_wrong"] and other not in json.dumps(rows)
            assert detail["validation"]["command"] == (
                f"gcloud org-policies describe {name} --effective --project={finding.project_id}"
            )
            assert detail["evidence"][0]["file"].endswith(".json")
    finally:
        store.__exit__(None, None, None)


def test_managed_creation_enforced_suppresses_the_legacy_finding(tmp_path, monkeypatch):
    unenforced = {"spec": {"rules": [{"enforce": False}]}}
    store, run = governance_run(
        tmp_path,
        monkeypatch,
        {
            CREATION: unenforced,
            UPLOAD: unenforced,
            MANAGED: {"spec": {"rules": [{"enforce": True}]}},
        },
    )
    try:
        findings = [f for f in store.candidates(run) if f.rule_id == "GCP-GOV-KEYS"]
        assert [UPLOAD in f.native_id for f in findings] == [True]
        creation = next(
            r for r in keys_results(store, run) if r.native_id and CREATION in r.native_id
        )
        assert str(creation.outcome) == "PASS" and MANAGED in creation.reasoning
    finally:
        store.__exit__(None, None, None)


def test_missing_constraint_record_is_unknown_never_pass(tmp_path, monkeypatch):
    store, run = governance_run(
        tmp_path, monkeypatch, {UPLOAD: {"spec": {"rules": [{"enforce": True}]}}}
    )
    try:
        outcomes = Counter(
            (str(r.outcome), CREATION in r.reasoning) for r in keys_results(store, run)
        )
        assert outcomes[("UNKNOWN", True)] == 1 and not outcomes[("PASS", True)]
    finally:
        store.__exit__(None, None, None)


@pytest.mark.parametrize(
    "body,shown",
    [
        ({"spec": {"rules": [{"enforce": False}]}}, "rules: enforce: false"),
        ({"spec": {"rules": []}}, "no rules"),
        ({"dryRunSpec": {"rules": [{"enforce": True}]}}, "dryRunSpec only (no live spec)"),
        (
            {"spec": {"rules": [{"enforce": True, "condition": {"expression": "x"}}]}},
            "rules: conditional rule (enforce: true)",
        ),
    ],
)
def test_observed_value_is_rendered(body, shown):
    from offline_analyzer.rules.gcp import observed_policy

    assert observed_policy(body) == shown


def test_other_gcp_rule_outcomes_unchanged(tmp_path):
    """Per-rule outcome counts on every synthetic GCP fixture, recorded before the ownership and
    key-governance changes, for all rules other than the six changed ones."""
    from pathlib import Path

    from tools.gcp_rule_outcomes import outcomes

    baseline = json.loads(Path("tests/gcp_rule_outcomes_baseline.json").read_text())
    changed = {
        "GCP-IAM-CROSSPROJECT",
        "GCP-IAM-BASIC",
        "GCP-IAM-IMPERSONATION",
        "GCP-ORG-SA-PRIVILEGED",
        "GCP-ORG-CROSSPROJECT-SA",
        "GCP-GOV-KEYS",
    }
    from offline_analyzer.rules.gcp import CORRECTED_RULES
    from offline_analyzer.rules.gcp_org import ORG_CORRECTED

    changed |= CORRECTED_RULES | ORG_CORRECTED
    current = outcomes(tmp_path)
    # Complete-source positive assurance is tested separately. Tightened collection gates
    # may change PASS to UNKNOWN; unrelated negative detection predicates must not be lost.
    for fixture, rules in baseline.items():
        for rule, counts in rules.items():
            if rule not in changed:
                assert current[fixture][rule].get("FAIL", 0) == counts.get("FAIL", 0), (
                    fixture,
                    rule,
                )
