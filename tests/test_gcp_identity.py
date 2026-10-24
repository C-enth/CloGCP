"""Service-account identity resolution (E1 platform-managed, E2 home project) for the
identity-aware GCP rules and attack paths. All projects, numbers and identities are synthetic."""

import json
from collections import Counter
from types import SimpleNamespace

import pytest

from offline_analyzer.attack_paths.cross import cross_paths
from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.rules import registry
from offline_analyzer.rules.gcp import binding_rule
from offline_analyzer.rules.gcp_identity import (
    EXTERNAL_OR_UNKNOWN,
    IN_ORG_NOT_ASSESSED,
    IN_SCOPE_OTHER_PROJECT,
    PLATFORM_MANAGED,
    SAME_PROJECT,
    UNKNOWN,
    Scope,
    classify_member,
)
from offline_analyzer.rules.gcp_org import matches

ALPHA, ALPHA_NO = "demo-alpha", "111111111111"
BETA, BETA_NO = "demo-beta", "222222222222"
GAMMA_NO = "333333333333"
SA = "serviceAccount:"
SAME_BY_ID = SA + f"app@{ALPHA}.iam.gserviceaccount.com"
SAME_BY_NUMBER = SA + f"{ALPHA_NO}@cloudbuild.gserviceaccount.com"
CLOUDSERVICES = SA + f"{ALPHA_NO}@cloudservices.gserviceaccount.com"
DEFAULT_COMPUTE = SA + f"{ALPHA_NO}-compute@developer.gserviceaccount.com"
SERVICE_AGENT = SA + f"service-{ALPHA_NO}@gcp-sa-pubsub.iam.gserviceaccount.com"
IN_SCOPE = SA + f"deployer@{BETA}.iam.gserviceaccount.com"
FOREIGN = SA + "worker@ext-foreign.iam.gserviceaccount.com"
POLICY_MEMBERS = [
    SAME_BY_NUMBER,
    SAME_BY_ID,
    CLOUDSERVICES,
    DEFAULT_COMPUTE,
    SERVICE_AGENT,
    IN_SCOPE,
    FOREIGN,
]
SCOPE = Scope(ALPHA, ALPHA_NO, {ALPHA: ALPHA_NO, BETA: BETA_NO}, {GAMMA_NO: "demo-gamma"})


def binding(role, members, condition=None, subject=f"projects/{ALPHA}"):
    config = {"role": role, "members": members, "subject": subject}
    if condition:
        config["condition"] = condition
    return SimpleNamespace(configuration=config, project_id=ALPHA)


def test_classes_and_documented_patterns():
    expected = {
        SAME_BY_ID: (SAME_PROJECT, ALPHA),
        SAME_BY_NUMBER: (SAME_PROJECT, ALPHA),
        CLOUDSERVICES: (PLATFORM_MANAGED, ALPHA),
        DEFAULT_COMPUTE: (SAME_PROJECT, ALPHA),
        SERVICE_AGENT: (PLATFORM_MANAGED, ALPHA),
        IN_SCOPE: (IN_SCOPE_OTHER_PROJECT, BETA),
        FOREIGN: (EXTERNAL_OR_UNKNOWN, "ext-foreign"),
        SA + f"{BETA_NO}-compute@developer.gserviceaccount.com": (IN_SCOPE_OTHER_PROJECT, BETA),
        SA + f"service-{GAMMA_NO}@gcp-sa-run.iam.gserviceaccount.com": (
            IN_ORG_NOT_ASSESSED,
            "demo-gamma",
        ),
        SA + "x@demo-gamma.iam.gserviceaccount.com": (IN_ORG_NOT_ASSESSED, "demo-gamma"),
        SA + "service-444444444444@gcp-sa-run.iam.gserviceaccount.com": (
            EXTERNAL_OR_UNKNOWN,
            "number 444444444444",
        ),
        # A user-created account named like an agent is resolved by its project ID.
        SA + f"service-{ALPHA_NO}@ext-foreign.iam.gserviceaccount.com": (
            EXTERNAL_OR_UNKNOWN,
            "ext-foreign",
        ),
        SA + "robot@system.gserviceaccount.com": (UNKNOWN, None),
    }
    for member, (trust, home) in expected.items():
        identity = classify_member(member, SCOPE)
        assert (identity.trust, identity.home) == (trust, home), member
        assert member in identity.text and trust in identity.text and identity.evidence
    assert classify_member("group:ops@example.invalid", SCOPE) is None


def test_one_policy_reports_only_the_foreign_out_of_scope_account():
    verdict = binding_rule(binding("roles/editor", POLICY_MEMBERS), "crossproject", SCOPE)
    assert verdict.outcome == Outcome.FAIL
    reported = verdict.reasoning.split("; informational link")[0]
    assert FOREIGN in reported and "owner project ext-foreign" in reported
    assert "class USER_MANAGED" in reported
    assert EXTERNAL_OR_UNKNOWN in reported
    for member in POLICY_MEMBERS[:-2]:
        assert member not in verdict.reasoning
    # The in-scope account is an informational link, never the reported member.
    assert IN_SCOPE in verdict.reasoning.split("; informational link")[1]
    linked = binding_rule(binding("roles/owner", [IN_SCOPE, SAME_BY_ID]), "crossproject", SCOPE)
    assert linked.outcome == Outcome.NOT_APPLICABLE and "Informational" in linked.reasoning
    assert IN_SCOPE in linked.reasoning and IN_SCOPE_OTHER_PROJECT in linked.reasoning
    same = binding_rule(binding("roles/editor", POLICY_MEMBERS[:5]), "crossproject", SCOPE)
    assert same.outcome == Outcome.PASS
    conditional = binding_rule(
        binding("roles/editor", [FOREIGN], {"expression": "request.time < timestamp('2027')"}),
        "crossproject",
        SCOPE,
    )
    assert conditional.outcome == Outcome.UNKNOWN


def test_missing_project_number_is_unknown_never_pass_or_dropped():
    scope = Scope(ALPHA, None, {ALPHA: None}, {})
    for member in (CLOUDSERVICES, DEFAULT_COMPUTE, SERVICE_AGENT):
        assert classify_member(member, scope).trust == UNKNOWN
    # Rules: a default account owned by number cannot be compared without the binding
    # project's number, so the cross-project rule is UNKNOWN (never PASS, never dropped).
    verdict = binding_rule(
        binding("roles/editor", [SAME_BY_ID, DEFAULT_COMPUTE]), "crossproject", scope
    )
    assert verdict.outcome == Outcome.UNKNOWN and DEFAULT_COMPUTE in verdict.reasoning
    # The expected Google APIs grant needs a verified owning project number.
    assert binding_rule(binding("roles/editor", [CLOUDSERVICES]), "basic", scope).outcome == (
        Outcome.UNKNOWN
    )


def test_expected_platform_grant_is_distinguished_from_unusual_agent_privileges():
    platform = binding_rule(binding("roles/editor", [CLOUDSERVICES]), "basic", SCOPE)
    assert platform.outcome == Outcome.NOT_APPLICABLE
    assert CLOUDSERVICES in platform.reasoning
    assert (
        binding_rule(binding("roles/editor", [SERVICE_AGENT]), "basic", SCOPE).outcome
        == Outcome.FAIL
    )
    assert platform.reasoning.startswith("Google-managed service agent (platform-managed)")
    # The legacy Cloud Build account is a default account: still counted.
    cloudbuild = binding_rule(binding("roles/editor", [SAME_BY_NUMBER]), "basic", SCOPE)
    assert cloudbuild.outcome == Outcome.FAIL and "class DEFAULT_SA" in cloudbuild.reasoning
    mixed = binding_rule(binding("roles/editor", [CLOUDSERVICES, SAME_BY_ID]), "basic", SCOPE)
    assert mixed.outcome == Outcome.FAIL and "Not counted" in mixed.reasoning
    assert SAME_BY_ID in mixed.reasoning.split("Not counted")[0]
    token = "roles/iam.serviceAccountTokenCreator"
    agent = binding_rule(binding(token, [SERVICE_AGENT]), "impersonation", SCOPE)
    assert agent.outcome == Outcome.FAIL and SERVICE_AGENT in agent.reasoning
    broad = binding_rule(binding(token, [SERVICE_AGENT, SAME_BY_ID]), "impersonation", SCOPE)
    assert broad.outcome == Outcome.FAIL
    # Without the opt-in scope the evaluation is unchanged.
    assert binding_rule(binding("roles/editor", [CLOUDSERVICES]), "basic").outcome == Outcome.FAIL


def test_default_compute_account_is_customer_operated_not_platform_managed():
    """Editor on the default compute account of the same project is still a finding; the same
    account form with another project's number is cross-project."""
    same = classify_member(DEFAULT_COMPUTE, SCOPE)
    assert (same.trust, same.home) == (SAME_PROJECT, ALPHA)
    basic = binding_rule(binding("roles/editor", [DEFAULT_COMPUTE]), "basic", SCOPE)
    assert basic.outcome == Outcome.FAIL and DEFAULT_COMPUTE in basic.reasoning
    assert SAME_PROJECT in basic.reasoning
    assert (
        binding_rule(binding("roles/editor", [DEFAULT_COMPUTE]), "crossproject", SCOPE).outcome
        == Outcome.PASS
    )
    privileged = matches("GCP-ORG-SA-PRIVILEGED", org_record([DEFAULT_COMPUTE]), ALPHA, SCOPE, {})
    assert len(privileged) == 1 and DEFAULT_COMPUTE in privileged[0]
    other = SA + "444444444444-compute@developer.gserviceaccount.com"
    assert classify_member(other, SCOPE).trust == EXTERNAL_OR_UNKNOWN
    cross = binding_rule(binding("roles/editor", [other]), "crossproject", SCOPE)
    assert cross.outcome == Outcome.FAIL and other in cross.reasoning
    assert "number 444444444444" in cross.reasoning
    org_hits = matches("GCP-ORG-CROSSPROJECT-SA", org_record([other]), ALPHA, SCOPE, {})
    assert len(org_hits) == 1 and other in org_hits[0]


def org_record(members, conditional=()):
    bindings = [{"role": "roles/editor", "members": members}]
    bindings += [
        {"role": "roles/editor", "members": [m], "condition": {"expression": "true"}}
        for m in conditional
    ]
    return {
        "resource": f"//cloudresourcemanager.googleapis.com/projects/{ALPHA}",
        "assetType": "cloudresourcemanager.googleapis.com/Project",
        "project": f"projects/{ALPHA_NO}",
        "policy": {"bindings": bindings},
    }


def test_org_rules_follow_the_same_classification():
    config = org_record(POLICY_MEMBERS, conditional=[SA + "c@ext-other.iam.gserviceaccount.com"])
    notes: dict = {}
    hits = matches("GCP-ORG-CROSSPROJECT-SA", config, ALPHA, SCOPE, notes)
    assert len(hits) == 1 and FOREIGN in hits[0] and EXTERNAL_OR_UNKNOWN in hits[0]
    assert len(notes["linked"]) == 1 and IN_SCOPE in notes["linked"][0]
    notes = {}
    hits = matches("GCP-ORG-SA-PRIVILEGED", config, ALPHA, SCOPE, notes)
    reported = " ".join(hits)
    assert SAME_BY_ID in reported and FOREIGN in reported and IN_SCOPE in reported
    assert DEFAULT_COMPUTE + f" (class DEFAULT_SA; owner project {ALPHA}; {SAME_PROJECT})" in (
        reported
    )
    assert SAME_BY_NUMBER in reported  # legacy Cloud Build account is DEFAULT_SA
    assert CLOUDSERVICES not in reported and any(CLOUDSERVICES in n for n in notes["platform"])
    assert SERVICE_AGENT in reported  # Editor is not the documented Pub/Sub agent grant
    missing = Scope(ALPHA, None, {}, {})
    notes = {}
    assert not matches(
        "GCP-ORG-CROSSPROJECT-SA", org_record([DEFAULT_COMPUTE]), ALPHA, missing, notes
    )
    assert DEFAULT_COMPUTE in notes["unknown"][0]


class FakeStore:
    def __init__(self, observations, sources):
        self._observations, self._sources = observations, sources

    def observations(self, run, provider=None):
        return iter(self._observations)

    def source_data(self, run):
        return iter(self._sources)

    def rows(self, sql, params=None):
        return []


def test_attack_path_edges_follow_the_same_classification():
    obs = SimpleNamespace(
        resource_type="GCP::AssetIAMSearchResult",
        configuration=org_record(
            POLICY_MEMBERS, conditional=[SA + "c@ext-x.iam.gserviceaccount.com"]
        ),
        project_id=ALPHA,
        observation_id="obs-synthetic",
    )
    sources = [
        {"format": "gcp-json-v1", "project_id": ALPHA, "project_number": ALPHA_NO},
        {"format": "gcp-json-v1", "project_id": BETA, "project_number": BETA_NO},
    ]
    paths = [
        p for p in cross_paths(FakeStore([obs], sources), "run") if p["attack_path"] == "XP-02"
    ]
    members = {p["steps"][1].removeprefix("run as ") for p in paths}
    assert members == {IN_SCOPE, FOREIGN}
    text = json.dumps(paths)
    assert IN_SCOPE_OTHER_PROJECT in text and EXTERNAL_OR_UNKNOWN in text
    for member in (SAME_BY_ID, CLOUDSERVICES, DEFAULT_COMPUTE, SERVICE_AGENT, SAME_BY_NUMBER):
        assert member not in members


@pytest.fixture(scope="module")
def assessed(tmp_path_factory):
    """Synthetic single-project package with the policy above, assessed end to end."""
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.ingestion.safety import sha256_file
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.gcp_fixture import build

    root = tmp_path_factory.mktemp("identity")
    package = build(root / "pkg", ALPHA, ALPHA_NO)
    manifest = json.loads((package / "manifest.json").read_text())
    for dataset in manifest["datasets"]:
        if dataset["operation"] == "gcp:projects.getIamPolicy":
            path = package / dataset["path"]
            policy = json.loads(path.read_text())
            policy["bindings"] += [
                {"role": "roles/editor", "members": POLICY_MEMBERS},
                {
                    "role": "roles/owner",
                    "members": [FOREIGN],
                    "condition": {"title": "synthetic", "expression": "true"},
                },
            ]
            path.write_text(json.dumps(policy))
            dataset["sha256"] = sha256_file(path)
    (package / "manifest.json").write_text(json.dumps(manifest))

    def run(name, enriched):
        workspace = root / name
        set_environment(workspace, "SYNTHETIC")
        registry.IDENTITY_ENRICHED, saved = enriched, registry.IDENTITY_ENRICHED
        try:
            store = Store(workspace)
            store.__enter__()
            run_id = import_package(store, package)
            assess(store, run_id)
        finally:
            registry.IDENTITY_ENRICHED = saved
        return store, run_id

    enriched = run("enriched", registry.IDENTITY_ENRICHED)
    plain = run("plain", frozenset())
    yield enriched, plain
    for store, _ in (enriched, plain):
        store.__exit__(None, None, None)


def test_end_to_end_only_foreign_cross_project_finding(assessed):
    (store, run), _ = assessed
    cross = [f for f in store.candidates(run) if f.rule_id == "GCP-IAM-CROSSPROJECT"]
    reported = " ".join(f.model_dump_json() for f in cross)
    assert FOREIGN in reported
    for member in (SAME_BY_ID, SAME_BY_NUMBER, CLOUDSERVICES, DEFAULT_COMPUTE, SERVICE_AGENT):
        assert member + " (" not in reported
    results = [r for r in store.results(run) if r.rule_id == "GCP-IAM-CROSSPROJECT"]
    assert {r.rule_version for r in results} == {"clogcp-1.0.0"}
    assert Counter(str(r.outcome) for r in results)["UNKNOWN"] >= 1  # conditional binding


def test_hygiene_rule_outcomes_unchanged(assessed):
    (store, run), (plain_store, plain_run) = assessed

    def outcomes(s, r):
        return Counter(
            (x.rule_id, x.rule_version, x.resource_id, str(x.outcome))
            for x in s.results(r)
            if x.rule_id not in registry.IDENTITY_ENRICHED
        )

    assert outcomes(store, run) == outcomes(plain_store, plain_run)


def test_existing_analyst_reviews_still_match_by_stable_finding_id(assessed):
    """A review recorded on the pre-change evaluation (opt-in disabled) keeps matching the
    identity-aware finding: the finding ID excludes the rule version and the text."""
    from offline_analyzer.findings.generate import record_decision

    (store, run), (plain_store, plain_run) = assessed
    enriched = {
        (f.rule_id, f.resource_id): f
        for f in store.candidates(run)
        if f.rule_id in registry.IDENTITY_ENRICHED
    }
    matched = 0
    for finding in plain_store.candidates(plain_run):
        if (
            finding.rule_id not in registry.IDENTITY_ENRICHED
            or (finding.rule_id, finding.resource_id) not in enriched
        ):
            continue
        assert finding.finding_id == stable_id("finding", [finding.rule_id, finding.resource_id])
        assert enriched[finding.rule_id, finding.resource_id].finding_id == finding.finding_id
        record_decision(plain_store, plain_run, finding.finding_id, "CONFIRMED", "analyst", "")
        decision = plain_store.latest_decision(
            enriched[finding.rule_id, finding.resource_id].finding_id
        )
        assert decision and decision.status == "CONFIRMED"
        matched += 1
    assert matched >= 2


def test_opt_in_and_version_bumps_are_limited_to_the_identity_rules():
    rules = {
        "GCP-IAM-CROSSPROJECT",
        "GCP-IAM-BASIC",
        "GCP-IAM-IMPERSONATION",
        "GCP-ORG-SA-PRIVILEGED",
        "GCP-ORG-CROSSPROJECT-SA",
    }
    assert registry.IDENTITY_ENRICHED == rules | {"XP-01", "XP-02"}
    bumped = {"GCP-IAM-CROSSPROJECT": "1.4.0", "GCP-IAM-BASIC": "1.4.0"}
    bumped |= {"GCP-IAM-IMPERSONATION": "1.4.0", "GCP-GOV-KEYS": "1.4.0"}
    # Organization scope rows need a complete organization search (GCP correctness RC):
    # the identity rules move 1.2.0 -> 1.3.0, the other scope-row rules 1.0.0 -> 1.1.0.
    bumped |= {"GCP-ORG-SA-PRIVILEGED": "1.3.0", "GCP-ORG-CROSSPROJECT-SA": "1.3.0"}
    bumped |= {"GCP-ORG-EXTERNAL-DOMAIN": "1.0.0", "GCP-ORG-FEDERATION": "1.1.0"}
    # PASS from complete project and parent IAM (GCP correctness RC phase 2).
    bumped |= {"GCP-KEY-PRIVILEGED": "1.3.0"}
    # Documented omitted `restrictions` from complete evidence (phase 3).
    bumped |= {"GCP-API-APP": "1.3.0", "GCP-API-API": "1.3.0", "GCP-API-BOTH": "1.3.0"}
    from offline_analyzer.rules.gcp import CORRECTED_RULES
    from offline_analyzer.rules.gcp_domains import SPECS
    from offline_analyzer.rules.gcp_org import ORG_CORRECTED

    bumped |= {rid: "clogcp-1.0.0" for rid in CORRECTED_RULES | ORG_CORRECTED | set(SPECS)}
    for rule in registry.PROVIDER_RULES:
        if rule.provider == "GCP":
            default = "1.1.0" if rule.rule_id.startswith("GCP-ORG-") else None
            expected = bumped.get(rule.rule_id, default)
            if expected:
                assert rule.version == expected, rule.rule_id
            elif rule.rule_id.startswith(("GCP-IAM-", "GCP-KEY-", "GCP-API-")):
                assert rule.version == "1.2.0", rule.rule_id
