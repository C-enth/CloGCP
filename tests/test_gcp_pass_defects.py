"""PASS defects from docs/GCP_CONTROL_AUTOMATION_AUDIT.md (GCP correctness RC, phase 2):
GCP-KEY-PRIVILEGED, GCP-LOG-AUDIT, GCP-LOG-EXCLUSION and GCP-ORG-FEDERATION. Missing,
denied or incomplete evidence never yields PASS. Synthetic data only."""

from types import SimpleNamespace

import pytest

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.gcp import exclusion, log_selectors
from offline_analyzer.rules.gcp_org import provider_state
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_estate import build_project, edit
from tools.fixtures.gcp_expanded import expanded22


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    return expanded22(tmp_path_factory.mktemp("template") / "t")


def run_for(tmp_path, template, index, changes=None):
    package = build_project(tmp_path / f"p{index}", index, template)
    if changes:
        edit(package, changes)
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    run = import_package(store, package)
    assess(store, run)
    return store, run


def outcome(store, run, rule, native):
    (found,) = [
        str(r.outcome)
        for r in store.results(run)
        if r.rule_id == rule and r.evaluation_scope == "RESOURCE" and r.native_id == native
    ]
    return found


def user_key(index):
    p = f"synth-gcp-{index:02d}"
    return f"projects/{p}/serviceAccounts/app@{p}.iam.gserviceaccount.com/keys/{index:04d}b"


# Estate: project 10 has complete project+parent IAM, a user key without Owner/Editor and an
# inherited organization exemption; project 20 adds an Owner/Editor binding and has no
# exemption anywhere; project 2 has the parent ancestor policies denied.


def test_key_privileged_passes_only_with_complete_iam_hierarchy(tmp_path, template):
    store, run = run_for(tmp_path, template, 10)
    try:
        assert outcome(store, run, "GCP-KEY-PRIVILEGED", user_key(10)) == "PASS"
    finally:
        store.__exit__()


def test_key_privileged_still_fails_with_owner_or_editor(tmp_path, template):
    store, run = run_for(tmp_path, template, 20)
    try:
        assert outcome(store, run, "GCP-KEY-PRIVILEGED", user_key(20)) == "FAIL"
    finally:
        store.__exit__()


def test_key_privileged_unknown_when_parent_policies_are_denied(tmp_path, template):
    store, run = run_for(tmp_path, template, 2)
    try:
        assert outcome(store, run, "GCP-KEY-PRIVILEGED", user_key(2)) == "UNKNOWN"
    finally:
        store.__exit__()


def test_key_privileged_unknown_without_any_parent_policy(tmp_path, template):
    parents = ("parent_org_iam", "parent_folder_iam", "organization_123_iam", "folder_123_iam")
    removed = {d: ("ABSENT", None) for d in parents}
    store, run = run_for(tmp_path, template, 10, removed)
    try:
        assert outcome(store, run, "GCP-KEY-PRIVILEGED", user_key(10)) == "UNKNOWN"
        assert outcome(store, run, "GCP-LOG-AUDIT", "projects/synth-gcp-10") == "UNKNOWN"
    finally:
        store.__exit__()


def test_log_audit_pass_fail_inherited_and_unknown(tmp_path, template):
    store, run = run_for(tmp_path, template, 20)
    try:
        assert outcome(store, run, "GCP-LOG-AUDIT", "projects/synth-gcp-20") == "PASS"
        # Resource-level IAM policies carry no audit configuration.
        assert outcome(store, run, "GCP-LOG-AUDIT", "buckets/synth-gcp-20-data") == (
            "NOT_APPLICABLE"
        )
        assert outcome(store, run, "GCP-LOG-AUDIT", "organizations/123") == "NOT_APPLICABLE"
    finally:
        store.__exit__()


def test_log_audit_inherited_exemption_fails_project_and_parent(tmp_path, template):
    store, run = run_for(tmp_path, template, 10)
    try:
        assert outcome(store, run, "GCP-LOG-AUDIT", "projects/synth-gcp-10") == "FAIL"
        assert outcome(store, run, "GCP-LOG-AUDIT", "organizations/123") == "FAIL"
    finally:
        store.__exit__()


def test_log_audit_unknown_when_ancestors_are_denied(tmp_path, template):
    store, run = run_for(tmp_path, template, 2)
    try:
        assert outcome(store, run, "GCP-LOG-AUDIT", "projects/synth-gcp-02") == "UNKNOWN"
    finally:
        store.__exit__()


def exclusion_obs(filter_text, disabled=None):
    config = {"filter": filter_text, **({"disabled": disabled} if disabled is not None else {})}
    return SimpleNamespace(configuration=config)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('log_id("cloudaudit.googleapis.com/data_access")', "FAIL"),
        ('log_id("cloudaudit.googleapis.com/activity") AND severity<WARNING', "FAIL"),
        ('logName="projects/p/logs/cloudaudit.googleapis.com%2Fdata_access"', "FAIL"),
        ('log_id("syslog") AND severity<WARNING', "PASS"),
        ('logName="projects/p/logs/nginx-access"', "PASS"),
        ('resource.type="gce_instance" AND severity<WARNING', "UNKNOWN"),
        ('log_id("syslog") OR log_id("cloudaudit.googleapis.com/data_access")', "UNKNOWN"),
        ('NOT log_id("syslog")', "UNKNOWN"),
        ('-log_id("syslog")', "UNKNOWN"),
        ('(log_id("syslog"))', "UNKNOWN"),
    ],
)
def test_exclusion_filter_outcomes(text, expected):
    assert str(exclusion(exclusion_obs(text)).outcome) == expected


def test_disabled_exclusion_is_not_applicable_and_selectors_parse():
    assert exclusion(exclusion_obs('log_id("x")', disabled=True)).outcome == (
        Outcome.NOT_APPLICABLE
    )
    assert log_selectors('log_id("a") AND severity>=ERROR') == ["a"]


def test_complete_evidence_without_exclusions_is_not_applicable(tmp_path, template):
    store, run = run_for(tmp_path, template, 2)  # exclusions EMPTY, sinks SUCCESS
    try:
        (row,) = [
            r
            for r in store.results(run)
            if r.rule_id == "GCP-LOG-EXCLUSION" and r.evaluation_scope == "COLLECTION_SCOPE"
        ]
        assert str(row.outcome) == "NOT_APPLICABLE"
    finally:
        store.__exit__()


def provider(name, condition=None, disabled=False, state="ACTIVE"):
    config = {"name": name, "disabled": disabled, "state": state}
    if condition:
        config["attributeCondition"] = condition
    return SimpleNamespace(configuration=config, native_id=name, observation_id="obs-" + name[-1])


POOL = "projects/900000000000/locations/global/workloadIdentityPools/ci/providers/"
WHOLE = [{"attribute": "*"}]
SUBJECT = [{"attribute": "subject"}]


def test_federation_whole_pool_without_condition_fails():
    info = {"items": [provider(POOL + "a")], "complete": True}
    assert provider_state(WHOLE, info)[0] == Outcome.FAIL


def test_federation_specific_subject_without_condition_needs_review():
    info = {"items": [provider(POOL + "a")], "complete": True}
    assert provider_state(SUBJECT, info)[0] == Outcome.MANUAL_VALIDATION_REQUIRED


def test_federation_conditions_are_shown_for_review():
    info = {"items": [provider(POOL + "a", "assertion.repository=='o/r'")], "complete": True}
    state, text, related = provider_state(WHOLE, info)
    assert state == Outcome.MANUAL_VALIDATION_REQUIRED and "assertion.repository" in text
    assert related == ("obs-a",)


def test_federation_disabled_providers_pass_only_with_complete_evidence():
    items = [provider(POOL + "a", disabled=True), provider(POOL + "b", state="DELETED")]
    assert provider_state(WHOLE, {"items": items, "complete": True})[0] == Outcome.PASS
    assert provider_state(WHOLE, {"items": items, "complete": False})[0] == (
        Outcome.MANUAL_VALIDATION_REQUIRED
    )
    assert provider_state(WHOLE, None)[0] == Outcome.MANUAL_VALIDATION_REQUIRED
