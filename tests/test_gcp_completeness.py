"""GCP collector 2.2 coverage completeness at import (GCP correctness RC, phase 1) and the
organization-scope rows. Synthetic packages only (tools/fixtures/gcp_estate.py)."""

import json
import shutil

import pytest

from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_estate import build_project, edit
from tools.fixtures.gcp_expanded import expanded, expanded22

FAILURES = (
    "FAILED",
    "API_DISABLED",
    "ACCESS_DENIED",
    "QUOTA_PROJECT_DENIED",
    "COMMAND_ERROR",
    "AUTH_ERROR",
    "TIMEOUT",
    "RATE_LIMITED",
    "NOT_FOUND",
    "HTTP_ERROR",
    "SERVER_ERROR",
)
VM_RULES = {r for r in ("GCP-VM-EXTERNAL-IP", "GCP-VM-DEFAULT-SA", "GCP-VM-SHIELDED")}


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    root = tmp_path_factory.mktemp("estate")
    return build_project(root / "project", 0, expanded22(root / "template"))


def assessed(tmp_path, package):
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    run = import_package(store, package)
    assess(store, run)
    return store, run


def variant(tmp_path, template, changes=None, **fields):
    target = tmp_path / "package"
    shutil.copytree(template, target)
    return edit(target, changes or {}, **fields)


def source_of(store, run, dataset):
    return next(
        s for s in store.source_data(run) if (s.get("gcp_metadata") or {}).get("dataset") == dataset
    )


def scope(store, run, rules):
    return {
        r.rule_id: str(r.outcome)
        for r in store.results(run)
        if r.rule_id in rules and r.evaluation_scope == "COLLECTION_SCOPE"
    }


def test_success_is_complete_and_needs_no_scope_row(tmp_path, template):
    store, run = assessed(tmp_path, variant(tmp_path, template))
    try:
        source = source_of(store, run, "instances")
        assert source["effective_coverage"] == "COMPLETE"
        assert source["gcp_metadata"]["pagination_complete"] is True
        assert (
            "COLLECTOR_PAGINATION_UNVERIFIED"
            not in source["gcp_metadata"]["completeness_limitations"]
        )
        # Resources were evaluated from complete evidence: no blanket scope row remains.
        assert scope(store, run, VM_RULES) == {}
        assert {str(r.outcome) for r in store.results(run) if r.rule_id == "GCP-VM-SHIELDED"} == {
            "PASS",
            "FAIL",
        }
    finally:
        store.__exit__()


def test_empty_successful_list_is_not_applicable(tmp_path, template):
    package = variant(tmp_path, template, {"instances": ("EMPTY", None)})
    store, run = assessed(tmp_path, package)
    try:
        assert source_of(store, run, "instances")["effective_coverage"] == "COMPLETE"
        assert set(scope(store, run, VM_RULES).values()) == {"NOT_APPLICABLE"}
    finally:
        store.__exit__()


def test_truncated_stays_partial_and_never_passes(tmp_path, template):
    body = json.loads((template / "compute" / "instances.json").read_text())
    package = variant(tmp_path, template, {"instances": ("TRUNCATED", body)})
    store, run = assessed(tmp_path, package)
    try:
        assert source_of(store, run, "instances")["effective_coverage"] == "PARTIAL"
        assert set(scope(store, run, VM_RULES).values()) == {"UNKNOWN"}
        assert not any(
            str(r.outcome) == "PASS" for r in store.results(run) if r.rule_id in VM_RULES
        )
    finally:
        store.__exit__()


def test_partial_rest_dataset_stays_partial(tmp_path, template):
    # PARTIAL is a REST status (some locations unreachable).
    body = [
        {
            "name": "projects/synth-gcp-00/locations/global/keyRings/r/cryptoKeys/k",
            "purpose": "ENCRYPT_DECRYPT",
            "rotationPeriod": "7776000s",
        }
    ]
    package = variant(tmp_path, template, {"kms_keys_1_1": ("PARTIAL", body)})
    store, run = assessed(tmp_path, package)
    try:
        assert source_of(store, run, "kms_keys_1_1")["effective_coverage"] == "PARTIAL"
        assert scope(store, run, {"GCP-KMS-ROTATION"}) == {"GCP-KMS-ROTATION": "UNKNOWN"}
    finally:
        store.__exit__()


@pytest.mark.parametrize("status", FAILURES)
def test_every_failure_status_stays_insufficient(tmp_path, template, status):
    store, run = assessed(tmp_path, variant(tmp_path, template, {"instances": (status, None)}))
    try:
        source = source_of(store, run, "instances")
        assert source["effective_coverage"] == "ERROR" and source["errors"]
        outcomes = set(scope(store, run, VM_RULES).values())
        assert outcomes == {"UNKNOWN"}  # compute is not a "resource API": no N/A from disabled
        assert not any(
            str(r.outcome) == "PASS" for r in store.results(run) if r.rule_id in VM_RULES
        )
    finally:
        store.__exit__()


def test_interrupted_collection_and_detail_limits_stay_partial(tmp_path, template):
    package = variant(tmp_path, template, collection_status="INTERRUPTED")
    store, run = assessed(tmp_path, package)
    try:
        assert source_of(store, run, "instances")["effective_coverage"] == "PARTIAL"
    finally:
        store.__exit__()


def test_collector_21_packages_without_checksums_stay_partial(tmp_path):
    store, run = assessed(tmp_path, expanded(tmp_path / "package"))
    try:
        coverages = {s["effective_coverage"] for s in store.source_data(run)}
        assert "COMPLETE" not in coverages
    finally:
        store.__exit__()


ORG_SCOPE = {
    "GCP-ORG-PUBLIC-SERVERLESS",
    "GCP-ORG-PUBLIC-DATA",
    "GCP-ORG-PUBLIC-OTHER",
    "GCP-ORG-BASIC-ROLE",
    "GCP-ORG-SA-PRIVILEGED",
    "GCP-ORG-IMPERSONATION",
    "GCP-ORG-CROSSPROJECT-SA",
    "GCP-ORG-DELETED-PRINCIPAL",
}
NO_MATCH = [
    {
        "resource": "//storage.googleapis.com/synth-gcp-00-data",
        "assetType": "storage.googleapis.com/Bucket",
        "project": "projects/900000000000",
        "policy": {"bindings": [{"role": "roles/viewer", "members": ["group:a@example.com"]}]},
    }
]


def org_variant(tmp_path, template, project_search, organization_search):
    return variant(
        tmp_path,
        template,
        {
            "asset_iam_search": project_search,
            "organization_123_iam_search": organization_search,
            "folder_123_iam_search": ("ACCESS_DENIED", None),
        },
    )


def test_no_iam_search_gives_unknown_organization_rows(tmp_path, template):
    package = org_variant(
        tmp_path, template, ("QUOTA_PROJECT_DENIED", None), ("ACCESS_DENIED", None)
    )
    store, run = assessed(tmp_path, package)
    try:
        rows = scope(store, run, ORG_SCOPE)
        assert set(rows) == ORG_SCOPE and set(rows.values()) == {"UNKNOWN"}
    finally:
        store.__exit__()


def test_project_search_alone_is_not_an_organization_pass(tmp_path, template):
    package = org_variant(tmp_path, template, ("SUCCESS", NO_MATCH), ("ACCESS_DENIED", None))
    store, run = assessed(tmp_path, package)
    try:
        assert set(scope(store, run, ORG_SCOPE).values()) == {"UNKNOWN"}
    finally:
        store.__exit__()


def test_complete_organization_search_without_match_passes(tmp_path, template):
    package = org_variant(tmp_path, template, ("SUCCESS", NO_MATCH), ("SUCCESS", NO_MATCH))
    store, run = assessed(tmp_path, package)
    try:
        assert set(scope(store, run, ORG_SCOPE).values()) == {"PASS"}
    finally:
        store.__exit__()


def test_truncated_organization_search_is_not_a_pass(tmp_path, template):
    package = org_variant(tmp_path, template, ("SUCCESS", NO_MATCH), ("TRUNCATED", NO_MATCH))
    store, run = assessed(tmp_path, package)
    try:
        assert set(scope(store, run, ORG_SCOPE).values()) == {"UNKNOWN"}
    finally:
        store.__exit__()
