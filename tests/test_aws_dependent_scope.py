"""Phase 0 (AWS readiness): collection-scope rows of per-resource datasets are decided by the
parent listing (docs/AWS_CONTROL_AUTOMATION_AUDIT.md, change 1), with the GCP counterpart
(empty successful list N/A, failures never PASS) checked alongside. Synthetic data only."""

import hashlib
import json
import shutil

import pytest

from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules.engine import assess, parent_state
from offline_analyzer.storage.store import Store
from tools.fixtures.aws_v030_native import ACCOUNT, REGION, extend, package
from tools.fixtures.gcp_estate import build_project, edit
from tools.fixtures.gcp_expanded import expanded22

KMS_RULES = {"SEC-KMS-ROTATION", "SEC-KMS-WILDCARD-PRINCIPAL"}
BUCKET = "R1-S3-BUCKET-PUBLIC-ACCESS"


def assessed(tmp_path, calls=(), mutate=None):
    root = package(tmp_path / "pkg")
    if mutate:
        mutate(root)
    extend(root, list(calls))
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    run = import_package(store, root)
    assess(store, run)
    return store, run


def scope(store, run, rules):
    return {
        (r.rule_id, r.region): str(r.outcome)
        for r in store.results(run)
        if r.rule_id in rules and r.evaluation_scope == "COLLECTION_SCOPE"
    }


def test_complete_bucket_listing_with_every_bucket_detail_needs_no_scope_row(tmp_path):
    store, run = assessed(tmp_path)
    try:
        assert scope(store, run, {BUCKET}) == {}  # was UNKNOWN: per-bucket calls are PARTIAL
        resource = {str(r.outcome) for r in store.results(run) if r.rule_id == BUCKET}
        assert resource == {"FAIL"}
    finally:
        store.__exit__()


def test_bucket_listing_with_missing_bucket_detail_stays_unknown(tmp_path):
    def two_buckets(root):
        page = next(root.rglob("list_buckets/page-000001.json"))
        body = json.loads(page.read_text())
        body["Buckets"].append({"Name": "synthetic-second-bucket"})
        page.write_text(json.dumps(body))
        rows = [json.loads(x) for x in (root / "operations.jsonl").read_text().splitlines()]
        for row in rows:
            if row["operation"] == "list_buckets":
                row["records_returned"] = len(body["Buckets"])
                row["files"][0]["sha256"] = hashlib.sha256(page.read_bytes()).hexdigest()
                row["files"][0]["bytes"] = page.stat().st_size
        (root / "operations.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
        )

    store, run = assessed(tmp_path, mutate=two_buckets)
    try:
        assert scope(store, run, {BUCKET}) == {(BUCKET, "global"): "UNKNOWN"}
    finally:
        store.__exit__()


def test_empty_complete_key_listing_is_not_applicable(tmp_path):
    calls = [{"service": "kms", "operation": "list_keys", "region": REGION,
              "pages": [{"Keys": [], "Truncated": False}]}]  # fmt: skip
    store, run = assessed(tmp_path, calls)
    try:
        # Previously no row at all: the KMS family counted as not supplied.
        assert scope(store, run, KMS_RULES) == {(r, REGION): "NOT_APPLICABLE" for r in KMS_RULES}
        assert not any(
            str(r.outcome) == "PASS" for r in store.results(run) if r.rule_id in KMS_RULES
        )
    finally:
        store.__exit__()


@pytest.mark.parametrize(("outcome", "code"), [("ACCESS_DENIED", "AccessDeniedException"),
                                               ("API_ERROR", "ThrottlingException")])  # fmt: skip
def test_failed_key_listing_is_a_collection_error(tmp_path, outcome, code):
    calls = [{"service": "kms", "operation": "list_keys", "region": REGION,
              "outcome": outcome, "code": code}]  # fmt: skip
    store, run = assessed(tmp_path, calls)
    try:
        assert scope(store, run, KMS_RULES) == {(r, REGION): "COLLECTION_ERROR" for r in KMS_RULES}
    finally:
        store.__exit__()


def test_snapshot_reads_the_members_parent_listings(tmp_path):
    calls = [{"service": "kms", "operation": "list_keys", "region": REGION,
              "pages": [{"Keys": [], "Truncated": False}]}]  # fmt: skip
    store, run = assessed(tmp_path, calls)
    try:
        snapshot = assess_enterprise(store, [run])
        assert scope(store, snapshot, KMS_RULES | {BUCKET}) == scope(
            store, run, KMS_RULES | {BUCKET}
        )
    finally:
        store.__exit__()


def op(status="SUCCEEDED", outcome="COMPLETE", pagination="NOT_PAGINATED", records=0):
    return {"status": status, "original_outcome": outcome, "pagination": pagination,
            "records_returned": records}  # fmt: skip


def test_parent_state_truth_table():
    assert parent_state([op()]) == ("EMPTY", 0)
    assert parent_state([op(records=3)]) == ("LISTED", 3)
    assert parent_state([op(status="FAILED", outcome="ACCESS_DENIED")]) == ("FAILED", 0)
    assert parent_state([op(pagination="TRUNCATED")]) is None  # truncated: never empty
    assert parent_state([op(outcome="PARTIAL")]) is None
    assert parent_state([op(status="SKIPPED", outcome="NOT_COLLECTED")]) is None
    assert parent_state([op(), op(records=2)]) is None  # disagreeing rows
    assert parent_state([]) is None and parent_state(None) is None
    assert parent_state([{**op(), "records_returned": None}]) is None


def test_account_identifier_is_synthetic():
    assert ACCOUNT == "123456789012"


@pytest.fixture(scope="module")
def gcp_template(tmp_path_factory):
    return expanded22(tmp_path_factory.mktemp("gcp") / "t")


@pytest.mark.parametrize(("status", "expected"), [("EMPTY", {"NOT_APPLICABLE"}),
                                                  ("ACCESS_DENIED", {"UNKNOWN"})])  # fmt: skip
def test_gcp_counterpart_empty_list_and_failure(tmp_path, gcp_template, status, expected):
    target = build_project(tmp_path / "p", 0, gcp_template)
    edit(target, {"instances": (status, None)})
    set_environment(tmp_path / "work", "SYNTHETIC")
    with Store(tmp_path / "work") as store:
        run = import_package(store, target)
        assess(store, run)
        rows = {
            str(r.outcome)
            for r in store.results(run)
            if r.rule_id == "GCP-VM-SHIELDED" and r.evaluation_scope == "COLLECTION_SCOPE"
        }
        assert rows == expected
        assert not any(
            str(r.outcome) == "PASS" for r in store.results(run) if r.rule_id == "GCP-VM-SHIELDED"
        )
    shutil.rmtree(tmp_path / "work")


def test_listed_resources_without_dependent_evidence_are_unknown(tmp_path):
    store, run = assessed(tmp_path)  # one trail listed; GetTrailStatus not collected
    try:
        (row,) = [
            r
            for r in store.results(run)
            if r.rule_id == "SEC-CLOUDTRAIL-LOGGING" and r.evaluation_scope == "COLLECTION_SCOPE"
        ]
        assert str(row.outcome) == "UNKNOWN" and "listed 1 resource" in row.reasoning
    finally:
        store.__exit__()
