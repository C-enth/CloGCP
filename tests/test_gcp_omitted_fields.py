"""Omitted-field semantics (GCP correctness RC, phase 3), written before the rule change.

Google APIs omit unset fields. An omitted field is read only where its absence is documented
and only from complete collection evidence; otherwise the outcome stays UNKNOWN.

- API keys (apikeys v2): "API keys without application restrictions can be used from
  anywhere" and "API keys without API restrictions can be used with all APIs that accept
  keys" (Google Cloud "Manage API keys"); the REST reference: "If no restrictions are
  specified, all targets are allowed." A key without `restrictions` is unrestricted.
- Cloud KMS: automatic rotation is disabled by clearing the rotation schedule
  (`rotationPeriod` and `nextRotationTime` set to null; console "Never (manual rotation)",
  Cloud KMS "Rotate a key"). An ENCRYPT_DECRYPT key with neither field has no automatic
  rotation.
Synthetic data only.
"""

import pytest

from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_estate import build_project, edit
from tools.fixtures.gcp_expanded import expanded, expanded22

KEY = "projects/900000000002/locations/global/keys/key-02"
KEY_ID = "projects/synth-gcp-02/locations/global/keys/key-02"  # canonical (project ID) form


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    return expanded22(tmp_path_factory.mktemp("template") / "t")


def assessed(tmp_path, template, index, changes=None):
    package = build_project(tmp_path / "p", index, template)
    if changes:
        edit(package, changes)
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    run = import_package(store, package)
    assess(store, run)
    return store, run


def outcomes(store, run, prefix, native=None):
    return {
        r.rule_id: str(r.outcome)
        for r in store.results(run)
        if r.rule_id.startswith(prefix)
        and r.evaluation_scope == "RESOURCE"
        and (native is None or r.native_id == native)
    }


def api_keys(record, status="SUCCESS"):
    return {
        "api_keys": (status, [record]),
        "api_keys_rest": (status, [record]),
        "api_key_detail_1": (status, record),
    }


UNRESTRICTED = {"name": KEY, "uid": "uid-02"}  # the API omits `restrictions`
API_ONLY = {**UNRESTRICTED, "restrictions": {"apiTargets": [{"service": "maps.googleapis.com"}]}}


def test_unrestricted_key_from_complete_evidence_fails(tmp_path, template):
    store, run = assessed(tmp_path, template, 2, api_keys(UNRESTRICTED))
    try:
        found = outcomes(store, run, "GCP-API-", KEY_ID)
        # The combined rule reports a key with neither restriction; the single-restriction
        # rules defer to it (NOT_APPLICABLE), as for keys with an empty restrictions object.
        assert found == {
            "GCP-API-BOTH": "FAIL",
            "GCP-API-APP": "NOT_APPLICABLE",
            "GCP-API-API": "NOT_APPLICABLE",
        }
    finally:
        store.__exit__()


def test_api_restriction_only_fails_the_application_criterion(tmp_path, template):
    store, run = assessed(tmp_path, template, 2, api_keys(API_ONLY))
    try:
        assert outcomes(store, run, "GCP-API-", KEY_ID) == {
            "GCP-API-BOTH": "PASS",
            "GCP-API-APP": "FAIL",
            "GCP-API-API": "PASS",
        }
    finally:
        store.__exit__()


def test_omitted_restrictions_from_truncated_evidence_stay_unknown(tmp_path, template):
    store, run = assessed(tmp_path, template, 2, api_keys(UNRESTRICTED, "TRUNCATED"))
    try:
        assert set(outcomes(store, run, "GCP-API-", KEY_ID).values()) == {"UNKNOWN"}
    finally:
        store.__exit__()


def test_omitted_restrictions_in_a_21_package_stay_unknown(tmp_path):
    from tools.fixtures.gcp_expanded import PROJECT  # noqa: F401 - documents the fixture

    package = expanded(tmp_path / "package")
    set_environment(tmp_path / "work", "SYNTHETIC")
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        results = [
            r
            for r in store.results(run)
            if r.rule_id.startswith("GCP-API-") and r.evaluation_scope == "RESOURCE"
        ]
        assert results and {str(r.outcome) for r in results} == {"UNKNOWN"}


ROTATED = {
    "name": "projects/synth-gcp-01/locations/global/keyRings/ring/cryptoKeys/rotated",
    "purpose": "ENCRYPT_DECRYPT",
    "rotationPeriod": "7776000s",
    "nextRotationTime": "2026-12-01T00:00:00Z",
}
STATIC = {
    "name": "projects/synth-gcp-01/locations/global/keyRings/ring/cryptoKeys/static",
    "purpose": "ENCRYPT_DECRYPT",
}
ONE_TIME = {**STATIC, "nextRotationTime": "2026-12-01T00:00:00Z"}


@pytest.mark.parametrize(
    ("record", "status", "expected"),
    [
        (ROTATED, "SUCCESS", "PASS"),
        (STATIC, "SUCCESS", "FAIL"),  # no rotation schedule: automatic rotation disabled
        (ONE_TIME, "SUCCESS", "UNKNOWN"),  # one field only: not the documented state
        (STATIC, "PARTIAL", "UNKNOWN"),  # incomplete evidence: absence is not evidence
        ({**STATIC, "purpose": "ASYMMETRIC_SIGN"}, "SUCCESS", "NOT_APPLICABLE"),
    ],
)
def test_kms_rotation_omitted_schedule(tmp_path, template, record, status, expected):
    store, run = assessed(tmp_path, template, 1, {"kms_keys_1_1": (status, [record])})
    try:
        assert outcomes(store, run, "GCP-KMS-ROTATION", record["name"]) == {
            "GCP-KMS-ROTATION": expected
        }
    finally:
        store.__exit__()
