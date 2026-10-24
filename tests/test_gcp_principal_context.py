"""E5: attached service-account privilege context for GCP-VM-DEFAULT-SA, GCP-VM-FULL-API-SCOPE
and GCP-NET-FW-*-INTERNET. Synthetic expanded packages only."""

import json
from collections import Counter

import pytest
from test_gcp_config import FIREWALL, NETWORK, SA
from test_gcp_coverage_notes import fail, rewrite

from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.rules import registry
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.gcp_config import FULL_SCOPE
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import PROJECT, expanded22

MEMBER = "serviceAccount:" + SA
CUSTOM = f"projects/{PROJECT}/roles/syntheticOperator"
RULES = (
    "GCP-VM-DEFAULT-SA",
    "GCP-VM-FULL-API-SCOPE",
    "GCP-NET-FW-ADMIN-INTERNET",
    "GCP-NET-FW-DB-INTERNET",
    "GCP-NET-FW-ANY-INTERNET",
)


def build(tmp_path, roles, parents="collected", project_iam=True):
    """Expanded package: one internet-exposed instance running the default compute account with
    cloud-platform scope, one public SSH firewall rule, and the given project role bindings."""
    folder = expanded22(tmp_path / "pkg")

    def update(manifest, root):
        for item in manifest["datasets"]:
            name = item["dataset"]
            if name == "instances" and item.get("file"):
                (root / item["file"]).write_text(
                    json.dumps(
                        [
                            {
                                "name": "web",
                                "zone": f"projects/{PROJECT}/zones/us-central1-a",
                                "status": "RUNNING",
                                "networkInterfaces": [
                                    {"network": NETWORK, "accessConfigs": [{"natIP": "192.0.2.1"}]}
                                ],
                                "serviceAccounts": [{"email": SA, "scopes": [FULL_SCOPE]}],
                            }
                        ]
                    )
                )
                item["record_count"] = 1
            elif name == "firewall_rules" and item.get("file"):
                (root / item["file"]).write_text(json.dumps([{"name": "public-ssh", **FIREWALL}]))
                item["record_count"] = 1
            elif name == "project_iam" and item.get("file"):
                if project_iam:
                    bindings = [{"role": role, "members": [MEMBER]} for role in roles]
                    (root / item["file"]).write_text(json.dumps({"bindings": bindings}))
                else:
                    fail(item, root, "ACCESS_DENIED", "ERROR: (gcloud) HTTPError 403: Forbidden")
            elif name == "folder_123_iam":
                if item.get("error_file"):
                    (root / item["error_file"]).unlink(missing_ok=True)
                if parents == "collected":
                    item.update(
                        status="SUCCESS",
                        file=f"{item['domain']}/{name}.json",
                        error_file=None,
                        record_count=1,
                        exit_code=0,
                    )
                    (root / item["file"]).write_text(json.dumps({"bindings": []}))
                else:
                    fail(item, root, "ACCESS_DENIED", "ERROR: (gcloud) HTTPError 403: Forbidden")

    return rewrite(folder, update)


def assessed(tmp_path, roles, **options):
    package = build(tmp_path, roles, **options)
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    store.__enter__()
    run = import_package(store, package)
    assess(store, run)
    return store, run


def findings(store, run):
    return {f.rule_id: f for f in store.candidates(run) if f.rule_id in RULES}


def test_default_account_with_editor_raises_severity(tmp_path):
    store, run = assessed(tmp_path, ["roles/editor"])
    try:
        found = findings(store, run)
        default = found["GCP-VM-DEFAULT-SA"]
        assert default.suggested_severity == "HIGH"  # MEDIUM base, raised
        assert "privileged role(s) roles/editor" in default.technical_observation
        assert SA in default.technical_observation and FULL_SCOPE in default.technical_observation
        basic = next(
            f
            for f in store.candidates(run)
            if f.rule_id == "GCP-IAM-BASIC" and SA in f.technical_observation
        )
        assert basic.finding_id in default.technical_observation  # reference to the SA's finding
        assert found["GCP-VM-FULL-API-SCOPE"].suggested_severity == "HIGH"  # external IP
        firewall = found["GCP-NET-FW-ADMIN-INTERNET"]
        assert firewall.suggested_severity == "HIGH" and SA in firewall.technical_observation
        versions = {r.rule_id: r.rule_version for r in store.results(run) if r.rule_id in RULES}
        assert set(versions.values()) == {"1.2.0", "clogcp-1.0.0"}
    finally:
        store.__exit__(None, None, None)


def test_narrow_roles_are_labelled_never_lowered(tmp_path):
    store, run = assessed(tmp_path, ["roles/logging.viewer"])
    try:
        found = findings(store, run)
        default = found["GCP-VM-DEFAULT-SA"]
        assert default.suggested_severity == "MEDIUM"
        assert (
            "attached service account holds only narrow roles (roles/logging.viewer)"
            in default.technical_observation
        )
        assert found["GCP-VM-FULL-API-SCOPE"].suggested_severity == "LOW"
    finally:
        store.__exit__(None, None, None)


@pytest.mark.parametrize(
    ("roles", "options", "reason"),
    [
        (["roles/editor"], {"project_iam": False}, "project IAM"),
        ([CUSTOM], {}, "UNRESOLVED"),
        (["roles/logging.viewer"], {"parents": "denied"}, "project-level roles only"),
    ],
    ids=["no-iam-evidence", "custom-role-without-detail", "parent-iam-denied"],
)
def test_unresolved_privileges_are_named_and_never_narrow(tmp_path, roles, options, reason):
    store, run = assessed(tmp_path, roles, **options)
    try:
        default = findings(store, run)["GCP-VM-DEFAULT-SA"]
        assert default.suggested_severity == "MEDIUM"  # base kept; never lowered, never PASS
        assert "privileges unresolved:" in default.technical_observation
        assert "narrow roles" not in default.technical_observation
        if reason != "UNRESOLVED":
            assert reason in default.technical_observation
        assert any("Attached service account privileges" in m for m in default.missing_evidence)
    finally:
        store.__exit__(None, None, None)


def test_other_rules_unchanged_and_finding_ids_stable(tmp_path, monkeypatch):
    store, run = assessed(tmp_path / "with", ["roles/editor"])
    try:
        enriched = {
            (r.rule_id, r.resource_id): (str(r.outcome), r.suggested_severity)
            for r in store.results(run)
        }
        ids = {f.finding_id for f in store.candidates(run)}
    finally:
        store.__exit__(None, None, None)
    monkeypatch.setattr(registry, "PRINCIPAL_CONTEXT_RULES", frozenset())
    store, run = assessed(tmp_path / "without", ["roles/editor"])
    try:
        plain = {
            (r.rule_id, r.resource_id): (str(r.outcome), r.suggested_severity)
            for r in store.results(run)
        }
        assert {f.finding_id for f in store.candidates(run)} == ids
    finally:
        store.__exit__(None, None, None)
    assert enriched.keys() == plain.keys()
    for key, (outcome, severity) in plain.items():
        assert enriched[key][0] == outcome, key  # outcomes never change
        if key[0] not in RULES:
            assert enriched[key][1] == severity, key
    raised = Counter(
        key[0] for key in plain if key[0] in RULES and enriched[key][1] != plain[key][1]
    )
    assert raised == {"GCP-VM-DEFAULT-SA": 1, "GCP-VM-FULL-API-SCOPE": 1}
    assert all(
        stable_id("finding", [rule, resource]) in ids
        for (rule, resource), (outcome, _) in plain.items()
        if outcome == "FAIL" and resource
    )
