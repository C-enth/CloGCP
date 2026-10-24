"""Versioned expanded contract, real persistence and deterministic engine regression."""

import json
import re

import pytest

from offline_analyzer.contracts.gcp_expanded_catalog import DATASETS, dataset_contract
from offline_analyzer.ingestion.gcp import inspect_package
from offline_analyzer.ingestion.gcp_legacy import manifest_detection
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import example_name, expanded


def test_catalog_covers_each_reviewed_definition_with_bounded_matching():
    assert len(DATASETS) == 115
    assert sum(r["naming"] == "DYNAMIC" for r in DATASETS) == 25
    assert len({r["collector_line"] for r in DATASETS}) == 115
    for row in DATASETS:
        name = example_name(row)
        assert dataset_contract(row["domain"], name) == row
        assert not dataset_contract("unrecognized", name)
        if row["naming"] == "DYNAMIC":
            assert not re.fullmatch(row["pattern"], name + "_unknown")
    assert not dataset_contract("security", "kms_keys_0_1")
    assert not dataset_contract("identity", "sa_keys_1000000")


@pytest.mark.parametrize("mixed", [False, True])
def test_expanded_import_assessment_and_reopen(tmp_path, mixed):
    folder = expanded(tmp_path / "evidence", mixed=mixed)
    package, diagnostics = inspect_package(folder)
    assert len(package.sources) == 115
    assert all(s["parser_supported"] for s in diagnostics["sources"])
    assert diagnostics["contract_version"] == "assessment-expanded-2.1"
    assert manifest_detection(folder)["selected_adapter"] == "gcp-expanded-2.1-adapter-1"
    assert diagnostics["real_export_validation"] == "NOT_ESTABLISHED"
    assert all(s.coverage != "COMPLETE" for s in package.sources)
    if mixed:
        assert set(diagnostics["original_status_totals"]) == {
            "SUCCESS",
            "EMPTY",
            "FAILED",
            "API_DISABLED",
            "ACCESS_DENIED",
            "COMMAND_ERROR",
            "AUTH_ERROR",
            "TRUNCATED",
            "RATE_LIMITED",
            "NOT_FOUND",
            "HTTP_ERROR",
            "SERVER_ERROR",
        }
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        observations = list(store.observations(run))
        assert any(o.resource_type == "GCP::ServiceAccountKey" for o in observations)
        assert any(o.resource_type == "GCP::KMSKeyVersion" for o in observations)
        assert (
            len([o for o in observations if o.resource_type == "GCP::InterconnectAttachment"]) == 2
        )
        assert all(o.evidence.locator for o in observations)
        assert list(store.candidates(run))
        assert not any(
            r.outcome == "PASS" and r.evaluation_scope == "COLLECTION_SCOPE"
            for r in store.results(run)
        )
    with Store(tmp_path / "workspace") as store:
        assert len(list(store.observations(run))) == len(observations)
        assert list(store.candidates(run))


@pytest.mark.parametrize(
    "change,code",
    [
        ("version", "UNSUPPORTED_MANIFEST_VERSION"),
        ("count", "GCP_TRANSPORT_RECORD_COUNT_MISMATCH"),
        ("shape", "GCP_EXPANDED_REST_ARRAY_REQUIRED"),
        ("duplicate", "GCP_DUPLICATE_DATASET"),
        ("malformed", "MALFORMED_JSON"),
        ("reference", "MANIFEST_FILE_REFERENCE_MISMATCH"),
        ("status", "LEGACY_GCP_MANIFEST_INVALID"),
    ],
)
def test_expanded_rejects_invalid_contract_without_run(tmp_path, change, code):
    folder = expanded(tmp_path / "evidence")
    path = folder / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    rest = next(d for d in manifest["datasets"] if d["dataset"] == "api_keys_rest")
    if change == "version":
        manifest["schema_version"] = "assessment-expanded-9.9"
    elif change == "count":
        rest["record_count"] = 2
    elif change == "shape":
        (folder / rest["file"]).write_text('{"name":"sample"}')
    elif change == "duplicate":
        manifest["datasets"].append(manifest["datasets"][0])
    elif change == "malformed":
        (folder / rest["file"]).write_text("{broken")
    elif change == "reference":
        rest["file"] = "api/project.json"
    else:
        rest["status"] = "INVENTED_STATUS"
    path.write_text(json.dumps(manifest))
    with Store(tmp_path / "workspace") as store:
        with pytest.raises(InputError, match=code):
            import_package(store, folder)
        assert not store.db.execute("SELECT run_id FROM runs").fetchall()


def test_shared_views_use_project_provider_and_source_metadata(tmp_path):
    from offline_analyzer.api.services import Views
    from offline_analyzer.reporting.cloud import dashboard

    folder = expanded(tmp_path / "evidence", mixed=True)
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        views = Views(store.workspace)

        def records(kind, **filters):
            return views.records(store, run, kind, "", "", "", 0, 100, filters)

        accounts = records("accounts", provider="GCP")
        assert accounts["total"] == 1 and accounts["items"][0]["project_id"] == "sample-project"
        assert records("accounts", provider="AWS")["total"] == 0
        assert records("accounts", project_id="other-project")["total"] == 0
        for kind in (
            "roles",
            "policies",
            "relationships",
            "gaps",
            "network",
            "evidence",
            "coverage",
        ):
            assert records(kind, provider="GCP")["total"] > 0
            assert records(kind, provider="AWS")["total"] == 0
            assert records(kind, project_id="other-project")["total"] == 0
        keys = records("evidence", dataset="sa_keys_1")
        assert keys["total"] == 1
        assert keys["items"][0]["resource_type"] == "GCP::ServiceAccountKey"
        assert keys["items"][0]["dataset"] == "sa_keys_1"
        assert records("coverage", collection_status="ACCESS_DENIED")["total"] == 1
        assert records("evidence", support="UNSUPPORTED")["total"] == 0
        summary = dashboard(store, run, "GCP")
        assert summary["providers"]["GCP"]["expected_scope_count"] == 1
        assert len(summary["datasets"]) == 115
        assert all(d["parser_supported"] for d in summary["datasets"])
        assert any(d["assessment_state"] == "NOT_EVALUATED" for d in summary["datasets"])
        assert any(d["assessment_state"] == "COLLECTION_FAILED" for d in summary["datasets"])


def test_truncated_source_never_produces_positive_evaluation(tmp_path):
    folder = expanded(tmp_path / "evidence")
    path = folder / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    dataset = next(d for d in manifest["datasets"] if d["dataset"] == "sa_keys_1")
    dataset["status"] = "TRUNCATED"
    source = folder / dataset["file"]
    values = json.loads(source.read_text())
    values[0]["validAfterTime"] = "2026-10-11T00:00:00Z"
    source.write_text(json.dumps(values))
    path.write_text(json.dumps(manifest))
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        results = [
            r
            for r in store.results(run)
            if r.rule_id == "GCP-KEY-AGE" and r.evaluation_scope == "RESOURCE"
        ]
        assert results and all(str(r.outcome) == "UNKNOWN" for r in results)
        sources = [s for s in store.source_data(run) if s["gcp_metadata"]["status"] == "TRUNCATED"]
        assert sources and all(s["effective_coverage"] == "PARTIAL" for s in sources)


def test_gcloud_rest_canonical_identity_preserves_distinct_provenance(tmp_path):
    folder = expanded(tmp_path / "evidence")
    native = "projects/sample-project/locations/global/keys/shared"
    (folder / "api/api_keys.json").write_text(json.dumps([{"name": native}]))
    (folder / "api/api_keys_rest.json").write_text(
        json.dumps([{"name": native.replace("sample-project", "123456789012")}])
    )
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        shared = [o for o in store.observations(run) if o.native_id == native]
        assert len(shared) == 2 and len({o.resource_id for o in shared}) == 1
        assert (
            len({ref.artifact_id for o in shared for ref in store.refs(run, [o.observation_id])})
            == 2
        )


def test_asset_summary_and_native_detail_share_identity_without_shared_rule_configuration(tmp_path):
    from offline_analyzer.api.services import Views

    folder = expanded(tmp_path / "evidence")
    native = "projects/sample-project/locations/global/keys/shared"
    (folder / "inventory/assets.json").write_text(
        json.dumps(
            [
                {
                    "name": "//apikeys.googleapis.com/" + native,
                    "assetType": "apikeys.googleapis.com/Key",
                }
            ]
        )
    )
    (folder / "api/api_keys.json").write_text(json.dumps([{"name": native, "restrictions": {}}]))
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        observed = [o for o in store.observations(run) if o.native_id == native]
        assert {o.resource_type for o in observed} == {"GCP::Asset", "GCP::APIKey"}
        assert len({o.resource_id for o in observed}) == 1
        resource_id = observed[0].resource_id
        assert any(
            r.resource_id == resource_id
            and r.rule_id == "GCP-API-BOTH"
            and str(r.outcome) == "FAIL"
            for r in store.results(run)
        )
        items = Views(store.workspace).records(store, run, "resources", "shared", "", "", 0, 100)
        assert items["total"] == 1
        assert items["items"][0]["resource_type"] == "GCP::APIKey"


def test_generated_contract_document_and_schema_match_definitions():
    from pathlib import Path

    from offline_analyzer.contracts.gcp_expanded import ExpandedManifest
    from tools.gcp_collector_contract import inventory, markdown

    assert Path("docs/GCP_COLLECTOR_CONTRACT.md").read_text() == markdown()
    assert len(inventory()["definitions"]) == 115
    assert (
        json.loads(Path("src/offline_analyzer/contracts/schemas/ExpandedManifest.json").read_text())
        == ExpandedManifest.model_json_schema()
    )


def test_parent_scope_summaries_keep_only_the_collected_project(tmp_path):
    folder = expanded(tmp_path / "evidence")
    path = folder / "inventory/folder_123_iam_search.json"
    path.write_text(
        json.dumps(
            [
                {
                    "resource": "//compute.googleapis.com/projects/other-project/"
                    "zones/example/instances/sample",
                    "policy": {"bindings": []},
                },
                {
                    "resource": "//compute.googleapis.com/projects/sample-project/"
                    "zones/example/instances/kept",
                    "policy": {"bindings": []},
                },
            ]
        )
    )
    manifest_path = folder / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for item in manifest["datasets"]:
        if item["dataset"] == "folder_123_iam_search":
            item["record_count"] = 2
    manifest_path.write_text(json.dumps(manifest))
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        # ADR-010: a parent-scope result about another project is never stored.
        assert not any(
            o.native_id and "other-project" in o.native_id for o in store.observations(run)
        )
        summary = next(
            o for o in store.observations(run) if o.native_id and o.native_id.endswith("/kept")
        )
        assert summary.project_id == "sample-project"
        assert summary.unresolved == ("GCP_PARENT_SCOPE_SUMMARY_NOT_EFFECTIVE_PERMISSIONS",)


def test_failed_project_inventory_retains_numeric_scoped_evidence_as_unknown(tmp_path):
    folder = expanded(tmp_path / "evidence")
    manifest_path = folder / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    project = next(d for d in manifest["datasets"] if d["dataset"] == "project")
    (folder / project["file"]).unlink()
    project.update(file=None, status="ACCESS_DENIED", record_count=None, exit_code=1)
    manifest_path.write_text(json.dumps(manifest))
    native = "projects/123456789012/locations/global/keys/unverified"
    (folder / "api/api_keys.json").write_text(json.dumps([{"name": native, "restrictions": {}}]))
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        observation = next(o for o in store.observations(run) if o.native_id == native)
        assert observation.unresolved == ("GCP_PROJECT_NUMBER_UNVERIFIED",)
        results = [r for r in store.results(run) if r.resource_id == observation.resource_id]
        assert results and all(str(r.outcome) == "UNKNOWN" for r in results)


def test_public_catalog_images_from_earlier_collectors_are_not_evidence(tmp_path):
    folder = expanded(tmp_path / "evidence")
    base = "https://www.googleapis.com/compute/v1/projects/"
    records = [
        {"name": "debian-12", "selfLink": base + "debian-cloud/global/images/debian-12"},
        {"name": "custom", "selfLink": base + "sample-project/global/images/custom"},
    ]
    manifest_path = folder / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    row = next(d for d in manifest["datasets"] if d["dataset"] == "images")
    (folder / row["file"]).write_text(json.dumps(records))
    row["record_count"] = 2
    manifest_path.write_text(json.dumps(manifest))
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        images = [o for o in store.observations(run) if o.resource_type == "GCP::Image"]
        assert len(images) == 1 and images[0].project_id == "sample-project"
        assert not any("debian-cloud" in o.model_dump_json() for o in store.observations(run))
