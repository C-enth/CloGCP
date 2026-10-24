"""Strict pilot-1.5 compatibility, partial evidence and retained archive safeguards."""

import json

import pytest

from offline_analyzer.ingestion.archive import unpack_package
from offline_analyzer.ingestion.gcp import inspect_package
from offline_analyzer.ingestion.gcp_legacy import manifest_detection
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tests.test_gcp_legacy import zip_pilot
from tools.fixtures.gcp_pilot15 import build


@pytest.mark.parametrize("transport", ["folder", "windows-zip"])
def test_pilot15_transport_normalization_analysis_and_statuses(tmp_path, transport):
    folder = build(tmp_path / "input")
    assert sum(path.is_file() for path in folder.rglob("*")) == 65
    if transport == "windows-zip":
        archive = zip_pilot(folder, tmp_path / "input.zip")
        folder = unpack_package(archive, tmp_path / "expanded")
    package, diagnostic = inspect_package(folder)
    assert len(package.sources) == 63
    assert diagnostic["contract_version"] == "pilot-1.5"
    assert diagnostic["adapter_profile"] == "gcp-pilot-1.5-adapter-1"
    assert diagnostic["original_status_totals"] == {
        "SUCCESS": 12,
        "EMPTY": 13,
        "API_DISABLED": 28,
        "AUTH_ERROR": 5,
        "ACCESS_DENIED": 5,
    }
    assert any(row["parser_supported"] is False for row in diagnostic["sources"])
    assert all(
        source.path is None and source.coverage == "ERROR"
        for source in package.sources
        if source.gcp_metadata["status"] not in {"SUCCESS", "EMPTY"}
    )
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        assert list(store.observations(run)) and list(store.results(run))
        assert list(store.candidates(run))
        assert len(list(store.source_data(run))) == 63


@pytest.mark.parametrize(
    "change,code",
    [
        ("version", "UNSUPPORTED_MANIFEST_VERSION"),
        ("unknown-field", "LEGACY_GCP_MANIFEST_INVALID"),
        ("status", "LEGACY_GCP_MANIFEST_INVALID"),
        ("metadata-mismatch", "MANIFEST_FILE_REFERENCE_MISMATCH"),
        ("extra-file", "MANIFEST_FILE_REFERENCE_MISMATCH"),
    ],
)
def test_pilot15_rejects_unknown_contracts_and_extra_artifacts(tmp_path, change, code):
    folder = build(tmp_path / "input")
    path = folder / "collection_manifest.json"
    data = json.loads(path.read_text())
    if change == "version":
        data["schema_version"] = "pilot-1.6"
    elif change == "unknown-field":
        data["unknown"] = True
    elif change == "status":
        data["datasets"][0]["status"] = "NEW_SUCCESS"
    elif change == "metadata-mismatch":
        (folder / "discovered_asset_types.json").write_text("[]")
    else:
        (folder / "unlisted.json").write_text("[]")
    path.write_text(json.dumps(data))
    with pytest.raises(InputError, match=code):
        inspect_package(folder)
    if change == "version":
        detection = manifest_detection(folder)
        assert detection["detected_version"] == "pilot-1.6"
        assert detection["selected_adapter"] == "NONE"
        assert detection["expected_versions"] == [
            "pilot-1.2.2",
            "pilot-1.5",
            "assessment-expanded-2.1",
            "assessment-expanded-2.2",
        ]
        assert detection["rejection_condition"]
