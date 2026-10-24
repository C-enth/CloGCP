"""Synthetic observed pilot structure; never customer-derived payloads."""

import json
import stat
import zipfile
from pathlib import Path

import pytest

from offline_analyzer.ingestion.archive import canonical_member, unpack_package
from offline_analyzer.ingestion.gcp import inspect_package
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import MAX_PACKAGE_FILES, InputError
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_pilot import PROJECT as PROJECT
from tools.fixtures.gcp_pilot import pilot


def zip_pilot(folder: Path, path: Path, windows: bool = True) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                name = p.relative_to(folder).as_posix()
                z.write(p, name.replace("/", "\\") if windows else name)
    return path


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("full_transport", [False, True])
def test_pilot_archive_to_findings_with_partial_collection(tmp_path, windows, full_transport):
    original = pilot(tmp_path / "original", full_transport=full_transport)
    archive = zip_pilot(original, tmp_path / "evidence.zip", windows)
    with zipfile.ZipFile(archive) as z:
        assert len(z.infolist()) == (65 if full_transport else 33) and z.testzip() is None
    extracted = tmp_path / "expanded"
    extracted.mkdir()
    root = unpack_package(archive, extracted)
    package, diagnostics = inspect_package(root)
    assert len(package.sources) == 32
    assert diagnostics["original_status_totals"] == {"SUCCESS": 8, "EMPTY": 5, "FAILED": 19}
    assert diagnostics["source_checksum_verified"] is False
    assert all(
        p.read_bytes() == (root / p.relative_to(original)).read_bytes()
        for p in original.rglob("*")
        if p.is_file()
    )
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, root)
        assess(store, run)
        assert any(f.provider == "GCP" for f in store.candidates(run))
        assert any(
            str(r.outcome) in {"UNKNOWN", "COLLECTION_ERROR"}
            for r in store.results(run)
            if r.provider == "GCP"
        )
        sources = list(store.source_data(run))
        assert sum(s["gcp_metadata"]["status"] == "FAILED" for s in sources) == 19
        assert all(
            s["record_count"] == 0 for s in sources if s["gcp_metadata"]["status"] == "FAILED"
        )
        assert any(
            s["gcp_metadata"]["error_category"] == "COLLECTOR_COMMAND_ERROR" for s in sources
        )


@pytest.mark.parametrize(
    "name",
    [
        "../file.json",
        "a\\..\\file.json",
        "/file.json",
        "C:\\file.json",
        "\\\\host\\file.json",
        "a//file.json",
        "a/./file.json",
        "a/CON.json",
    ],
)
def test_portable_path_rejection(name):
    with pytest.raises(InputError, match="UNSAFE_ARCHIVE_PATH"):
        canonical_member(name)


@pytest.mark.parametrize("kind", ["collision", "case", "symlink", "ratio", "crc", "invalid"])
def test_archive_safety_remains_enforced(tmp_path, kind):
    path = tmp_path / "bad.zip"
    if kind == "invalid":
        path.write_bytes(b"not a zip")
    else:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("collection_manifest.json", "{}")
            if kind == "collision":
                z.writestr("a\\file.json", "{}")
                z.writestr("a/file.json", "{}")
            elif kind == "case":
                z.writestr("A/file.json", "{}")
                z.writestr("a/FILE.json", "{}")
            elif kind == "symlink":
                info = zipfile.ZipInfo("link.json")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "outside")
            elif kind == "ratio":
                z.writestr("large.json", "0" * 1000000, compress_type=zipfile.ZIP_DEFLATED)
            else:
                z.writestr("data.json", "UNIQUE_BODY")
        if kind == "crc":
            path.write_bytes(path.read_bytes().replace(b"UNIQUE_BODY", b"CHANGED_TXT"))
    with pytest.raises(InputError):
        unpack_package(path, tmp_path / "out")


@pytest.mark.parametrize(
    "change,code",
    [
        ("version", "UNSUPPORTED_MANIFEST_VERSION"),
        ("missing", "MISSING_DECLARED_EVIDENCE"),
        ("identity", "GCP_PROJECT_IDENTITY_MISMATCH"),
        ("extra", "MANIFEST_FILE_REFERENCE_MISMATCH"),
        ("json", "MALFORMED_JSON"),
        ("empty", "LEGACY_EMPTY_RECORD_MISMATCH"),
    ],
)
def test_legacy_validation_failures(tmp_path, change, code):
    folder = pilot(tmp_path / "input")
    manifest = folder / "collection_manifest.json"
    if change == "version":
        data = json.loads(manifest.read_text())
        data["schema_version"] = "pilot-new"
        manifest.write_text(json.dumps(data))
    elif change == "missing":
        (folder / "identity/project_iam.json").unlink()
    elif change == "identity":
        (folder / "inventory/project.json").write_text('{"projectId":"other-project"}')
    elif change == "extra":
        (folder / "extra.stderr.txt").write_text("not declared")
    elif change == "json":
        (folder / "identity/project_iam.json").write_text("broken")
    else:
        (folder / "api/api_keys.json").write_text('[{"name":"key"}]')
    with pytest.raises(InputError, match=code):
        inspect_package(folder)


def test_utf8_bom_native_json_preserves_raw_bytes(tmp_path):
    folder = pilot(tmp_path / "input")
    path = folder / "identity/project_iam.json"
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    expected = path.read_bytes()
    with Store(tmp_path / "work") as store:
        run = import_package(store, folder)
        assess(store, run)
        assert list(store.candidates(run))
        assert path.read_bytes() == expected


@pytest.mark.parametrize("transport", ["folder", "windows-zip"])
def test_finder_metadata_does_not_become_evidence_or_reject_original_folder(tmp_path, transport):
    folder = pilot(tmp_path / "input", full_transport=True)
    (folder / ".DS_Store").write_bytes(b"synthetic OS metadata")
    (folder / "inventory/.DS_Store").write_bytes(b"synthetic OS metadata")
    if transport == "windows-zip":
        folder = unpack_package(zip_pilot(folder, tmp_path / "input.zip"), tmp_path / "out")
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assert len(list(store.source_data(run))) == 32
        assert all(s["path"] is None or s["path"].endswith(".json") for s in store.source_data(run))
        assess(store, run)
        assert list(store.candidates(run))


@pytest.mark.parametrize("kind", ["large", "symlink", "unknown"])
def test_metadata_exception_preserves_size_link_and_unknown_file_rejection(tmp_path, kind):
    folder = pilot(tmp_path / "input")
    path = folder / ".DS_Store"
    if kind == "large":
        path.write_bytes(b"x" * (64 * 1024 + 1))
        code = "OS_METADATA_BYTE_LIMIT"
    elif kind == "symlink":
        path.symlink_to(folder / "collection_manifest.json")
        code = "UNSAFE_ARCHIVE_MEMBER"
    else:
        (folder / ".DS_Store.exe").write_bytes(b"not metadata")
        code = "MANIFEST_FILE_REFERENCE_MISMATCH"
    with pytest.raises(InputError, match=code):
        inspect_package(folder)


def test_archive_byte_limits_and_existing_symlinks(tmp_path, monkeypatch):
    from offline_analyzer.ingestion import archive as module

    folder = pilot(tmp_path / "input")
    package = zip_pilot(folder, tmp_path / "input.zip")
    monkeypatch.setattr(module, "MAX_BYTES", 8)
    with pytest.raises(InputError, match="ARCHIVE_BYTE_LIMIT"):
        unpack_package(package, tmp_path / "bounded")
    monkeypatch.setattr(module, "MAX_BYTES", 64 * 1024 * 1024)
    output = tmp_path / "out"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (output / "inventory").symlink_to(outside, target_is_directory=True)
    with pytest.raises(InputError, match="UNSAFE_ARCHIVE"):
        unpack_package(package, output)
    assert not list(outside.iterdir())


def test_local_zip_verifier_and_origin_gate(tmp_path):
    from offline_analyzer.verification import main, verify_package

    folder = pilot(tmp_path / "input")
    archive = zip_pilot(folder, tmp_path / "input.zip")
    before = archive.read_bytes()
    output = tmp_path / "diagnostics.json"
    assert main(["--package", str(archive), "--origin", "synthetic", "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["original_status_totals"] == {"SUCCESS": 8, "EMPTY": 5, "FAILED": 19}
    assert report["declared_input_origin"] == "synthetic"
    assert report["real_export_validation"] == "NOT_ESTABLISHED"
    assert archive.read_bytes() == before
    with pytest.raises(InputError, match="INPUT_ORIGIN_CONFLICT"):
        verify_package(archive, origin="tool-generated")


@pytest.mark.parametrize(
    "feature,code",
    [
        ("encryption", "ENCRYPTED_ARCHIVE"),
        ("compression", "UNSUPPORTED_ARCHIVE_COMPRESSION"),
        ("count", "ARCHIVE_MEMBER_LIMIT"),
    ],
)
def test_zip_transport_feature_rejections(tmp_path, feature, code):
    import struct

    path = tmp_path / "features.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("collection_manifest.json", "{}")
        if feature == "count":
            for i in range(MAX_PACKAGE_FILES + 76):
                z.writestr(f"file-{i}.json", "{}")
    if feature != "count":
        data = bytearray(path.read_bytes())
        offset = data.index(b"PK\x01\x02")
        struct.pack_into(
            "<H",
            data,
            offset + (8 if feature == "encryption" else 10),
            1 if feature == "encryption" else 99,
        )
        path.write_bytes(data)
    with pytest.raises(InputError, match=code):
        unpack_package(path, tmp_path / "out")


def test_failed_stdout_is_not_required_to_be_valid_json(tmp_path):
    folder = pilot(tmp_path / "input")
    failed = folder / "compute/instances.json"
    failed.write_text("Collector command failed before producing JSON\n")
    package, diagnostics = inspect_package(folder)
    source = next(s for s in package.sources if s.operation == "gcp:compute.instances.list")
    assert source.coverage == "ERROR" and source.path is None
    assert source.gcp_metadata["local_file_sha256"]
    assert diagnostics["original_status_totals"] == {"SUCCESS": 8, "EMPTY": 5, "FAILED": 19}
    with Store(tmp_path / "work") as store:
        run = import_package(store, folder)
        assess(store, run)
        assert list(store.candidates(run))
        assert not any(o.resource_type == "GCP::ComputeInstance" for o in store.observations(run))
