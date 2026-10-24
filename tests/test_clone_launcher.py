"""A clone launches verified packaged files, never the incomplete source root."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bootstrap():
    spec = importlib.util.spec_from_file_location("clone_bootstrap", ROOT / "run-portable.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package(root, bootstrap, extra=None):
    files = {"CloGCP.cmd": b"@echo off\r\nexit /b 0\r\n", "verify.py": b"# verifier fixture\n"}
    manifest = {
        "schema": "clogcp-portable-1",
        "product": "CloGCP",
        "files": [
            {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in files.items()
        ],
    }
    with zipfile.ZipFile(root / "CloGCP.zip", "w") as zipped:
        for name, data in files.items():
            zipped.writestr("CloGCP/" + name, data)
        zipped.writestr("CloGCP/portable-manifest.json", json.dumps(manifest))
        if extra:
            zipped.writestr(extra, b"unexpected")
    bootstrap.EXPECTED_SHA256 = hashlib.sha256((root / "CloGCP.zip").read_bytes()).hexdigest()


def test_clone_prepares_package_and_reuses_without_touching_workspace(tmp_path, bootstrap):
    package(tmp_path, bootstrap)
    workspace = tmp_path / "existing-assessment"
    workspace.mkdir()
    database = workspace / "assessment.duckdb"
    database.write_bytes(b"synthetic preservation marker")
    app = bootstrap.prepare(tmp_path)
    assert app.parent.name == bootstrap.EXPECTED_SHA256
    assert (app / "portable-manifest.json").is_file()
    (app / ".venv").mkdir()
    marker = app / ".venv/keep.txt"
    marker.write_bytes(b"existing isolated runtime")
    assert bootstrap.prepare(tmp_path) == app
    assert marker.read_bytes() == b"existing isolated runtime"
    assert database.read_bytes() == b"synthetic preservation marker"
    assert not (tmp_path / "portable-manifest.json").exists()


def test_changed_zip_is_rejected_before_extraction(tmp_path, bootstrap):
    package(tmp_path, bootstrap)
    with (tmp_path / "CloGCP.zip").open("ab") as stream:
        stream.write(b"mutation")
    with pytest.raises(ValueError, match="checksum mismatch"):
        bootstrap.prepare(tmp_path)
    assert not (tmp_path / ".portable").exists()


@pytest.mark.parametrize("member", ["../escape", "CloGCP/../../escape", "CloGCP/C:/escape"])
def test_unsafe_archive_is_rejected_before_extraction(tmp_path, bootstrap, member):
    package(tmp_path, bootstrap, extra=member)
    with pytest.raises(ValueError, match="Unsafe"):
        bootstrap.prepare(tmp_path)
    assert not (tmp_path / ".portable").exists()


@pytest.mark.parametrize("name", ["verify.py", "portable-manifest.json", "CloGCP.cmd"])
def test_changed_cache_never_runs_or_overwrites_files(tmp_path, bootstrap, name):
    package(tmp_path, bootstrap)
    app = bootstrap.prepare(tmp_path)
    (app / name).write_bytes(b"changed")
    with pytest.raises(ValueError, match="missing or changed|file changed"):
        bootstrap.prepare(tmp_path)
    assert (app / name).read_bytes() == b"changed"


def test_batch_clone_dispatch_precedes_source_verification():
    batch = (ROOT / "CloGCP.cmd").read_bytes()
    assert batch.index(b"run-portable.py") < batch.index(b"verify.py")
    assert batch.count(b"\n") == batch.count(b"\r\n")
    setup = (ROOT / "setup-windows.ps1").read_text()
    assert setup.index("This is a source checkout") < setup.index("(Join-Path $Root 'verify.py')")


def test_wrong_python_has_clear_message(bootstrap, monkeypatch, capsys):
    monkeypatch.setattr(sys, "version_info", (3, 11, 0))
    assert bootstrap.main() == 1
    assert "Python 3.12 is required" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "win32", reason="Native cmd.exe and Python launcher required")
def test_native_clone_launcher_in_folder_with_spaces(tmp_path, bootstrap):
    if not shutil.which("py"):
        pytest.skip("Windows Python launcher required")
    folder = tmp_path / "clone folder with spaces"
    folder.mkdir()
    package(folder, bootstrap)
    script = (
        (ROOT / "run-portable.py")
        .read_text()
        .replace(
            "e7e0be798760c50a2285de8c6634c64dd92c9a72c4ee87cd261dc6cdcaf50621",
            bootstrap.EXPECTED_SHA256,
        )
    )
    (folder / "run-portable.py").write_text(script)
    shutil.copy2(ROOT / "CloGCP.cmd", folder / "CloGCP.cmd")
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "CloGCP.cmd"], cwd=folder, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
