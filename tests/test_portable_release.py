"""Portable source boundary, integrity and platform-script contracts."""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

from tools.portable_release import ROOT, assemble


def test_portable_source_has_runtime_assets_pins_scripts_and_no_private_data(tmp_path):
    target = assemble(ROOT, tmp_path / "release", revision="a" * 40)
    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        assert {
            "CloSec.command",
            "CloSec.cmd",
            "requirements.txt",
            "setup-macos.sh",
            "start-macos.sh",
            "setup-windows.ps1",
            "start-windows.ps1",
            "verify.py",
            "portable-manifest.json",
        } <= set(names)
        assert not any(
            part in {"private", "data", "artifacts", "tests", "tools", "node_modules"}
            for name in names
            for part in Path(name).parts
        )
        assert not any(
            Path(name).suffix in {".xlsx", ".duckdb", ".rtf", ".whl", ".exe"} for name in names
        )
        for launcher in ("CloSec.command", "setup-macos.sh", "start-macos.sh"):
            assert archive.getinfo(launcher).external_attr >> 16 == 0o100755
        assert archive.getinfo("verify.py").external_attr >> 16 == 0o100644
        batch = archive.read("CloSec.cmd")  # cmd.exe misreads labels with bare LF endings.
        assert batch.count(b"\n") == batch.count(b"\r\n") > 0
        assert "src/offline_analyzer/api/assets/build-info.json" in names
        assert "src/offline_analyzer/contracts/schemas/LocalJob.json" in names
        manifest = json.loads(archive.read("portable-manifest.json"))
        assert manifest["git_revision"] == "a" * 40
        assert not manifest["customer_evidence_included"]
        archive.extractall(tmp_path / "extracted")  # Trusted builder output only.
    spec = importlib.util.spec_from_file_location("portable_verify", "packaging/portable/verify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.verify(tmp_path / "extracted")["result"] == "PASS"
    (tmp_path / "extracted/requirements.txt").write_text("modified")
    with pytest.raises(ValueError, match="integrity mismatch"):
        module.verify(tmp_path / "extracted")


def test_portable_requirements_exclude_builders_and_use_pinned_runtime_dependencies():
    requirements = (ROOT / "requirements.txt").read_text().splitlines()
    lines = [line for line in requirements if line and not line.startswith("#")]
    assert lines and all("==" in line for line in lines)
    assert not any(
        name in "\n".join(lines) for name in ("pyinstaller", "playwright", "pytest", "boto3")
    )
    assert "duckdb==1.5.6" in lines and "python-multipart==0.0.32" in lines
