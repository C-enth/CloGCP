"""A source clone plus its launcher runs the release's runtime files; no committed archives."""

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from tools.runtime_manifest import LOCKS, MANIFEST, manifest, runtime_files

ROOT = Path(__file__).resolve().parents[1]


def load_verify():
    spec = importlib.util.spec_from_file_location("clogcp_verify", ROOT / "verify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_runtime_manifest_is_current_and_verifies():
    assert (ROOT / MANIFEST).read_bytes() == manifest(runtime_files(ROOT))
    result = load_verify().verify(ROOT)
    assert result["result"] == "PASS" and result["mode"] == "source-clone"


def fake_root(tmp_path: Path) -> Path:
    files = {"verify.py": b"# fixture\n", "src/app.py": b"print('ok')\n"}
    for name, data in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(data)
    (tmp_path / MANIFEST).write_text(
        json.dumps(
            {
                "schema": "clogcp-runtime-1",
                "product": "CloGCP",
                "files": [
                    {"path": n, "bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()}
                    for n, d in files.items()
                ],
            }
        )
    )
    return tmp_path


@pytest.mark.parametrize("change", ["modified", "missing", "symlink", "no-manifest"])
def test_changed_clone_files_stop_the_launcher(tmp_path, change):
    root = fake_root(tmp_path)
    verify = load_verify()
    assert verify.verify(root)["files"] == 2
    target = root / "src/app.py"
    if change == "modified":
        target.write_bytes(b"print('changed')\n")
    elif change == "missing":
        target.unlink()
    elif change == "symlink":
        target.unlink()
        target.symlink_to(root / "verify.py")
    else:
        (root / MANIFEST).unlink()
    with pytest.raises((ValueError, OSError)):
        verify.verify(root)


def test_no_release_archive_is_committed_and_locks_are():
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    assert not [n for n in tracked if n.endswith((".zip", ".whl"))]
    for lock in LOCKS:
        lines = [x for x in (ROOT / lock).read_text().splitlines() if "==" in x]
        assert lines and all("--hash=sha256:" in line for line in lines)


def test_launchers_run_the_clone_directly_and_install_only_locked_wheels():
    batch = (ROOT / "CloGCP.cmd").read_bytes()
    assert b"run-portable" not in batch and b".zip" not in batch
    assert batch.count(b"\n") == batch.count(b"\r\n")
    assert batch.index(b"setup-windows.ps1") < batch.index(b"verify.py")
    for name in ("setup-macos.sh", "setup-windows.ps1"):
        text = (ROOT / name).read_text()
        assert "CLOGCP_WHEELHOUSE" in text and "verify.py" in text
        assert "--no-index" in text and "--require-hashes" in text and "--only-binary" in text
        assert "source checkout" not in text
    assert "verify.py" in (ROOT / "CloGCP.command").read_text()
