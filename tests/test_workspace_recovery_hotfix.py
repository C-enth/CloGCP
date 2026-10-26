"""P0 workspace recovery: large synthetic files, atomic publication and failures."""

import errno
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_gcp_final_workflow import baseline  # noqa: F401

from offline_analyzer.api.app import create_app
from offline_analyzer.clogcp_profile import ensure_workspace
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.storage import side_by_side as recovery
from offline_analyzer.storage.location import prepare_open
from offline_analyzer.storage.store import Store


def large_file(path: Path) -> str:
    """67 MiB + 39 bytes, with a distinct tail; never buffer the whole file."""
    block = bytes(range(256)) * 4096
    digest = hashlib.sha256()
    with path.open("wb") as stream:
        for _ in range(67):
            stream.write(block)
            digest.update(block)
        tail = b"synthetic-workspace-integrity-tail!!!\x00\x01"
        assert len(tail) == 39
        stream.write(tail)
        digest.update(tail)
    return digest.hexdigest()


@pytest.fixture
def workspace(tmp_path):
    source = tmp_path / "source"
    ensure_workspace(source)
    with Store(source) as store:
        store.db.execute("INSERT INTO runs VALUES ('synthetic-b1', '2026-10-26', 'synthetic')")
    (source / "synthetic-evidence.bin").write_bytes(b"immutable synthetic evidence")
    return source


def test_large_hash_streams_all_bytes_and_ingestion_budget_is_unchanged(tmp_path, monkeypatch):
    path = tmp_path / "large.bin"
    expected = large_file(path)
    with pytest.raises(ValueError, match="file exceeds byte budget"):
        sha256_file(path)
    opened, reads = os.fdopen, []

    class Probe:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, count):
            reads.append(count)
            assert 0 < count <= recovery.HASH_CHUNK_BYTES
            return self.stream.read(count)

    monkeypatch.setattr(os, "fdopen", lambda *a, **kw: Probe(opened(*a, **kw)))
    assert recovery.workspace_sha256(path) == expected
    assert len(reads) > 67
    assert recovery.file_inventory(tmp_path) == {"large.bin": expected}


def test_large_b1_b2_recovery_opens_and_preserves_all_files_and_records(
    baseline,  # noqa: F811
    tmp_path,
    monkeypatch,
):
    source, b1, b2, existing = baseline
    (source / "clogcp-workspace.json").write_text(
        json.dumps({"schema": "clogcp-workspace-1", "product": "CloGCP"})
    )
    expected = large_file(source / "large-synthetic-evidence.bin")
    before, tables = recovery.file_inventory(source), recovery.database_inventory(source)
    target = tmp_path / "recovered"
    result = recovery.recover_copy(source, target, upgrade_additive=True)
    assert result["destination_files"]["large-synthetic-evidence.bin"] == expected
    assert result["tables"] == tables == result["destination_tables"]
    assert all(recovery.file_inventory(target)[name] == digest for name, digest in before.items())
    monkeypatch.setenv("CLOGCP_PROFILE", "1")
    assert prepare_open(target)["read_only_preflight"]
    origin = "http://127.0.0.1:8765"
    with TestClient(
        create_app(target, origin=origin, bootstrap="synthetic"), base_url=origin
    ) as client:
        session = client.post(
            "/api/session", json={}, headers={"Origin": origin, "X-Bootstrap-Token": "synthetic"}
        )
        assert session.status_code == 200
        response = client.get("/api/runs")
        assert response.status_code == 200
        assert all(run in response.text for run in [b1, b2, existing])
        assert recovery.database_inventory(target) == tables
    assert recovery.file_inventory(source) == before
    assert recovery.database_inventory(source) == tables
    assert not list(tmp_path.glob(".clogcp-recovery-*"))


@pytest.mark.parametrize("failure", ["interrupt", "disk_full", "corrupt_copy", "manifest_write"])
def test_failed_recovery_never_publishes_or_changes_source(
    workspace, tmp_path, monkeypatch, failure
):
    source, target = workspace, tmp_path / "new-workspace"
    before, tables = recovery.file_inventory(source), recovery.database_inventory(source)
    copytree = recovery.shutil.copytree

    def copy(*args, **kwargs):
        # copytree recursively invokes itself with more positional arguments.
        if Path(args[0]) != source:
            return copytree(*args, **kwargs)
        if failure in {"interrupt", "disk_full"}:
            Path(args[1]).mkdir()
            (Path(args[1]) / "partial.bin").write_bytes(b"partial")
            if failure == "interrupt":
                raise KeyboardInterrupt
            raise OSError(errno.ENOSPC, "synthetic full disk")
        value = copytree(*args, **kwargs)
        if failure == "corrupt_copy":
            (Path(args[1]) / "synthetic-evidence.bin").write_bytes(b"corrupt")
        return value

    monkeypatch.setattr(recovery.shutil, "copytree", copy)
    if failure == "manifest_write":
        monkeypatch.setattr(
            recovery.os,
            "fsync",
            lambda fd: (_ for _ in ()).throw(OSError(errno.ENOSPC, "synthetic full disk")),
        )
    with pytest.raises((KeyboardInterrupt, OSError, ValueError)):
        recovery.recover_copy(source, target)
    assert not target.exists()
    assert not list(tmp_path.glob(".clogcp-recovery-*"))
    assert recovery.file_inventory(source) == before
    assert recovery.database_inventory(source) == tables


def test_low_disk_space_refuses_before_creating_a_copy(workspace, tmp_path, monkeypatch):
    before = recovery.file_inventory(workspace)
    monkeypatch.setattr(recovery.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    with pytest.raises(ValueError, match="INSUFFICIENT_WORKSPACE_COPY_SPACE"):
        recovery.recover_copy(workspace, tmp_path / "target")
    assert recovery.file_inventory(workspace) == before
    assert not list(tmp_path.glob(".clogcp-recovery-*"))
    assert not (tmp_path / "target").exists()


@pytest.mark.parametrize("kind", ["file", "directory", "broken", "source_root", "target_parent"])
def test_links_are_refused_without_following_them(workspace, tmp_path, kind):
    external = tmp_path / "external"
    external.mkdir()
    (external / "sentinel").write_bytes(b"do not touch")
    source, target = workspace, tmp_path / "target"
    link = workspace / "unsafe-link"
    if kind == "source_root":
        source = tmp_path / "source-link"
        source.symlink_to(workspace, target_is_directory=True)
    elif kind == "target_parent":
        parent = tmp_path / "parent-link"
        parent.symlink_to(external, target_is_directory=True)
        target = parent / "target"
    else:
        link.symlink_to(
            external
            if kind == "directory"
            else external / ("missing" if kind == "broken" else "sentinel"),
            target_is_directory=kind == "directory",
        )
    with pytest.raises(ValueError, match="SYMLINK_OR_REPARSE"):
        recovery.recover_copy(source, target)
    assert not (tmp_path / "target").exists()
    assert not (external / "target").exists()
    assert (external / "sentinel").read_bytes() == b"do not touch"


def test_reparse_points_and_path_traversal_are_refused(workspace, tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="PATH_TRAVERSAL"):
        recovery.recover_copy(workspace, tmp_path / "child" / ".." / "target")
    original = Path.lstat
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda p: (
            SimpleNamespace(st_mode=0o40700, st_file_attributes=0x400)
            if p == workspace
            else original(p)
        ),
    )
    with pytest.raises(ValueError, match="SYMLINK_OR_REPARSE"):
        recovery.recover_copy(workspace, tmp_path / "target")


def test_hard_kill_leaves_only_marked_unpublished_copy(workspace, tmp_path):
    before, tables = recovery.file_inventory(workspace), recovery.database_inventory(workspace)
    target = tmp_path / "target"
    code = """
import os,sys
from pathlib import Path
from offline_analyzer.storage import side_by_side as r
def interrupted(source, target, **kwargs):
    Path(target).mkdir()
    (Path(target)/'partial.bin').write_bytes(b'partial')
    os._exit(91)
r.shutil.copytree=interrupted
r.recover_copy(Path(sys.argv[1]),Path(sys.argv[2]))
"""
    env = {**os.environ, "PYTHONPATH": str(Path(recovery.__file__).resolve().parents[2])}
    result = subprocess.run([sys.executable, "-c", code, str(workspace), str(target)], env=env)
    assert result.returncode == 91
    assert not target.exists()
    containers = list(tmp_path.glob(".clogcp-recovery-*"))
    assert len(containers) == 1 and (containers[0] / recovery.INCOMPLETE).is_file()
    with pytest.raises(ValueError, match="INCOMPLETE_WORKSPACE_RECOVERY"):
        recovery.compatible(containers[0] / "workspace")
    assert recovery.file_inventory(workspace) == before
    assert recovery.database_inventory(workspace) == tables
    # A new explicit attempt uses a fresh private container, never the partial data.
    assert recovery.recover_copy(workspace, target)["recovery_verified"]


def test_hash_refuses_a_file_changed_while_reading(tmp_path, monkeypatch):
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"a" * (2 * recovery.HASH_CHUNK_BYTES))
    changed = False

    def mutate():
        nonlocal changed
        if not changed:
            changed = True
            with path.open("ab") as stream:
                stream.write(b"changed")

    monkeypatch.setattr("offline_analyzer.provenance.execution.checkpoint", mutate)
    with pytest.raises(ValueError, match="FILE_CHANGED_DURING_HASH"):
        recovery.workspace_sha256(path)


def test_existing_destination_and_historical_recovery_record_are_preserved(workspace, tmp_path):
    old = workspace / "side-by-side-recovery.json"
    old.write_text('{"synthetic": "previous recovery audit"}')
    target = tmp_path / "target"
    target.mkdir()
    sentinel = target / "sentinel"
    sentinel.write_text("existing destination")
    with pytest.raises(ValueError, match="NEW_SIBLING"):
        recovery.recover_copy(workspace, target)
    assert sentinel.read_text() == "existing destination"
    result = recovery.recover_copy(workspace, tmp_path / "another-target")
    assert result["manifest_file"] != old.name
    assert (tmp_path / "another-target" / old.name).read_bytes() == old.read_bytes()


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows junction required")
def test_native_windows_junctions_are_refused(workspace, tmp_path):
    external, junction = tmp_path / "external", tmp_path / "junction"
    external.mkdir()
    (external / "sentinel").write_text("do not follow")
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)], check=True, capture_output=True
    )
    with pytest.raises(ValueError, match="SYMLINK_OR_REPARSE"):
        recovery.recover_copy(workspace, junction / "target")
    with pytest.raises(ValueError, match="SYMLINK_OR_REPARSE"):
        recovery.file_inventory(junction)
    assert (external / "sentinel").read_text() == "do not follow"
    assert not (external / "target").exists()


def test_path_and_handle_file_identities_may_differ(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"same stable file")
    original = os.fstat

    def distinct_handle_identity(fd):
        value = original(fd)
        return SimpleNamespace(
            st_dev=value.st_dev + 1,
            st_ino=value.st_ino + 1,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(recovery.os, "fstat", distinct_handle_identity)
    assert recovery.workspace_sha256(path) == hashlib.sha256(b"same stable file").hexdigest()
