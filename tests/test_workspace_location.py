"""User-defined workspace location: pointer, safety checks, read-only inspection, crash
recovery, schema guard, pre-migration backup, lock, verified copy/backup and privacy.
Synthetic workspaces in temporary folders only; the pointer lives in a temporary config
folder (CLOSEC_CONFIG_DIR) so the real user configuration is never touched."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from offline_analyzer.api.app import create_app
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.launcher import WorkspaceLock, resolve_workspace
from offline_analyzer.storage import location as loc
from offline_analyzer.storage.store import Store

ORIGIN, TOKEN = "http://127.0.0.1:8765", "synthetic-location-token"
REPO = Path.cwd()


@pytest.fixture(autouse=True)
def private_config(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOSEC_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.delenv("CLOSEC_WORKSPACE", raising=False)


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory) -> Path:
    """One assessed synthetic GCP workspace with a decision, an exclusion and a draft."""
    from offline_analyzer.contracts.exclusion import ExclusionRequest
    from offline_analyzer.findings.exclusions import record as exclude
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from tools.gcp_fixture import build

    root = tmp_path_factory.mktemp("synthetic")
    workspace = root / "workspace"
    set_environment(workspace, "SYNTHETIC")
    with Store(workspace) as store:
        run = import_package(store, build(root / "package", "demo-alpha", "123456789012"))
        assess(store, run)
        findings = list(store.candidates(run))
        record_decision(store, run, findings[0].finding_id, "CONFIRMED", "Synthetic", "note")
        exclude(
            store,
            run,
            findings[1].finding_id,
            ExclusionRequest(
                action="EXCLUDE", reason="FALSE_POSITIVE", note="Synthetic", analyst="Synthetic"
            ),
        )
    return workspace


def clone(source: Path, target: Path) -> Path:
    shutil.copytree(source, target)
    return target


def hashes(folder: Path) -> dict[str, str]:
    return {
        p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


# ---------------------------------------------------------------- resolution and pointer
def test_default_behaviour_is_unchanged_when_nothing_is_chosen(tmp_path):
    default = tmp_path / "default"
    assert resolve_workspace(None, default) == ("DEFAULT", default)
    assert not (tmp_path / "config").exists()  # nothing written by resolving


def test_explicit_environment_and_remembered_locations(tmp_path, monkeypatch, synthetic):
    default, explicit = tmp_path / "default", tmp_path / "explicit"
    loc.write_pointer(synthetic)
    pointer = tmp_path / "config" / loc.POINTER
    assert set(json.loads(pointer.read_text())) == {"path", "updated_utc"}
    assert stat.S_IMODE(pointer.stat().st_mode) == 0o600
    assert resolve_workspace(None, default) == ("REMEMBERED", synthetic)
    monkeypatch.setenv("CLOSEC_WORKSPACE", str(tmp_path / "env"))
    assert resolve_workspace(None, default) == ("ENVIRONMENT", tmp_path / "env")
    assert resolve_workspace(explicit, default) == ("COMMAND_LINE", explicit)


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"path": "relative/path", "updated_utc": "2026-01-01T00:00:00"}),
        json.dumps({"updated_utc": "2026-01-01T00:00:00"}),
        "MISSING_FOLDER",
        "NOT_A_WORKSPACE",
    ],
)
def test_corrupt_or_stale_pointer_asks_instead_of_failing(tmp_path, content):
    folder = tmp_path / "config"
    folder.mkdir()
    if content == "MISSING_FOLDER":
        content = json.dumps({"path": str(tmp_path / "gone"), "updated_utc": "2026-01-01T00:00:00"})
    if content == "NOT_A_WORKSPACE":
        (tmp_path / "other").mkdir()
        (tmp_path / "other" / "notes.txt").write_text("x")
        content = json.dumps(
            {"path": str(tmp_path / "other"), "updated_utc": "2026-01-01T00:00:00"}
        )
    (folder / loc.POINTER).write_text(content)
    assert resolve_workspace(None, tmp_path / "default") == ("SETUP", None)


# ---------------------------------------------------------------- safety checks
def test_safety_warnings_and_blocks(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    assert "GIT_REPOSITORY" in loc.location_checks(repo / "workspace")["warnings"]
    home = tmp_path / "home"  # a home directory that is itself a git repository
    (home / ".git").mkdir(parents=True)
    assert "GIT_REPOSITORY" in loc.location_checks(home / "Library" / "workspace")["warnings"]
    for synced in ("Dropbox", "OneDrive", "Google Drive", "Library/Mobile Documents"):
        assert "SYNC_FOLDER" in loc.location_checks(tmp_path / synced / "ws")["warnings"]
    assert "NETWORK_OR_REMOVABLE" in loc.location_checks(Path("/Volumes/USB/ws"))["warnings"]
    locked = tmp_path / "readonly"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        assert "NOT_WRITABLE" in loc.location_checks(locked / "ws")["warnings"]
    finally:
        locked.chmod(0o700)
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o755)
    assert "WORLD_READABLE" in loc.location_checks(shared)["warnings"]
    monkeypatch.setattr(loc.shutil, "disk_usage", lambda _: shutil._ntuple_diskusage(1, 1, 10))
    assert "LOW_FREE_SPACE" in loc.location_checks(tmp_path / "ws")["warnings"]
    monkeypatch.undo()
    assert "SOURCE_TREE" in loc.location_checks(REPO / "artifacts" / "ws")["blocked"]
    release = tmp_path / "CLoSec"
    release.mkdir()
    (release / "CloSec.command").write_text("#!/bin/sh\n")
    assert "RELEASE_FOLDER" in loc.location_checks(release / "ws")["blocked"]
    clean = tmp_path / "clean" / "ws"
    found = loc.location_checks(clean)
    assert not found["blocked"] and set(found["warnings"]) <= {
        "GIT_REPOSITORY"
    }  # tmp may sit in a repo
    assert all(code in loc.MESSAGES for code in loc.MESSAGES)


@pytest.mark.parametrize(
    ("path", "code"),
    [
        (r"\\fileserver\share\CloSec\workspace", "NETWORK_OR_REMOVABLE"),
        (r"C:\Users\analyst\OneDrive - Contoso\CloSec", "SYNC_FOLDER"),
        (r"C:\Users\analyst\Dropbox\CloSec", "SYNC_FOLDER"),
        ("C:\\Engagements\\" + "very-long-folder-name\\" * 9 + "workspace", "PATH_TOO_LONG"),
    ],
)
def test_windows_paths_by_text(path, code):
    assert code in loc.location_checks(path, windows=True)["warnings"]


def test_windows_plain_path_and_non_ascii_have_no_warning():
    for path in (r"D:\CloSec\workspace", "D:\\Prüfung\\Kundenprojekt 2026\\workspace"):
        assert loc.location_checks(path, windows=True)["warnings"] == []


# ---------------------------------------------------------------- inspection and open
def test_open_existing_from_a_different_path_keeps_counts(tmp_path, synthetic):
    moved = clone(synthetic, tmp_path / "elsewhere with space é" / "workspace")
    original, found = loc.inspect_workspace(synthetic), loc.inspect_workspace(moved)
    assert original["ok"] and found["ok"] and found["schema"] == "CURRENT"
    assert found["counts"] == original["counts"]
    assert found["counts"]["confirmations"] == 1 and found["counts"]["exclusion_records"] == 1
    before = hashes(moved)
    loc.inspect_workspace(moved)
    assert hashes(moved) == before  # inspection is read-only
    lock = WorkspaceLock(moved)
    try:
        report = loc.prepare_open(moved)
    finally:
        lock.close()
    assert report["counts"] == original["counts"] and report["integrity"] == "OK"
    assert not report["recovered"] and not report["migrated"]


@pytest.mark.parametrize(
    ("setup", "code"),
    [("file", "NOT_A_DIRECTORY"), ("empty", "NOT_A_WORKSPACE"), ("wal", "WAL_WITHOUT_DATABASE")],
)
def test_non_workspace_folders_are_refused(tmp_path, setup, code):
    target = tmp_path / "candidate"
    if setup == "file":
        target.write_text("x")
    else:
        target.mkdir()
        if setup == "wal":
            (target / "assessment.duckdb.wal").write_bytes(b"x")
    assert loc.inspect_workspace(target)["code"] == code
    assert code in loc.ERRORS


def test_unclean_shutdown_with_leftover_journal_recovers(tmp_path, synthetic):
    workspace = clone(synthetic, tmp_path / "crashed")
    code = (
        "import os,sys; sys.path.insert(0,'src'); from pathlib import Path; "
        "from offline_analyzer.storage.store import Store; "
        f"s=Store(Path({str(workspace)!r})); "
        "s.db.execute(\"INSERT INTO decisions VALUES ('synthetic-d','f','2026-01-01',"
        '\'{\\"status\\":\\"CONFIRMED\\"}\')"); os._exit(0)'
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=REPO)
    assert (workspace / "assessment.duckdb.wal").exists()
    found = loc.inspect_workspace(workspace)
    assert found["ok"] and found["unclean_shutdown"]
    assert found["counts"]["confirmations"] == 2  # the journal is replayed read-only
    lock = WorkspaceLock(workspace)
    try:
        report = loc.prepare_open(workspace)
    finally:
        lock.close()
    assert report["recovered"] and report["integrity"] == "OK"
    assert report["counts"] == found["counts"]
    assert not (workspace / "assessment.duckdb.wal").exists()


def test_newer_schema_is_refused_and_left_unchanged(tmp_path, synthetic):
    workspace = clone(synthetic, tmp_path / "newer")
    with Store(workspace) as store:
        store.db.execute("INSERT INTO schema_info VALUES (2)")
        store.db.execute("CHECKPOINT")
    before = hashes(workspace)
    assert loc.inspect_workspace(workspace)["code"] == "NEWER_SCHEMA"
    lock = WorkspaceLock(workspace)
    try:
        with pytest.raises(InputError, match="WORKSPACE_NEWER_SCHEMA"):
            loc.prepare_open(workspace)
    finally:
        lock.close()
    after = hashes(workspace)
    after.pop(".gui-owner.lock", None)
    before.pop(".gui-owner.lock", None)
    assert after == before


def test_older_schema_is_backed_up_then_migrated(tmp_path, synthetic):
    import duckdb

    workspace = clone(synthetic, tmp_path / "older")
    db = duckdb.connect(str(workspace / "assessment.duckdb"))
    db.execute("DROP TABLE path_reviews")
    db.close()
    found = loc.inspect_workspace(workspace)
    assert found["ok"] and found["schema"] == "OLDER" and found["missing_tables"] == 1
    lock = WorkspaceLock(workspace)
    try:
        report = loc.prepare_open(workspace)
    finally:
        lock.close()
    assert report["migrated"] and report["integrity"] == "OK"
    (backup,) = (tmp_path / "older-backups").glob("pre-migration-*")
    assert report["backup"]["files"] == len(loc.workspace_files(backup))
    old = duckdb.connect(str(backup / "assessment.duckdb"), read_only=True)
    assert "path_reviews" not in {r[0] for r in old.execute("SHOW TABLES").fetchall()}
    old.close()
    with Store(workspace) as store:
        assert store.db.execute("SELECT count(*) FROM path_reviews").fetchone()[0] == 0


def test_single_writer_lock_names_the_other_process(tmp_path, synthetic):
    workspace = clone(synthetic, tmp_path / "locked")
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys,time; sys.path.insert(0,'src'); from pathlib import Path; "
            "from offline_analyzer.launcher import WorkspaceLock; "
            f"held=WorkspaceLock(Path({str(workspace)!r})); "
            "print('held', flush=True); time.sleep(60)",
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        assert loc.lock_holder(workspace) == holder.pid
        found = loc.inspect_workspace(workspace)
        assert found["code"] == "IN_USE" and found["locked_by_pid"] == holder.pid
        launched = subprocess.run(
            [
                sys.executable,
                "-m",
                "offline_analyzer.launcher",
                "--workspace",
                str(workspace),
                "--no-browser",
                "--port",
                "0",
            ],
            cwd=REPO,
            env={**os.environ, "PYTHONPATH": str(REPO / "src")},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert launched.returncode == 1
        assert f"workspace in use by CloSec process {holder.pid}" in launched.stdout
        assert str(workspace) not in launched.stdout + launched.stderr
    finally:
        holder.kill()
        holder.wait()
    assert loc.lock_holder(workspace) is None


# ---------------------------------------------------------------- copy and backup
def test_copy_is_verified_and_never_touches_the_original(tmp_path, synthetic):
    workspace = clone(synthetic, tmp_path / "source")
    before = hashes(workspace)
    with Store(workspace) as store:
        expected = loc.counts(store.db)
    report = loc.copy_tree(workspace, tmp_path / "target", expected)
    assert report["counts"] == expected and report["files"] == len(before)
    assert hashes(tmp_path / "target") == {k: v for k, v in before.items()}
    assert hashes(workspace) == before


def test_copy_failing_midway_leaves_no_copy_and_the_original_intact(
    tmp_path, synthetic, monkeypatch
):
    workspace = clone(synthetic, tmp_path / "source")
    before = hashes(workspace)
    calls = {"n": 0}
    real = shutil.copyfile

    def flaky(source, target):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("synthetic disk full")
        return real(source, target)

    monkeypatch.setattr(loc.shutil, "copyfile", flaky)
    with pytest.raises(OSError):
        loc.copy_tree(workspace, tmp_path / "target", None)
    assert not (tmp_path / "target").exists()
    assert not list(tmp_path.glob("target.partial-*"))
    assert hashes(workspace) == before


def test_copy_refuses_non_empty_or_nested_targets(tmp_path, synthetic):
    workspace = clone(synthetic, tmp_path / "source")
    full = tmp_path / "full"
    full.mkdir()
    (full / "keep.txt").write_text("x")
    with pytest.raises(InputError, match="TARGET_NOT_EMPTY"):
        loc.copy_tree(workspace, full, None)
    assert (full / "keep.txt").read_text() == "x"
    with pytest.raises(InputError, match="TARGET_INSIDE_WORKSPACE"):
        loc.copy_tree(workspace, workspace / "inner", None)


# ---------------------------------------------------------------- API and privacy
def client_for(workspace: Path, **location) -> TestClient:
    app = create_app(
        workspace, origin=ORIGIN, bootstrap=TOKEN, location={"source": "DEFAULT", **location}
    )
    client = TestClient(app, base_url=ORIGIN)
    client.__enter__()
    response = client.post("/api/session", headers={"x-bootstrap-token": TOKEN, "origin": ORIGIN})
    client.headers.update({"x-csrf-token": response.json()["csrf"], "origin": ORIGIN})
    return client


def test_api_open_create_change_backup_and_privacy(tmp_path, synthetic):
    workspace = clone(synthetic, tmp_path / "current")
    other = clone(synthetic, tmp_path / "other")
    client = client_for(workspace)
    try:
        info = client.get("/api/workspace").json()
        assert info["path"] == str(workspace.resolve()) and info["source"] == "DEFAULT"
        assert str(workspace) not in client.get("/api/environment").text
        # Confirmation is required; blocked locations are refused.
        body = {"purpose": "open", "path": str(other)}
        assert client.post("/api/workspace/apply", json=body).json()["error"] == (
            "LOCATION_CONFIRMATION_REQUIRED"
        )
        blocked = {"purpose": "create", "path": str(REPO / "artifacts" / "x"), "confirm": True}
        assert client.post("/api/workspace/apply", json=blocked).json()["error"] == (
            "LOCATION_BLOCKED"
        )
        # Open existing: read-only check, then pointer only after confirmation.
        check = client.post("/api/workspace/check", json=body).json()
        assert check["inspection"]["ok"] and check["inspection"]["counts"]["findings"] > 0
        accept = bool(check["checks"]["warnings"])
        opened = client.post(
            "/api/workspace/apply", json={**body, "confirm": True, "accept_warnings": accept}
        ).json()
        assert opened["restart_required"] and loc.read_pointer() == ("VALID", other.resolve())
        # Warnings need explicit acceptance.
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        warned = client.post(
            "/api/workspace/apply",
            json={"purpose": "create", "path": str(repo / "ws"), "confirm": True},
        )
        assert warned.status_code == 409 and not (repo / "ws").exists()
        # Create new: empty owner-only folder.
        new = tmp_path / "brand new"
        created = client.post(
            "/api/workspace/apply",
            json={"purpose": "create", "path": str(new), "confirm": True, "accept_warnings": True},
        ).json()
        assert created["restart_required"] and new.is_dir() and not any(new.iterdir())
        assert stat.S_IMODE(new.stat().st_mode) == 0o700
        # Change location = verified copy; the previous folder is unchanged.
        before = hashes(workspace)
        moved = client.post(
            "/api/workspace/apply",
            json={
                "purpose": "change",
                "path": str(tmp_path / "moved"),
                "confirm": True,
                "accept_warnings": True,
            },
        ).json()
        assert moved["counts_match"] and moved["previous_kept"]
        assert moved["previous_path"] == str(workspace.resolve())
        current = {k: v for k, v in hashes(workspace).items() if k != "application.log"}
        assert current == {k: v for k, v in before.items() if k != "application.log"}
        # Backup now: timestamped subfolder with manifest, never overwritten.
        backups = tmp_path / "backups"
        backups.mkdir(mode=0o700)
        done = client.post(
            "/api/workspace/apply",
            json={
                "purpose": "backup",
                "path": str(backups),
                "confirm": True,
                "accept_warnings": True,
            },
        ).json()
        destination = Path(done["destination"])
        assert destination.parent == backups and destination.name.startswith("closec-backup-")
        assert done["counts_match"] and (destination / "closec-backup-manifest.json").is_file()
        # Return to default clears the pointer.
        assert client.post(
            "/api/workspace/apply", json={"purpose": "default", "confirm": True}
        ).json()["restart_required"]
        assert loc.read_pointer() == ("ABSENT", None)
        # Privacy: no path in the log (hash only), diagnostics or the report export.
        log = (workspace / "application.log").read_text()
        for path in (workspace, other, new, tmp_path / "moved", backups, destination):
            assert str(path) not in log and str(path.resolve()) not in log
        assert "location=" in log
        job = client.post(
            "/api/runs/" + client.get("/api/runs").json()[0]["run_id"] + "/reports",
            json={"kind": "assessment"},
        ).json()
        for _ in range(200):
            status = client.get(f"/api/jobs/{job['id']}").json()
            if status["status"] in {"SUCCEEDED", "FAILED"}:
                break
            import time

            time.sleep(0.1)
        diagnostic = client.get(f"/api/jobs/{job['id']}/diagnostic").text
        assert str(workspace) not in diagnostic
        report = client.get(f"/api/reports/{status['result']['id']}/download")
        with zipfile.ZipFile(__import__("io").BytesIO(report.content)) as bundle:
            for name in bundle.namelist():
                assert str(workspace).encode() not in bundle.read(name)
    finally:
        client.__exit__(None, None, None)


def test_pointer_is_outside_workspace_repository_and_archive(tmp_path, monkeypatch):
    monkeypatch.delenv("CLOSEC_CONFIG_DIR")
    folder = loc.config_dir()
    assert not folder.is_relative_to(REPO)
    if sys.platform == "darwin":
        assert folder == Path.home() / "Library" / "Application Support" / "CloSec"
    from tools.portable_release import DOCUMENTS

    assert loc.POINTER not in DOCUMENTS
