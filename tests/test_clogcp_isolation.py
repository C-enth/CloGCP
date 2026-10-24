"""The independent profile must never open an unmarked CloSec database for writing."""

import hashlib
import os

import pytest

from offline_analyzer.clogcp_profile import configure, ensure_workspace
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.storage.store import Store


def test_config_and_workspace_environment_are_separate(monkeypatch, tmp_path):
    old = tmp_path / "closec-settings"
    new = tmp_path / "clogcp-settings"
    monkeypatch.setenv("CLOSEC_CONFIG_DIR", str(old))
    monkeypatch.setenv("CLOSEC_WORKSPACE", str(tmp_path / "old-workspace"))
    monkeypatch.setenv("CLOGCP_CONFIG_DIR", str(new))
    monkeypatch.setenv("CLOGCP_PROFILE", "")
    workspace = configure()
    assert os.environ["CLOSEC_CONFIG_DIR"] == str(new)
    assert "CLOSEC_WORKSPACE" not in os.environ
    assert "clogcp" in str(workspace).lower()
    assert not old.exists() and not new.exists()


def test_existing_unmarked_workspace_is_refused_before_store_open(monkeypatch, tmp_path):
    work = tmp_path / "original"
    with Store(work):
        pass
    database = work / "assessment.duckdb"
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    monkeypatch.setenv("CLOGCP_PROFILE", "1")
    with pytest.raises(InputError, match="REFUSES_EXISTING"):
        Store(work)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    assert not (work / "clogcp-workspace.json").exists()


def test_new_isolated_workspace_is_idempotent(monkeypatch, tmp_path):
    work = tmp_path / "new"
    monkeypatch.setenv("CLOGCP_PROFILE", "1")
    ensure_workspace(work)
    with Store(work) as store:
        assert list(store.rows("SELECT count(*) FROM runs")) == [(0,)]
    ensure_workspace(work)
    with Store(work) as store:
        assert list(store.rows("SELECT count(*) FROM runs")) == [(0,)]
