"""Explicit copy-only upgrades and non-migrating CloGCP opening, synthetic only."""

import pytest

from offline_analyzer.clogcp_profile import ensure_workspace
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.storage.consolidation_schema import TABLES
from offline_analyzer.storage.location import prepare_open
from offline_analyzer.storage.side_by_side import (
    compatible,
    database_inventory,
    file_inventory,
    recover_copy,
)
from offline_analyzer.storage.store import Store


def test_previous_clogcp_schema_requires_explicit_verified_copy(tmp_path, monkeypatch):
    source, target = tmp_path / "previous", tmp_path / "upgraded"
    ensure_workspace(source)
    with Store(source) as store:
        store.db.execute("INSERT INTO runs VALUES ('old-b1', '2026-10-01', 'synthetic')")
        for table in TABLES:
            store.db.execute(f'DROP TABLE "{table}"')
    before, tables = file_inventory(source), database_inventory(source)
    monkeypatch.setenv("CLOGCP_PROFILE", "1")
    with pytest.raises(InputError, match="EXPLICIT_VERSIONED_WORKSPACE_UPGRADE_REQUIRED"):
        prepare_open(source)
    assert before == file_inventory(source)
    with pytest.raises(InputError, match="EXPLICIT_VERSIONED_WORKSPACE_UPGRADE_REQUIRED"):
        recover_copy(source, target)
    assert not target.exists()
    report = recover_copy(source, target, upgrade_additive=True)
    assert report["source_modified"] is False and report["records_migrated"] is False
    assert set(report["additive_tables_created_in_copy"]) == set(TABLES)
    assert before == file_inventory(source)
    assert tables == database_inventory(source)
    after = database_inventory(target)
    assert all(after[k] == value for k, value in tables.items())
    assert all(after[k]["rows"] == 0 for k in TABLES)
    compatible(target)
    copied = file_inventory(target)
    assert prepare_open(target)["read_only_preflight"] is True
    assert copied == file_inventory(target)
