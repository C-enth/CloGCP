"""Platform-neutral delivery contract tests. These do not validate Windows execution."""

import json
import sys
from pathlib import Path

import pytest

from offline_analyzer import launcher
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.storage.store import Store
from tools.fixtures.scale import generate


def test_frozen_workspace_is_separate_from_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "User data ü"))
    assert launcher.default_workspace() == tmp_path / "User data ü/OfflineAWSAnalyzer/workspace"
    monkeypatch.delenv("LOCALAPPDATA")
    with pytest.raises(RuntimeError):
        launcher.default_workspace()
    monkeypatch.setenv("LOCALAPPDATA", "relative")
    with pytest.raises(RuntimeError):
        launcher.default_workspace()


def test_source_workspace_default_preserved(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert launcher.default_workspace() == Path("artifacts/gui-workspace")


def test_restricted_workspace_reports_only_sanitized_stage(tmp_path, monkeypatch, capsys):
    def deny(_):
        raise PermissionError("private customer path must never enter console output")

    monkeypatch.setattr(launcher, "WorkspaceLock", deny)
    monkeypatch.setattr(sys, "argv", ["launcher", "--workspace", str(tmp_path)])
    assert launcher.main() == 1
    assert "workspace access" in capsys.readouterr().out


def test_scale_generation_is_deterministic_and_retains_duplicate_refs(tmp_path):
    first, second = tmp_path / "input space ü", tmp_path / "input2"
    expected = generate(first, 2, 5, 2, 2)
    assert generate(second, 2, 5, 2, 2) == expected
    assert {p.relative_to(first): sha256_file(p) for p in first.rglob("*.json")} == {
        p.relative_to(second): sha256_file(p) for p in second.rglob("*.json")
    }
    with Store(tmp_path / "workspace ü") as store:
        run = import_package(store, first / "package-000")
        occurrences = store.db.execute("SELECT count(*) FROM evidence_refs").fetchone()[0]
        canonical = store.db.execute("SELECT count(*) FROM observations").fetchone()[0]
        assert occurrences == expected["expected"]["raw_records"]
        assert occurrences - canonical == expected["expected"]["duplicate_occurrences"]
        assert import_package(store, first / "package-000") == run
        assert store.db.execute("SELECT count(*) FROM observations").fetchone()[0] == canonical


def test_rejected_tail_rolls_back_flushed_import_batches(tmp_path):
    inputs = tmp_path / "input"
    generate(inputs, 1, 160, 1, 1)
    folder = inputs / "package-000"
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    source = next(s for s in manifest["sources"] if "prowler" in (s["path"] or ""))
    file = folder / source["path"]
    events = json.loads(file.read_text())
    events[-1]["cloud"]["provider"] = "unsupported"
    file.write_text(json.dumps(events))
    source["sha256"] = sha256_file(file)
    manifest_path.write_text(json.dumps(manifest))
    with Store(tmp_path / "work") as store:
        with pytest.raises(InputError, match="UNSUPPORTED_PROWLER_PROVIDER"):
            import_package(store, folder)
        for table in ("runs", "sources", "observations", "evidence_refs"):
            assert store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_scale_security_assertions_check_missing_evidence_and_actual_deny(tmp_path):
    from offline_analyzer.rules.engine import assess
    from tools.scale_security_check import check

    inputs = tmp_path / "synthetic"
    generate(inputs, 1, 5, 1, 1)
    with Store(tmp_path / "work") as store:
        run = import_package(store, inputs / "package-000")
        assess(store, run)
    result = check(tmp_path / "work")
    assert result["checks"]["missing_metadata_unknown"] == 1
    assert result["checks"]["native_rds_fail_scanner_contradiction"] == 1
    assert result["checks"]["applicable_explicit_deny_checked"] == 1


def test_lifecycle_log_contains_only_fixed_events_and_is_bounded(tmp_path):
    launcher.lifecycle_log(tmp_path, "STARTED")
    launcher.lifecycle_log(tmp_path, "STOPPED")
    lines = (tmp_path / "application.log").read_text().splitlines()
    assert [line.split()[-1] for line in lines] == ["STARTED", "STOPPED"]
    with pytest.raises(ValueError):
        launcher.lifecycle_log(tmp_path, "customer path or token")
    (tmp_path / "application.log").write_bytes(b"x" * (256 * 1024 + 1))
    launcher.lifecycle_log(tmp_path, "STARTUP_FAILED")
    assert (tmp_path / "application.log").stat().st_size == 256 * 1024 + 1


def test_bundled_public_schemas_match_current_contracts(tmp_path, monkeypatch):
    from offline_analyzer.contracts import schema

    generated = tmp_path / "schemas"
    monkeypatch.setattr(sys, "argv", ["schema", str(generated)])
    schema.main()
    bundled = Path("src/offline_analyzer/contracts/schemas")
    assert {p.name for p in bundled.glob("*.json")} == {p.name for p in generated.glob("*.json")}
    for path in generated.glob("*.json"):
        assert json.loads(path.read_text()) == json.loads((bundled / path.name).read_text())


def test_source_control_timeout_leaves_runtime_metadata_unknown(monkeypatch):
    import subprocess

    from offline_analyzer.api.runtime import RuntimeIdentity

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("git", 3)

    monkeypatch.setattr(subprocess, "run", timeout)
    identity = RuntimeIdentity()
    status = identity.status()
    assert status["working_tree_modified"] is None
    assert status["compatible"] is True
