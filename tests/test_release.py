"""Release safeguards: environment separation, backup/restore, crash recovery, audit."""

import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import duckdb
import pytest
from fastapi.testclient import TestClient

from offline_analyzer.api.app import create_app
from offline_analyzer.cli import main
from offline_analyzer.findings.generate import record_decision, validation_status
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import (
    record_run_origin,
    run_origins,
    set_environment,
    workspace_environment,
)
from offline_analyzer.launcher import WorkspaceLock
from offline_analyzer.release_audit import audit
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.backup import backup, restore
from offline_analyzer.storage.store import Store
from tests.test_api import ORIGIN, TOKEN, authenticated, await_job, upload_package
from tools.fixtures.r12_demo import build


def cli(workspace, *args):
    return main(["--workspace", str(workspace), *map(str, args)])


@pytest.fixture
def package(tmp_path):
    build(tmp_path / "package")
    return tmp_path / "package"


def test_environment_label_is_immutable_and_enforced(tmp_path, package, capsys):
    work = tmp_path / "synthetic"
    assert cli(work, "environment", "set", "--label", "synthetic", "--name", "training") == 0
    assert cli(work, "environment", "set", "--label", "assessment") == 1
    assert "WORKSPACE_ENVIRONMENT_IMMUTABLE" in capsys.readouterr().err
    assert cli(work, "import", package, "--origin", "tool-generated") == 1
    assert "SYNTHETIC_WORKSPACE_REJECTS_TOOL_GENERATED" in capsys.readouterr().err
    assert cli(work, "import", package) == 0  # defaults to synthetic in a synthetic workspace
    run = capsys.readouterr().out.strip()
    assert run_origins(work)[run] == "synthetic"
    assert cli(work, "assess", "--run", run) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["workspace_environment"] == "SYNTHETIC"
    assert summary["dataset_origin"] == "SYNTHETIC"
    assert summary["customer_findings_eligible"] is False

    pilot = tmp_path / "pilot"
    set_environment(pilot, "ASSESSMENT", "pilot")
    assert cli(pilot, "import", package) == 1
    assert "ORIGIN_REQUIRED_FOR_ASSESSMENT_WORKSPACE" in capsys.readouterr().err
    assert cli(pilot, "import", package, "--origin", "synthetic") == 1
    assert "ASSESSMENT_WORKSPACE_REJECTS_SYNTHETIC" in capsys.readouterr().err
    assert cli(pilot, "import", package, "--origin", "tool-generated") == 0
    pilot_run = capsys.readouterr().out.strip()
    assert cli(pilot, "summary", "--run", pilot_run) == 0
    labels = json.loads(capsys.readouterr().out)
    assert labels["customer_findings_eligible"] is True  # labels only; not real-export proof


def test_run_origin_cannot_change_and_mixed_enterprise_is_refused(tmp_path):
    record_run_origin(tmp_path, "run-a", "synthetic")
    record_run_origin(tmp_path, "run-a", "synthetic")
    with pytest.raises(InputError, match="RUN_ORIGIN_CONFLICT"):
        record_run_origin(tmp_path, "run-a", "tool-generated")
    from offline_analyzer.inventory.environment import enterprise_origin

    set_environment(tmp_path / "w", "ASSESSMENT")
    with Store(tmp_path / "w") as store:
        for run in ("run-x", "run-y"):
            store.db.execute("INSERT INTO runs VALUES (?, '2026-10-10', '{}')", [run])
        record_run_origin(store.workspace, "run-x", "tool-generated")
        record_run_origin(store.workspace, "run-y", "synthetic")
        with pytest.raises(InputError, match="ENTERPRISE_MEMBERS_MUST_BE_TOOL_GENERATED"):
            enterprise_origin(store, ["run-x", "run-y"])
        assert enterprise_origin(store, ["run-x"]) == "tool-generated"


def test_api_environment_origin_and_compatibility_report(tmp_path, package):
    work = tmp_path / "pilot"
    set_environment(work, "ASSESSMENT", "pilot-1")
    app = create_app(work, origin=ORIGIN, bootstrap=TOKEN)
    with TestClient(app, base_url=ORIGIN) as client:
        headers = authenticated(client)
        environment = client.get("/api/environment").json()
        # Workspace identity scopes saved browser selections (added with commit 8fa3045).
        assert len(environment.pop("workspace_id")) == 64
        assert environment == {
            "label": "ASSESSMENT",
            "name": "pilot-1",
            "customer_reporting_approved": True,
        }
        rejected = upload_package(client, headers, package)  # declares synthetic
        from offline_analyzer.ingestion.errors import explanation

        assert rejected.json() == explanation("ASSESSMENT_WORKSPACE_REJECTS_SYNTHETIC")
        names = sorted(p.name for p in package.iterdir())
        files = [("files", (n, (package / n).read_bytes(), "application/json")) for n in names]
        preview = client.post(
            "/api/uploads",
            headers=headers,
            files=files,
            data={"paths": json.dumps(names), "context": '{"origin":"tool-generated"}'},
        )
        body = preview.json()
        assert body["diagnostics"]["declared_origin"] == "tool-generated"
        report = client.get(f"/api/reports/{body['compatibility_report']}/download")
        assert report.status_code == 200
        summary = report.json()
        assert summary["raw_values_included"] is False
        text = report.text
        for private in ("111111111111", "t-admin-target", "o-golden00001"):
            assert private not in text  # sanitized: counts and field names only
        kinds = {r["kind"] for r in client.get("/api/reports").json()}
        assert "compatibility" in kinds
        run = await_job(
            client,
            client.post("/api/import", headers=headers, json={"upload_id": body["upload_id"]}),
        )["run_id"]
        runs = {r["run_id"]: r["origin"] for r in client.get("/api/runs").json()}
        assert runs[run] == "tool-generated"


def populated(tmp_path, package):
    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC", "backup-test")
    with Store(work) as store:
        run = import_package(store, package)
        record_run_origin(work, run, "synthetic")
        assess(store, run)
        finding = next(store.candidates(run))
        record_decision(store, run, finding.finding_id, "NEEDS_VALIDATION", "analyst", "check")
    return work, run, finding


def test_backup_restore_round_trip_preserves_decisions(tmp_path, package, capsys):
    work, run, finding = populated(tmp_path, package)
    assert cli(work, "backup", "--output", tmp_path / "backup") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["runs"] == 1 and result["files"] > 3
    assert cli(tmp_path / "restored", "restore", "--from", tmp_path / "backup") == 0
    with Store(tmp_path / "restored") as store:
        restored = next(c for c in store.candidates(run) if c.finding_id == finding.finding_id)
        assert validation_status(store, restored)[0] == "NEEDS_VALIDATION"
        assert len(list(store.results(run))) > 0
    assert workspace_environment(tmp_path / "restored").label == "SYNTHETIC"
    assert run_origins(tmp_path / "restored")[run] == "synthetic"
    assert cli(tmp_path / "restored", "restore", "--from", tmp_path / "backup") == 1
    assert "RESTORE_TARGET_NOT_EMPTY" in capsys.readouterr().err


def test_backup_refuses_running_gui_and_restore_detects_tampering(tmp_path, package):
    work, _, _ = populated(tmp_path, package)
    lock = WorkspaceLock(work)
    try:
        with pytest.raises(InputError, match="WORKSPACE_IN_USE_STOP_APPLICATION_FIRST"):
            backup(work, tmp_path / "while-running")
    finally:
        lock.close()
    backup(work, tmp_path / "backup")
    raw = next((tmp_path / "backup" / "raw").iterdir())
    raw.write_bytes(raw.read_bytes() + b" ")
    with pytest.raises(InputError, match="BACKUP_INTEGRITY_FAILURE"):
        restore(tmp_path / "backup", tmp_path / "t1")
    backup(work, tmp_path / "backup2")
    (tmp_path / "backup2" / "raw" / "unexpected.json").write_text("{}")
    with pytest.raises(InputError, match="BACKUP_CONTENT_MISMATCH"):
        restore(tmp_path / "backup2", tmp_path / "t2")
    backup(work, tmp_path / "backup3")
    (tmp_path / "backup3" / "raw" / "link.json").symlink_to(
        tmp_path / "backup3" / "backup-manifest.json"
    )
    with pytest.raises(InputError, match="SYMLINK_IN_BACKUP"):
        restore(tmp_path / "backup3", tmp_path / "t3")
    assert not (tmp_path / "t1").exists() and not (tmp_path / "t2").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal-based kill")
def test_database_recovers_after_writer_is_killed_mid_import(tmp_path, package):
    """A hard-killed importer leaves no partial run; the next open recovers and reimports."""
    work = tmp_path / "work"
    marker = tmp_path / "inside-transaction"
    script = textwrap.dedent(f"""
        import time
        from pathlib import Path
        from offline_analyzer.storage.store import Store
        from offline_analyzer.ingestion.importer import import_package
        original = Store.put_observations
        def slow(self, run_id, batch):
            original(self, run_id, batch)  # rows written inside the open transaction
            Path({str(marker)!r}).write_text("x")
            time.sleep(60)
        Store.put_observations = slow
        with Store(Path({str(work)!r})) as store:
            import_package(store, Path({str(package)!r}))
    """)
    process = subprocess.Popen(
        [sys.executable, "-c", script], env={**os.environ, "PYTHONPATH": "src"}
    )
    for _ in range(600):
        if marker.exists():
            break
        time.sleep(0.05)
    assert marker.exists(), "child never reached the import transaction"
    os.kill(process.pid, signal.SIGKILL)
    process.wait()
    with Store(work) as store:
        assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
        assert store.db.execute("SELECT count(*) FROM observations").fetchone()[0] == 0
        run = import_package(store, package)
        assess(store, run)
        assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 1


def test_release_audit_passes_and_detects_injected_violations(tmp_path, package):
    from offline_analyzer.enterprise.snapshot import assess_enterprise

    work, run, _ = populated(tmp_path, package)
    with Store(work) as store:
        enterprise = assess_enterprise(store, [run])
    report = audit(work, enterprise)
    assert report["result"] == "PASS" and report["invariant_violations"] == 0
    assert report["workspace_environment"] == "SYNTHETIC"
    relationships = report["relationships"]
    assert (
        relationships["total"]
        == relationships["structural_configuration_references"]
        + relationships["authorization_or_exposure_relationships"]
    )
    assert report["findings"]["candidates"] > 0
    assert "111111111111" not in json.dumps(report)
    db = duckdb.connect(str(work / "assessment.duckdb"))
    edge = db.execute(
        "SELECT relationship_id, data FROM enterprise_edges WHERE run_id=? LIMIT 1", [enterprise]
    ).fetchone()
    data = json.loads(edge[1])
    data.update(status="DERIVED_SUPPORTED", missing=["synthetic missing dependency"])
    db.execute(
        "UPDATE enterprise_edges SET status='DERIVED_SUPPORTED', data=? WHERE relationship_id=?",
        [json.dumps(data), edge[0]],
    )
    finding = db.execute(
        "SELECT finding_id, data FROM findings WHERE run_id=? LIMIT 1", [enterprise]
    ).fetchone()
    tampered = json.loads(finding[1])
    tampered.update(suggested_severity="CRITICAL", finding_class="BASELINE_DEVIATION")
    db.execute(
        "UPDATE findings SET data=? WHERE finding_id=? AND run_id=?",
        [json.dumps(tampered), finding[0], enterprise],
    )
    db.close()
    broken = audit(work, enterprise)
    assert broken["result"] == "FAIL"
    assert broken["relationships"]["violations"]["supported_with_missing_dependencies"] == 1
    assert broken["findings"]["violations"]["critical_without_supported_gap"] == 1


def test_dashboard_flags_stale_accounts_and_separates_structural_references(tmp_path):
    from datetime import UTC, datetime

    from offline_analyzer.contracts.r0 import Package
    from offline_analyzer.enterprise.queries import EnterpriseViews
    from offline_analyzer.enterprise.snapshot import assess_enterprise
    from tools.fixtures.r11_demo import build as build_r11

    build_r11(tmp_path / "current")
    build(tmp_path / "old")  # r12: accounts 555... and 999... appear only here
    manifest = tmp_path / "old" / "manifest.json"
    package = Package.model_validate_json(manifest.read_bytes())
    aged = package.model_copy(
        update={
            "sources": tuple(
                s.model_copy(update={"collected_at": datetime(2026, 9, 20, tzinfo=UTC)})
                for s in package.sources
            )
        }
    )
    manifest.write_text(aged.model_dump_json())
    with Store(tmp_path / "work") as store:
        old = import_package(store, tmp_path / "old")
        current = import_package(store, tmp_path / "current")
        run = assess_enterprise(store, [old, current])
        dashboard = EnterpriseViews().dashboard(store, run)
    window = dashboard["collection_window"]
    assert window["stale_after_days"] == 7 and window["spread_hours"] > 24 * 7
    assert {"555555555555", "999999999999"} <= set(window["stale_accounts"])
    assert "222222222222" not in window["stale_accounts"]  # also collected currently
    categories = dashboard["relationship_categories"]
    assert sum(categories.values()) == dashboard["relationships"]
