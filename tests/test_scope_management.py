"""Synthetic scoped lifecycle, failure safety and no unrelated-data deletion."""

import json
from pathlib import Path

import pytest

from offline_analyzer.assessment import manage
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import record_run_origin, set_environment
from offline_analyzer.reporting.cloud import dashboard
from offline_analyzer.rules.engine import assess, verify_raw
from offline_analyzer.storage.backup import backup, restore
from offline_analyzer.storage.store import Store
from tools.fixtures.r12_demo import build as aws_build
from tools.gcp_fixture import build as gcp_build


@pytest.fixture
def mixed(tmp_path):
    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        aws_build(tmp_path / "aws")
        aws = import_package(store, tmp_path / "aws")
        record_run_origin(work, aws, "synthetic")
        assess(store, aws)
        projects = []
        for project, number in [("demo-alpha", "123456789012"), ("demo-beta", "222222222222")]:
            root = gcp_build(tmp_path / project, project, number)
            run = import_package(store, root)
            record_run_origin(work, run, "synthetic")
            assess(store, run)
            projects.append(run)
        run = assess_enterprise(store, [aws, *projects])
        record_run_origin(work, run, "synthetic")
    return work, run


@pytest.mark.parametrize("provider,scope", [("AWS", "111111111111"), ("GCP", "demo-alpha")])
def test_exact_scope_delete_reassess_reopen_and_reimport(mixed, tmp_path, provider, scope):
    work, run = mixed
    with Store(work) as store:
        old = {(s["provider"], s["scope_id"]): s["resources"] for s in manage.scopes(store)}
        preview = manage.plan(store, provider, scope)
        assert preview["snapshots"] >= 2 and preview["resources"] > 0
        assert not preview["shared_raw_blocked"]
        result = manage.delete_scope(store, provider, scope, preview["preview_token"], scope, True)
        remaining = {(s["provider"], s["scope_id"]): s["resources"] for s in manage.scopes(store)}
        assert (provider, scope) not in remaining
        for key, value in remaining.items():
            assert value == old[key]
        assert not (work / ".scope-journal.json").exists()
        for (r,) in store.rows("SELECT run_id FROM runs"):
            verify_raw(store, r)
        assert dashboard(store, result["run_id"])
        assert not store.db.execute(
            f"SELECT 1 FROM observations WHERE {manage.observation_predicate(provider)}", [scope]
        ).fetchone()
    with Store(work) as store:
        if provider == "GCP":
            root = gcp_build(tmp_path / "reimport", scope, "123456789012")
        else:
            root = tmp_path / "aws"
        again = import_package(store, root)
        record_run_origin(work, again, "synthetic")
        assess(store, again)
        assert (provider, scope) in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}
    saved = tmp_path / "backup"
    backup(work, saved)
    restored = tmp_path / "restored"
    restore(saved, restored)
    with Store(restored) as store:
        assert store.db.execute("SELECT count(*) FROM scope_audit").fetchone()[0] == 1


@pytest.mark.parametrize(
    "confirmation,confirmed",
    [
        ("", True),
        ("demo-alph", True),
        ("DEMO-ALPHA", True),
        ("demo-beta", True),
        ("demo-alpha", False),
        ("111111111111", True),
    ],
)
def test_confirmation_never_approximates(mixed, confirmation, confirmed):
    work, _ = mixed
    with Store(work) as store:
        preview = manage.plan(store, "GCP", "demo-alpha")
        with pytest.raises(InputError, match="SCOPE_CONFIRMATION_REQUIRED"):
            manage.delete_scope(
                store, "GCP", "demo-alpha", preview["preview_token"], confirmation, confirmed
            )
        assert any(s["scope_id"] == "demo-alpha" for s in manage.scopes(store))


def test_stale_preview_refused(mixed):
    work, _ = mixed
    with Store(work) as store:
        p = manage.plan(store, "GCP", "demo-alpha")
        with pytest.raises(InputError, match="SCOPE_PREVIEW_STALE"):
            manage.delete_scope(
                store, "GCP", "demo-alpha", p["preview_token"] + "x", "demo-alpha", True
            )


def test_replacement_keeps_history_and_excludes_old_project_from_active_snapshot(mixed, tmp_path):
    work, old = mixed
    root = gcp_build(tmp_path / "new", "demo-alpha", "123456789012")
    # A timestamp refresh produces a new immutable import even with unchanged configuration.
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text())
    data["assessment_id"] = "refresh"
    manifest.write_text(json.dumps(data))
    with Store(work) as store:
        before = list(store.db.execute("SELECT run_id FROM runs").fetchall())
        result = manage.replace_scope(store, "GCP", "demo-alpha", root, "synthetic")
        assert result["run_id"] != old
        assert all(
            store.db.execute("SELECT 1 FROM runs WHERE run_id=?", [r]).fetchone() for (r,) in before
        )
        assert store.db.execute("SELECT count(*) FROM scope_retired_runs").fetchone()[0] >= 1
        metrics = dashboard(store, result["run_id"])
        assert metrics["providers"]["GCP"]["imported_scopes"] == ["demo-alpha", "demo-beta"]
        assert metrics["providers"]["AWS"]["imported_scope_count"] == 5


def test_failed_replacement_never_activates(mixed, tmp_path, monkeypatch):
    work, old = mixed
    root = gcp_build(tmp_path / "new", "demo-alpha", "123456789012")
    with Store(work) as store:
        before = list(
            store.db.execute("SELECT run_id,package FROM runs ORDER BY run_id").fetchall()
        )
        monkeypatch.setattr(
            manage, "assess", lambda *a: (_ for _ in ()).throw(InputError("SYNTHETIC_FAILURE"))
        )
        with pytest.raises(InputError, match="SYNTHETIC_FAILURE"):
            manage.replace_scope(store, "GCP", "demo-alpha", root, "synthetic")
        assert (
            list(store.db.execute("SELECT run_id,package FROM runs ORDER BY run_id").fetchall())
            == before
        )
        assert not (work / ".scope-journal.json").exists()


def test_replacement_scope_and_environment_refused(mixed, tmp_path):
    work, _ = mixed
    root = gcp_build(tmp_path / "other", "demo-beta", "222222222222")
    with Store(work) as store:
        with pytest.raises(InputError, match="REPLACEMENT_SCOPE_MISMATCH"):
            manage.replace_scope(store, "GCP", "demo-alpha", root, "synthetic")
        with pytest.raises(InputError, match="SYNTHETIC_WORKSPACE_REJECTS"):
            manage.replace_scope(store, "GCP", "demo-alpha", root, "tool-generated")


def test_database_swap_crash_is_recovered_before_read(mixed, monkeypatch):
    work, _ = mixed
    real = manage.recover_locked
    with Store(work) as store:
        p = manage.plan(store, "GCP", "demo-alpha")
        monkeypatch.setattr(
            manage, "recover_locked", lambda *a: (_ for _ in ()).throw(InputError("INTERRUPTED"))
        )
        with pytest.raises(InputError, match="INTERRUPTED"):
            manage.delete_scope(store, "GCP", "demo-alpha", p["preview_token"], "demo-alpha", True)
        assert (work / ".scope-journal.json").exists()
    monkeypatch.setattr(manage, "recover_locked", real)
    with Store(work) as store:
        assert not any(s["scope_id"] == "demo-alpha" for s in manage.scopes(store))
        assert not (work / ".scope-journal.json").exists()


def test_deletion_checkpoint_rolls_back_before_new_database_install(mixed, monkeypatch):
    work, _ = mixed
    original = Path.rename

    def fail_install(path, destination):
        if path.name == "assessment.duckdb" and path.parent.name == "compact":
            raise OSError("synthetic interruption")
        return original(path, destination)

    with Store(work) as store:
        p = manage.plan(store, "GCP", "demo-alpha")
        monkeypatch.setattr(Path, "rename", fail_install)
        with pytest.raises(OSError):
            manage.delete_scope(store, "GCP", "demo-alpha", p["preview_token"], "demo-alpha", True)
        assert any(s["scope_id"] == "demo-alpha" for s in manage.scopes(store))


def test_report_revisions_and_cross_scope_paths_are_invalidated(mixed):
    from offline_analyzer.contracts.report_finding import ReportApproval, ReportEdit
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.findings.report_ready import (
        approve_revision,
        approved_revisions,
        report_detail,
        save_revision,
        sections_for,
    )
    from offline_analyzer.findings.sre import record_sre
    from offline_analyzer.inventory.cloud import relationships
    from offline_analyzer.release_audit import audit

    work, run = mixed
    reviewed = {}
    with Store(work) as store:
        for project in ("demo-alpha", "demo-beta"):
            finding = next(
                f for f in store.candidates(run) if f.provider == "GCP" and f.project_id == project
            )
            reviewed[project] = finding.finding_id
            record_sre(store, run, [finding.finding_id], "GAP_CONFIRMED", "synthetic-reviewer")
            record_decision(
                store,
                run,
                finding.finding_id,
                "CONFIRMED",
                "synthetic-reviewer",
                "Synthetic evidence reviewed",
            )
            revision = save_revision(
                store,
                run,
                finding.finding_id,
                ReportEdit(
                    expected_revision=0,
                    member_ids=[finding.finding_id],
                    sections=sections_for(finding),
                    include_in_report=True,
                    analyst="synthetic-reviewer",
                ),
            )
            for kind in ("RECOMMENDATION", "NARRATIVE"):
                revision = approve_revision(
                    store,
                    run,
                    finding.finding_id,
                    ReportApproval(
                        expected_revision=revision.revision, kind=kind, analyst="synthetic-reviewer"
                    ),
                )
        assert len(approved_revisions(store, run)) == 2
        beta = finding.finding_id
        preview = manage.plan(store, "GCP", "demo-alpha")
        deleted = manage.delete_scope(
            store, "GCP", "demo-alpha", preview["preview_token"], "demo-alpha", True
        )
        new = deleted["run_id"]
        # SRE verdicts follow analyst decisions: purged with the deleted scope only.
        remaining = {fid for (fid,) in store.rows("SELECT finding_id FROM sre_validations")}
        assert remaining == {reviewed["demo-beta"]}
        assert approved_revisions(store, new) == []
        assert report_detail(store, new, beta)["evidence_state"] == "NEEDS_REVIEW"
        assert all(e["project_id"] != "demo-alpha" for e in relationships(store, new)["items"])
        assert not store.db.execute(
            "SELECT 1 FROM evidence_refs r LEFT JOIN observations o USING(run_id,observation_id) "
            "WHERE o.observation_id IS NULL"
        ).fetchone()
        assert not store.db.execute(
            "SELECT 1 FROM evidence_refs r LEFT JOIN artifacts a USING(run_id,artifact_id) "
            "WHERE a.artifact_id IS NULL"
        ).fetchone()
    assert audit(work)["result"] == "PASS"


def test_shared_raw_configuration_blocks_deletion(tmp_path):
    from offline_analyzer.ingestion.safety import sha256_file
    from tools.fixtures.demo import build_package

    root = tmp_path / "aws"
    build_package(root)
    # One source deliberately contains two owned account configurations.
    path = root / "rds-111111111111.json"
    payload = json.loads(path.read_text())
    payload["DBInstances"].append(
        {
            "DBInstanceArn": "arn:aws:rds:us-east-1:222222222222:db:shared",
            "DBInstanceIdentifier": "shared",
            "StorageEncrypted": True,
            "Engine": "postgres",
        }
    )
    path.write_text(json.dumps(payload))
    meta = json.loads((root / "manifest.json").read_text())
    for source in meta["sources"]:
        if source["path"] == path.name:
            source["sha256"] = sha256_file(path)
    (root / "manifest.json").write_text(json.dumps(meta))
    with Store(tmp_path / "work") as store:
        run = import_package(store, root)
        assess(store, run)
        preview = manage.plan(store, "AWS", "111111111111")
        assert preview["shared_raw_blocked"]
        with pytest.raises(InputError, match="SHARED_RAW_SCOPE_DELETION_UNSUPPORTED"):
            manage.delete_scope(
                store, "AWS", "111111111111", preview["preview_token"], "111111111111", True
            )
        assert len(list(store.candidates(run))) > 0


def test_interrupted_replacement_discards_only_new_raw(mixed, tmp_path, monkeypatch):
    from offline_analyzer.ingestion.safety import sha256_file

    work, _ = mixed
    root = gcp_build(tmp_path / "refresh", "demo-alpha", "123456789012")
    path = root / "source-001.json"
    # Refresh fixture metadata without adding actual credentials.
    data = json.loads(path.read_text())
    data[0]["displayName"] = "Synthetic refresh"
    path.write_text(json.dumps(data))
    manifest = root / "manifest.json"
    meta = json.loads(manifest.read_text())
    for dataset in meta["datasets"]:
        if dataset["path"] == path.name:
            dataset["sha256"] = sha256_file(path)
    manifest.write_text(json.dumps(meta))
    new_hash = sha256_file(path)
    with Store(work) as store:
        old_files = {p.name for p in (work / "raw").iterdir()}
        monkeypatch.setattr(
            manage, "assess", lambda *a: (_ for _ in ()).throw(InputError("STOPPED"))
        )
        with pytest.raises(InputError, match="STOPPED"):
            manage.replace_scope(store, "GCP", "demo-alpha", root, "synthetic")
        assert (work / "raw" / (new_hash + ".json")).is_file()
    with Store(work) as store:
        assert {p.name for p in (work / "raw").iterdir()} == old_files
        assert any(s["scope_id"] == "demo-alpha" for s in manage.scopes(store))


def test_aws_replacement_preserves_other_scopes(mixed, tmp_path):
    work, old = mixed
    root = tmp_path / "aws-refresh"
    aws_build(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text())
    scope = "111111111111"
    data["sources"] = [s for s in data["sources"] if s["account_id"] == scope]
    data["targets"] = [t for t in data["targets"] if t["account_id"] == scope]
    data["sources"][0]["collected_at"] = "2026-10-12T12:00:00Z"
    manifest.write_text(json.dumps(data))
    with Store(work) as store:
        result = manage.replace_scope(store, "AWS", scope, root, "synthetic")
        assert result["run_id"] != old
        metrics = dashboard(store, result["run_id"])
        assert metrics["providers"]["AWS"]["imported_scope_count"] == 5
        assert metrics["providers"]["GCP"]["imported_scope_count"] == 2
        members = json.loads(
            store.db.execute(
                "SELECT members FROM enterprise_snapshots WHERE run_id=?", [result["run_id"]]
            ).fetchone()[0]
        )
        owners = [
            s["account_id"]
            for member in members
            for s in store.source_data(member)
            if s.get("account_id") == scope
        ]
        assert owners and len(owners) == len(data["sources"])


def test_unparsed_collector_raw_bytes_are_in_deletion_plan(tmp_path):
    from offline_analyzer.ingestion import collector
    from tools.collector_fixture import convert

    source = tmp_path / "source"
    aws_build(source)
    package = convert(source, tmp_path / "collector")[0]
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        summary = collector.stored_summary(store.workspace, run)
        scope = summary["account_id"]
        unsupported = next(r for r in summary["operations"] if r["import_handling"] != "IMPORTED")
        raw = "raw/" + unsupported["artifact_sha256"] + ".json"
        assert (store.workspace / raw).is_file()
        preview = manage.plan(store, "AWS", scope)
        assert raw in preview["files"]
        manage.delete_scope(store, "AWS", scope, preview["preview_token"], scope, True)
        assert not (store.workspace / raw).exists()
        assert not manage.scopes(store)


def test_gcp_deletion_preview_counts_dynamic_paths_and_edges(mixed):
    work, _ = mixed
    with Store(work) as store:
        selected = next(s for s in manage.scopes(store) if s["scope_id"] == "demo-alpha")
        assert selected["investigations"] > 0
        preview = manage.plan(store, "GCP", "demo-alpha")
        assert preview["relationship_edges"] > 0
        assert preview["investigations"] == selected["investigations"]
        assert preview["relationship_edges_truncated"] is False
