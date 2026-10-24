"""Full backend purge of one account/project on a synthetic multi-account workspace."""

import json
from pathlib import Path

import pytest

from offline_analyzer.assessment import manage
from offline_analyzer.assessment.purge_verify import EVIDENCE_TABLES, scan
from offline_analyzer.contracts.exclusion import ExclusionRequest
from offline_analyzer.contracts.report_finding import ReportEdit
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.enterprise.validation import validate_snapshot
from offline_analyzer.findings.exclusions import excluded, record
from offline_analyzer.findings.finalisation import freeze
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.findings.report_ready import report_detail, save_revision, sections_for
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.labels import scope_names
from offline_analyzer.inventory.environment import record_run_origin, set_environment
from offline_analyzer.rules.engine import assess, verify_raw
from offline_analyzer.storage.backup import restore
from offline_analyzer.storage.store import Store
from tools.fixtures.r12_demo import build as aws_build
from tools.gcp_fixture import build as gcp_build

ANALYST = "Synthetic analyst"
TARGET = ("GCP", "demo-alpha")


@pytest.fixture
def estate(tmp_path):
    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        aws_build(tmp_path / "aws")
        members = [import_package(store, tmp_path / "aws")]
        for project, number in [("demo-alpha", "123456789012"), ("demo-beta", "222222222222")]:
            members.append(import_package(store, gcp_build(tmp_path / project, project, number)))
        for run in members:
            record_run_origin(work, run, "synthetic")
            assess(store, run)
        run = assess_enterprise(store, members)
        record_run_origin(work, run, "synthetic")
    return work, run


def snapshot_of_others(store) -> dict:
    """Everything that belongs to scopes other than the target, independent of run IDs."""
    others = {}
    for s in manage.scopes(store):
        key = (s["provider"], s["scope_id"])
        if key != TARGET:
            others[key] = (s["resources"], s["findings"], s["datasets"])
    findings = {
        fid
        for fid, raw in store.rows("SELECT finding_id,data FROM findings")
        if manage.source_finding_scope(json.loads(raw)) != TARGET
    }
    raw = sorted(p.name for p in (store.workspace / "raw").iterdir())
    return {"scopes": others, "findings": findings, "raw": raw}


def owned(store, run, scope):
    return next(f for f in store.candidates(run) if f.provider == "GCP" and f.project_id == scope)


def test_purge_removes_scope_everywhere_and_leaves_other_scopes_untouched(estate, tmp_path):
    work, run = estate
    job = work / "jobs" / ("a" * 32 + ".json")
    job.parent.mkdir(exist_ok=True)
    job.write_text(json.dumps({"result": {"sources": [{"project_id": "demo-alpha"}]}}))
    unrelated_job = work / "jobs" / ("b" * 32 + ".json")
    unrelated_job.write_text(json.dumps({"result": {"project_id": "demo-alpha-2"}}))
    with Store(work) as store:
        alpha, beta = owned(store, run, "demo-alpha"), owned(store, run, "demo-beta")
        for f in (alpha, beta):
            record_decision(store, run, f.finding_id, "CONFIRMED", ANALYST, "Synthetic")
            record(
                store,
                run,
                f.finding_id,
                ExclusionRequest(action="EXCLUDE", reason="DUPLICATE", analyst=ANALYST),
            )
        record(store, run, beta.finding_id, ExclusionRequest(action="RESTORE", analyst=ANALYST))
        # A consolidated draft covering both projects, owned by the retained project.
        save_revision(
            store,
            run,
            beta.finding_id,
            ReportEdit(
                expected_revision=0,
                analyst=ANALYST,
                sections=sections_for(beta),
                member_ids=[alpha.finding_id, beta.finding_id],
                consolidation_basis="Synthetic consolidation across two projects",
            ),
        )
        before = snapshot_of_others(store)
        beta_decisions = store.db.execute(
            "SELECT count(*) FROM decisions WHERE finding_id=?", [beta.finding_id]
        ).fetchone()[0]
        # The scan detects references before the purge, in the database and in files.
        found = scan(store, "GCP", ["demo-alpha"])
        assert found["database"]["observations"] > 0 and found["files"]["raw"] > 0
        assert found["files"]["database file"] >= 1 and found["files"]["jobs"] == 1
        preview = manage.plan(store, *TARGET)
        assert preview["removed"]["findings"] > 0 and preview["removed"]["exclusions"] == 1
        assert preview["removed"]["job_records"] == 1 and preview["removed"]["scope_labels"] >= 0
        assert preview["retained_affected"]["consolidated_drafts_other_scopes"] == 1
        assert preview["retained_affected"]["snapshots_rebuilt_with_other_scopes"] >= 1
        assert preview["retained_affected"]["frozen_editions_unchanged"] == 0
        assert not preview["frozen_decision_required"]
        result = manage.delete_scope(store, *TARGET, preview["preview_token"], TARGET[1], True)

        # Nothing that names the target remains anywhere in the backend.
        verification = result["verification"]
        assert verification["status"] == "CLEAN" and verification["references"] == 0
        assert verification["references_removed"]["total"] > 0
        assert verification["references_removed"]["database_rows"]["observations"] > 0
        assert verification["references_removed"]["files"]["raw"] > 0
        for group in ("cross_account_evidence_retained", "other_retained"):
            assert verification[group]["total"] == 0
        assert verification["analyst_drafts_mentioning"] == {"drafts": [], "revisions": 0}
        assert verification["superseded_frozen_editions_retained"] == 0
        assert verification["identifiers_checked"] == 2 and not verification["wal_present"]
        assert "demo-alpha" not in json.dumps(result)
        assert not job.exists() and unrelated_job.exists()
        assert result["removed_job_records"] == ["a" * 32]
        # Other accounts/projects are untouched.
        after = snapshot_of_others(store)
        assert after["scopes"] == before["scopes"]
        assert after["findings"] == before["findings"]
        assert set(after["raw"]) < set(before["raw"])
        assert (
            store.db.execute(
                "SELECT count(*) FROM decisions WHERE finding_id=?", [beta.finding_id]
            ).fetchone()[0]
            == beta_decisions
        )
        assert alpha.finding_id not in excluded(store)
        assert ("GCP", "demo-alpha") not in scope_names(store)
        # The consolidated draft is kept without the purged project and must be reviewed.
        new = result["run_id"]
        draft = report_detail(store, new, beta.finding_id)
        assert [s["finding_id"] for s in draft["revision"]["snapshots"]] == [beta.finding_id]
        assert draft["evidence_state"] == "NEEDS_REVIEW"
        # Consolidated validation (A2) still reconciles on the rebuilt snapshot.
        assert validate_snapshot(store, new)["status"] == "PASS"
        for (r,) in store.rows("SELECT run_id FROM runs"):
            verify_raw(store, r)
    # The automatic pre-purge backup restores the full prior workspace.
    saved = Path(result["backup"]["path"])
    assert saved.parent == work.parent / "work-backups" and not saved.is_relative_to(work)
    restored = tmp_path / "restored"
    restore(saved, restored)
    with Store(restored) as store:
        assert TARGET in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}


def test_backup_is_skipped_only_when_explicitly_declined(estate):
    work, _ = estate
    with Store(work) as store:
        preview = manage.plan(store, *TARGET)
        result = manage.delete_scope(
            store, *TARGET, preview["preview_token"], TARGET[1], True, backup=False
        )
        assert result["backup"] is None and result["verification"]["clean"]
    assert not (work.parent / "work-backups").exists()


def test_aws_purge_reports_references_left_in_other_scopes_evidence(estate):
    work, _ = estate
    with Store(work) as store:
        account = "111111111111"
        preview = manage.plan(store, "AWS", account)
        result = manage.delete_scope(store, "AWS", account, preview["preview_token"], account, True)
        verification = result["verification"]
        # Other accounts' own evidence still names the account: reported, never "clean".
        assert verification["status"] == "RETAINED_REFERENCES" and not verification["clean"]
        retained = verification["cross_account_evidence_retained"]
        assert retained["total"] > 0 and retained["files"]["raw"] > 0
        assert set(retained["database_rows"]) <= EVIDENCE_TABLES
        assert verification["other_retained"]["total"] == 0
        assert verification["analyst_drafts_mentioning"]["revisions"] == 0
        assert verification["references_removed"]["total"] > 0
        assert not verification["wal_present"]
        assert account not in json.dumps(result)
        assert not store.db.execute(
            f"SELECT 1 FROM observations WHERE {manage.observation_predicate('AWS')}", [account]
        ).fetchone()


def test_interrupted_purge_leaves_no_partial_state(estate, monkeypatch):
    work, _ = estate
    with Store(work) as store:
        before = snapshot_of_others(store)
        scopes_before = manage.scopes(store)
        preview = manage.plan(store, *TARGET)

        def interrupted(*_args):
            raise InputError("SYNTHETIC_INTERRUPTION")

        monkeypatch.setattr(manage, "reassess_runs", interrupted)
        with pytest.raises(InputError, match="SYNTHETIC_INTERRUPTION"):
            manage.delete_scope(store, *TARGET, preview["preview_token"], TARGET[1], True)
        assert manage.scopes(store) == scopes_before
        assert snapshot_of_others(store) == before
        assert not (work / ".scope-journal.json").exists()
    # Interrupted after the journal is written: completed on the next open, never half-done.
    monkeypatch.undo()
    real = manage.recover_locked
    with Store(work) as store:
        preview = manage.plan(store, *TARGET)
        monkeypatch.setattr(
            manage, "recover_locked", lambda *a: (_ for _ in ()).throw(OSError("crash"))
        )
        with pytest.raises(OSError):
            manage.delete_scope(store, *TARGET, preview["preview_token"], TARGET[1], True)
    monkeypatch.setattr(manage, "recover_locked", real)
    with Store(work) as store:
        assert TARGET not in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}
        assert snapshot_of_others(store)["scopes"] == before["scopes"]
        assert not (work / ".scope-journal.json").exists()


def test_frozen_edition_blocks_purge_until_owner_decides(estate):
    work, run = estate
    with Store(work) as store:
        for scope in ("demo-alpha", "demo-beta"):
            f = owned(store, run, scope)
            record_decision(store, run, f.finding_id, "CONFIRMED", ANALYST, "Synthetic")
        freeze(store, run, ANALYST, True)
        frozen_before = store.db.execute("SELECT data FROM finalized_assessments").fetchall()
        preview = manage.plan(store, *TARGET)
        assert preview["frozen_decision_required"] and preview["frozen_editions"] == 1
        assert "frozen" in preview["limitations"][0]
        with pytest.raises(InputError, match="FROZEN_EDITION_DECISION_REQUIRED"):
            manage.delete_scope(store, *TARGET, preview["preview_token"], TARGET[1], True)
        assert TARGET in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}
        assert (
            store.db.execute("SELECT data FROM finalized_assessments").fetchall() == frozen_before
        )
    assert not (work.parent / "work-backups").exists()


def test_verification_lists_drafts_still_mentioning_the_identifier_without_values(estate):
    work, run = estate
    with Store(work) as store:
        alpha, beta = owned(store, run, "demo-alpha"), owned(store, run, "demo-beta")
        sections = sections_for(beta).model_copy(update={"title": "Shared gap with demo-alpha"})
        save_revision(
            store,
            run,
            beta.finding_id,
            ReportEdit(
                expected_revision=0,
                analyst=ANALYST,
                sections=sections,
                member_ids=[alpha.finding_id, beta.finding_id],
                consolidation_basis="Same configuration as in demo-alpha and demo-beta",
            ),
        )
        preview = manage.plan(store, *TARGET)
        result = manage.delete_scope(store, *TARGET, preview["preview_token"], TARGET[1], True)
        verification = result["verification"]
        assert verification["status"] == "RETAINED_REFERENCES" and not verification["clean"]
        drafts = verification["analyst_drafts_mentioning"]
        assert drafts["revisions"] == 1 and len(drafts["drafts"]) == 1
        assert drafts["drafts"][0]["draft"] == "Shared gap with [purged identifier]"
        assert verification["cross_account_evidence_retained"]["total"] == 0
        assert "demo-alpha" not in json.dumps(result)


def frozen_estate(store, run):
    for scope in ("demo-alpha", "demo-beta"):
        f = owned(store, run, scope)
        record_decision(store, run, f.finding_id, "CONFIRMED", ANALYST, "Synthetic")
    freeze(store, run, ANALYST, True)
    return store.db.execute("SELECT run_id,data FROM finalized_assessments").fetchall()


REASON = "Synthetic: project withdrawn from scope after finalisation"


def test_frozen_edition_override_keeps_edition_marks_superseded_and_needs_backup(estate, tmp_path):
    from offline_analyzer.findings.finalisation import frozen

    work, run = estate
    with Store(work) as store:
        editions = frozen_estate(store, run)
        preview = manage.plan(store, *TARGET)
        token = preview["preview_token"]
        args = (store, *TARGET, token, TARGET[1], True)
        for kwargs, code in (
            ({}, "FROZEN_EDITION_DECISION_REQUIRED"),
            (
                dict(supersede=True, supersede_confirmation="demo-beta", supersede_reason=REASON),
                "SUPERSEDE_CONFIRMATION_REQUIRED",
            ),
            (
                dict(supersede=True, supersede_confirmation=TARGET[1], supersede_reason="short"),
                "SUPERSEDE_REASON_REQUIRED",
            ),
            (
                dict(
                    supersede=True,
                    supersede_confirmation=TARGET[1],
                    supersede_reason=REASON,
                    backup=False,
                ),
                "SUPERSEDE_REQUIRES_BACKUP",
            ),
        ):
            with pytest.raises(InputError, match=code):
                manage.delete_scope(*args, **kwargs)
        assert not (work.parent / "work-backups").exists()
        assert TARGET in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}

        result = manage.delete_scope(
            *args, supersede=True, supersede_confirmation=TARGET[1], supersede_reason=REASON
        )
        assert result["superseded_editions"] == 1
        # The edition record is kept unchanged and marked superseded with time and reason.
        assert store.db.execute("SELECT run_id,data FROM finalized_assessments").fetchall() == (
            editions
        )
        mark = frozen(store, run)["superseded"]
        assert len(mark) == 1 and mark[0]["status"] == "SUPERSEDED"
        assert mark[0]["reason"] == REASON and mark[0]["superseded_at"]
        assert "demo-alpha" not in json.dumps(mark)
        # Audit entry names the scope only by digest.
        audit = store.db.execute("SELECT scope_id,action FROM scope_audit").fetchall()
        assert audit == [(manage.audit_scope(*TARGET), "DELETE_SUPERSEDE")]
        verification = result["verification"]
        assert verification["superseded_frozen_editions_retained"] == 1
        assert verification["status"] == "RETAINED_REFERENCES"
        assert TARGET not in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}
    # The pre-purge backup holds the edition exactly.
    restored = tmp_path / "restored"
    restore(Path(result["backup"]["path"]), restored)
    with Store(restored) as store:
        assert store.db.execute("SELECT run_id,data FROM finalized_assessments").fetchall() == (
            editions
        )


def test_override_refused_when_backup_does_not_hold_the_edition(estate, tmp_path, monkeypatch):
    from offline_analyzer.storage.backup import backup_open

    work, run = estate
    stale = tmp_path / "stale-backup"
    with Store(work) as store:
        backup_open(store, stale)  # taken before the edition existed
        frozen_estate(store, run)
        monkeypatch.setattr(
            manage, "pre_purge_backup", lambda _s: dict(path=str(stale), files=0, bytes=0)
        )
        preview = manage.plan(store, *TARGET)
        with pytest.raises(InputError, match="SUPERSEDE_BACKUP_UNVERIFIED"):
            manage.delete_scope(
                store,
                *TARGET,
                preview["preview_token"],
                TARGET[1],
                True,
                supersede=True,
                supersede_confirmation=TARGET[1],
                supersede_reason=REASON,
            )
        assert TARGET in {(s["provider"], s["scope_id"]) for s in manage.scopes(store)}
        assert not store.db.execute("SELECT 1 FROM finalized_supersessions").fetchone()


def test_single_file_removal_follows_the_frozen_edition_rule(estate):
    work, run = estate
    with Store(work) as store:
        editions = frozen_estate(store, run)
        sha = manage.files(store, *TARGET)[0]["sha256"]
        preview = manage.file_plan(store, sha)
        assert preview["frozen_decision_required"] and "frozen" in preview["limitations"][0]
        args = (store, sha, preview["preview_token"], sha[:12], True)
        with pytest.raises(InputError, match="FROZEN_EDITION_DECISION_REQUIRED"):
            manage.delete_file(*args)
        with pytest.raises(InputError, match="SUPERSEDE_CONFIRMATION_REQUIRED"):
            manage.delete_file(
                *args, supersede=True, supersede_confirmation=sha[:12], supersede_reason=REASON
            )
        assert (work / "raw" / f"{sha}.json").exists()
        assert store.db.execute("SELECT run_id,data FROM finalized_assessments").fetchall() == (
            editions
        )
        result = manage.delete_file(
            *args, supersede=True, supersede_confirmation=TARGET[1], supersede_reason=REASON
        )
        assert result["superseded_editions"] == 1 and Path(result["backup"]["path"]).is_dir()
        assert not (work / "raw" / f"{sha}.json").exists()
        assert store.db.execute("SELECT run_id,data FROM finalized_assessments").fetchall() == (
            editions
        )
        assert store.db.execute("SELECT action FROM scope_audit").fetchall() == [
            ("DELETE_FILE_SUPERSEDE",)
        ]
        assert "demo-alpha" not in json.dumps(
            store.db.execute("SELECT * FROM scope_audit").fetchall()
        )
