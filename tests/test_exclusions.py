"""Client-report exclusions on synthetic data: hidden from reports, evidence untouched."""

import io
import zipfile

import pytest
from openpyxl import load_workbook
from pydantic import ValidationError

from offline_analyzer.contracts.exclusion import ExclusionRequest
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings.exclusions import excluded, listing, record
from offline_analyzer.findings.finalisation import freeze
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.reporting.assessment_report import export_assessment, model
from offline_analyzer.reporting.cloud import dashboard
from offline_analyzer.reporting.sre_reports import finalized, rows
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.r12_demo import build as aws_build
from tools.gcp_fixture import build as gcp_build

ANALYST = "Synthetic analyst"


def exclude(reason="FALSE_POSITIVE", note=""):
    return ExclusionRequest(action="EXCLUDE", reason=reason, note=note, analyst=ANALYST)


RESTORE = ExclusionRequest(action="RESTORE", analyst=ANALYST)


@pytest.fixture()
def estate(tmp_path):
    aws_build(tmp_path / "aws")
    gcp_build(tmp_path / "gcp")
    work = tmp_path / "work"
    with Store(work) as store:
        aws = import_package(store, tmp_path / "aws")
        gcp = import_package(store, tmp_path / "gcp")
        run = assess_enterprise(store)
    return work, run, aws, gcp


def test_reason_is_required_and_other_needs_a_note():
    with pytest.raises(ValidationError):
        ExclusionRequest(action="EXCLUDE", analyst=ANALYST)
    with pytest.raises(ValidationError):
        exclude("OTHER")
    assert exclude("OTHER", "Synthetic explanation").reason == "OTHER"
    with pytest.raises(ValidationError):
        exclude("NOT_A_REASON")


def test_excluded_finding_leaves_reports_counts_and_exports_but_not_evidence(estate, tmp_path):
    work, run, _aws, _gcp = estate
    with Store(work) as store:
        target = next(f for f in store.candidates(run) if f.provider == "GCP")
        fid = target.finding_id
        for f in [target, next(f for f in store.candidates(run) if f.provider == "AWS")]:
            record_decision(store, run, f.finding_id, "CONFIRMED", ANALYST, "Synthetic")
        evidence_before = store.db.execute(
            "SELECT data FROM findings WHERE run_id=? AND finding_id=?", [run, fid]
        ).fetchone()
        evaluations_before = store.db.execute(
            "SELECT count(*), sum(hash(data)) FROM evaluations WHERE run_id=?", [run]
        ).fetchone()
        gcp_before = dashboard(store, run)["providers"]["GCP"]
        assert fid in {r["id"] for r in finalized(store, run)["findings"]}

        entry = record(store, run, fid, exclude("DUPLICATE", "Same as another synthetic item"))
        assert entry.reason == "DUPLICATE" and entry.recorded_at.tzinfo
        assert fid not in {r["id"] for r in rows(store, run)}
        view = finalized(store, run)
        assert fid not in {r["id"] for r in view["findings"]} and view["excluded"] == 1
        data = model(store, run, "valid")
        assert fid not in {f["id"] for f in data["findings"]} and data["excluded"] == 1
        gcp_after = dashboard(store, run)["providers"]["GCP"]
        assert gcp_after["excluded_findings"] == 1
        assert gcp_after["candidate_findings"] == gcp_before["candidate_findings"] - 1
        severity = target.suggested_severity
        assert gcp_after["severity"].get(severity, 0) == gcp_before["severity"][severity] - 1
        export = tmp_path / "report.zip"
        export_assessment(store, run, export, include="valid")
        with zipfile.ZipFile(export) as archive:
            for name in archive.namelist():
                assert fid.encode() not in archive.read(name)
            book = next(n for n in archive.namelist() if n.endswith(".xlsx"))
            sheet_text = " ".join(
                str(c.value)
                for ws in load_workbook(io.BytesIO(archive.read(book)))
                for row in ws
                for c in row
                if c.value
            )
            assert "1 finding(s) not reported" in sheet_text
        section = listing(store, run)["items"]
        assert [i["id"] for i in section] == [fid]
        assert section[0]["reason_label"] == "Duplicate of another finding"
        # Evidence and the evaluated finding are never modified.
        assert (
            store.db.execute(
                "SELECT data FROM findings WHERE run_id=? AND finding_id=?", [run, fid]
            ).fetchone()
            == evidence_before
        )
        assert (
            store.db.execute(
                "SELECT count(*), sum(hash(data)) FROM evaluations WHERE run_id=?", [run]
            ).fetchone()
            == evaluations_before
        )
        with pytest.raises(InputError, match="FINDING_ALREADY_EXCLUDED"):
            record(store, run, fid, exclude())
        record(store, run, fid, RESTORE)  # Undo
        assert fid in {r["id"] for r in finalized(store, run)["findings"]}
        assert listing(store, run)["items"] == []
        with pytest.raises(InputError, match="FINDING_NOT_EXCLUDED"):
            record(store, run, fid, RESTORE)


def test_exclusion_survives_reevaluation_enterprise_rebuild_and_restart(estate):
    work, run, aws, gcp = estate
    with Store(work) as store:
        assess(store, gcp)
        fid = next(store.candidates(gcp)).finding_id
        record(store, gcp, fid, exclude())
        # Finding identity is rule + canonical resource; unchanged by re-evaluation.
        assess(store, gcp)
        assert fid in {f.finding_id for f in store.candidates(gcp)}
        rebuilt = assess_enterprise(store, [aws, gcp])
        assert fid in {f.finding_id for f in store.candidates(rebuilt)}
        assert fid not in {r["id"] for r in rows(store, rebuilt)}
    with Store(work) as store:  # restart
        assert fid in excluded(store)
        assert fid not in {f["id"] for f in model(store, run)["findings"]}


def test_frozen_edition_is_not_altered_by_later_exclusions(estate):
    work, run, aws, _gcp = estate
    with Store(work) as store:
        chosen = [next(f for f in store.candidates(run) if f.provider == p) for p in ("AWS", "GCP")]
        for f in chosen:
            record_decision(store, run, f.finding_id, "CONFIRMED", ANALYST, "Synthetic")
        freeze(store, run, ANALYST, True)
        before = finalized(store, run)
        with pytest.raises(InputError, match="ASSESSMENT_FINALIZED"):
            record(store, run, chosen[0].finding_id, exclude())
        # An exclusion recorded on another, editable run leaves the frozen edition as is.
        assess(store, aws)
        record(store, aws, chosen[0].finding_id, exclude())
        assert finalized(store, run) == before
        assert chosen[0].finding_id in {f["id"] for f in before["findings"]}
