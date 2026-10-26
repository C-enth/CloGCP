"""Phase E: GCP frozen-edition feed into an AWS workspace (synthetic data only)."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from offline_analyzer.contracts.exclusion import ExclusionRequest
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings.exclusions import record as exclude
from offline_analyzer.findings.finalisation import freeze, frozen
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.reporting import gcp_feed
from offline_analyzer.reporting.assessment_report import export_assessment, model
from offline_analyzer.reporting.cloud import dashboard
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures import aws_fake_cloud as fake
from tools.fixtures.gcp_estate import estate


@pytest.fixture(scope="module")
def gcp(tmp_path_factory):
    """A finalized GCP edition: 3 projects, confirmed findings, one false positive."""
    root = tmp_path_factory.mktemp("gcp")
    set_environment(root / "work", "SYNTHETIC")
    store = Store(root / "work")
    runs = []
    for package in estate(root / "packages", 3):
        run = import_package(store, package)
        assess(store, run)
        runs.append(run)
    snapshot = assess_enterprise(store, runs)
    query = "SELECT finding_id FROM findings WHERE run_id=? ORDER BY finding_id"
    ids = [f for (f,) in store.rows(query, [snapshot])]
    excluded = ids[0]
    request = ExclusionRequest(
        action="EXCLUDE", reason="FALSE_POSITIVE", note="synthetic", analyst="Synthetic"
    )
    exclude(store, snapshot, excluded, request)
    for finding in ids[1:12]:
        record_decision(store, snapshot, finding, "CONFIRMED", "Synthetic Analyst", "synthetic")
    freeze(store, snapshot, "Synthetic Analyst", True)
    exported = gcp_feed.export_edition(store, snapshot, root / "out")
    edition_before = json.dumps(frozen(store, snapshot), sort_keys=True, default=str)
    store.db.close()
    return {"root": root, "snapshot": snapshot, "excluded": excluded, "export": exported,
            "edition_before": edition_before}  # fmt: skip


@pytest.fixture
def aws(tmp_path):
    """Two synthetic AWS accounts, imported, assessed and combined into a snapshot."""
    cloud = fake.fleet(2)
    with fake.installed(cloud) as collector:
        cfg = fake.config(tmp_path / "evidence", regions=("ap-south-1",))
        results = [collector.collect_account(cfg, fake.fleet_account(i), None) for i in range(2)]
    set_environment(tmp_path / "work", "SYNTHETIC")
    store = Store(tmp_path / "work")
    from offline_analyzer.cli import private_copy

    runs = []
    for result in results:
        with private_copy(store.workspace, Path(result["zip"])) as root:
            run = import_package(store, root)
        assess(store, run)
        runs.append(run)
    return store, assess_enterprise(store, runs)


def bundle(gcp) -> Path:
    return Path(gcp["export"]["file"])


def test_bundle_contains_no_raw_evidence(gcp):
    with zipfile.ZipFile(bundle(gcp)) as archive:
        names = sorted(archive.namelist())
        text = b"".join(archive.read(n) for n in names).decode()
    assert names == sorted("GCP-FROZEN-EDITION/" + n for n in (
        *gcp_feed.FILES, "manifest.json", "signature.json"))  # fmt: skip
    findings = json.loads(zipfile.ZipFile(bundle(gcp)).read("GCP-FROZEN-EDITION/findings.json"))
    assert findings and all(set(f) <= set(gcp_feed.FINDING_FIELDS) for f in findings)
    for marker in ('"configuration"', '"observation_ids"', '"evidence_refs"', '"observed"',
                   "artifact-", gcp["export"]["key"]):  # fmt: skip
        assert marker not in text
    assert gcp["excluded"] not in {f["id"] for f in findings}


def test_import_link_and_consolidated_counts(gcp, aws):
    store, run = aws
    summary = gcp_feed.import_edition(store, bundle(gcp), gcp["export"]["key"])
    assert summary["read_only"] and summary["edition_id"] == gcp["export"]["edition_id"]
    assert summary["collector_versions"] and summary["counts"]["excluded_findings"] == 1
    aws_only = model(store, run, "all")
    gcp_feed.link(store, run, summary["edition_id"])
    data = model(store, run, "all")
    frozen_rows = [f for f in data["findings"] if f.get("frozen")]
    assert len(frozen_rows) == summary["counts"]["findings"]
    assert len(data["findings"]) == len(aws_only["findings"]) + len(frozen_rows)
    assert data["reconciliation"]["status"] == "PASS"
    assert data["provider_scope"] == "GCP + AWS"
    assert all(f["source"].startswith("GCP frozen edition") for f in frozen_rows)
    assert gcp["excluded"] not in {f["id"] for f in data["findings"]}
    assert any(gcp["excluded"] in e["finding_ids"] for e in data["excluded_findings"])
    view = dashboard(store, run)
    assert view["providers"]["GCP"]["frozen"] and view["frozen_editions"]
    assert view["reconciliation"]["consolidated"] == (
        view["providers"]["AWS"]["candidate_findings"] + len(frozen_rows)
    )
    assert view["cross_cloud"]["status"] == "NOT_CORRELATED"
    assert sum(r["frozen_gcp_findings"] for r in view["stride"]) <= len(frozen_rows)


def test_reports_gcp_only_aws_only_and_both(gcp, aws, tmp_path):
    store, run = aws
    summary = gcp_feed.import_edition(store, bundle(gcp), gcp["export"]["key"])
    gcp_feed.link(store, run, summary["edition_id"])
    counts = {}
    for provider in ("GCP", "AWS", ""):
        data = model(store, run, "all", provider)
        assert data["register_reconciliation"]["status"] == "PASS"
        assert {member for row in data["contextual_register"] for member in row["_members"]} == {
            finding["id"] for finding in data["findings"]
        }
        counts[provider or "both"] = (
            sum(f["provider"] == "AWS" for f in data["findings"]),
            sum(f["provider"] == "GCP" for f in data["findings"]),
        )
        target = tmp_path / f"report-{provider or 'both'}.zip"
        export_assessment(store, run, target, include="all", provider=provider)
        with zipfile.ZipFile(target) as archive:
            assert any(n.endswith(".docx") for n in archive.namelist())
            workbook = next(n for n in archive.namelist() if n.endswith(".xlsx"))
            assert zipfile.ZipFile(io.BytesIO(archive.read(workbook))).namelist()
    assert counts["GCP"][0] == 0 and counts["GCP"][1] == summary["counts"]["findings"]
    assert counts["AWS"][1] == 0 and counts["AWS"][0] > 0
    assert counts["both"] == (counts["AWS"][0], counts["GCP"][1])


def test_reconciliation_mismatch_blocks_export(gcp, aws, tmp_path, monkeypatch):
    store, run = aws
    summary = gcp_feed.import_edition(store, bundle(gcp), gcp["export"]["key"])
    gcp_feed.link(store, run, summary["edition_id"])
    original = gcp_feed.report_findings
    monkeypatch.setattr(gcp_feed, "report_findings", lambda record: original(record)[1:])
    with pytest.raises(InputError, match="CONSOLIDATED_RECONCILIATION_FAILED"):
        export_assessment(store, run, tmp_path / "blocked.zip", include="all")
    assert not (tmp_path / "blocked.zip").exists()


def rewrite(source: Path, target: Path, change) -> Path:
    with zipfile.ZipFile(source) as archive:
        files = {i.filename: archive.read(i) for i in archive.infolist()}
    change(files)
    with zipfile.ZipFile(target, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return target


def test_tampered_or_wrongly_keyed_bundles_are_rejected(gcp, aws, tmp_path):
    store, _run = aws
    key = gcp["export"]["key"]
    root = "GCP-FROZEN-EDITION/"

    def drop_finding(files):
        rows = json.loads(files[root + "findings.json"])
        files[root + "findings.json"] = json.dumps(rows[1:]).encode()

    def forge_manifest(files):
        drop_finding(files)
        manifest = json.loads(files[root + "manifest.json"])
        for entry in manifest["files"]:
            if entry["path"] == "findings.json":
                entry["sha256"] = hashlib.sha256(files[root + "findings.json"]).hexdigest()
        files[root + "manifest.json"] = json.dumps(manifest).encode()

    cases = [
        (rewrite(bundle(gcp), tmp_path / "a.zip", drop_finding), key, "GCP_EDITION_HASH_MISMATCH"),
        (rewrite(bundle(gcp), tmp_path / "b.zip", forge_manifest), key,
         "GCP_EDITION_SIGNATURE_INVALID"),
        (bundle(gcp), "0" * 64, "GCP_EDITION_SIGNATURE_INVALID"),
        (rewrite(bundle(gcp), tmp_path / "c.zip", lambda f: f.update({root + "extra.json": b"{}"})),
         key, "GCP_EDITION_BUNDLE_LAYOUT"),
    ]  # fmt: skip
    for path, used, code in cases:
        with pytest.raises(InputError, match=code):
            gcp_feed.import_edition(store, path, used)
    assert gcp_feed.editions(store) == []


def test_edition_is_read_only_and_gcp_data_unchanged(gcp, aws):
    store, run = aws
    summary = gcp_feed.import_edition(store, bundle(gcp), gcp["export"]["key"])
    again = gcp_feed.import_edition(store, bundle(gcp), gcp["export"]["key"])
    assert again["bundle_sha256"] == summary["bundle_sha256"]
    gcp_feed.link(store, run, summary["edition_id"])
    frozen_id = next(f["id"] for f in model(store, run, "all")["findings"] if f.get("frozen"))
    with pytest.raises(InputError, match="FINDING_NOT_FOUND_IN_RUN"):
        record_decision(store, run, frozen_id, "REJECTED", "Synthetic", "attempt")
    # The stored bundle is verified on every read: a changed copy is refused.
    stored = store.workspace / "frozen-editions" / f"{summary['edition_id']}.zip"
    stored.write_bytes(stored.read_bytes() + b"x")
    with pytest.raises(InputError, match="GCP_EDITION_STORED_BUNDLE_CHANGED"):
        model(store, run, "all")
    # The GCP workspace and its edition are unchanged by export and import.
    gcp_store = Store(gcp["root"] / "work")
    try:
        assert (
            json.dumps(frozen(gcp_store, gcp["snapshot"]), sort_keys=True, default=str)
            == (gcp["edition_before"])
        )
    finally:
        gcp_store.db.close()


def test_link_refuses_runs_with_live_gcp_data(gcp, aws, tmp_path):
    store, _run = aws
    summary = gcp_feed.import_edition(store, bundle(gcp), gcp["export"]["key"])
    package = estate(tmp_path / "gcp-live", 1)[0]
    live = import_package(store, package)
    with pytest.raises(InputError, match="RUN_HAS_LIVE_GCP_DATA"):
        gcp_feed.link(store, live, summary["edition_id"])


def test_edition_endpoints(gcp, aws, tmp_path):
    from test_workflow_api import client, wait

    store, run = aws
    store.db.close()
    test, headers = client(gcp["root"] / "work")
    with test:
        exported = test.post(
            f"/api/runs/{gcp['snapshot']}/gcp-edition/export", json={}, headers=headers
        ).json()
        assert len(exported["key"]) == 64 and exported["file"].endswith(".zip")
        download = test.get(f"/api/gcp-editions/exports/{exported['file']}", headers=headers)
        assert download.status_code == 200
        (tmp_path / exported["file"]).write_bytes(download.content)
    journal = "".join(
        p.read_text(errors="replace") for p in (gcp["root"] / "work").rglob("*") if p.is_file()
        and p.suffix in {".json", ".jsonl"}
    )  # fmt: skip
    assert exported["key"] not in journal  # the signing key is never written to the workspace
    test, headers = client(store.workspace)
    with test:
        job = test.post(
            "/api/gcp-editions/import",
            json={"path": str(tmp_path / exported["file"]), "key": exported["key"]},
            headers=headers,
        ).json()
        done = wait(test, headers, job)
        assert done["status"] == "SUCCEEDED", done
        edition = done["result"]["edition_id"]
        assert test.get("/api/gcp-editions", headers=headers).json()["items"][0]["read_only"]
        linked = test.post(
            f"/api/runs/{run}/gcp-edition", json={"edition_id": edition}, headers=headers
        ).json()
        assert run in linked["linked_runs"]
        view = test.get(f"/api/runs/{run}/cloud/dashboard", headers=headers)
        assert test.get(f"/api/runs/{run}/gcp-edition", headers=headers).json()["edition"]
        paths = test.get(f"/api/runs/{run}/cloud/paths", headers=headers).json()
        assert paths["frozen_edition"]["edition_id"] == edition
        assert any(p.get("frozen") for p in paths["items"]) or not linked["counts"]["paths"]
        assert (
            view.status_code == 200 and view.json()["frozen_editions"][0]["edition_id"] == edition
        )
