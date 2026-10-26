"""Phase D: bulk import of batch packages, scope reconciliation, business-group shards, the
additive-schema backup and the cap registry (no silent truncation). Synthetic data only."""

import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path

import pytest

from offline_analyzer.enterprise.shards import assess_sharded, combined, coverage_note, plan
from offline_analyzer.ingestion.bulk import bulk_import, expected_accounts
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.storage.store import Store
from tools.fixtures import aws_fake_cloud as fake

GROUPS = ("Payments", "Data")


@pytest.fixture(scope="module")
def packages(tmp_path_factory):
    """Four accounts in two business groups; account 0 collected twice (older + newer)."""
    root = tmp_path_factory.mktemp("bulk")
    cloud = fake.fleet(4)
    folder = root / "evidence"
    with fake.installed(cloud) as collector:
        cfg = fake.config(folder, regions=("ap-south-1",))
        results = {}
        for i in range(4):
            account = fake.fleet_account(i)
            results[account] = collector.collect_account(
                cfg, account, None, account_name=f"Synthetic {i}", business_group=GROUPS[i % 2]
            )
        older = results[fake.fleet_account(0)]
        newer = collector.collect_account(
            cfg, fake.fleet_account(0), None, account_name="Synthetic 0", business_group="Payments"
        )
    for path in folder.iterdir():
        if path.is_dir():
            shutil.rmtree(path)  # the bulk folder holds ZIPs and sidecars only
    return {"folder": folder, "older": Path(older["zip"]).name, "newer": Path(newer["zip"]).name}


def workspace(tmp_path):
    set_environment(tmp_path / "work", "SYNTHETIC")
    return Store(tmp_path / "work")


def copy(packages, tmp_path):
    target = tmp_path / "evidence"
    shutil.copytree(packages["folder"], target)
    return target


def test_bulk_import_latest_wins_and_reconciles(tmp_path, packages):
    folder = copy(packages, tmp_path)
    store = workspace(tmp_path)
    expected = [fake.fleet_account(i) for i in (0, 1, 2, 3, 9)]
    report = bulk_import(store, folder, expected=expected)
    rows = {r["file"]: r for r in report["packages"]}
    assert rows[packages["older"]]["status"] == "SUPERSEDED"
    assert rows[packages["newer"]]["status"] == "IMPORTED"
    assert report["counts"] == {
        "IMPORTED": 4,
        "ALREADY_IMPORTED": 0,
        "SUPERSEDED": 1,
        "REJECTED": 0,
    }
    assert all(r["sidecar"] == "MATCH" for r in rows.values())
    recon = report["reconciliation"]
    assert recon["missing"] == [fake.fleet_account(9)]
    assert recon["unexpected"] == []
    assert recon["duplicates"] == [fake.fleet_account(0)]
    assert {r["business_group"] for r in rows.values()} == set(GROUPS)
    analyzed = store.db.execute("SELECT count(*) FROM assessments").fetchone()[0]
    assert analyzed == 4
    # Resume: the same folder again imports nothing new.
    again = bulk_import(store, folder, expected=expected)
    assert again["counts"]["IMPORTED"] == 0 and again["counts"]["ALREADY_IMPORTED"] == 4
    assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 4


def test_one_bad_package_never_blocks_the_others(tmp_path, packages):
    folder = copy(packages, tmp_path)
    account0 = {packages["older"], packages["newer"]}
    victims = sorted(p for p in folder.glob("*.zip") if p.name not in account0)
    # Sidecar mismatch on one package; a tampered evidence page in another.
    victims[0].with_name(victims[0].name + ".sha256").write_text(
        "0" * 64 + "  " + victims[0].name + "\n"
    )
    tampered = victims[1]
    with zipfile.ZipFile(tampered) as source:
        items = [(i, source.read(i)) for i in source.infolist()]
    with zipfile.ZipFile(tampered, "w") as target:
        for info, data in items:
            if "/regions/" in info.filename and info.filename.endswith("page-000001.json"):
                data = data.replace(b"synthetic", b"tampered!", 1)
            target.writestr(info, data)
    tampered.with_name(tampered.name + ".sha256").write_text(
        hashlib.sha256(tampered.read_bytes()).hexdigest() + "  " + tampered.name + "\n"
    )
    (folder / "not-a-package.zip").write_bytes(b"not a zip")
    store = workspace(tmp_path)
    report = bulk_import(store, folder)
    rows = {r["file"]: r for r in report["packages"]}
    assert rows[victims[0].name]["code"] == "ZIP_SHA256_SIDECAR_MISMATCH"
    assert rows[tampered.name]["status"] == "REJECTED"
    assert rows["not-a-package.zip"]["code"] == "BULK_ARCHIVE_UNREADABLE"
    assert report["counts"]["IMPORTED"] == 2


def corrupt(archive: Path) -> None:
    """Change one evidence page inside the ZIP and refresh the sidecar, so only the package's
    own checksums (checked at import) detect it."""
    with zipfile.ZipFile(archive) as source:
        items = [(i, source.read(i)) for i in source.infolist()]
    with zipfile.ZipFile(archive, "w") as target:
        for info, data in items:
            if "/regions/" in info.filename and info.filename.endswith("page-000001.json"):
                data = data.replace(b"synthetic", b"tampered!", 1)
            target.writestr(info, data)
    archive.with_name(archive.name + ".sha256").write_text(
        hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n"
    )


def test_corrupt_newest_package_falls_back_to_the_older_one(tmp_path, packages):
    folder = copy(packages, tmp_path)
    corrupt(folder / packages["newer"])
    store = workspace(tmp_path)
    report = bulk_import(store, folder)
    rows = {r["file"]: r for r in report["packages"]}
    newer, older = rows[packages["newer"]], rows[packages["older"]]
    assert newer["status"] == "REJECTED" and newer["code"] == "ARTIFACT_CHECKSUM_MISMATCH"
    assert older["status"] == "IMPORTED" and older["run_id"]
    assert older["fallback"] == "latest package invalid, fell back to older"
    assert report["fallbacks"] == [
        {
            "account_id": fake.fleet_account(0),
            "imported": packages["older"],
            "invalid": [packages["newer"]],
            "codes": ["ARTIFACT_CHECKSUM_MISMATCH"],
        }
    ]
    assert report["counts"]["IMPORTED"] == 4 and report["counts"]["REJECTED"] == 1


def test_expected_account_list_parsing():
    accounts, problems = expected_accounts(
        "account_id,business_group\n111111111111,A\n111111111111\n12345\n# note\n222222222222"
    )
    assert accounts == ["111111111111", "222222222222"]
    assert len(problems) == 2


def test_business_group_shards_reconcile_and_are_disclosed(tmp_path, packages):
    folder = copy(packages, tmp_path)
    store = workspace(tmp_path)
    bulk_import(store, folder)
    layout = plan(store)
    assert layout["single_snapshot_fits"] and not layout["sharded"]
    assert sorted(s["group"] for s in layout["shards"]) == sorted(GROUPS)
    result = assess_sharded(store, force=True)  # force: exercise the sharded path
    assert result["shard_set"] and len(result["runs"]) == 2
    view = combined(store, result["shard_set"])
    assert view["cross_group_correlation"] == "NOT_ASSESSED"
    assert view["totals"]["findings"] == sum(s["findings"] for s in view["shards"])
    assert view["totals"]["accounts"] == 4
    note = coverage_note(store, result["runs"][0])
    assert note["code"] == "SHARDED_ENTERPRISE_ASSESSMENT" and "not correlated" in note["reason"]
    from offline_analyzer.reporting.assessment_report import model

    data = model(store, result["runs"][0], "all")
    assert any(n["code"] == "SHARDED_ENTERPRISE_ASSESSMENT" for n in data["coverage_notes"])


def test_additive_tables_back_up_an_existing_database(tmp_path):
    import duckdb

    from offline_analyzer.storage.consolidation_schema import TABLES

    store = workspace(tmp_path)
    store.db.close()
    database = tmp_path / "work" / "assessment.duckdb"
    with duckdb.connect(str(database)) as db:
        for table in TABLES:
            db.execute(f"DROP TABLE {table}")
    Store(tmp_path / "work").db.close()
    backups = list((tmp_path / "work" / "schema-backups").glob("*.duckdb"))
    assert len(backups) == 1
    with duckdb.connect(str(backups[0]), read_only=True) as db:
        names = {n for (n,) in db.execute("SELECT table_name FROM duckdb_tables()").fetchall()}
    assert "runs" in names and not set(TABLES) & names
    Store(tmp_path / "work").db.close()  # tables now exist: no further backup
    assert len(list((tmp_path / "work" / "schema-backups").glob("*.duckdb"))) == 1


# Every numeric cap in the analyzer is either reported (truncation record or flag with shown
# and total) or refuses the whole operation with an explicit error. A new cap must be added
# here with its handling, so no cap can drop records silently.
CAPS = {
    "PATH_LIMIT": "RECORDED",  # Word attack-path limit -> truncation note
    "MAX_TEXT": "REFUSED",  # custom limitation text length
    "MAX_PACKAGES": "REFUSED",  # bulk import folder size
    "MAX_OPERATIONS": "REFUSED",
    "MAX_PACKAGE_FILES": "REFUSED",
    "MAX_DEPTH": "REFUSED",
    "MAX_EVENTS": "REFUSED",
    "MAX_STRING": "REFUSED",
    "MAX_RECORDS": "REFUSED",
    "MAX_EDGES": "RECORDED",  # enterprise relationship budget -> truncation record
    "CROSS_LIMIT": "RECORDED",
    "INVESTIGATION_LIMIT": "RECORDED",
    "MAX_CELLS": "REFUSED",
    "MAX_ROWS": "REFUSED",
    "WINDOWS_PATH_BUDGET": "REFUSED",
    "MAX_TRANSITIONS": "RECORDED",  # IAM budgets -> truncation record (AP-06 case)
    "MAX_PASSROLE": "RECORDED",
    "MAX_BULK": "REFUSED",
    "SNIPPET_LIMIT": "RECORDED",  # evidence snippet: flagged as truncated in the drawer
    "LIMIT": "RECORDED",  # aws_identity rendered text: split, never dropped
    "MAX_RELATED_PER_SCOPE": "REFUSED",
    "MAX_MEMBERS": "REFUSED",
    "MAX_OBSERVATIONS": "REFUSED",
    "MAX_FACT_ENTRIES": "RECORDED",
    "MANIFEST_BYTES": "REFUSED",
    "FACTS_BYTES": "REFUSED",
    "MAX_METADATA_TOTAL": "REFUSED",
    "MAX_FILE": "REFUSED",  # GCP frozen-edition bundle member size
    "MAX_BUNDLE": "REFUSED",  # GCP frozen-edition bundle size
    "MAX_ROTATION_SECONDS": "NOT_A_CAP",  # rule threshold, not a view limit
}


def test_every_cap_is_reported_or_refused():
    pattern = re.compile(
        r"^\s*((?:MAX_[A-Z_]+)|(?:[A-Z_]*LIMIT[A-Z_]*)|(?:[A-Z_]*BUDGET[A-Z_]*)|"
        r"(?:[A-Z_]*_BYTES))\s*=\s*[0-9]",
        re.M,
    )
    found = set()
    for path in Path("src/offline_analyzer").rglob("*.py"):
        for name in pattern.findall(path.read_text(encoding="utf-8")):
            if name.endswith("_BYTES") and name not in CAPS:
                continue  # byte limits refuse the input (json_input, archive, uploads)
            found.add(name)
    assert found - CAPS.keys() == set(), "classify the new cap in CAPS"


def test_truncation_records_carry_shown_and_total():
    from offline_analyzer.provenance.truncation import note, record

    entry = record("AWS PassRole budget", "snapshot", 976, 1000, "24 principals not evaluated")
    assert entry["dropped"] == 24
    assert "976 of 1000" in note(entry)["reason"]
    assert json.dumps(entry)  # serializable for API, GUI banner and report


def test_bulk_import_and_shard_endpoints(tmp_path, packages):
    from test_workflow_api import client, wait

    folder = copy(packages, tmp_path)
    set_environment(tmp_path / "api-work", "SYNTHETIC")
    test, headers = client(tmp_path / "api-work")
    with test:
        job = test.post(
            "/api/bulk-import",
            json={"folder": str(folder), "expected_accounts": fake.fleet_account(0) + "\n"},
            headers=headers,
        ).json()
        done = wait(test, headers, job)
        assert done["status"] == "SUCCEEDED", done
        report = done["result"]
        assert report["counts"]["IMPORTED"] == 4
        assert len(report["reconciliation"]["unexpected"]) == 3
        stored = test.get(f"/api/bulk-import/{report['bulk_id']}", headers=headers).json()
        assert stored["counts"] == report["counts"]
        layout = test.post("/api/enterprise/shard-plan", json={}, headers=headers).json()
        assert layout["single_snapshot_fits"] and layout["members"] == 4
        job = test.post("/api/enterprise/assess-sharded", json={"force": True}, headers=headers)
        done = wait(test, headers, job.json())
        assert done["status"] == "SUCCEEDED", done
        shard_set = done["result"]["shard_set"]
        view = test.get(f"/api/enterprise/shards/{shard_set}", headers=headers).json()
        assert view["cross_group_correlation"] == "NOT_ASSESSED" and len(view["shards"]) == 2
        run = done["result"]["runs"][0]
        shard = test.get(f"/api/runs/{run}/enterprise/shard", headers=headers).json()["shard"]
        assert shard["shard_set"] == shard_set
        missing = test.post("/api/bulk-import", json={"folder": str(tmp_path / "nope")},
                            headers=headers).json()  # fmt: skip
        assert wait(test, headers, missing)["status"] == "FAILED"
