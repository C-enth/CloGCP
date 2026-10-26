"""Phase C: AWS batch collector on a synthetic fleet (fake cloud): per-account isolation,
checkpoint restart, --retry-failed resume, shared throttle, hub sign-in expiry, health
verdicts, fleet roll-up and masked terminal output. Synthetic data only."""

import csv
import json
from pathlib import Path

import pytest

from tools.fixtures import aws_fake_cloud as fake

FAST = ["--max-attempts", "2"]


def accounts_file(path: Path, accounts, groups=("Payments", "Data")):
    rows = "".join(
        f"{a},{groups[i % len(groups)]},Synthetic {i:03d}\n" for i, a in enumerate(accounts)
    )
    path.write_text("account_id,business_group,name\n" + rows)
    return path


def run(cloud, tmp_path, *extra):
    with fake.installed(cloud, "batch") as batch:
        # Fast backoff so throttling tests stay quick; behaviour is unchanged.
        batch.assessment.DEFAULT_OPTIONS.update(backoff_base=0.01, backoff_cap=0.02)
        code = batch.main(
            [
                "--accounts",
                str(tmp_path / "accounts.csv"),
                "--role",
                "CloSecEvidenceReadOnly",
                "--regions",
                "ap-south-1",
                "eu-west-1",
                "--output",
                str(tmp_path / "batch"),
                "--assessment-id",
                "SYNTHETIC",
                "--concurrency",
                "3",
                *FAST,
                *extra,
            ]
        )
    out = tmp_path / "batch"
    manifest = json.loads((out / "batch-manifest.json").read_text())
    return code, {r["account_id"]: r for r in manifest["accounts"]}, manifest


@pytest.fixture
def fleet6(tmp_path):
    cloud = fake.fleet(6)
    ids = [fake.fleet_account(i) for i in range(6)]
    cloud.accounts[ids[1]].assume_error = "AccessDenied"
    cloud.faults += [
        fake.Fault("guardduty", "list_detectors", "AccessDeniedException", account=ids[2]),
        fake.Fault("rds", "describe_db_instances", "Throttling", account=ids[3]),
    ]
    accounts_file(tmp_path / "accounts.csv", ids)
    return cloud, ids


def test_batch_isolates_accounts_and_writes_one_package_each(tmp_path, fleet6, capsys):
    cloud, ids = fleet6
    code, rows, manifest = run(cloud, tmp_path)
    out = capsys.readouterr().out
    assert code == 1
    assert rows[ids[0]]["state"] == "DONE" and rows[ids[0]]["verdict"] == "READY"
    assert rows[ids[1]]["state"] == "FAILED" and rows[ids[1]]["verdict"] == "ACCESS GAP"
    assert "role not assumable" in rows[ids[1]]["reasons"][0]
    assert rows[ids[2]]["verdict"] == "ACCESS GAP"
    assert any("guardduty.list_detectors" in r for r in rows[ids[2]]["reasons"])
    assert rows[ids[3]]["verdict"] == "RE-COLLECT" and rows[ids[3]]["retries"] >= 2
    for account in (ids[0], ids[2], ids[3], ids[4], ids[5]):
        row = rows[account]
        assert Path(row["zip"]).is_file() and Path(row["zip"] + ".sha256").is_file()
        assert account in Path(row["zip"]).name  # one account per package
        assert row["collector_version"] == "0.3.3"
        assert row["datasets_by_status"]["COMPLETE"] > 100
        assert row["business_group"] in {"Payments", "Data"}
    assert len(list((tmp_path / "batch/evidence").glob("*.zip"))) == 5
    assert manifest["throttle_events"] >= 2  # shared throttle saw the RDS throttling
    roll = json.loads((tmp_path / "batch/fleet-rollup.json").read_text())
    assert roll["verdicts"] == {"ACCESS GAP": 2, "READY": 3, "RE-COLLECT": 1}
    assert roll["organization_access"] == {"ACCESS_DENIED": 5}
    repeated = {(r["dataset"], r["status"]): r["accounts"] for r in roll["repeated"]}
    assert repeated[("guardduty.list_detectors", "ACCESS_DENIED")] == 1
    limitations = (tmp_path / "batch/fleet-limitations.md").read_text()
    assert "Organization controls (SCPs, RCPs) not assessed in 5 account(s)" in limitations
    with (tmp_path / "batch/accounts-result.csv").open() as handle:
        assert len(list(csv.DictReader(handle))) == 6
    for account in ids:  # masked terminal output
        assert account not in out
    assert "FAKE" not in out and "SessionToken" not in out  # never prints credentials


def test_restart_skips_finished_and_retry_failed_resumes(tmp_path, fleet6):
    cloud, ids = fleet6
    run(cloud, tmp_path)
    before = len(cloud.calls)
    # Restart without changes: finished accounts are skipped; only the failed one re-runs.
    _code, rows, _ = run(cloud, tmp_path)
    assert {call[0] for call in cloud.calls[before:]} <= {ids[1]}
    assert rows[ids[0]]["state"] == "DONE"
    # Access fixed centrally; --retry-failed re-runs only non-READY accounts, resuming.
    cloud.accounts[ids[1]].assume_error = None
    cloud.faults.clear()
    before = len(cloud.calls)
    code, rows, _ = run(cloud, tmp_path, "--retry-failed")
    touched = {a for a, *_ in cloud.calls[before:]}
    assert touched <= {ids[1], ids[2], ids[3]}
    assert code == 0 and {r["verdict"] for r in rows.values()} == {"READY"}
    assert rows[ids[2]]["resumed_from"] and rows[ids[3]]["resumed_from"]
    assert rows[ids[1]]["resumed_from"] is None  # never collected before: fresh run
    manifest = json.loads((Path(rows[ids[3]]["run_directory"]) / "manifest.json").read_text())
    assert manifest["collection_facts"]["carried_operations"] > 100


def test_expired_hub_sign_in_stops_the_batch_gracefully(tmp_path, capsys):
    cloud = fake.fleet(6, hub_expires_after=2)
    ids = [fake.fleet_account(i) for i in range(6)]
    accounts_file(tmp_path / "accounts.csv", ids)
    with fake.installed(cloud, "batch") as batch:
        batch.assessment.DEFAULT_OPTIONS.update(backoff_base=0.01, backoff_cap=0.02)
        batch.main(
            [
                "--accounts", str(tmp_path / "accounts.csv"), "--role", "CloSecEvidenceReadOnly",
                "--regions", "ap-south-1", "--output", str(tmp_path / "batch"),
                "--assessment-id", "SYNTHETIC", "--concurrency", "1",
            ]
        )  # fmt: skip
    out = capsys.readouterr().out
    manifest = json.loads((tmp_path / "batch/batch-manifest.json").read_text())
    states = [r["state"] for r in manifest["accounts"]]
    assert states.count("DONE") == 2
    assert "INTERRUPTED" in states and "NOT_STARTED" in states
    assert "Sign in again, then rerun with --retry-failed" in out
    cloud.hub_expires_after = None
    code, rows, _ = run(cloud, tmp_path, "--retry-failed")
    assert code == 0 and all(r["state"] == "DONE" for r in rows.values())


def test_account_list_validation(tmp_path):
    from tools.fixtures.aws_fake_cloud import installed

    good = fake.fleet_account(0)
    (tmp_path / "list.txt").write_text(
        f"# accounts\n{good}, Payments\n{good}\n12345\n000000000001,Bad/Group\n"
    )
    with installed(fake.fleet(1), "fleet") as fleet:
        accounts, problems = fleet.read_accounts(tmp_path / "list.txt")
        assert accounts == [{"account_id": good, "business_group": "Payments", "name": ""}]
        assert [p["problem"] for p in problems] == [
            "DUPLICATE_ACCOUNT_ID",
            "INVALID_ACCOUNT_ID",
            "INVALID_BUSINESS_GROUP",
        ]
        assert fleet.mask(good) == "********" + good[-4:]
