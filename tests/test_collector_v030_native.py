"""Actual AWS collector v0.3.x journal format: adapter, assessment and collector parity."""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from offline_analyzer.contracts.aws_operation_names import API_OPERATIONS
from offline_analyzer.ingestion.collector import inspect_collector
from offline_analyzer.ingestion.collector_v030_native import DERIVED, canonical
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.aws_v030_native import ACCOUNT, package, record

COLLECTOR = Path("collectors/aws/assessment.py")


def collector_record_keys() -> list[set[str]]:
    tree = ast.parse(COLLECTOR.read_text())
    keys = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "rec":
            if isinstance(node.value, ast.Dict):
                keys.append({k.value for k in node.value.keys})
    return keys


def test_fixture_journal_matches_collector_record_schema():
    found = collector_record_keys()
    assert len(found) == 3  # api(), skipped() and run_prowler()
    # 0.3.1 adds api_operation/truncation to api(); every 0.3.0 key is still written.
    fixture = set(record())
    assert all(fixture <= keys for keys in found)
    assert {"api_operation", "truncation"} <= found[0]


def test_operation_names_come_from_botocore_table_not_case_conversion():
    assert canonical("rds", "describe_db_instances")[0] == "rds:DescribeDBInstances"
    assert canonical("wafv2", "list_web_acls")[0] == "wafv2:ListWebACLs"
    assert canonical("s3", "get_bucket_policy")[0] == "s3api:GetBucketPolicy"
    assert canonical("collector", "remaining_operations") == (
        "collector:RemainingOperations",
        False,
    )
    registry = ast.literal_eval(
        next(
            n.value
            for n in ast.parse(COLLECTOR.read_text()).body
            if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == "REGIONAL"
        )
    )
    missing = [
        f"{s}.{o}" for s, ops in registry.items() for o in ops if f"{s}.{o}" not in API_OPERATIONS
    ]
    assert missing == []


def test_native_package_maps_pages_absence_and_truncation(tmp_path):
    root = package(tmp_path / "evidence")
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    package_model, summary = inspect_collector(root)
    rows = {(r["operation"], r["original_outcome"]): r for r in summary["operations"]}
    auth = rows[("iam:GetAccountAuthorizationDetails", "COMPLETE")]
    assert auth["derivation"] == "PAGES_MERGED_BUILD_FULL_RESULT"
    assert auth["pagination"] == "ALL_PAGES_MERGED" and len(auth["source_pages"]) == 2
    merged = json.loads((root / auth["artifact_path"]).read_text())
    assert len(merged["RoleDetailList"]) == 2 and "Marker" not in merged
    bpa = rows[("s3api:GetPublicAccessBlock", "NOT_ENABLED")]
    assert bpa["interpretation"] == "AWS_DEFINED_CONFIGURATION_ABSENCE"
    assert bpa["status"] == "SUCCEEDED" and bpa["artifact_path"].startswith(DERIVED + "/")
    waf = rows[("wafv2:ListWebACLs", "COMPLETE")]
    assert waf["pagination"] == "TRUNCATED"  # residual NextMarker never yields complete
    org = rows[("organizations:DescribeOrganization", "API_ERROR")]
    assert org["status"] == "FAILED" and org["error_code"] == "AWSOrganizationsNotInUseException"
    assert waf["import_handling"] == "UNSUPPORTED_OPERATION_RETAINED"
    assert rows[("guardduty:ListDetectors", "COMPLETE")]["import_handling"] == "IMPORTED"
    assert rows[("sts:GetCallerIdentity", "COMPLETE")]["derivation"]
    assert summary["original_outcomes"]["ACCESS_DENIED"] == 1
    assert summary["unlisted_files"] == []
    assert {s.account_id for s in package_model.sources} == {ACCOUNT}
    # Original collector files are never modified; derived artifacts are separate.
    assert all(p.read_bytes() == data for p, data in before.items())
    again = inspect_collector(root)[1]
    assert [r["artifact_sha256"] for r in again["operations"]] == [
        r["artifact_sha256"] for r in summary["operations"]
    ]


def test_native_package_assessment_finds_expected_exposures(tmp_path):
    root = package(tmp_path / "evidence")
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, root)
        assess(store, run)
        rules = {
            json.loads(d)["rule_id"]
            for (d,) in store.rows("SELECT data FROM findings WHERE run_id=?", [run])
        }
        outcomes = dict(
            store.rows(
                "SELECT json_extract_string(data,'$.rule_id'), outcome FROM evaluations "
                "WHERE run_id=? AND json_extract_string(data,'$.rule_id') IN "
                "('R1-S3-ACCOUNT-BPA','R0-CLOUDTRAIL-VALIDATION')",
                [run],
            )
        )
    assert {
        "R1-S3-BUCKET-PUBLIC-ACCESS",
        "R0-CLOUDTRAIL-VALIDATION",
        "R1-IAM-ROLE-TRUST-CONDITIONS",
        "R1-IAM-INSTANCE-ROLE-PRIVILEGE",
        "R0-EC2-IMDSV2",
    } <= rules
    # Account BPA absence is an AWS-defined configuration state, so it fails, not UNKNOWN.
    assert outcomes["R1-S3-ACCOUNT-BPA"] == "FAIL"


@pytest.mark.parametrize(
    "tamper,code",
    [
        ("page", "ARTIFACT_CHECKSUM_MISMATCH"),
        ("account", "COLLECTOR_JOURNAL_SCOPE_MISMATCH"),
        ("outcome", "COLLECTION_OUTCOME_UNSUPPORTED"),
    ],
)
def test_native_package_rejects_tampering(tmp_path, tamper, code):
    import hashlib

    root = package(tmp_path / "evidence")
    journal = root / "operations.jsonl"
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    if tamper == "page":
        page = root / rows[0]["files"][0]["path"]
        page.write_text(page.read_text().replace("synthetic-app-admin", "tampered-role"))
    else:
        rows[0]["account_id" if tamper == "account" else "outcome"] = (
            "999999999999" if tamper == "account" else "MAYBE"
        )
        journal.write_text("".join(json.dumps(r) + "\n" for r in rows))
        lines = []
        for line in (root / "checksums.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            if name == "operations.jsonl":
                digest = hashlib.sha256(journal.read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (root / "checksums.sha256").write_text("\n".join(lines) + "\n")
    with pytest.raises(InputError, match=code):
        inspect_collector(root)


def test_cli_imports_collector_zip_without_modifying_source(tmp_path):
    archive = package(tmp_path / "evidence", archive=True)
    folder = archive.with_suffix("")
    before = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*"))
    workspace = tmp_path / "workspace"
    command = [sys.executable, "-m", "offline_analyzer.cli", "--workspace", str(workspace)]
    env = {"PYTHONPATH": "src"}
    for arguments in (["import", str(archive)], ["import", str(folder)]):
        result = subprocess.run(
            [*command, *arguments, "--origin", "synthetic"],
            capture_output=True,
            text=True,
            env={**__import__("os").environ, **env},
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().startswith("run-")
    assert sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*")) == before
    assert not (folder / DERIVED).exists()


def test_collector_sources_are_portable_and_corrected():
    source = COLLECTOR.read_text()
    tree = ast.parse(source)
    top_level = {
        alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names
    }
    assert "resource" not in top_level  # POSIX-only module is imported optionally
    compact = "".join(source.split()).replace("'", '"')
    assert '"TrailName"ifdep=="get_event_selectors"else"Name"' in compact
    gcp = Path("collectors/gcp/GCP_Security_Evidence_Collector.ps1").read_text(encoding="utf-8")
    # No unbounded process waits: every WaitForExit() follows a bounded wait in its block.
    # Every unbounded flush WaitForExit() follows a bounded wait on the same process.
    bounded = re.findall(r"\$(\w+)\.WaitForExit\(\$CommandTimeoutSeconds \* 1000\)", gcp)
    unbounded = re.findall(r"\$(\w+)\.WaitForExit\(\)", gcp)
    assert bounded and sorted(unbounded) == sorted(bounded)
    assert "$SchemaVersion = 'assessment-expanded-2.2'" in gcp
    assert "X-Goog-User-Project" in gcp and "checksums.sha256" in gcp


def test_collector_contract_and_coverage_matrix_are_current():
    result = subprocess.run(
        [sys.executable, "tools/collector_contract.py", "--check"],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": "src:."},
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    contract = json.loads(Path("collectors/collector-analyzer-contract.json").read_text())
    aws, gcp = contract["providers"]
    assert aws["collector_version"] == "0.3.2" and aws["accepted_collector_versions"] == [
        "0.3.0",
        "0.3.1",
        "0.3.2",
    ]
    assert "assessment-expanded-2.2" in gcp["accepted_manifest_schemas"]
    evaluated = {r["operation"] for r in aws["datasets"] if r["lifecycle"] == "EVALUATED"}
    assert {"cloudtrail:GetEventSelectors", "guardduty:ListDetectors"} <= evaluated


def test_latent_internet_ingress_is_reported_without_changing_reachability_rule(tmp_path):
    root = package(tmp_path / "evidence")
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, root)
        assess(store, run)
        outcomes = dict(
            store.rows(
                "SELECT json_extract_string(data,'$.rule_id'), outcome FROM evaluations "
                "WHERE run_id=? AND json_extract_string(data,'$.rule_id') LIKE '%SG%'",
                [run],
            )
        )
    # SSH from 0.0.0.0/0 without an in-use public interface: R1 keeps its reachability
    # semantics (PASS with latent note) and the separate observation reports the deviation.
    assert outcomes == {"R1-EC2-SG-SENSITIVE-INGRESS": "PASS", "SEC-EC2-SG-LATENT-EXPOSURE": "FAIL"}
