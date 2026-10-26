"""Phase B: AWS collector 0.3.3 run unchanged on a synthetic fake cloud, and its analyzer
contract (accepted 0.3.0-0.3.3, distinct statuses, retries, organization facts, resume,
package integrity, manifest facts consumed by coverage reasons). Synthetic data only."""

import ast
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from offline_analyzer.cli import private_copy
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.reporting import aws_collection
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures import aws_fake_cloud as fake

COLLECTOR = Path("collectors/aws/assessment.py")
ACCOUNT = fake.fleet_account(0)
FAST = {"backoff_base": 0.01, "backoff_cap": 0.02, "max_attempts": 3}


def collect(tmp_path, cloud, *, regions=("ap-south-1", "eu-west-1"), **kwargs):
    with fake.installed(cloud) as collector:
        cfg = fake.config(tmp_path / "evidence", regions=regions)
        options = collector.resolve_options(cfg, FAST)
        result = collector.collect_account(cfg, ACCOUNT, list(regions), options=options, **kwargs)
        return collector, result


def journal(result):
    lines = Path(result["run_directory"], "operations.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def imported(tmp_path, archive):
    workspace = tmp_path / "work"
    if not workspace.exists():
        set_environment(workspace, "SYNTHETIC")
    store = Store(workspace)
    with private_copy(workspace, Path(archive)) as root:
        run = import_package(store, root)
    assess(store, run)
    return store, run


def test_package_integrity_and_analyzer_import(tmp_path):
    _collector, result = collect(tmp_path, fake.fleet(1), account_name="Synthetic 000")
    archive = Path(result["zip"])
    sidecar = archive.with_name(archive.name + ".sha256")
    digest, name = sidecar.read_text(encoding="utf-8").split()
    assert name == archive.name and digest == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert result["zip_sha256"] == digest
    names = zipfile.ZipFile(archive).namelist()
    assert all("\\" not in n and n.startswith("AWS-EVIDENCE/") for n in names)
    root = Path(result["run_directory"])
    for path in root.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            data.decode("utf-8")  # every file is UTF-8
            assert b"\r\n" not in data, path.name
    manifest = json.loads((root / "manifest.json").read_text())
    assert manifest["collector_version"] == "0.3.3"
    assert manifest["collection_facts"].keys() == aws_collection.FACT_CONSUMERS.keys()
    assert manifest["collection_facts"]["encoding"] == "UTF-8"
    store, run = imported(tmp_path, archive)
    summary = __import__(
        "offline_analyzer.ingestion.collector", fromlist=["stored_summary"]
    ).stored_summary(store.workspace, run)
    assert summary["collection_facts"]["regions_succeeded"] == ["ap-south-1", "eu-west-1"]
    query = "SELECT json_extract_string(data,'$.rule_id') FROM findings WHERE run_id=?"
    rules = {r for (r,) in store.rows(query, [run])}
    assert {"R0-EC2-IMDSV2", "R1-S3-BUCKET-PUBLIC-ACCESS", "SEC-KMS-ROTATION"} <= rules


def test_distinct_statuses_are_journaled_and_never_pass(tmp_path):
    cloud = fake.fleet(1)
    cloud.faults += [
        fake.Fault("guardduty", "list_detectors", "AccessDeniedException", region="ap-south-1"),
        fake.Fault("rds", "describe_db_instances", "Throttling", region="ap-south-1"),
        fake.Fault(
            "config",
            "describe_configuration_recorder_status",
            "ReadTimeoutError",
            region="ap-south-1",
        ),  # fmt: skip
        fake.Fault("securityhub", "describe_hub", "EndpointConnectionError", region="eu-west-1"),
        fake.Fault("macie2", "get_macie_session", "SubscriptionRequiredException"),
    ]
    _collector, result = collect(tmp_path, cloud, regions=("ap-south-1", "eu-west-1", "me-south-1"))
    rows = {(r["service"], r["operation"], r["region"]): r for r in journal(result)}
    assert rows[("guardduty", "list_detectors", "ap-south-1")]["outcome"] == "ACCESS_DENIED"
    throttled = rows[("rds", "describe_db_instances", "ap-south-1")]
    assert throttled["outcome"] == "THROTTLED" and throttled["attempts"] == 3
    assert throttled["retried_statuses"] == ["THROTTLED", "THROTTLED"]
    assert (
        rows[("config", "describe_configuration_recorder_status", "ap-south-1")]["outcome"]
        == "TIMEOUT"
    )
    assert rows[("securityhub", "describe_hub", "eu-west-1")]["outcome"] == "CONNECTION_ERROR"
    assert rows[("macie2", "get_macie_session", "ap-south-1")]["outcome"] == "SERVICE_NOT_IN_USE"
    assert rows[("collector", "region_scope", "me-south-1")]["outcome"] == "REGION_NOT_ENABLED"
    facts = json.loads(Path(result["run_directory"], "manifest.json").read_text())[
        "collection_facts"
    ]
    assert facts["regions_not_enabled"] == ["me-south-1"]
    assert facts["regions_partial"] == ["ap-south-1", "eu-west-1"]
    assert facts["retries"]["total"] >= 6  # one entry per retry, all journaled
    entry = facts["retries"]["entries"][0]
    assert {"service", "operation", "region", "attempt", "status", "code", "delay_seconds"} <= (
        entry.keys()
    )
    store, run = imported(tmp_path, result["zip"])
    outcomes = dict(store.rows(
        "SELECT json_extract_string(data,'$.rule_id') || '@' || coalesce(json_extract_string("
        "data,'$.region'),''), outcome FROM evaluations WHERE run_id=? AND json_extract_string("
        "data,'$.evaluation_scope')='COLLECTION_SCOPE'", [run]))  # fmt: skip
    assert outcomes["SEC-GUARDDUTY-ENABLED@ap-south-1"] != "PASS"
    assert outcomes["SEC-CONFIG-RECORDING@ap-south-1"] != "PASS"
    assert outcomes["SEC-SECURITYHUB-ENABLED@eu-west-1"] != "PASS"
    categories = {}
    for source in store.source_data(run):
        from offline_analyzer.reporting.coverage_reasons import source_category

        if source.get("errors"):
            categories[source["operation"] + "@" + source["region"]] = source_category(source)
    assert categories["guardduty:ListDetectors@ap-south-1"] == "AWS_ACCESS_DENIED"
    assert categories["rds:DescribeDBInstances@ap-south-1"] == "AWS_THROTTLED_AFTER_RETRIES"
    notes = aws_collection.account_notes(store, run)[ACCOUNT]
    assert notes["AWS_REGIONS_NOT_ENABLED"] == 1 and notes["AWS_RETRIES_PERFORMED"] >= 6


def test_retry_then_success_keeps_only_the_final_attempt(tmp_path):
    cloud = fake.fleet(1)
    cloud.faults.append(fake.Fault("ec2", "describe_instances", "RequestLimitExceeded", times=2,
                                   region="ap-south-1"))  # fmt: skip
    _collector, result = collect(tmp_path, cloud)
    row = next(r for r in journal(result) if (r["operation"], r["region"]) == (
        "describe_instances", "ap-south-1"))  # fmt: skip
    assert row["outcome"] == "COMPLETE" and row["attempts"] == 3
    assert len(row["files"]) == 1
    imported(tmp_path, result["zip"])  # no duplicate or stray artifact


def test_organization_chain_with_scp_and_rcp_content(tmp_path):
    cloud = fake.fleet(1)
    cloud.accounts[ACCOUNT].member = False  # delegated administrator access
    _collector, result = collect(tmp_path, cloud)
    rows = journal(result)
    listed = [(r["request_parameters"]["TargetId"], r["request_parameters"]["Filter"])
              for r in rows if r["operation"] == "list_policies_for_target"]  # fmt: skip
    nodes = [ACCOUNT, "ou-syn1-unit0001", fake.ROOT]
    assert listed == [(n, t) for n in nodes for t in ("SERVICE_CONTROL_POLICY",
                                                     "RESOURCE_CONTROL_POLICY")]  # fmt: skip
    described = [r["request_parameters"]["PolicyId"] for r in rows
                 if r["operation"] == "describe_policy"]  # fmt: skip
    assert described == ["p-FullAWSAccess", "p-rcp00000001"]  # each policy once, root included
    facts = json.loads(Path(result["run_directory"], "manifest.json").read_text())[
        "collection_facts"
    ]["organization"]
    assert facts["access"] == "COLLECTED" and facts["hierarchy_reached_root"]
    assert facts["organization_id"] == fake.ORGANIZATION
    assert facts["management_account_id"] == fake.MANAGEMENT
    assert facts["policy_types"]["RESOURCE_CONTROL_POLICY"]["policies_described"] == 1
    store, run = imported(tmp_path, result["zip"])
    from types import SimpleNamespace

    from offline_analyzer.iam.analysis import ORG_KINDS, load
    from offline_analyzer.iam.organizations import OrganizationModel
    from offline_analyzer.rules.aws_identity import organization_note

    holder = SimpleNamespace(
        org=OrganizationModel(load(store, run, ORG_KINDS), list(store.source_data(run)))
    )
    assert organization_note(holder, ACCOUNT) is None  # organization controls assessed
    assert (
        "AWS_ORGANIZATION_ACCESS_MISSING" not in aws_collection.account_notes(store, run)[ACCOUNT]
    )


@pytest.mark.parametrize(
    ("change", "access", "note"),
    [("member", "ACCESS_DENIED", "AWS_ORGANIZATION_ACCESS_MISSING"),
     ("outside", "NOT_IN_ORGANIZATION", "AWS_NOT_IN_ORGANIZATION")],
)  # fmt: skip
def test_missing_organization_access_is_explicit(tmp_path, change, access, note):
    cloud = fake.fleet(1)
    if change == "outside":
        cloud.accounts[ACCOUNT].in_organization = False
    _collector, result = collect(tmp_path, cloud)
    facts = json.loads(Path(result["run_directory"], "manifest.json").read_text())[
        "collection_facts"
    ]["organization"]
    assert facts["access"] == access
    store, run = imported(tmp_path, result["zip"])
    assert aws_collection.account_notes(store, run)[ACCOUNT][note] == 1


def test_expired_credentials_interrupt_then_resume(tmp_path):
    cloud = fake.fleet(1, credential_ttl_calls=60, hub_expires_after=1)
    collector, first = collect(tmp_path, cloud)
    summary = first["summary"]
    assert summary["status"] == "INTERRUPTED"
    assert summary["interruption_reason"] == "CREDENTIALS_EXPIRED"
    rows = journal(first)
    assert rows[-1]["operation"] == "remaining_operations"
    assert rows[-1]["error"]["code"] == "CREDENTIALS_EXPIRED"
    definitive = [r for r in rows if r["outcome"] in {"COMPLETE", "NOT_ENABLED"}]
    cloud.hub_expires_after = None
    cloud.credential_ttl_calls = 10**9
    _collector, second = collect(tmp_path, cloud, resume=first["run_directory"])
    facts = json.loads(Path(second["run_directory"], "manifest.json").read_text())[
        "collection_facts"
    ]
    assert (
        facts["resumed_from"]
        == json.loads(Path(first["run_directory"], "manifest.json").read_text())["collection_id"]
    )
    assert facts["carried_operations"] == len(definitive)
    resumed = journal(second)
    carried = [r for r in resumed if r.get("carried_from")]

    def key(r):
        return r["service"], r["operation"], r["region"], json.dumps(r["request_parameters"])

    assert sorted(map(key, carried)) == sorted(map(key, definitive))
    pairs = zip(sorted(carried, key=key), sorted(definitive, key=key), strict=True)
    assert all(r["files"] == o["files"] for r, o in pairs)
    assert second["summary"]["status"] in {"COMPLETE", "PARTIAL"}
    assert second["summary"]["interruption_reason"] is None
    store, run = imported(tmp_path, second["zip"])
    assert aws_collection.account_notes(store, run)[ACCOUNT]["AWS_COLLECTION_RESUMED"] == len(
        definitive
    )


def test_no_enabled_region_and_role_failure_raise_before_evidence(tmp_path):
    cloud = fake.fleet(1)
    with fake.installed(cloud) as collector:
        cfg = fake.config(tmp_path / "evidence", regions=("me-south-1",))
        with pytest.raises(collector.NoEnabledRegion):
            collector.collect_account(cfg, ACCOUNT, ["me-south-1"])
        cloud.accounts[ACCOUNT].assume_error = "AccessDenied"
        with pytest.raises(collector.AssumeRoleFailed):
            collector.collect_account(fake.config(tmp_path / "evidence"), ACCOUNT, None)
    assert not any((tmp_path / "evidence").glob("*__*"))


def rewrite(root: Path, mutate):
    manifest = json.loads((root / "manifest.json").read_text())
    mutate(manifest)
    (root / "manifest.json").write_text(json.dumps(manifest))
    lines = []
    for line in (root / "checksums.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name == "manifest.json":
            digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (root / "checksums.sha256").write_text("\n".join(lines) + "\n")


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda m: m["collection_facts"].update(unexpected=1), "COLLECTOR_V030_FACTS_INVALID"),
        (lambda m: m.pop("collection_facts"), "COLLECTOR_V030_FACTS_INVALID"),
        (lambda m: m.update(business_group="bad/group"), "COLLECTOR_BUSINESS_GROUP_INVALID"),
        (lambda m: m.update(collector_version="0.3.2"), "COLLECTOR_V030_FACTS_UNSUPPORTED"),
    ],
)
def test_manifest_facts_are_validated(tmp_path, mutate, code):
    from offline_analyzer.ingestion.collector import inspect_collector

    _collector, result = collect(tmp_path, fake.fleet(1))
    root = Path(result["run_directory"])
    rewrite(root, mutate)
    with pytest.raises(InputError, match=code):
        inspect_collector(root)


def test_033_outcomes_are_refused_in_older_journals(tmp_path):
    from offline_analyzer.ingestion.collector import inspect_collector
    from tools.fixtures.aws_v030_native import extend, package

    root = package(tmp_path / "pkg")
    extend(root, [{"service": "kms", "operation": "list_keys", "region": "ap-south-1",
                   "outcome": "THROTTLED", "code": "Throttling"}])  # fmt: skip
    with pytest.raises(InputError, match="COLLECTION_OUTCOME_UNSUPPORTED"):
        inspect_collector(root)


def literal_sets(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            try:
                found[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return found


def test_collector_and_analyzer_tables_are_in_sync():
    collector = literal_sets(COLLECTOR)
    for name in ("THROTTLED", "EXPIRED", "TIMEOUTS", "CONNECTION", "DENIED"):
        analyzer = getattr(aws_collection, name)
        assert set(collector[name]) <= analyzer, name
    assert set(collector["NOT_IN_USE"]) <= aws_collection.NOT_IN_USE
    assert set(collector["CREDENTIAL_ERRORS"]) <= aws_collection.CREDENTIAL_ERRORS
    # Every manifest fact the collector writes has a consumer, and every reason has text.
    tree = ast.parse(COLLECTOR.read_text(encoding="utf-8"))
    function = next(n for n in tree.body if getattr(n, "name", "") == "collection_facts")
    returned = next(n.value for n in ast.walk(function) if isinstance(n, ast.Return))
    keys = {k.value for k in returned.keys}
    assert keys == aws_collection.FACT_CONSUMERS.keys()
    for consumers in aws_collection.FACT_CONSUMERS.values():
        for code in () if consumers == "PROVENANCE" else consumers:
            assert code in aws_collection.NOTE_REASONS or code in aws_collection.ERROR_REASONS
    contract = json.loads(Path("collectors/collector-analyzer-contract.json").read_text())
    aws = contract["providers"][0]
    assert aws["collector_version"] == "0.3.3"
    assert aws["accepted_collector_versions"] == ["0.3.0", "0.3.1", "0.3.2", "0.3.3"]
    assert {"THROTTLED", "REGION_NOT_ENABLED"} <= set(aws["journal"]["outcomes"])
    assert set(aws["manifest_collection_facts"]["consumers"]) == keys
