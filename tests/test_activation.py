"""Synthetic activation regressions; no customer package/schema or Windows execution."""

import importlib.util
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from offline_analyzer.api.app import create_app
from offline_analyzer.ingestion.archive import unpack_package
from offline_analyzer.ingestion.collector import inspect_collector, sanitized, stored_summary
from offline_analyzer.ingestion.collector_v030 import probe
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.pilot import main as pilot
from offline_analyzer.storage.store import Store
from tests.test_api import ORIGIN, TOKEN, authenticated, await_job
from tests.test_collector import fixture
from tools.fixtures.r12_demo import build

spec = importlib.util.spec_from_file_location("v030_fixture", "tools/collector_v030_fixture.py")
v030 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v030)


@pytest.fixture
def package(tmp_path):
    build(tmp_path / "native")
    original = fixture.convert(tmp_path / "native", tmp_path / "canonical")[0]
    return v030.convert(original, tmp_path / "v030")


def rows(package):
    return [json.loads(line) for line in (package / "operations.jsonl").read_text().splitlines()]


def rewrite(package, data):
    (package / "operations.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data))
    v030.checksums(package)


def zipped(package):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for p in package.rglob("*"):
            if p.is_file():
                archive.writestr("package/" + p.relative_to(package).as_posix(), p.read_bytes())
    return data.getvalue()


def test_v030_adapter_reuses_importer_preserves_original_outcomes(package, tmp_path):
    loaded, summary = inspect_collector(package)
    assert loaded.sources and summary["collector_schema_verified"] is False
    assert sum(summary["original_outcomes"].values()) == len(rows(package))
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assert import_package(store, package) == run
    assert stored_summary(tmp_path / "work", run) == summary
    public = json.dumps(sanitized(summary))
    assert "111111111111" not in public and "responses/" not in public
    assert "transport_digests" not in public and "original_outcome" in public


@pytest.mark.parametrize("transport", ["folder", "zip"])
def test_v030_finder_metadata_preserves_declared_checksums(package, tmp_path, transport):
    (package / ".DS_Store").write_bytes(b"Synthetic OS metadata")
    if transport == "zip":
        archive = tmp_path / "evidence.zip"
        archive.write_bytes(zipped(package))
        package = unpack_package(archive, tmp_path / "expanded")
    loaded, summary = inspect_collector(package)
    assert loaded.sources and summary["original_outcomes"]
    data = rows(package)
    output = next(row["path"] for row in data if row.get("path"))
    (package / output).write_text("{}")
    with pytest.raises(InputError, match="ARTIFACT_CHECKSUM_MISMATCH"):
        inspect_collector(package)


@pytest.mark.parametrize(
    "case",
    [
        "checksum",
        "unlisted",
        "traversal",
        "duplicate_key",
        "missing_time",
        "unknown_outcome",
        "missing_pages",
    ],
)
def test_v030_rejects_invalid_transport_or_profile(package, case):
    data = rows(package)
    if case == "checksum":
        (package / data[0]["path"]).write_text("{}")
    elif case == "unlisted":
        (package / "unchecked.json").write_text("{}")
    elif case == "traversal":
        (package / "checksums.sha256").write_text("0" * 64 + "  ../outside.json\n")
    elif case == "duplicate_key":
        (package / "operations.jsonl").write_text(
            '{"operation":"ec2:DescribeInstances","operation":"ec2:DescribeInstances"}\n'
        )
        v030.checksums(package)
    else:
        if case == "missing_time":
            data[0].pop("completed_at")
        elif case == "unknown_outcome":
            data[0]["status"] = "UNKNOWN"
        else:
            data[0].pop("pages")
        rewrite(package, data)
    with pytest.raises((InputError, ValueError)):
        inspect_collector(package)


def test_local_probe_retains_all_286_attempts_without_inventing_schema(package, tmp_path):
    template = rows(package)[0]
    statuses = {
        "COMPLETE": 229,
        "NOT_ENABLED": 27,
        "API_ERROR": 8,
        "NOT_COLLECTED": 17,
        "ACCESS_DENIED": 4,
        "PARTIAL": 1,
    }
    data = [
        {**template, "status": status} for status, count in statuses.items() for _ in range(count)
    ]
    for r in data:
        r.pop("completed_at")  # Probe is useful before the real layout is established.
    rewrite(package, data)
    result = probe(package)
    assert result["attempts"] == 286 and result["original_outcomes"] == statuses
    assert result["index_rows_missing_required_fields"] == 286
    assert (
        pilot(
            [
                "--package",
                str(package),
                "--output",
                str(tmp_path / "probe"),
                "--origin",
                "synthetic",
                "--expected-attempts",
                "286",
            ]
        )
        == 2
    )
    report = json.loads((tmp_path / "probe/CloSec-pilot-compatibility.json").read_text())
    assert report["index_probe"]["attempts"] == 286
    assert "111111111111" not in json.dumps(report)


def test_pilot_zip_pipeline_reconciles_without_approvals(package, tmp_path):
    archive = tmp_path / "transport.zip"
    archive.write_bytes(zipped(package))
    output = tmp_path / "pilot"
    assert (
        pilot(
            [
                "--package",
                str(archive),
                "--output",
                str(output),
                "--origin",
                "synthetic",
                "--execute",
                "--workspace",
                str(tmp_path / "work"),
            ]
        )
        == 0
    )
    report = json.loads((output / "CloSec-pilot-compatibility.json").read_text())
    assert report["assessment"]["excel_reconciled"]
    assert report["assessment"]["release_audit"]["result"] == "PASS"
    assert report["assessment"]["approvals_created"] == 0
    assert report["real_export_validation"] == "NOT_ESTABLISHED"
    assert "111111111111" not in json.dumps(report)


def test_zip_ancillary_files_only_allowed_inside_collector_transport(package, tmp_path):
    archive = tmp_path / "transport.zip"
    archive.write_bytes(zipped(package))
    expanded = tmp_path / "expanded"
    expanded.mkdir()
    root = unpack_package(archive, expanded)
    assert (root / "scanners/prowler/synthetic/execution.log").is_file()
    with zipfile.ZipFile(archive, "a") as z:
        z.writestr("package/scanners/execute.py", "print('unsafe')")
    clean = tmp_path / "clean"
    clean.mkdir()
    with pytest.raises(InputError, match="JSON_ONLY"):
        unpack_package(archive, clean)
    assert not list(clean.iterdir())


def test_known_pilot_outcomes_remain_unknown_or_absent_not_service_wide(package):
    data = rows(package)
    template = {k: data[0][k] for k in ("region", "started_at", "completed_at")}
    data.extend(
        [
            {
                **template,
                "operation": "cloudtrail:GetEventSelectors",
                "status": "API_ERROR",
                "error_code": "InvalidParameterException",
            },
            {
                **template,
                "operation": "s3:GetBucketReplication",
                "status": "API_ERROR",
                "error_code": "ReplicationConfigurationNotFoundError",
            },
            {
                **template,
                "operation": "kms:GetKeyPolicy",
                "region": "global",
                "status": "ACCESS_DENIED",
                "error_code": "AccessDeniedException",
                "request_parameters": {"KeyId": "synthetic-key", "PolicyName": "default"},
            },
            {
                **template,
                "operation": "organizations:ListRoots",
                "region": "global",
                "status": "ACCESS_DENIED",
                "error_code": "AccessDeniedException",
            },
            {
                **template,
                "operation": "macie2:GetMacieSession",
                "status": "ACCESS_DENIED",
                "error_code": "AccessDeniedException",
            },
            {**template, "operation": "cloudsplaining:Scan", "status": "NOT_COLLECTED"},
            {**template, "operation": "steampipe:Scan", "status": "NOT_COLLECTED"},
        ]
    )
    rewrite(package, data)
    loaded, summary = inspect_collector(package)
    assert next(s for s in loaded.sources if s.operation == "kms:GetKeyPolicy").coverage == "ERROR"
    outcomes = {r["operation"]: r for r in summary["operations"]}
    assert "ABSENT" in outcomes["s3api:GetBucketReplication"]["interpretation"]
    assert outcomes["s3api:GetBucketReplication"]["original_outcome"] == "API_ERROR"
    assert "TRAILNAME" in outcomes["cloudtrail:GetEventSelectors"]["interpretation"]
    assert "SERVICE_STATE_UNKNOWN" in outcomes["macie2:GetMacieSession"]["interpretation"]
    assert "UNRESOLVED" in outcomes["organizations:ListRoots"]["interpretation"]


def test_outside_region_artifact_is_not_assessed(package, tmp_path):
    data = rows(package)
    row = next(r for r in data if r["path"] and r["operation"] != "prowler:Scan")
    operation, path = row["operation"], row["path"]
    row["resource_region"] = "ap-south-1"
    rewrite(package, data)
    loaded, summary = inspect_collector(package)
    assert all(s.path != path for s in loaded.sources)
    result = next(r for r in summary["operations"] if r["operation"] == operation)
    assert result["interpretation"] == "RESOURCE_OUTSIDE_APPROVED_REGION_NOT_ASSESSED"


def test_v030_api_zip_import_and_workspace_isolation(package, tmp_path):
    app = create_app(tmp_path / "work", origin=ORIGIN, bootstrap=TOKEN)
    with TestClient(app, base_url=ORIGIN) as client:
        headers = authenticated(client)
        response = client.post(
            "/api/uploads",
            headers=headers,
            files=[("files", ("v030.zip", zipped(package), "application/zip"))],
            data={"paths": '["v030.zip"]', "context": '{"origin":"synthetic"}'},
        )
        assert response.status_code == 200, response.text
        preview = response.json()
        assert preview["can_import"] and preview["collection"]["original_outcomes"]
        job = client.post("/api/import", headers=headers, json={"upload_id": preview["upload_id"]})
        assert await_job(client, job)["run_id"]
    set_environment(tmp_path / "assessment", "ASSESSMENT")
    with (
        Store(tmp_path / "assessment") as store,
        pytest.raises(InputError, match="ASSESSMENT_WORKSPACE_REJECTS_SYNTHETIC"),
    ):
        import_package(store, package)


def test_v030_folder_import_preserves_transport_and_framework_outputs(package, tmp_path):
    compliance = package / "scanners/prowler/synthetic/compliance/framework.csv"
    compliance.parent.mkdir()
    compliance.write_text("synthetic,framework output\n")
    v030.checksums(package)
    with TestClient(
        create_app(tmp_path / "work", origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN
    ) as client:
        headers = authenticated(client)
        paths = sorted(p for p in package.rglob("*") if p.is_file())
        response = client.post(
            "/api/uploads",
            headers=headers,
            files=[("files", (p.name, p.read_bytes(), "application/octet-stream")) for p in paths],
            data={
                "paths": json.dumps([p.relative_to(package).as_posix() for p in paths]),
                "context": '{"origin":"synthetic"}',
            },
        )
        assert response.status_code == 200
        preview = response.json()
        assert preview["can_import"]
        assert preview["collection"]["totals"]["operations"] == len(rows(package))
        assert (
            compliance.relative_to(package).as_posix()
            not in preview["collection"]["unlisted_files"]
        )
        job = client.post("/api/import", headers=headers, json={"upload_id": preview["upload_id"]})
        assert await_job(client, job)["run_id"]
        saved = tmp_path / "work/uploads" / preview["upload_id"]
        assert {p.relative_to(package): p.read_bytes() for p in paths} == {
            p.relative_to(saved): p.read_bytes() for p in saved.rglob("*") if p.is_file()
        }


def test_v030_missing_optional_summaries_do_not_block_native_evidence(package):
    for name in ("collection-summary.json", "retry-requests.json"):
        (package / name).unlink()
    v030.checksums(package)
    loaded, summary = inspect_collector(package)
    assert loaded.sources and summary["totals"]["operations"] == len(rows(package))


def test_partial_prowler_5261_remains_usable(package, tmp_path):
    from offline_analyzer.verification import verify_package
    from tools.fixtures.demo import build_package

    build_package(tmp_path / "scanner")
    events = json.loads((tmp_path / "scanner/prowler.json").read_text())
    for event in events:
        event["metadata"]["product"]["version"] = "5.26.1"
    (package / "partial-scanner.json").write_text(json.dumps(events))
    data = rows(package)
    template = data[0]
    data.append(
        {
            "operation": "prowler:Scan",
            "region": template["region"],
            "started_at": template["started_at"],
            "completed_at": template["completed_at"],
            "status": "PARTIAL",
            "pages": 1,
            "path": "partial-scanner.json",
            "format": "prowler-ocsf-5.26.1",
            "tool_version": "5.26.1",
            "error_code": "networkfirewall_logging_enabled",
        }
    )
    rewrite(package, data)
    package_data, summary = inspect_collector(package)
    scanner = next(s for s in package_data.sources if s.format == "prowler-ocsf-5.26.1")
    assert scanner.coverage == "PARTIAL"
    diagnostics = verify_package(package, origin="synthetic")
    scan = next(s for s in diagnostics["sources"] if s["profile"] == "prowler-ocsf-5.26.1")
    assert scan["parser_accepted"] and scan["normalized_resource_records"] > 0
    assert summary["operations"][-1]["original_error_code"] == "networkfirewall_logging_enabled"
    assert diagnostics["real_export_validation"] == "NOT_ESTABLISHED"


def test_finding_triage_filters_and_stale_validation_are_consistent(tmp_path):
    from offline_analyzer.api.services import Views
    from offline_analyzer.findings.generate import record_decision, validation_status
    from offline_analyzer.rules.engine import assess

    build(tmp_path / "input")
    with Store(tmp_path / "work") as store:
        run = import_package(store, tmp_path / "input")
        assess(store, run)
        views = Views(store.workspace)
        finding = next(store.candidates(run))
        record_decision(store, run, finding.finding_id, "CONFIRMED", "synthetic-reviewer", "review")
        filters = {
            "finding_class": finding.finding_class,
            "security_domain": finding.security_domain,
            "evidence_confidence": finding.evidence_confidence,
            "resource": finding.native_id,
            "validation": "CONFIRMED",
            "priority": True,
        }
        matched = views.records(
            store,
            run,
            "findings",
            "",
            finding.account_id,
            finding.suggested_severity,
            0,
            100,
            filters,
        )
        assert any(f["finding_id"] == finding.finding_id for f in matched["items"])
        assert all(f["analyst_status"] == "CONFIRMED" for f in matched["items"])
        changed = finding.model_copy(
            update={"technical_observation": "Changed synthetic evidence conclusion"}
        )
        store.db.execute(
            "UPDATE findings SET data=? WHERE run_id=? AND finding_id=?",
            [changed.model_dump_json(), run, changed.finding_id],
        )
        assert validation_status(store, changed)[0] == "NEEDS_REVALIDATION"
        assert views.records(store, run, "findings", "", "", "", 0, 100, filters)["total"] == 0
        filters["validation"] = "NEEDS_REVALIDATION"
        stale = views.records(store, run, "findings", "", "", "", 0, 100, filters)
        assert stale["items"][0]["analyst_status"] == "NEEDS_REVALIDATION"
        candidates = views.records(
            store,
            run,
            "findings",
            "",
            "",
            "",
            0,
            100,
            {"priority": True, "validation": "CANDIDATE"},
        )
        assert all(f["finding_id"] != finding.finding_id for f in candidates["items"])
        ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        assert [ranks[f["suggested_severity"]] for f in candidates["items"]] == sorted(
            ranks[f["suggested_severity"]] for f in candidates["items"]
        )
