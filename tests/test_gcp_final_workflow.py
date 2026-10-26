"""Synthetic acceptance: preserved B1/B2, independent paths, delta composition and QA."""

import json
import threading
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from clogcp_delta.collector import DeltaError, collect, command, decode, load
from clogcp_delta.models import Plan, Request
from clogcp_delta.planner import plan_missing
from offline_analyzer.api.app import create_app
from offline_analyzer.attack_paths.versioned import latest, recalculate
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.evidence.composition import compose, description
from offline_analyzer.findings.finalisation import freeze
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.findings.sre import record_sre
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import set_environment
from offline_analyzer.storage.side_by_side import (
    compatible,
    database_inventory,
    file_inventory,
    recover_copy,
)
from offline_analyzer.storage.store import Store
from tools.gcp_fixture import build

NOW = datetime(2026, 10, 26, tzinfo=UTC)
MATRIX_HASH = "a" * 64
PROJECTS = ["demo-alpha", "demo-bravo"]


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()

    def collect(self, request, quota):
        with self.lock:
            self.calls.append((request.operation, request.resource))
        if request.operation == "BUCKET_IAM":
            return (
                {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
                "COMPLETE",
                True,
            )
        if request.operation == "FOLDER_METADATA":
            return {"name": request.resource, "parent": "organizations/123"}, "COMPLETE", True
        if request.operation == "FOLDER_IAM":
            return {"bindings": []}, "COMPLETE", True
        if request.operation == "DISCOVERY_ENGINES":
            return (
                [
                    {
                        "name": request.resource + "/engines/synthetic-engine",
                        "displayName": "Synthetic",
                    }
                ],
                "COMPLETE",
                True,
            )
        return None, "QUOTA_PROJECT_DENIED", False


def delta_plan():
    requests = []
    for i, project in enumerate(PROJECTS):
        for op, resource in [
            ("BUCKET_IAM", "synthetic-bucket-" + str(i)),
            ("FOLDER_METADATA", "folders/12345"),
            ("FOLDER_IAM", "folders/12345"),
            ("DISCOVERY_ENGINES", f"projects/{project}/locations/global/collections/synthetic"),
            ("DISCOVERY_DATASTORES", f"projects/{project}/locations/global/collections/synthetic"),
        ]:
            requests.append(
                Request(
                    request_id=f"synthetic-{i}-{op}",
                    project_id=project,
                    operation=op,
                    resource=resource,
                )
            )
    return Plan(
        approved_by="Synthetic analyst",
        approved_at=NOW,
        matrix_sha256=MATRIX_HASH,
        catalogue_reconciled=True,
        requests=requests,
        requests_per_second_per_api=10,
    )


@pytest.fixture
def baseline(tmp_path):
    work = tmp_path / "original"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        b1 = import_package(store, build(tmp_path / "b1", PROJECTS[0], "111111111111"))
        b1_import = b1
        b1 = assess_enterprise(store, [b1_import])
        candidates = list(store.candidates(b1))
        assert candidates
        record_decision(store, b1, candidates[0].finding_id, "CONFIRMED", "Synthetic", "B1")
        record_sre(store, b1, [candidates[0].finding_id], "GAP_CONFIRMED", "Synthetic SRE", "B1")
        freeze(store, b1, "Synthetic", True)
        b2 = import_package(store, build(tmp_path / "b2", PROJECTS[1], "222222222222"))
        # This assessment existed before the upgrade. Acceptance must not rebuild it.
        existing = assess_enterprise(store, [b1_import, b2])
    (work / "reports").mkdir(exist_ok=True)
    (work / "reports" / "original-report.txt").write_text("Synthetic frozen report")
    return work, b1, b2, existing


def test_side_by_side_open_and_independent_recalculation_preserve_every_record(
    baseline, tmp_path, monkeypatch
):
    original, b1, b2, run = baseline
    before_files, before_tables = file_inventory(original), database_inventory(original)
    copy = tmp_path / "upgraded"
    report = recover_copy(original, copy)
    assert report["recovery_verified"] and report["tables"] == before_tables
    # Opening the new application cannot migrate or regenerate assessment records.
    copied_files = file_inventory(copy)
    origin = "http://127.0.0.1:8765"
    with TestClient(
        create_app(copy, origin=origin, bootstrap="synthetic"), base_url=origin
    ) as client:
        session = client.post(
            "/api/session", json={}, headers={"Origin": origin, "X-Bootstrap-Token": "synthetic"}
        )
        headers = {"Origin": origin, "X-CSRF-Token": session.json()["csrf"]}
        assert client.get("/api/runs").status_code == 200
        assert database_inventory(copy) == before_tables
        assert all(file_inventory(copy).get(k) == v for k, v in copied_files.items())

        def forbidden(*args, **kwargs):
            raise AssertionError(
                "Path-only action invoked an import, security analysis or enterprise rebuild"
            )

        monkeypatch.setattr("offline_analyzer.rules.engine.assess", forbidden)
        monkeypatch.setattr("offline_analyzer.ingestion.importer.import_package", forbidden)
        monkeypatch.setattr("offline_analyzer.enterprise.snapshot.build_snapshot", forbidden)
        for selected in (b1, run, run):
            response = client.post(
                f"/api/runs/{selected}/attack-path-evaluations", headers=headers, json={}
            )
            assert response.status_code == 200, response.text
            result = response.json()
            assert not any(
                result[k]
                for k in [
                    "findings_modified",
                    "analyst_sre_validations_modified",
                    "security_analysis_rerun",
                    "evidence_reimported",
                    "enterprise_rebuilt",
                ]
            )
            assert (
                client.get(f"/api/runs/{selected}/attack-path-evaluations").json()["latest"][
                    "evaluation_id"
                ]
                == result["evaluation_id"]
            )
    assert len(latest(copy, run)["versions"]) == 2
    assert latest(copy, run)["latest"]["prior_kind"] == "VERSIONED_PATH_EVALUATION"
    assert database_inventory(copy) == before_tables
    assert all(file_inventory(copy).get(k) == v for k, v in copied_files.items())
    assert file_inventory(original) == before_files
    assert database_inventory(original) == before_tables


def test_multiscope_delta_import_composition_export_and_independent_finalizer(baseline, tmp_path):
    from zipfile import ZipFile

    from clogcp_report_finalizer.core import finalize
    from offline_analyzer.reporting.assessment_report import export_assessment

    original, b1, b2, run = baseline
    before_files = file_inventory(original)
    work = tmp_path / "upgraded"
    recover_copy(original, work)
    before = database_inventory(work)
    baseline_paths = recalculate(work, run)
    transport, plan = FakeTransport(), delta_plan()
    package = tmp_path / "delta"
    manifest = collect(
        plan,
        package,
        execute=True,
        transport=transport,
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    assert len(manifest.results) == 10 and len(transport.calls) == 8
    assert sum(r.state == "QUOTA_PROJECT_DENIED" for r in manifest.results) == 2
    with Store(work) as store:
        delta = import_package(store, package)
        assert import_package(store, package) == delta
        derived = compose(store, run, delta)
        assert compose(store, run, delta) == derived
        details = description(store, derived)
        assert details["temporally_mixed"] and not details["simultaneous_state_established"]
        assert details["reconciliation"]
        assert len(list(store.candidates(derived))) == len(
            {f.finding_id for f in store.candidates(derived)}
        )
        assert all(not r["approval_copied"] for r in details["reconciliation"])
        destination = tmp_path / "consolidated.zip"
        export_assessment(
            store, derived, destination, include="valid", provider="GCP", grouped=False
        )
    recalculated = recalculate(work, derived)
    assert recalculated["new_path_count"]
    assert recalculated["prior_kind"] == "BASE_ANALYSIS_PATH_EVALUATION"
    assert recalculated["comparison_base_run"] == run
    assert recalculated["old_path_count"] == baseline_paths["new_path_count"]
    assert all(p["classification"] != "SUPPORTED" for p in latest(work, derived)["paths"])
    with ZipFile(destination) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".xlsx"))
        source = tmp_path / "consolidated.xlsx"
        source.write_bytes(archive.read(name))
    final = finalize(source, tmp_path / "client", origin="SYNTHETIC")
    assert final["client_observations"] > 0 and final["qa_issues"] > 0
    assert (tmp_path / "client" / "Assessor-QA-Exceptions.json").is_file()
    # Appending new versions changes only their rows; original rows and every review stay exact.
    with Store(work, read_only=True) as store, Store(original, read_only=True) as old:
        for (table,) in old.db.execute("SHOW TABLES").fetchall():
            previous = old.db.execute(f'SELECT * FROM "{table}"').fetchall()
            current = store.db.execute(f'SELECT * FROM "{table}"').fetchall()
            assert set(previous) <= set(current), table
        assert database_inventory(original) == before
    assert file_inventory(original) == before_files


def test_planner_skips_success_does_not_guess_missing_resource_names():
    matrix = {
        "bucket_iam": [{"project": PROJECTS[0], "bucket_count": 2}],
        "folder_iam": [{"folder": "12345", "projects": PROJECTS}],
        "discovery_configuration": PROJECTS,
    }
    inventory = [
        {
            "project_id": PROJECTS[0],
            "operation": "gcp:storage.buckets.getIamPolicy",
            "request_parameters": {"subject": "buckets/synthetic-one"},
            "effective_coverage": "COMPLETE",
        }
    ]
    plan, pending = plan_missing(
        matrix,
        inventory,
        selected_projects=PROJECTS,
        selected_folders=["folders/12345"],
        approved_by="Synthetic",
        approved_at=NOW,
        matrix_sha256=MATRIX_HASH,
    )
    assert len(plan.requests) == 4
    assert len(pending) == 3
    assert all(r.operation.startswith("FOLDER") for r in plan.requests)


def test_delta_dry_run_integrity_retries_and_scope_limits(tmp_path):
    plan = delta_plan()
    result = collect(plan, tmp_path / "dry", origin="synthetic")
    assert not result.executed and all(r.state == "NOT_COLLECTED" for r in result.results)
    assert all(not r.file for r in result.results)
    with pytest.raises(DeltaError, match="MATRIX_HASH"):
        collect(
            plan, tmp_path / "bad", execute=True, transport=FakeTransport(), matrix_sha256="b" * 64
        )
    assert not (tmp_path / "bad").exists()
    with pytest.raises(ValueError, match="RESOURCE_OUTSIDE"):
        Request(
            request_id="bad",
            project_id=PROJECTS[0],
            operation="DISCOVERY_RESOURCE",
            resource=f"projects/{PROJECTS[1]}/locations/global/collections/a/engines/b",
        )
    for request in plan.requests:
        cmd = command(request, None)
        if cmd:
            assert not {"set-iam-policy", "enable", "add-iam-policy-binding"}.intersection(cmd)
    with pytest.raises(DeltaError, match="DUPLICATE_JSON_KEY"):
        decode(b'{"a":1,"a":2}')

    class Retry(FakeTransport):
        def collect(self, request, quota):
            self.calls.append((request.operation, request.resource))
            return (
                (None, "API_ERROR", False)
                if len(self.calls) < 3
                else ({"bindings": []}, "COMPLETE", True)
            )

    transport = Retry()
    retry = collect(
        plan.model_copy(update={"requests": plan.requests[:1]}),
        tmp_path / "retry",
        execute=True,
        transport=transport,
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    assert len(transport.calls) == 3 and retry.results[0].state == "COMPLETE"
    altered = tmp_path / "retry" / retry.results[0].file
    altered.write_text('{"bindings":[{}]}')
    from offline_analyzer.ingestion.gcp_delta import inspect_package

    with pytest.raises(InputError, match="CHECKSUM"):
        inspect_package(tmp_path / "retry")


def test_compatibility_rejects_pending_recovery_without_changes(baseline):
    work, *_ = baseline
    (work / ".scope-journal.json").write_text("{}")
    before = file_inventory(work)
    with pytest.raises(InputError, match="EXPLICIT_WORKSPACE_RECOVERY"):
        compatible(work)
    assert file_inventory(work) == before


@pytest.mark.parametrize("case", ["newer", "older", "same-time-conflict", "equivalent", "denied"])
def test_policy_precedence_and_failed_attempts_preserve_baseline(case, tmp_path):
    from offline_analyzer.contracts.gcp import GCPDataset, GCPManifest
    from offline_analyzer.ingestion.safety import sha256_file

    package = build(tmp_path / "base")
    policy = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
    (package / "bucket.json").write_text(json.dumps(policy))
    base_time = datetime(2026, 10, 25, tzinfo=UTC)
    manifest = GCPManifest.model_validate_json((package / "manifest.json").read_bytes())
    additional = GCPDataset(
        project_id=PROJECTS[0],
        operation="gcp:storage.buckets.getIamPolicy",
        parameters={"subject": "buckets/synthetic-bucket"},
        started_at=base_time,
        completed_at=base_time,
        status="SUCCESS",
        record_count=1,
        path="bucket.json",
        sha256=sha256_file(package / "bucket.json"),
        pagination_complete=True,
        normalized_resource_types=["GCP::IAMPolicy"],
        applicable_rules=[],
    )
    manifest = manifest.model_copy(update={"datasets": (*manifest.datasets, additional)})
    (package / "manifest.json").write_text(manifest.model_dump_json())
    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    request = Request(
        request_id="synthetic-bucket",
        project_id=PROJECTS[0],
        operation="BUCKET_IAM",
        resource="synthetic-bucket",
    )
    plan = delta_plan().model_copy(update={"requests": [request]})

    class Change:
        def collect(self, request, quota):
            if case == "denied":
                return None, "DENIED", False
            return policy if case == "equivalent" else {"bindings": []}, "COMPLETE", True

    delta_directory = tmp_path / "delta"
    collected = collect(
        plan,
        delta_directory,
        execute=True,
        transport=Change(),
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    when = datetime(
        2026, 10, 24 if case == "older" else 25 if case == "same-time-conflict" else 26, tzinfo=UTC
    )
    collected = collected.model_copy(
        update={
            "results": [
                r.model_copy(update={"started_at": when, "completed_at": when})
                for r in collected.results
            ]
        }
    )
    (delta_directory / "manifest.json").write_text(collected.model_dump_json())
    with Store(work) as store:
        base = import_package(store, package)
        delta = import_package(store, delta_directory)
        baseline_rows = store.db.execute(
            "SELECT * FROM observations WHERE run_id=?", [base]
        ).fetchall()
        derived = compose(store, base, delta)
        policies = [
            o
            for o in store.observations(derived)
            if o.resource_type == "GCP::IAMPolicy" and o.native_id == "buckets/synthetic-bucket"
        ]
        if case in {"denied", "same-time-conflict"}:
            assert not policies
        elif case in {"older", "equivalent"}:
            assert len(policies) == 1 and policies[0].configuration["bindings"]
        else:
            assert len(policies) == 1 and not policies[0].configuration["bindings"]
        assert description(store, derived)["events"]
        assert (
            store.db.execute("SELECT * FROM observations WHERE run_id=?", [base]).fetchall()
            == baseline_rows
        )
        from offline_analyzer.enterprise.validation import validate_snapshot

        assert validate_snapshot(store, derived)["status"] == "PASS"


def test_discovery_pagination_retries_and_partial_failures_are_bounded(monkeypatch):
    from types import SimpleNamespace
    from urllib.error import HTTPError

    from clogcp_delta.collector import Transport

    monkeypatch.setattr("clogcp_delta.collector.shutil.which", lambda _: "/synthetic/gcloud")
    auth_calls = []

    def auth(args, **kwargs):
        auth_calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"synthetic-memory-only-token-123456")

    monkeypatch.setattr("clogcp_delta.collector.subprocess.run", auth)
    monkeypatch.setattr("clogcp_delta.collector.time.sleep", lambda _: None)
    request = Request(
        request_id="synthetic-paged",
        project_id=PROJECTS[0],
        operation="DISCOVERY_ENGINES",
        resource=f"projects/{PROJECTS[0]}/locations/global/collections/synthetic",
    )
    responses = [
        HTTPError("https://synthetic.invalid", 429, "synthetic", {}, None),
        {
            "engines": [{"name": request.resource + "/engines/one"}],
            "nextPageToken": "synthetic-next",
        },
        {"engines": [{"name": request.resource + "/engines/two"}]},
    ]
    seen = []

    class Response:
        def __init__(self, value):
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, maximum):
            assert maximum <= 16 * 1024 * 1024 + 1
            return json.dumps(self.value).encode()

    class Opener:
        def open(self, http_request, **kwargs):
            seen.append(http_request.full_url)
            value = responses.pop(0)
            if isinstance(value, Exception):
                # HTTPError.read needs a bounded, passive body.
                import io

                value.fp = io.BytesIO(b"quota exceeded")
                raise value
            return Response(value)

    monkeypatch.setattr("clogcp_delta.collector.build_opener", lambda *_: Opener())
    transport = Transport()
    transport.limiter.wait = lambda _: None
    value, state, complete = transport.collect(request, "demo-quota")
    assert state == "COMPLETE" and complete and len(value) == 2
    assert len(seen) == 3 and "pageToken=synthetic-next" in seen[-1]
    assert auth_calls[0][1]["capture_output"]
    responses[:] = [
        {"engines": [{"name": request.resource + "/engines/one"}], "nextPageToken": "still-more"}
    ]
    transport.max_pages = 1
    _, state, complete = transport.collect(request, None)
    assert state == "PARTIAL" and not complete


def test_delta_redacts_sensitive_fields_before_persistence(tmp_path):
    plan = delta_plan().model_copy(update={"requests": delta_plan().requests[:1]})

    class Redaction:
        def collect(self, request, quota):
            return (
                {
                    "bindings": [],
                    "keyString": "synthetic-sensitive-value",
                    "privateKeyData": "synthetic-sensitive-value",
                },
                "COMPLETE",
                True,
            )

    result = collect(
        plan,
        tmp_path / "delta",
        execute=True,
        transport=Redaction(),
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    assert result.results[0].state == "PARTIAL" and result.results[0].redacted_fields == 2
    assert not result.results[0].pagination_complete
    assert all(
        "synthetic-sensitive-value" not in p.read_text()
        for p in (tmp_path / "delta").rglob("*.json")
    )


def test_interrupted_new_version_resumes_without_touching_baseline(baseline, tmp_path, monkeypatch):
    from offline_analyzer.evidence import composition

    work, _, _, base = baseline
    collect(
        delta_plan(),
        tmp_path / "delta",
        execute=True,
        transport=FakeTransport(),
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    with Store(work) as store:
        delta = import_package(store, tmp_path / "delta")
        old_rows = store.db.execute("SELECT * FROM findings WHERE run_id=?", [base]).fetchall()
        old_reviews = store.db.execute("SELECT * FROM decisions").fetchall()
        real_assess = composition.assess

        def interrupted(*args):
            raise InputError("SYNTHETIC_INTERRUPTION")

        monkeypatch.setattr(composition, "assess", interrupted)
        with pytest.raises(InputError, match="SYNTHETIC_INTERRUPTION"):
            compose(store, base, delta)
        count = store.db.execute("SELECT count(*) FROM runs").fetchone()[0]
        monkeypatch.setattr(composition, "assess", real_assess)
        resumed = compose(store, base, delta)
        assert compose(store, base, delta) == resumed
        assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == count
        assert description(store, resumed)["materialized_sha256"]
        assert (
            store.db.execute("SELECT * FROM findings WHERE run_id=?", [base]).fetchall() == old_rows
        )
        assert store.db.execute("SELECT * FROM decisions").fetchall() == old_reviews


def test_inventory_recovers_observed_scope_when_legacy_parameters_are_absent(tmp_path):
    from offline_analyzer.evidence.inventory import export_inventory

    collect(
        delta_plan(),
        tmp_path / "delta",
        execute=True,
        transport=FakeTransport(),
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        imported = import_package(store, tmp_path / "delta")
        # Model an older adapter's absent folder/Discovery request parameters. The
        # immutable source files and observed resource names still identify the scope.
        for sid, raw in store.db.execute(
            "SELECT source_id,data FROM sources WHERE run_id=?", [imported]
        ).fetchall():
            source = json.loads(raw)
            source["request_parameters"] = {}
            store.db.execute(
                "UPDATE sources SET data=? WHERE run_id=? AND source_id=?",
                [json.dumps(source), imported, sid],
            )
    before = file_inventory(work)
    path = tmp_path / "inventory.json"
    export_inventory(work, imported, path)
    assert file_inventory(work) == before
    matrix = {
        "folder_iam": [{"folder": "12345", "projects": PROJECTS}],
        "discovery_configuration": PROJECTS,
    }
    plan, pending = plan_missing(
        matrix,
        load(path),
        selected_projects=PROJECTS,
        selected_folders=["folders/12345"],
        approved_by="Synthetic",
        approved_at=NOW,
        matrix_sha256=MATRIX_HASH,
    )
    assert not pending
    assert plan and {r.operation for r in plan.requests} == {"DISCOVERY_DATASTORES"}
    assert len(plan.requests) == 2


def test_versioned_export_honors_provider_scope_and_review_decisions(baseline, tmp_path):
    from zipfile import ZipFile

    from offline_analyzer.reporting.assessment_report import export_assessment

    work, _, _, run = baseline
    recalculate(work, run)
    paths = latest(work, run)["paths"]
    assert {p["project_id"] for p in paths} == set(PROJECTS)
    linked = next(p for p in paths if p["project_id"] == PROJECTS[1] and p["original_finding_ids"])
    rejected = linked["original_finding_ids"][0]
    with Store(work) as store:
        record_decision(store, run, rejected, "REJECTED", "Synthetic", "Synthetic report policy")
        for provider, scope, include in [
            ("GCP", PROJECTS[0], "valid"),
            ("GCP", "", "confirmed"),
            ("AWS", "", "valid"),
        ]:
            output = tmp_path / f"{provider}-{scope}-{include}.zip"
            export_assessment(
                store, run, output, include=include, provider=provider, scope=scope, grouped=False
            )
            with ZipFile(output) as z:
                if provider == "AWS":
                    assert "attack-path-evaluation-v2.json" not in z.namelist()
                    continue
                exported = json.loads(z.read("attack-path-evaluation-v2.json"))
                if scope:
                    assert exported["paths"]
                assert all(not scope or p["project_id"] == scope for p in exported["paths"])
                assert all(rejected not in p["original_finding_ids"] for p in exported["paths"])
                if include == "confirmed":
                    approved = {
                        f.finding_id
                        for f in store.candidates(run)
                        if store.latest_decision(f.finding_id)
                        and store.latest_decision(f.finding_id).status == "CONFIRMED"
                    }
                    assert all(set(p["original_finding_ids"]) & approved for p in exported["paths"])
                assert exported["evaluation"]["new_path_count"] == len(exported["paths"])


def test_discovery_known_project_number_alias_is_scoped_and_normalized(tmp_path):
    from offline_analyzer.ingestion.gcp_delta import inspect_package

    number = "111111111111"
    parent = f"projects/{PROJECTS[0]}/locations/global/collections/synthetic"
    numeric = parent.replace(PROJECTS[0], number)
    inventory = [{"project_id": PROJECTS[0], "project_number": number}]
    plan, _ = plan_missing(
        {"discovery_configuration": [PROJECTS[0]]},
        inventory,
        selected_projects=[PROJECTS[0]],
        selected_folders=[],
        approved_by="Synthetic",
        approved_at=NOW,
        matrix_sha256=MATRIX_HASH,
        discovery_scopes={PROJECTS[0]: [parent, numeric]},
    )
    assert len(plan.requests) == 2
    assert all(r.project_number == number for r in plan.requests)

    class NumericResponse:
        def collect(self, request, quota):
            suffix = (
                "/engines/synthetic"
                if request.operation == "DISCOVERY_ENGINES"
                else "/dataStores/synthetic"
            )
            return [{"name": numeric + suffix}], "COMPLETE", True

    package = tmp_path / "delta"
    collect(
        plan,
        package,
        execute=True,
        transport=NumericResponse(),
        matrix_sha256=MATRIX_HASH,
        origin="synthetic",
    )
    inspect_package(package)
    work = tmp_path / "work"
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        imported = import_package(store, package)
        assert all(
            o.native_id.startswith(f"projects/{PROJECTS[0]}/") for o in store.observations(imported)
        )
    with pytest.raises(ValueError, match="RESOURCE_OUTSIDE"):
        Request(
            request_id="unknown-number",
            project_id=PROJECTS[0],
            project_number=number,
            operation="DISCOVERY_ENGINES",
            resource=numeric.replace(number, "222222222222"),
        )
