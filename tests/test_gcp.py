"""Synthetic GCP import-to-review/report and shared multi-cloud correctness gates."""

import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook
from pydantic import ValidationError

from offline_analyzer.api.app import create_app
from offline_analyzer.api.services import Views
from offline_analyzer.contracts.gcp import GCPDataset, GCPManifest
from offline_analyzer.contracts.report_finding import ReportApproval, ReportEdit
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.findings.report_ready import approve_revision, report_detail, save_revision
from offline_analyzer.ingestion.archive import unpack_package
from offline_analyzer.ingestion.gcp import guided_manifest, inspect_package
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.inventory.cloud import relationships
from offline_analyzer.inventory.environment import record_run_origin, set_environment
from offline_analyzer.reporting.cloud import dashboard, methodology_matrix
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.gcp import evaluate
from offline_analyzer.storage.store import Store
from tests.test_api import ORIGIN, TOKEN, authenticated, await_job, upload_package
from tools.fixtures.r12_demo import build as aws_build
from tools.gcp_fixture import PROJECT, TIME, build


def alter(directory: Path, operation: str, payload=None, **changes):
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    dataset = next(d for d in manifest["datasets"] if d["operation"] == operation)
    if payload is not None:
        native = directory / dataset["path"]
        native.write_text(json.dumps(payload))
        dataset.update(
            sha256=sha256_file(native),
            record_count=len(payload) if isinstance(payload, list) else 1,
        )
    dataset.update(changes)
    path.write_text(json.dumps(manifest))


def imported(tmp_path):
    package = build(tmp_path / "gcp")
    store = Store(tmp_path / "work")
    run = import_package(store, package)
    record_run_origin(store.workspace, run, "synthetic")
    assess(store, run)
    return store, run, package


def test_native_vertical_slice_and_scope_denominators(tmp_path):
    store, run, package = imported(tmp_path)
    with store:
        candidates = list(store.candidates(run))
        assert candidates and all(c.provider == "GCP" and c.account_id is None for c in candidates)
        assert {c.rule_id for c in candidates} >= {
            "GCP-API-BOTH",
            "GCP-KEY-PERSISTENT",
            "GCP-KEY-AGE",
            "GCP-KEY-PRIVILEGED",
            "GCP-IAM-BASIC",
            "GCP-IAM-PUBLIC",
            "GCP-IAM-IMPERSONATION",
            "GCP-IAM-CROSSPROJECT",
            "GCP-GOV-KEYS",
            "GCP-LOG-AUDIT",
        }
        assert all(c.evidence for c in candidates)
        assert store.db.execute("SELECT count(*) FROM decisions").fetchone()[0] == 0
        for obs in store.observations(run):
            assert obs.resource_id.startswith("gcp://")
            assert store.refs(run, [obs.observation_id])
        summary = dashboard(store, run)["providers"]["GCP"]
        assert summary["expected_scope_count"] == 2
        assert summary["imported_scope_count"] == summary["assessed_scope_count"] == 1
        assert all(
            r.outcome == "UNKNOWN" for r in store.results(run) if r.project_id == "demo-missing"
        )
        assert relationships(store, run)["items"]
        assert all(
            e["evidence"] and e["authorization"] == "NOT_ESTABLISHED"
            for e in relationships(store, run)["items"]
        )
        assert import_package(store, package) == run


@pytest.mark.parametrize(
    "case,code",
    [
        ("checksum", "ARTIFACT_CHECKSUM_MISMATCH"),
        ("project", "GCP_PROJECT_IDENTITY_MISMATCH"),
        ("secret", "CREDENTIAL_MATERIAL_REJECTED"),
        ("count", "GCP_RECORD_COUNT_MISMATCH"),
        ("unlisted", "GCP_UNLISTED_OR_MISSING_ARTIFACT"),
    ],
)
def test_untrusted_package_refused(tmp_path, case, code):
    package = build(tmp_path / "gcp")
    op = "gcp:apikeys.keys.list"
    if case == "checksum":
        (package / "source-001.json").write_text("[]")
    elif case == "project":
        alter(
            package,
            op,
            [{"name": "projects/other-project/locations/global/keys/key", "restrictions": {}}],
        )
    elif case == "secret":
        alter(
            package, op, [{"name": "projects/demo-alpha/keys/key", "keyString": "synthetic-secret"}]
        )
    elif case == "count":
        alter(package, op, record_count=500)
    else:
        (package / "unlisted.json").write_text("{}")
    with Store(tmp_path / "work") as store:
        with pytest.raises(InputError, match=code):
            import_package(store, package)
        assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


@pytest.mark.parametrize(
    "status",
    [
        "SUCCESS",
        "EMPTY",
        "PARTIAL",
        "ACCESS_DENIED",
        "NOT_COLLECTED",
        "FAILED",
        "UNKNOWN",
        "UNSUPPORTED",
        "NOT_APPLICABLE",
    ],
)
def test_collection_statuses_and_empty_do_not_pass(tmp_path, status):
    package = build(tmp_path / "gcp")
    op = "gcp:apikeys.keys.list"
    if status in {"SUCCESS", "EMPTY", "PARTIAL"}:
        alter(
            package,
            op,
            []
            if status == "EMPTY"
            else [{"name": "projects/demo-alpha/keys/demo", "restrictions": {}}],
            status=status,
            pagination_complete=status != "PARTIAL",
        )
    else:
        manifest = json.loads((package / "manifest.json").read_text())
        dataset = next(d for d in manifest["datasets"] if d["operation"] == op)
        (package / dataset["path"]).unlink()
        dataset.update(
            path=None, sha256=None, record_count=0, status=status, pagination_complete=False
        )
        (package / "manifest.json").write_text(json.dumps(manifest))
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        scopes = [
            r
            for r in store.results(run)
            if r.project_id == PROJECT
            and r.rule_id == "GCP-API-BOTH"
            and r.evaluation_scope == "COLLECTION_SCOPE"
        ]
        assert all(r.outcome != "PASS" for r in scopes)
        if status == "EMPTY":
            assert scopes[0].outcome == "NOT_APPLICABLE"
        if status not in {"SUCCESS", "EMPTY"}:
            assert scopes[0].outcome == "UNKNOWN"


def test_pagination_guided_import_and_unsupported_inventory(tmp_path):
    package = build(tmp_path / "gcp")
    alter(
        package,
        "gcp:apikeys.keys.list",
        {"keys": [], "nextPageToken": "synthetic-page"},
        record_count=0,
        status="PARTIAL",
        pagination_complete=False,
    )
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        assert any(
            r.rule_id == "GCP-API-BOTH" and r.outcome == "UNKNOWN" for r in store.results(run)
        )
    raw = tmp_path / "manual"
    raw.mkdir()
    (raw / "keys.json").write_text('[{"name":"projects/demo-alpha/keys/demo","restrictions":{}}]')
    with pytest.raises(InputError, match="GCP_GUIDED_SOURCE_REQUIRED"):
        guided_manifest(raw, ["keys.json"], {})
    guided_manifest(
        raw, ["keys.json"], {"project_id": PROJECT, "operation": "gcp:apikeys.keys.list"}
    )
    package, diagnostics = inspect_package(raw)
    assert package.sources[0].gcp_metadata["provenance"] == "manual-unverified"
    assert diagnostics["sources"][0]["effective_coverage"] == "PARTIAL"


@pytest.mark.parametrize(
    "operation",
    [
        "gcp:apikeys.keys.list",
        "gcp:iam.serviceAccountKeys.list",
        "gcp:projects.getIamPolicy",
        "gcp:orgpolicy.getEffectivePolicy",
    ],
)
def test_positive_negative_and_incomplete_context(tmp_path, operation):
    store, run, _ = imported(tmp_path)
    with store:
        obs = next(
            o
            for o in store.observations(run)
            if o.operation == operation and o.resource_type != "GCP::IAMPolicy"
        )
        context = list(store.observations(run))
        if operation == "gcp:apikeys.keys.list":
            assert evaluate("GCP-API-BOTH", obs).outcome == "FAIL"
            negative = obs.model_copy(
                update={
                    "configuration": {
                        "restrictions": {
                            "apiTargets": [{"service": "maps.googleapis.com"}],
                            "serverKeyRestrictions": {"allowedIps": ["192.0.2.1"]},
                        }
                    }
                }
            )
            assert evaluate("GCP-API-BOTH", negative).outcome == "PASS"
            assert evaluate("GCP-API-APP", negative).outcome == "PASS"
            assert evaluate("GCP-API-API", negative).outcome == "PASS"
            assert (
                evaluate("GCP-API-BOTH", obs.model_copy(update={"configuration": {}})).outcome
                == "UNKNOWN"
            )
        elif operation == "gcp:iam.serviceAccountKeys.list":
            assert evaluate("GCP-KEY-PERSISTENT", obs).outcome == "FAIL"
            assert evaluate("GCP-KEY-AGE", obs).outcome == "FAIL"
            assert evaluate("GCP-KEY-PRIVILEGED", obs, context).outcome == "FAIL"
            assert (
                evaluate(
                    "GCP-KEY-AGE",
                    obs.model_copy(
                        update={"configuration": {**obs.configuration, "validAfterTime": TIME}}
                    ),
                ).outcome
                == "PASS"
            )
            assert (
                evaluate(
                    "GCP-KEY-PERSISTENT",
                    obs.model_copy(update={"configuration": {"keyType": "SYSTEM_MANAGED"}}),
                ).outcome
                == "NOT_APPLICABLE"
            )
            assert (
                evaluate(
                    "GCP-KEY-AGE",
                    obs.model_copy(update={"configuration": {"keyType": "USER_MANAGED"}}),
                ).outcome
                == "UNKNOWN"
            )
        elif operation == "gcp:projects.getIamPolicy":
            obs = next(
                o
                for o in context
                if o.resource_type == "GCP::IAMBinding" and o.configuration["role"] == "roles/owner"
            )
            assert evaluate("GCP-IAM-BASIC", obs).outcome == "FAIL"
            assert (
                evaluate(
                    "GCP-IAM-BASIC",
                    obs.model_copy(
                        update={"configuration": {**obs.configuration, "role": "roles/viewer"}}
                    ),
                ).outcome
                == "PASS"
            )
            assert (
                evaluate(
                    "GCP-IAM-BASIC",
                    obs.model_copy(
                        update={
                            "configuration": {
                                **obs.configuration,
                                "condition": {"expression": "true"},
                            }
                        }
                    ),
                ).outcome
                == "UNKNOWN"
            )
        else:
            assert evaluate("GCP-GOV-KEYS", obs).outcome == "FAIL"
            assert (
                evaluate(
                    "GCP-GOV-KEYS",
                    obs.model_copy(
                        update={
                            "configuration": {
                                **obs.configuration,
                                "booleanPolicy": {"enforced": True},
                            }
                        }
                    ),
                ).outcome
                == "PASS"
            )
            assert (
                evaluate(
                    "GCP-GOV-KEYS",
                    obs.model_copy(
                        update={"configuration": {**obs.configuration, "_parameters": {}}}
                    ),
                ).outcome
                == "UNKNOWN"
            )


def approve(store, run, finding):
    record_decision(
        store, run, finding.finding_id, "CONFIRMED", "synthetic-reviewer", "Synthetic validation"
    )
    sections = report_detail(store, run, finding.finding_id)["sections"]
    revision = save_revision(
        store,
        run,
        finding.finding_id,
        ReportEdit(
            expected_revision=0,
            analyst="synthetic-reviewer",
            sections=sections,
            member_ids=[finding.finding_id],
            include_in_report=True,
        ),
    )
    for kind in ("RECOMMENDATION", "NARRATIVE"):
        revision = approve_revision(
            store,
            run,
            finding.finding_id,
            ReportApproval(
                expected_revision=revision.revision, analyst="synthetic-reviewer", kind=kind
            ),
        )
    return revision


def test_shared_approvals_consolidated_exports_and_reopen(tmp_path):
    store, run, _ = imported(tmp_path)
    workspace = store.workspace
    with store:
        finding = next(c for c in store.candidates(run) if c.rule_id == "GCP-API-BOTH")
        approve(store, run, finding)
        aws_build(tmp_path / "aws")
        aws_run = import_package(store, tmp_path / "aws")
        record_run_origin(workspace, aws_run, "synthetic")
        combined = assess_enterprise(store, [run, aws_run])
        summary = dashboard(store, combined)
        assert summary["providers"]["AWS"]["candidate_findings"] == 8
        assert summary["providers"]["GCP"]["approved_findings"] == 1
        assert {c.provider for c in store.candidates(combined)} == {"AWS", "GCP"}
        assert not any(
            e["source"].startswith("arn:") or e["destination"].startswith("arn:")
            for e in relationships(store, combined)["items"]
        )
        views = Views(workspace)
        assert (
            views.records(store, combined, "findings", "", "", "", 0, 100, {"provider": "GCP"})[
                "total"
            ]
            == summary["providers"]["GCP"]["candidate_findings"]
        )
        for kind in ("excel", "approved-rtf", "approved-text"):
            export = views.export(store, combined, kind)
            file = (
                workspace
                / "reports"
                / (
                    export["id"]
                    + {"excel": ".xlsx", "approved-rtf": ".rtf", "approved-text": ".txt"}[kind]
                )
            )
            assert file.stat().st_size > 0
            if kind == "excel":
                wb = load_workbook(file, read_only=True)
                rows = list(wb["Unified Findings Register"].values)[3:]
                assert len(rows) == sum(
                    p["candidate_findings"] for p in summary["providers"].values()
                )
                assert {row[1] for row in rows} == {"AWS", "GCP"}
                wb.close()
            if kind == "approved-text":
                assert PROJECT in file.read_text() and finding.title in file.read_text()
    with Store(workspace) as reopened:
        assert dashboard(reopened, combined)["providers"]["GCP"]["approved_findings"] == 1
    assert len(methodology_matrix()["controls"]) == 204
    assert all(not r["full_control_coverage"] for r in methodology_matrix()["implementations"])


def test_gcp_zip_folder_guided_api_and_origin_isolation(tmp_path):
    package = build(tmp_path / "gcp")
    archive = tmp_path / "package.zip"
    with zipfile.ZipFile(archive, "w") as out:
        for file in package.iterdir():
            out.write(file, "package/" + file.name)
    dest = tmp_path / "extracted"
    dest.mkdir()
    assert inspect_package(unpack_package(archive, dest))[0]
    app = create_app(tmp_path / "work", origin=ORIGIN, bootstrap=TOKEN)
    with TestClient(app, base_url=ORIGIN) as client:
        headers = authenticated(client)
        response = client.post(
            "/api/uploads",
            headers=headers,
            files=[("files", ("package.zip", archive.read_bytes(), "application/zip"))],
            data={"paths": '["package.zip"]', "context": '{"origin":"synthetic","provider":"GCP"}'},
        )
        assert response.status_code == 200, response.text
        preview = response.json()
        run = await_job(
            client,
            client.post("/api/import", headers=headers, json={"upload_id": preview["upload_id"]}),
        )["run_id"]
        await_job(client, client.post(f"/api/runs/{run}/assess", headers=headers, json={}))
        assert (
            client.get(f"/api/runs/{run}/cloud/dashboard?provider=GCP").json()["providers"]["GCP"][
                "candidate_findings"
            ]
            > 0
        )
        assert client.get(f"/api/runs/{run}/cloud/paths").json()["items"]
        assert upload_package(client, headers, package).json()["can_import"]
        assert client.get("/api/gcp/contract").status_code == 200
    private = tmp_path / "assessment"
    set_environment(private, "ASSESSMENT")
    with Store(private) as store:
        with pytest.raises(InputError, match="ASSESSMENT_WORKSPACE_REJECTS_SYNTHETIC"):
            import_package(store, package)
        manifest = json.loads((package / "manifest.json").read_text())
        manifest["dataset_origin"] = "tool-generated"
        (package / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(InputError, match="GCP_SYNTHETIC_ORIGIN_CONFLICT"):
            import_package(store, package)


def test_manifest_incomplete_success_rejected():
    with pytest.raises(ValidationError):
        GCPDataset(
            project_id=PROJECT,
            operation="gcp:apikeys.keys.list",
            status="SUCCESS",
            record_count=0,
            path="keys.json",
            sha256="0" * 64,
            pagination_complete=False,
        )
    with pytest.raises(ValidationError):
        GCPManifest(
            collector_version="test",
            assessment_id="test",
            expected_projects=[PROJECT],
            collected_projects=["demo-beta"],
            dataset_origin="synthetic",
            datasets=[],
        )


@pytest.mark.parametrize(
    "rule_id",
    [
        "GCP-API-APP",
        "GCP-API-API",
        "GCP-API-BOTH",
        "GCP-KEY-PERSISTENT",
        "GCP-KEY-AGE",
        "GCP-KEY-PRIVILEGED",
        "GCP-IAM-BASIC",
        "GCP-IAM-PUBLIC",
        "GCP-IAM-IMPERSONATION",
        "GCP-IAM-CROSSPROJECT",
        "GCP-GOV-KEYS",
        "GCP-LOG-AUDIT",
        "GCP-LOG-EXCLUSION",
        "GCP-SCC-OBSERVATION",
    ],
)
def test_each_rule_positive_negative_incomplete_unsupported_and_provenance(tmp_path, rule_id):
    from offline_analyzer.rules.gcp import BY_ID

    store, run, _ = imported(tmp_path)
    with store:
        context = list(store.observations(run))
        spec = BY_ID[rule_id]
        choices = [o for o in context if o.resource_type == spec.resource_type]
        if rule_id == "GCP-SCC-OBSERVATION":
            base = next(o for o in context if o.resource_type == "GCP::APIKey")
            obs = base.model_copy(
                update={
                    "resource_type": spec.resource_type,
                    "configuration": {
                        "state": "ACTIVE",
                        "category": "SYNTHETIC_OBSERVATION",
                        "resourceName": base.native_id,
                    },
                }
            )
        elif rule_id == "GCP-API-APP":
            obs = choices[0].model_copy(
                update={
                    "configuration": {
                        "restrictions": {"apiTargets": [{"service": "maps.googleapis.com"}]}
                    }
                }
            )
        elif rule_id == "GCP-API-API":
            obs = choices[0].model_copy(
                update={
                    "configuration": {
                        "restrictions": {"serverKeyRestrictions": {"allowedIps": ["192.0.2.1"]}}
                    }
                }
            )
        else:
            obs = next(o for o in choices if evaluate(rule_id, o, context).outcome == "FAIL")
        positive = evaluate(rule_id, obs, context)
        assert positive.outcome == "FAIL"
        assert obs.evidence and store.refs(run, [obs.observation_id])
        assert spec.provider == "GCP" and spec.version
        if rule_id.startswith("GCP-API-"):
            negative = {
                "restrictions": {
                    "apiTargets": [{"service": "maps.googleapis.com"}],
                    "serverKeyRestrictions": {"allowedIps": ["192.0.2.1"]},
                }
            }
            unsupported = {"restrictions": {"apiTargets": "unsupported"}}
        elif rule_id.startswith("GCP-KEY-"):
            negative = {"keyType": "USER_MANAGED", "disabled": True}
            unsupported = {"keyType": "UNSUPPORTED"}
        elif rule_id.startswith("GCP-IAM-"):
            negative = {
                "role": "roles/viewer",
                "members": ["user:approved@example.invalid"],
                "subject": "projects/demo-alpha",
            }
            unsupported = {
                "role": "projects/demo-alpha/roles/custom",
                "members": ["allUsers"],
                "condition": {"expression": "unsupported()"},
            }
        elif rule_id == "GCP-GOV-KEYS":
            negative = {**obs.configuration, "booleanPolicy": {"enforced": True}}
            unsupported = {"constraint": "constraints/unsupported"}
        elif rule_id == "GCP-LOG-AUDIT":
            negative = {"auditConfigs": []}
            unsupported = {"auditConfigs": "unsupported"}
        elif rule_id == "GCP-LOG-EXCLUSION":
            negative = {"disabled": True}
            unsupported = {"filter": "severity < ERROR"}
        else:
            negative = {"state": "INACTIVE"}
            unsupported = {"state": "UNSUPPORTED"}
        assert (
            evaluate(rule_id, obs.model_copy(update={"configuration": negative}), context).outcome
            != "FAIL"
        )
        assert evaluate(rule_id, obs.model_copy(update={"configuration": {}}), []).outcome in {
            "UNKNOWN",
            "NOT_APPLICABLE",
        }
        assert evaluate(
            rule_id, obs.model_copy(update={"configuration": unsupported}), []
        ).outcome in {"UNKNOWN", "NOT_APPLICABLE"}


def test_unknown_operations_retained_and_backup_restores_shared_review(tmp_path):
    from offline_analyzer.release_audit import audit
    from offline_analyzer.storage.backup import backup, restore

    package = build(tmp_path / "gcp")
    manifest = json.loads((package / "manifest.json").read_text())
    source = next(
        d for d in manifest["datasets"] if d["operation"] == "gcp:serviceusage.services.list"
    )
    source.update(
        operation="gcp:unsupported.resources.list",
        parser_profile="unsupported",
        status="UNSUPPORTED",
    )
    (package / "manifest.json").write_text(json.dumps(manifest))
    workspace = tmp_path / "work"
    with Store(workspace) as store:
        run = import_package(store, package)
        record_run_origin(workspace, run, "synthetic")
        assess(store, run)
        assert any(o.resource_type == "GCP::Unsupported" for o in store.observations(run))
        finding = next(c for c in store.candidates(run) if c.rule_id == "GCP-API-BOTH")
        approve(store, run, finding)
    assert audit(workspace, run)["result"] == "PASS"
    backup(workspace, tmp_path / "backup")
    restore(tmp_path / "backup", tmp_path / "restored")
    with Store(tmp_path / "restored") as store:
        assert dashboard(store, run)["providers"]["GCP"]["approved_findings"] == 1
    assert audit(tmp_path / "restored", run)["result"] == "PASS"


def extra_dataset(directory, operation, payload, parameters=None):
    manifest = json.loads((directory / "manifest.json").read_text())
    name = f"extra-{len(manifest['datasets'])}.json"
    path = directory / name
    path.write_text(json.dumps(payload))
    manifest["datasets"].append(
        GCPDataset(
            project_id=PROJECT,
            operation=operation,
            parameters=parameters or {},
            started_at=TIME,
            completed_at=TIME,
            status="SUCCESS",
            pagination_complete=True,
            record_count=len(payload) if isinstance(payload, list) else 1,
            path=name,
            sha256=sha256_file(path),
        ).model_dump(mode="json")
    )
    (directory / "manifest.json").write_text(json.dumps(manifest))


@pytest.mark.parametrize(
    "context,expected",
    [
        ("unenforced", "FAIL"),
        ("enforced", "PASS"),
        ("missing", "UNKNOWN"),
        ("unsupported", "UNKNOWN"),
    ],
)
def test_storage_public_binding_with_effective_prevention_context(tmp_path, context, expected):
    package = build(tmp_path / "gcp")
    extra_dataset(
        package,
        "gcp:storage.buckets.getIamPolicy",
        {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        {"subject": "buckets/demo-bucket"},
    )
    extra_dataset(
        package,
        "gcp:storage.buckets.list",
        [
            {
                "name": "demo-bucket",
                "iamConfiguration": {
                    "publicAccessPrevention": "enforced" if context == "enforced" else "inherited"
                },
            }
        ],
    )
    if context in {"unenforced", "unsupported"}:
        extra_dataset(
            package,
            "gcp:orgpolicy.getEffectivePolicy",
            {
                "constraint": "constraints/storage.publicAccessPrevention",
                "booleanPolicy": {"enforced": False} if context == "unenforced" else None,
            },
            {"constraint": "constraints/storage.publicAccessPrevention", "effective": "true"},
        )
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        result = next(
            r
            for r in store.results(run)
            if r.rule_id == "GCP-STORAGE-PUBLIC"
            and r.native_id
            and r.native_id.startswith("buckets/")
        )
        assert result.outcome == expected
        if expected == "FAIL":
            assert len(result.evidence) == 3
            finding = next(c for c in store.candidates(run) if c.rule_id == "GCP-STORAGE-PUBLIC")
            assert finding.finding_class == "POTENTIAL_EXPOSURE" and finding.missing_evidence
        binding = next(
            o
            for o in store.observations(run)
            if o.resource_type == "GCP::IAMBinding" and o.native_id.startswith("buckets/")
        )
        negative = binding.model_copy(
            update={
                "configuration": {
                    **binding.configuration,
                    "members": ["user:approved@example.invalid"],
                }
            }
        )
        assert (
            evaluate("GCP-STORAGE-PUBLIC", negative, list(store.observations(run))).outcome
            == "PASS"
        )
        conditional = binding.model_copy(
            update={
                "configuration": {**binding.configuration, "condition": {"expression": "unknown"}}
            }
        )
        assert evaluate("GCP-STORAGE-PUBLIC", conditional, []).outcome == "UNKNOWN"


@pytest.mark.parametrize(
    "case,status",
    [
        ("equivalent", "EQUIVALENT_NATIVE_CONDITION"),
        ("stale", "STALE_OR_UNRESOLVED_TIME"),
        ("different", "SUPPLEMENTARY_UNCORRELATED"),
        ("contradictory", "CONTRADICTORY_NATIVE_SNAPSHOT"),
    ],
)
def test_scc_native_exact_deduplication_and_contradiction(tmp_path, case, status):
    from offline_analyzer.correlation.gcp import scc_correlations

    package = build(tmp_path / "gcp")
    key = json.loads((package / "source-004.json").read_text())[0]
    if case == "contradictory":
        alter(package, "gcp:iam.serviceAccountKeys.list", [{**key, "validAfterTime": TIME}])
    finding = {
        "name": "organizations/123/sources/456/findings/synthetic-key",
        "category": "SERVICE_ACCOUNT_KEY_NOT_ROTATED",
        "state": "ACTIVE",
        "resourceName": "//iam.googleapis.com/"
        + (key["name"] if case != "different" else key["name"] + "-other"),
        "severity": "CRITICAL",
        "eventTime": "2020-01-01T00:00:00Z" if case == "stale" else TIME,
    }
    alter(package, "gcp:securitycenter.findings.list", [{"finding": finding}], status="SUCCESS")
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        correlation = scc_correlations(store, run)[0]
        assert correlation["status"] == status
        assert correlation["original_severity"] == "CRITICAL"
        original = next(o for o in store.observations(run) if o.resource_type == "GCP::SCCFinding")
        assert (
            original.source_finding_id == finding["name"] and original.source_severity == "CRITICAL"
        )
        scc_candidates = [c for c in store.candidates(run) if c.rule_id == "GCP-SCC-OBSERVATION"]
        if case == "equivalent":
            assert not scc_candidates
            native = next(c for c in store.candidates(run) if c.rule_id == "GCP-KEY-AGE")
            assert original.evidence in native.evidence
        else:
            assert scc_candidates and scc_candidates[0].suggested_severity == "MEDIUM"
            assert scc_candidates[0].review_status == "CANDIDATE"


def test_guided_numeric_resource_names_ask_for_the_project_number(tmp_path):
    keys = '[{"name":"projects/222222222222/locations/global/keys/demo","restrictions":{}}]'
    settings = {"project_id": PROJECT, "operation": "gcp:apikeys.keys.list"}
    for number, code in (
        (None, "GCP_PROJECT_NUMBER_REQUIRED"),
        ("333333333333", "GCP_PROJECT_IDENTITY_MISMATCH"),
        ("222222222222", None),
    ):
        raw = tmp_path / f"manual-{number}"
        raw.mkdir()
        (raw / "keys.json").write_text(keys)
        guided_manifest(raw, ["keys.json"], {**settings, "project_number": number})
        with Store(tmp_path / f"work-{number}") as store:
            if code is None:
                assert import_package(store, raw)
                continue
            with pytest.raises(InputError, match=code) as caught:
                import_package(store, raw)
            assert caught.value.identity_context["observed_identity"] == "222222222222"
            assert caught.value.identity_context["file"] == "keys.json"
            assert store.db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
