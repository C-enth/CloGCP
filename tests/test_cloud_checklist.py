"""Shared checklist classification, organization-wide GCP rules and cross-scope paths.

All identities, projects and domains are synthetic.
"""

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

from offline_analyzer.attack_paths.cross import cross_paths
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.inventory.environment import record_run_origin
from offline_analyzer.methodology.cloud_checklist import (
    AWS,
    GCP,
    TITLES,
    applies,
    control_ids,
    describe,
    matrix,
)
from offline_analyzer.methodology.coverage_spec import BY_CONTROL
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.registry import PROVIDER_RULES
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import expanded22

# PROD is the collected project of the synthetic package; OPS is outside the collection.
PROD, OPS = ("sample-project", "123456789012"), ("ops-tools", "222222222222")
ORG = "organizations/123"


def record(resource: str, asset: str, project, bindings: list[tuple[str, list[str]]]) -> dict:
    return {
        "resource": resource,
        "assetType": asset,
        "project": f"projects/{project[1]}",
        "organization": ORG,
        "policy": {"bindings": [{"role": r, "members": m} for r, m in bindings]},
    }


ORG_SEARCH = [
    record(
        f"//cloudresourcemanager.googleapis.com/projects/{PROD[0]}",
        "cloudresourcemanager.googleapis.com/Project",
        PROD,
        [
            ("roles/owner", ["user:alice@example.com"]),
            (
                "roles/editor",
                [
                    f"serviceAccount:{PROD[1]}-compute@developer.gserviceaccount.com",
                    f"serviceAccount:{PROD[1]}@cloudservices.gserviceaccount.com",
                    f"serviceAccount:deployer@{OPS[0]}.iam.gserviceaccount.com",
                ],
            ),
            ("roles/iam.serviceAccountUser", ["user:vendor@partner.example"]),
            (
                "roles/iam.serviceAccountTokenCreator",
                [f"serviceAccount:firebase-adminsdk-abcde@{PROD[0]}.iam.gserviceaccount.com"],
            ),
            ("roles/viewer", ["deleted:user:gone@example.com?uid=1"]),
        ],
    ),
    record(
        f"//cloudresourcemanager.googleapis.com/projects/{OPS[0]}",
        "cloudresourcemanager.googleapis.com/Project",
        OPS,
        [
            (
                "roles/iam.serviceAccountTokenCreator",
                [f"serviceAccount:firebase-adminsdk-fghij@{OPS[0]}.iam.gserviceaccount.com"],
            )
        ],
    ),
    record(
        f"//run.googleapis.com/projects/{PROD[0]}/locations/us-central1/services/web",
        "run.googleapis.com/Service",
        PROD,
        [("roles/run.invoker", ["allUsers"])],
    ),
    record(
        f"//iam.googleapis.com/projects/{OPS[0]}/serviceAccounts/bridge@{OPS[0]}.iam.gserviceaccount.com",
        "iam.googleapis.com/ServiceAccount",
        OPS,
        [
            (
                "roles/iam.workloadIdentityUser",
                [
                    f"principalSet://iam.googleapis.com/projects/{OPS[1]}/locations/global/"
                    "workloadIdentityPools/aws-pool/attribute.aws_role/"
                    "arn:aws:sts::123456789012:assumed-role/bridge-role"
                ],
            )
        ],
    ),
]


@pytest.fixture(scope="module")
def org_run(tmp_path_factory):
    root = tmp_path_factory.mktemp("org")
    package = expanded22(root / "package")
    manifest_path = package / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for item in manifest["datasets"]:
        if item["dataset"] == "organization_123_iam_search":
            if item.get("error_file"):
                (package / item["error_file"]).unlink(missing_ok=True)
            item.update(
                status="SUCCESS",
                file="inventory/organization_123_iam_search.json",
                error_file=None,
                record_count=len(ORG_SEARCH),
            )
            (package / item["file"]).write_text(json.dumps(ORG_SEARCH))
        elif item["dataset"] == "asset_iam_search" and item.get("file"):
            # A real project-scope search returns the same policy as the org-scope search.
            (package / item["file"]).write_text(json.dumps(ORG_SEARCH[:1]))
            item["record_count"] = 1
    manifest_path.write_text(json.dumps(manifest))
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(package).as_posix()}"
        for p in sorted(
            p for p in package.rglob("*") if p.is_file() and p.name != "checksums.sha256"
        )
    ]
    (package / "checksums.sha256").write_text("\n".join(lines) + "\n")
    store = Store(root / "work")
    store.__enter__()
    run = import_package(store, package)
    record_run_origin(root / "work", run, "synthetic")
    assess(store, run)
    yield store, run
    store.__exit__(None, None, None)


def test_every_control_is_classified_for_both_clouds():
    ids = control_ids()
    assert len(ids) == 204 and set(ids) == set(TITLES)
    for control in ids:
        assert describe(control)["checklist_domain"] and describe(control)["checklist_title"]
    # Directory, on-premises and device controls are outside cloud evidence.
    assert applies("2.3.1") == applies("3.1.1") == applies("4.2.1") == ()
    assert applies("1.6.4") == (GCP,) and applies("AWS-15") == (AWS,)
    assert applies("1.5.2") == (AWS, GCP)


def test_every_rule_maps_to_one_checklist_control():
    for rule in PROVIDER_RULES:
        link = rule.methodology
        assert link and link.control_id in BY_CONTROL, rule.rule_id
        assert link.criteria and not link.full_coverage
        assert rule.provider in applies(link.control_id), rule.rule_id


def test_org_rules_cover_only_the_collected_project(org_run):
    """ADR-010: org-wide search results outside the collected project are never stored."""
    store, run = org_run
    observed = Counter((r.rule_id, str(r.outcome)) for r in store.results(run))
    assert observed[("GCP-ORG-PUBLIC-SERVERLESS", "FAIL")] == 1
    assert observed[("GCP-ORG-IMPERSONATION", "FAIL")] == 1
    assert observed[("GCP-ORG-DELETED-PRINCIPAL", "FAIL")] == 1
    assert observed[("GCP-ORG-EXTERNAL-DOMAIN", "MANUAL_VALIDATION_REQUIRED")] == 2
    # Basic roles on the collected project are evaluated by the project IAM rules.
    assert not observed[("GCP-ORG-BASIC-ROLE", "FAIL")]
    findings = {(f.rule_id, f.project_id): f for f in store.candidates(run)}
    assert {project for _, project in findings} == {PROD[0]}
    # A grant containing a non-Firebase principal keeps HIGH.
    assert findings[("GCP-ORG-IMPERSONATION", PROD[0])].suggested_severity == "HIGH"
    stored = [o.model_dump(mode="json") for o in store.observations(run)]
    resources = [str(o["configuration"].get("resource", "")) for o in stored]
    assert not any(f"projects/{OPS[0]}" in r for r in resources)
    assert OPS[1] not in json.dumps(stored)
    for finding in store.candidates(run):
        assert finding.methodology_id and finding.mapping_status == "PROPOSED"
        assert finding.review_status == "CANDIDATE"


def test_collected_scope_filter():
    from types import SimpleNamespace

    from offline_analyzer.normalization.gcp_expanded import in_collected_scope

    source = SimpleNamespace(project_id="p-1", project_number="42")
    parents = {"organizations/7", "folders/8"}
    keep = [
        {"project": "projects/42", "resource": "//storage.googleapis.com/bucket"},
        {"resource": "//cloudresourcemanager.googleapis.com/projects/p-1"},
        {"resource": "//cloudresourcemanager.googleapis.com/organizations/7"},
        {"resource": "//cloudresourcemanager.googleapis.com/folders/8"},
    ]
    drop = [
        {"project": "projects/99", "resource": "//run.googleapis.com/projects/other/x"},
        {"resource": "//cloudresourcemanager.googleapis.com/projects/other"},
        {"resource": "//cloudresourcemanager.googleapis.com/folders/9"},
        {"resource": "//storage.googleapis.com/bucket-without-project"},
    ]
    assert all(in_collected_scope(r, source, parents) for r in keep)
    assert not any(in_collected_scope(r, source, parents) for r in drop)


def test_checklist_matrix_never_passes_and_marks_absent_clouds(org_run):
    store, run = org_run
    rows = {r["control_id"]: r for r in matrix(store.results(run), assessed={GCP})}
    assert all(r[p]["outcome"] != "PASS" for r in rows.values() for p in ("aws", "gcp"))
    assert rows["1.6.4"]["gcp"]["outcome"] == "FAIL"
    assert rows["1.9.3"]["gcp"]["outcome"] == "FAIL"
    assert rows["1.6.5"]["aws"]["outcome"] == "NOT ASSESSED"
    assert rows["3.1.1"]["gcp"]["outcome"] == "NOT APPLICABLE"
    assert rows["7.4.1"]["gcp"]["outcome"] in {"MANUAL VALIDATION", "INSUFFICIENT EVIDENCE"}


def test_attack_paths_stay_within_the_collected_project(org_run):
    store, run = org_run
    paths = cross_paths(store, run)
    kinds = Counter((p["attack_path"], p["feasibility"]) for p in paths)
    # An invoker binding alone does not resolve ingress and service restrictions.
    assert kinds[("XP-03", "INSUFFICIENT_EVIDENCE")] == 1
    impersonation = [p for p in paths if p["attack_path"] == "XP-01"]
    assert any("vendor@partner.example" in p["steps"][0] for p in impersonation)
    assert all(p["feasibility"] == "INSUFFICIENT_EVIDENCE" for p in impersonation)
    # The AWS bridge was granted on a service account in an uncollected project.
    assert not [p for p in paths if p["attack_path"] == "XC-01"]
    assert all(p["project_id"] == PROD[0] for p in paths)
    assert all("exploitation not performed" in p["qualification"] for p in paths)


def test_expanded_22_records_are_typed(org_run):
    store, run = org_run
    kinds = Counter(o.resource_type for o in store.observations(run, provider="GCP"))
    # Only the collected project's own records (project policy, Cloud Run service) remain.
    assert kinds["GCP::AssetIAMSearchResult"] == 3


def test_private_paths_never_published():
    assert (
        not Path("src/offline_analyzer/methodology/cloud_checklist.py")
        .read_text()
        .count("data/private")
    )
