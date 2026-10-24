"""Per-principal GCP role lookup over collected evidence. All projects, identities and
organizations are synthetic; rows are written into a temporary workspace database."""

import json
import time
from pathlib import Path

import pytest

from offline_analyzer.iam.gcp_principals import (
    INHERITED_GAP,
    PRIVILEGED_ROLES,
    build,
    directory,
    lookup,
    principal_runs,
)
from offline_analyzer.storage.store import Store

ORG = "organizations/666666666666"
SA = "serviceAccount:{}@{}.iam.gserviceaccount.com"


class Workspace:
    """Writes synthetic runs, sources and observations with the stored JSON shapes."""

    def __init__(self, store: Store):
        self.store, self.count = store, 0

    def project(self, project, number, ancestors=(ORG,), parent_iam="COMPLETE", created="1"):
        run = f"run-{project}-{created}"
        self.store.db.execute("INSERT INTO runs VALUES (?,?,?)", [run, created, "synthetic"])
        self.source(run, project, number, "gcp:projects.getIamPolicy", f"projects/{project}")
        for scope in ancestors:
            kind = "folders" if scope.startswith("folders/") else "organizations"
            self.source(
                run,
                project,
                number,
                f"gcp:{kind}.getIamPolicy",
                scope,
                coverage=parent_iam,
                ancestors=ancestors,
            )
        return run

    def source(self, run, project, number, operation, subject, coverage="COMPLETE", ancestors=()):
        self.count += 1
        data = {
            "format": "gcp-json-v1",
            "artifact_id": f"artifact-{self.count}",
            "project_id": project,
            "project_number": number,
            "operation": operation,
            "effective_coverage": coverage,
            "request_parameters": {"subject": subject},
            "gcp_metadata": {
                "dataset": operation.split(":")[1].split(".")[0] + "_iam",
                "scope_ancestors": list(ancestors) or [ORG],
                "error_category": None if coverage == "COMPLETE" else "ACCESS_DENIED",
            },
        }
        self.store.db.execute(
            "INSERT INTO sources VALUES (?,?,?)", [run, f"source-{self.count}", json.dumps(data)]
        )

    def binding(self, run, project, subject, role, members, condition=None):
        config = {"role": role, "members": members, "subject": subject}
        if condition:
            config["condition"] = condition
        self.observation(run, project, "GCP::IAMBinding", "gcp:projects.getIamPolicy", config)

    def observation(self, run, project, kind, operation, config):
        self.count += 1
        data = {
            "observation_id": f"obs-{self.count}",
            "resource_type": kind,
            "operation": operation,
            "project_id": project,
            "configuration": config,
            "evidence": {"artifact_id": "artifact-1", "locator": "records[0]"},
        }
        self.store.db.execute(
            "INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?)",
            [
                run,
                data["observation_id"],
                None,
                None,
                "global",
                "gcp",
                None,
                kind,
                json.dumps(data),
            ],
        )


@pytest.fixture
def workspace(tmp_path):
    with Store(Path(tmp_path)) as store:
        yield Workspace(store)


def two_projects(w: Workspace):
    alpha = w.project("demo-alpha", "111111111111")
    beta = w.project("demo-beta", "222222222222")
    w.binding(
        alpha, "demo-alpha", "projects/demo-alpha", "roles/editor", [SA.format("app", "demo-alpha")]
    )
    w.binding(
        beta, "demo-beta", "projects/demo-beta", "roles/viewer", [SA.format("app", "demo-alpha")]
    )
    w.binding(
        alpha,
        "demo-alpha",
        "projects/demo-alpha",
        "roles/storage.admin",
        [SA.format("cond", "demo-alpha")],
        {
            "title": "synthetic window",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        },
    )
    w.binding(
        alpha,
        "demo-alpha",
        "projects/demo-alpha",
        "roles/viewer",
        [SA.format("narrow", "demo-alpha"), "group:ops@example.invalid"],
    )
    return alpha, beta


def test_same_account_with_roles_in_two_projects(workspace):
    alpha, _ = two_projects(workspace)
    result = lookup(workspace.store, alpha, SA.format("app", "demo-alpha"))
    assert result["status"] == "RESOLVED" and result["privilege"] == "PRIVILEGED"
    rows = {(b["project_id"], b["role"]): b for b in result["bindings"]}
    assert set(rows) == {("demo-alpha", "roles/editor"), ("demo-beta", "roles/viewer")}
    assert rows["demo-alpha", "roles/editor"]["trust"] == "SAME_PROJECT"
    assert rows["demo-alpha", "roles/editor"]["privileged"] is True
    assert rows["demo-beta", "roles/viewer"]["trust"] == "IN_SCOPE_OTHER_PROJECT"
    assert rows["demo-beta", "roles/viewer"]["privileged"] is False
    assert all(b["scope"] == "project" and b["dataset"] for b in result["bindings"])
    assert {p["project_id"] for p in result["projects"]} == {"demo-alpha", "demo-beta"}
    # A bare email is matched in its service-account form.
    assert (
        lookup(workspace.store, alpha, "app@demo-alpha.iam.gserviceaccount.com")["binding_count"]
        == 2
    )


def test_conditional_binding_is_listed_with_its_condition(workspace):
    alpha, _ = two_projects(workspace)
    (row,) = lookup(workspace.store, alpha, SA.format("cond", "demo-alpha"))["bindings"]
    assert row["conditional"] and row["condition"]["title"] == "synthetic window"
    assert row["privileged"] is True  # roles/storage.admin: an *Admin role


def test_account_without_bindings_and_narrow_account(workspace):
    alpha, _ = two_projects(workspace)
    none = lookup(workspace.store, alpha, SA.format("none", "demo-alpha"))
    assert none["binding_count"] == 0 and none["status"] == "RESOLVED"
    assert none["privilege"] == "NONE_OBSERVED"
    narrow = lookup(workspace.store, alpha, SA.format("narrow", "demo-alpha"))
    assert narrow["privilege"] == "NARROW"


def test_group_is_listed_as_a_group_and_members_are_never_invented(workspace):
    alpha, _ = two_projects(workspace)
    group = lookup(workspace.store, alpha, "group:ops@example.invalid")
    assert group["principal_kinds"] == ["group"] and group["members"] == [
        "group:ops@example.invalid"
    ]
    assert [b["member"] for b in group["bindings"]] == ["group:ops@example.invalid"]
    assert group["bindings"][0]["trust"] is None
    assert any("Group membership is not collected" in n for n in group["notes"])
    # A user is never credited with the group's roles.
    user = lookup(workspace.store, alpha, "user:someone@example.invalid")
    assert user["binding_count"] == 0


def test_parent_iam_denied_gives_unresolved_never_narrow(workspace):
    run = workspace.project(
        "demo-gamma", "333333333333", ancestors=("folders/700", ORG), parent_iam="ERROR"
    )
    workspace.binding(
        run, "demo-gamma", "projects/demo-gamma", "roles/viewer", [SA.format("svc", "demo-gamma")]
    )
    result = lookup(workspace.store, run, SA.format("svc", "demo-gamma"))
    assert result["status"] == "UNRESOLVED" and result["privilege"] == "UNRESOLVED"
    (project,) = result["projects"]
    assert project["reason"].startswith(INHERITED_GAP) and "ACCESS_DENIED" in project["reason"]


def test_project_under_a_parent_not_collected_is_unresolved(workspace):
    run = workspace.project("demo-delta", "444444444444", ancestors=())
    workspace.store.db.execute(
        "UPDATE sources SET data=json_merge_patch(data, ?) WHERE run_id=?",
        [json.dumps({"gcp_metadata": {"scope_ancestors": ["folders/701"]}}), run],
    )
    workspace.binding(
        run, "demo-delta", "projects/demo-delta", "roles/viewer", [SA.format("svc", "demo-delta")]
    )
    result = lookup(workspace.store, run, SA.format("svc", "demo-delta"))
    assert result["status"] == "UNRESOLVED" and result["privilege"] == "UNRESOLVED"
    assert "folders/701: not collected" in result["projects"][0]["reason"]


def test_custom_role_without_detail_is_unresolved_and_detail_lists_permissions(workspace):
    alpha, _ = two_projects(workspace)
    custom = "projects/demo-alpha/roles/syntheticOperator"
    workspace.binding(
        alpha, "demo-alpha", "projects/demo-alpha", custom, [SA.format("ops", "demo-alpha")]
    )
    result = lookup(workspace.store, alpha, SA.format("ops", "demo-alpha"))
    assert result["status"] == "UNRESOLVED" and result["privilege"] == "UNRESOLVED"
    assert result["bindings"][0]["role_status"] == "UNRESOLVED"
    workspace.observation(
        alpha,
        "demo-alpha",
        "GCP::CustomRole",
        "gcp:iam.roles.get",
        {
            "name": custom,
            "includedPermissions": ["compute.instances.get", "compute.instances.list"],
        },
    )
    detailed = lookup(workspace.store, alpha, SA.format("ops", "demo-alpha"))
    row = detailed["bindings"][0]
    assert row["permissions"] == ["compute.instances.get", "compute.instances.list"]
    assert row["role_status"] == "RESOLVED" and row["privileged"] is None
    assert detailed["privilege"] == "UNRESOLVED"  # listed, not classified: never NARROW


def test_privileged_list_follows_the_documented_definition():
    from offline_analyzer.iam.gcp_principals import privileged

    for role in (
        "roles/owner",
        "roles/editor",
        "roles/compute.instanceAdmin.v1",
        "roles/storage.admin",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.workloadIdentityUser",
        "roles/resourcemanager.projectIamAdmin",
    ):
        assert privileged(role), role
    for role in ("roles/viewer", "roles/storage.objectViewer", "roles/logging.viewer"):
        assert not privileged(role), role
    assert "roles/owner" in PRIVILEGED_ROLES


def test_selected_run_and_latest_import_per_project(workspace):
    alpha, beta = two_projects(workspace)
    newer = workspace.project("demo-beta", "222222222222", created="2")
    runs = principal_runs(workspace.store, alpha)
    assert alpha in runs and newer in runs and beta not in runs
    assert principal_runs(workspace.store, beta) == sorted({beta, alpha})


def test_directory_lists_observed_principals(workspace):
    alpha, _ = two_projects(workspace)
    listing = directory(workspace.store, alpha, "demo-alpha")
    members = {row["member"]: row for row in listing["items"]}
    assert members[SA.format("app", "demo-alpha")]["privileged_bindings"] == 1
    assert members[SA.format("app", "demo-alpha")]["projects"] == 2
    assert "group:ops@example.invalid" not in members  # filtered by the query


def test_real_import_shapes(tmp_path):
    """Expanded synthetic package: parent folder IAM unavailable gives UNRESOLVED."""
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from tools.fixtures.gcp_expanded import expanded22

    package = expanded22(tmp_path / "pkg")
    set_environment(tmp_path / "work", "SYNTHETIC")
    with Store(tmp_path / "work") as store:
        run = import_package(store, package)
        assess(store, run)
        result = lookup(store, run, "serviceAccount:worker@sample-project.iam.gserviceaccount.com")
        assert result["status"] == "UNRESOLVED" and result["privilege"] == "PRIVILEGED"
        scopes = {b["scope"] for b in result["bindings"]}
        assert {"project", "service account", "bucket", "organization"} <= scopes
        assert INHERITED_GAP in result["projects"][0]["reason"]


def test_performance_45_projects_5000_bindings(workspace):
    runs = []
    for p in range(45):
        project = f"demo-perf-{p:02d}"
        run = workspace.project(project, f"5{p:011d}")
        runs.append(run)
        for b in range(112 if p < 40 else 104):
            members = [
                SA.format(f"svc{b % 60}", f"demo-perf-{(p + b) % 45:02d}"),
                "group:team@example.invalid",
            ]
            role = "roles/editor" if b % 25 == 0 else f"roles/synthetic.role{b % 7}"
            workspace.binding(run, project, f"projects/{project}", role, members)
    total = workspace.store.db.execute(
        "SELECT count(*) FROM observations WHERE kind='GCP::IAMBinding'"
    ).fetchone()[0]
    assert total == 5000
    started = time.perf_counter()
    index = build(workspace.store, principal_runs(workspace.store, runs[0]))
    built = time.perf_counter() - started
    started = time.perf_counter()
    result = index.lookup(SA.format("svc0", "demo-perf-00"))
    listing = index.directory("svc", 0, 50)
    queried = time.perf_counter() - started
    assert len(index.projects) == 45 and result["binding_count"] > 0 and listing["total"] > 0
    print(f"PERF build={built:.3f}s query={queried:.3f}s")
    assert built < 10 and queried < 1, (built, queried)


def test_missing_parent_field_is_not_proof_of_a_standalone_project(workspace):
    from offline_analyzer.iam.gcp_principals import NO_PARENT_RECORDED

    run = workspace.project("demo-solo", "555555555555", ancestors=())
    workspace.store.db.execute(
        "UPDATE sources SET data=json_merge_patch(data, ?) WHERE run_id=?",
        [json.dumps({"gcp_metadata": {"scope_ancestors": []}}), run],
    )
    workspace.observation(
        run,
        "demo-solo",
        "GCP::Project",
        "gcp:projects.get",
        {"projectId": "demo-solo", "projectNumber": "555555555555"},
    )
    workspace.binding(
        run, "demo-solo", "projects/demo-solo", "roles/viewer", [SA.format("svc", "demo-solo")]
    )
    result = lookup(workspace.store, run, SA.format("svc", "demo-solo"))
    assert result["status"] == "UNRESOLVED" and result["privilege"] == "UNRESOLVED"
    assert result["projects"][0]["reason"] == NO_PARENT_RECORDED
