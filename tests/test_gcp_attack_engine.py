"""Synthetic-only permission, discovery, history and immutable reanalysis acceptance."""

import csv
import hashlib
import json
import time
from datetime import UTC, datetime

import pytest
from test_cloud_checklist import org_run  # noqa: F401

from offline_analyzer.attack_paths.cross import cross_paths
from offline_analyzer.attack_paths.gcp_engine import discover, evaluate
from offline_analyzer.attack_paths.gcp_reanalysis import reanalyze
from offline_analyzer.contracts.gcp_attack_path import (
    Condition,
    DiscoveryLimits,
    GCPAttackPathRegister,
    classify,
)
from offline_analyzer.contracts.r0 import EvidenceRef, Normalized
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.findings.sre import record_sre
from offline_analyzer.iam.gcp_permissions import (
    ACCESS_TOKEN,
    ACT_AS,
    ID_TOKEN,
    SIGN_BLOB,
    SIGN_JWT,
    WORKLOAD_MECHANISMS,
    PermissionIndex,
)
from offline_analyzer.reporting.gcp_attack_path_register import COLUMNS, write_register
from offline_analyzer.storage.store import Store

PROJECT = "synthetic-alpha"
ORG = "organizations/123456"
SA = f"runtime@{PROJECT}.iam.gserviceaccount.com"
SUBJECT = f"projects/{PROJECT}/serviceAccounts/{SA}"
USER = f"serviceAccount:caller@{PROJECT}.iam.gserviceaccount.com"


def obs(kind, config, name="synthetic", project=PROJECT, operation="gcp:synthetic"):
    oid = hashlib.sha256(
        json.dumps([kind, config, name, project], sort_keys=True).encode()
    ).hexdigest()
    return Normalized(
        observation_id=oid,
        provider="GCP",
        project_id=project,
        resource_id=f"gcp://{project}/{kind}/{name}",
        native_id=name,
        account_id=None,
        region="global",
        resource_type=kind,
        partition="gcp",
        source_tool="gcp",
        source_version="synthetic",
        source_check_id=operation,
        source_status="SUCCESS",
        source_severity=None,
        collected_at=datetime(2026, 10, 25, tzinfo=UTC),
        operation=operation,
        configuration=config,
        evidence=EvidenceRef(artifact_id="synthetic", locator="/0"),
        integrity_sha256="0" * 64,
    )


def binding(
    role="roles/iam.serviceAccountTokenCreator",
    subject=SUBJECT,
    member=USER,
    condition=None,
    project=PROJECT,
):
    return obs(
        "GCP::IAMBinding",
        {"role": role, "subject": subject, "members": [member], "condition": condition},
        project=project,
    )


def context(project=PROJECT):
    sources = []
    for scope in (f"projects/{project}", ORG):
        for operation in ("deny_policies", "principal_access_boundaries"):
            sources.append(
                {
                    "project_id": project,
                    "operation": "gcp:expanded." + operation,
                    "request_parameters": {"subject": scope},
                    "effective_coverage": "COMPLETE",
                    "record_count": 0,
                    "gcp_metadata": {"scope_ancestors": [ORG]},
                }
            )
    return sources


def account(email=SA, project=PROJECT):
    return obs(
        "GCP::ServiceAccount",
        {"email": email, "disabled": False},
        f"projects/{project}/serviceAccounts/{email}",
        project,
    )


def run(observations, sources=None, **kwargs):
    return discover(
        observations, context() if sources is None else sources, run_id="synthetic-run", **kwargs
    )


@pytest.mark.parametrize("permission", [ACCESS_TOKEN, ID_TOKEN, SIGN_JWT, SIGN_BLOB])
def test_direct_creator_permissions_are_distinct(permission):
    index = PermissionIndex([binding()], context())
    result = index.evaluate(USER, permission, SUBJECT, PROJECT)
    assert result.state == result.allow_state == "AVAILABLE"
    assert result.observation_ids
    assert index.evaluate(USER, ACT_AS, SUBJECT, PROJECT).allow_state == "CONTRADICTED"


def credentials_api():
    return obs(
        "GCP::Service", {"config": {"name": "iamcredentials.googleapis.com"}, "state": "ENABLED"}
    )


def test_supported_is_configuration_only_and_every_mandatory_input_is_required():
    observations = [binding(), account(), credentials_api()]
    paths = run(observations).paths
    assert paths and all(p.classification == "SUPPORTED" for p in paths)
    assert all(p.exploitation_verification == "UNVERIFIED" for p in paths)
    assert all(p.exploitation_requirements for p in paths)
    for reduced in ([binding(), account()], [binding(), credentials_api()]):
        assert all(p.classification not in {"SUPPORTED", "BLOCKED"} for p in run(reduced).paths)
    user = "user:external@example.test"
    p = PermissionIndex([binding(member=user)], context()).evaluate(
        user, ACCESS_TOKEN, SUBJECT, PROJECT
    )
    assert p.allow_state == "AVAILABLE" and p.state == "UNCOLLECTED"


def test_disabled_and_conflicting_target_accounts():
    disabled = obs("GCP::ServiceAccount", {"email": SA, "disabled": True}, SUBJECT)
    paths = run([binding(), disabled, credentials_api()]).paths
    assert all(p.classification == "BLOCKED" for p in paths)
    conflict = run([binding(), disabled, account(), credentials_api()]).paths
    assert all(p.classification == "INSUFFICIENT_EVIDENCE" for p in conflict)


def test_conflicting_custom_roles_and_foreign_scope_never_grant_permission():
    role = f"projects/{PROJECT}/roles/custom"
    definitions = [
        obs(
            "GCP::CustomRole",
            {"name": role, "includedPermissions": permissions},
            operation="gcp:iam.roles.get",
        )
        for permissions in ([ACCESS_TOKEN], [])
    ]
    index = PermissionIndex([binding(role), *definitions], context())
    assert index.evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).state == "UNSUPPORTED"
    unrelated = PermissionIndex([binding(subject="projects/another-project")], context())
    assert unrelated.evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).allow_state == "UNCOLLECTED"


def test_conditional_supported_context_and_legacy_reclassification_count():
    b = binding(condition={"expression": "resource.name.startsWith('projects/')"})
    result = run([b, account(), credentials_api()])
    assert result.paths and all(p.classification == "CONDITIONAL" for p in result.paths)
    # Four former generic token-creator conclusions split into independently modeled
    # mechanisms. Historical PROVEN values survive solely as reconciliation history.
    old = [
        {
            "path_id": "legacy-token-creator",
            "entry_point": USER,
            "steps": [USER, SA],
            "proof_status": "PROVEN",
            "hops": [{"observation_ids": [b.observation_id]}],
        }
    ]
    updated = run([b, account(), credentials_api()], legacy_paths=old)
    reclassified = [
        p for p in updated.paths if p.legacy_paths and p.classification == "CONDITIONAL"
    ]
    assert len(reclassified) == 4


def test_actas_cannot_prove_direct_token_and_workload_permissions_are_separate():
    b = binding("roles/iam.serviceAccountUser")
    index = PermissionIndex([b], context())
    assert index.evaluate(USER, ACT_AS, SUBJECT, PROJECT).state == "AVAILABLE"
    token = index.evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT)
    assert token.allow_state == "CONTRADICTED" and token.state == "UNCOLLECTED"
    result = run([b, account()])
    assert not any(p.mechanism == "access-token" for p in result.paths)
    assert any(
        p.mechanism == "actAs-only-direct-token" and p.classification == "UNSUPPORTED"
        for p in result.paths
    )
    workload = [p for p in result.paths if p.family == "workload-identity"]
    assert len(workload) == 3
    assert all(p.classification == "INSUFFICIENT_EVIDENCE" for p in workload)


def test_custom_workload_mechanism_resolves_permissions_but_keeps_execution_unverified():
    role = f"projects/{PROJECT}/roles/jobRunner"
    permissions = list(WORKLOAD_MECHANISMS["run-job-create-execute"])
    detail = obs(
        "GCP::CustomRole",
        {"name": role, "includedPermissions": permissions},
        operation="gcp:iam.roles.get",
    )
    observations = [
        binding("roles/iam.serviceAccountUser"),
        account(),
        detail,
        binding(role, f"projects/{PROJECT}"),
    ]
    index = PermissionIndex(observations, context())
    assert all(
        index.evaluate(USER, p, f"projects/{PROJECT}", PROJECT).state == "AVAILABLE"
        for p in permissions
    )
    path = next(p for p in run(observations).paths if p.mechanism == "run-job-create-execute")
    assert path.prerequisites[1].state == "AVAILABLE"
    assert path.classification == "INSUFFICIENT_EVIDENCE"
    assert path.exploitation_verification == "UNVERIFIED"
    assert "service prerequisites" in path.remaining_verification[0]


def test_inherited_grant_requires_known_ancestry_and_custom_role_details():
    parent = binding(subject=ORG)
    index = PermissionIndex([parent], context())
    assert index.evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).state == "AVAILABLE"
    assert (
        PermissionIndex([parent], []).evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).state
        == "UNCOLLECTED"
    )
    role = f"projects/{PROJECT}/roles/tokenOnly"
    custom = binding(role)
    assert (
        PermissionIndex([custom], context()).evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).state
        == "UNCOLLECTED"
    )
    detail = obs(
        "GCP::CustomRole",
        {"name": role, "includedPermissions": [ACCESS_TOKEN]},
        operation="gcp:iam.roles.get",
    )
    idx = PermissionIndex([custom, detail], context())
    assert idx.evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).state == "AVAILABLE"
    assert idx.evaluate(USER, SIGN_JWT, SUBJECT, PROJECT).allow_state == "CONTRADICTED"


def test_conditions_pab_and_project_only_empty_collections_fail_closed():
    conditional = binding(
        condition={"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    )
    assert (
        PermissionIndex([conditional], context())
        .evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT)
        .state
        == "CONDITIONAL"
    )
    for sources in (
        [],
        context()[:2],
        [{**s, "record_count": 1} for s in context()],
        [{**s, "effective_coverage": "PARTIAL"} for s in context()],
    ):
        result = run([binding(), account()], sources)
        assert result.paths
        assert all(p.classification not in {"SUPPORTED", "BLOCKED"} for p in result.paths)


def deny(condition=None, exceptions=None):
    rule = {
        "deniedPrincipals": [
            "principal://iam.googleapis.com/projects/-/serviceAccounts/" + USER.split(":", 1)[1]
        ],
        "deniedPermissions": ["iam.googleapis.com/serviceAccounts.getAccessToken"],
    }
    if condition:
        rule["denialCondition"] = condition
    if exceptions:
        rule["exceptionPrincipals"] = exceptions
    return obs(
        "GCP::IAMDenyPolicy",
        {"rules": [{"denyRule": rule}], "_parameters": {"subject": f"projects/{PROJECT}"}},
    )


def test_exact_deny_blocks_only_the_matching_mechanism_with_evidence():
    d = deny()
    paths = run([binding(), account(), d]).paths
    token = next(p for p in paths if p.mechanism == "access-token")
    assert token.classification == "BLOCKED"
    assert token.prerequisites[0].observation_ids == [d.observation_id]
    assert (
        next(p for p in paths if p.mechanism == "id-token").classification
        == "INSUFFICIENT_EVIDENCE"
    )
    for unresolved in (deny(condition={"expression": "true"}), deny(exceptions=[USER])):
        # Nonempty restriction context must be supplied by the original collector metadata.
        sources = [{**s, "record_count": 1} for s in context()]
        p = next(
            p
            for p in run([binding(), account(), unresolved], sources).paths
            if p.mechanism == "access-token"
        )
        assert p.classification == "INSUFFICIENT_EVIDENCE"


def test_google_managed_target_not_assumed_immune_and_federation_not_assumed_usable():
    agent = "service-123456@gcp-sa-example.iam.gserviceaccount.com"
    target = f"projects/{PROJECT}/serviceAccounts/{agent}"
    result = run([binding(subject=target), account(agent)])
    # An observed grant forms a candidate even for a Google-managed target. Service
    # restrictions prevent a support claim (rather than silently dropping the target).
    assert any(p.identity == agent for p in result.paths)
    assert all(p.classification != "SUPPORTED" for p in result.paths)
    wi = run([binding("roles/iam.workloadIdentityUser"), account()])
    assert all(p.prerequisites[0].state == "UNSUPPORTED" for p in wi.paths)
    assert all(p.classification not in {"SUPPORTED", "BLOCKED"} for p in wi.paths)


def test_serverless_identity_network_blockers_vm_and_gke_without_findings():
    service_name = f"projects/{PROJECT}/locations/region/services/web"
    service = obs(
        "GCP::RunService",
        {"template": {"serviceAccount": SA}, "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"},
        service_name,
    )
    public = binding("roles/run.invoker", service_name, "allUsers")
    vm = obs(
        "GCP::ComputeInstance",
        {
            "networkInterfaces": [{"network": "net", "accessConfigs": [{"natIP": "192.0.2.1"}]}],
            "serviceAccounts": [{"email": SA}],
        },
        f"projects/{PROJECT}/zones/zone/instances/vm",
    )
    firewall = obs(
        "GCP::Firewall",
        {
            "network": "net",
            "direction": "INGRESS",
            "sourceRanges": ["0.0.0.0/0"],
            "denied": [{"IPProtocol": "all"}],
        },
    )
    gke = obs(
        "GCP::GKECluster",
        {"nodeConfig": {"serviceAccount": SA}},
        f"projects/{PROJECT}/locations/region/clusters/cluster",
    )
    result = run(
        [service, public, vm, firewall, gke, binding("roles/editor", member="serviceAccount:" + SA)]
    )
    assert {"public-serverless-identity", "public-vm-identity", "gke-identity"} <= {
        p.family for p in result.paths
    }
    serverless = next(p for p in result.paths if p.family == "public-serverless-identity")
    assert serverless.classification == "BLOCKED"
    assert serverless.path_id not in result.active_path_ids
    vm_path = next(p for p in result.paths if p.family == "public-vm-identity")
    assert vm_path.classification == "INSUFFICIENT_EVIDENCE"
    assert any("potential blockers" in c.reason for c in vm_path.prerequisites)
    assert all(not p.original_finding_ids for p in result.paths)


def test_public_storage_blocker_and_authenticated_users_are_not_anonymous():
    name = "buckets/synthetic-bucket"
    bucket = obs("GCP::Bucket", {"iamConfiguration": {"publicAccessPrevention": "enforced"}}, name)
    result = run([bucket, binding("roles/storage.objectViewer", name, "allUsers")])
    assert result.paths[0].classification == "BLOCKED" and not result.active_path_ids
    other = run([binding("roles/storage.objectViewer", name, "allAuthenticatedUsers")])
    assert other.paths[0].classification == "INSUFFICIENT_EVIDENCE"
    assert any(c.name == "authenticated Google identity" for c in other.paths[0].prerequisites)


def test_cross_project_chains_and_root_cause_deduplication():
    other = "synthetic-bravo"
    other_sa = f"runtime@{other}.iam.gserviceaccount.com"
    result = run(
        [
            binding(),
            account(),
            account(other_sa, other),
            binding(
                subject=f"projects/{other}/serviceAccounts/{other_sa}",
                member="serviceAccount:" + SA,
                project=other,
            ),
            binding(
                "roles/storage.objectViewer",
                "buckets/data",
                "serviceAccount:" + other_sa,
                project=other,
            ),
        ],
        context() + context(other),
    )
    chains = [p for p in result.paths if p.entry_point == USER and p.identity == other_sa]
    assert chains and any(len(p.relationships) >= 2 for p in chains)
    assert len(result.root_cause_groups) < len(result.paths)
    duplicate = run([binding(), binding(), account()])
    plain = run([binding(), account()])
    assert [p.path_id for p in duplicate.paths] == [p.path_id for p in plain.paths]


def test_legacy_proven_retained_never_implicitly_approved():
    b = binding("roles/iam.serviceAccountUser")
    legacy = [
        {
            "path_id": "legacy-xp01",
            "proof_status": "PROVEN",
            "feasibility": "FEASIBLE",
            "entry_point": USER,
            "steps": [USER, SA],
            "analyst_review": "CONFIRMED",
            "hops": [{"observation_ids": [b.observation_id]}],
        }
    ]
    original = json.dumps(legacy, sort_keys=True)
    result = run([b, account()], legacy_paths=legacy)
    assert result.paths and all(p.legacy_paths for p in result.paths)
    assert all(p.legacy_paths[0]["prior_status"] == "PROVEN" for p in result.paths)
    assert all(
        p.analyst_review == "UNREVIEWED" and p.finding_validation == "NOT_INHERITED"
        for p in result.paths
    )
    assert all(p.classification != "SUPPORTED" for p in result.paths)
    assert json.dumps(legacy, sort_keys=True) == original


@pytest.mark.parametrize("state", ["AVAILABLE", "CONTRADICTED"])
def test_decisive_states_require_evidence(state):
    with pytest.raises(ValueError):
        Condition(name="missing", state=state, reason="no evidence")
    assert classify([]) == "INSUFFICIENT_EVIDENCE"
    assert (
        classify([Condition(name="missing", state="UNCOLLECTED", reason="not collected")])
        == "INSUFFICIENT_EVIDENCE"
    )


def test_limits_and_runtime():
    observations = [account(), binding(subject=f"projects/{PROJECT}")]
    observations += [account(f"runtime-{n}@{PROJECT}.iam.gserviceaccount.com") for n in range(120)]
    start = time.perf_counter()
    result = run(observations, limits=DiscoveryLimits(max_candidates=30, max_depth=3))
    assert len(result.paths) <= 30 and result.truncated
    assert time.perf_counter() - start < 5
    assert result.elapsed_seconds < 5
    assert all(p.classification != "SUPPORTED" for p in result.paths)
    clipped = run(observations, limits=DiscoveryLimits(max_nodes=1))
    assert clipped.visited_nodes == 1 and clipped.truncated
    bounded = run(observations, limits=DiscoveryLimits(max_bindings=1))
    assert bounded.truncated
    with pytest.raises(ValueError):
        DiscoveryLimits(max_depth=0)


def test_separate_register_formula_safety_and_blocked_history(tmp_path):
    result = run([binding(), account(), deny()])
    write_register(result, tmp_path / "new-evaluation")
    parsed = GCPAttackPathRegister.model_validate_json(
        (tmp_path / "new-evaluation/attack-path-evaluation-v2.json").read_text()
    )
    assert parsed == result
    with (tmp_path / "new-evaluation/active-attack-paths.csv").open() as stream:
        data = list(csv.reader(stream))
    assert tuple(data[0]) == COLUMNS
    assert all(row[COLUMNS.index("Qualified state")] != "BLOCKED" for row in data[1:])
    with pytest.raises(FileExistsError):
        write_register(result, tmp_path / "new-evaluation")


def test_xp01_source_and_all_historical_database_rows_unchanged(org_run, tmp_path):  # noqa: F811
    store, run_id = org_run
    finding = next(store.candidates(run_id))
    record_decision(store, run_id, finding.finding_id, "CONFIRMED", "Synthetic assessor", "")
    record_sre(store, run_id, [finding.finding_id], "GAP_CONFIRMED", "Synthetic SRE")
    historical_report = store.workspace / "reports/synthetic-original.txt"
    historical_report.parent.mkdir(exist_ok=True)
    historical_report.write_text("Synthetic original report: immutable during reanalysis")
    tables = [name for (name,) in store.rows("SELECT table_name FROM duckdb_tables()")]
    before = {table: list(store.rows(f'SELECT * FROM "{table}" ORDER BY ALL')) for table in tables}
    paths = cross_paths(store, run_id)
    xp01 = next(p for p in paths if p["attack_path"] == "XP-01")
    assert xp01["proof_status"] == "HYPOTHESIS"
    assert "getAccessToken" in xp01["hops"][0]["justification"]
    assert xp01["evidence_classification"] == "INSUFFICIENT_EVIDENCE"
    register = evaluate(store, run_id)
    assert register.paths
    after = {table: list(store.rows(f'SELECT * FROM "{table}" ORDER BY ALL')) for table in tables}
    assert after == before
    assert all(p.finding_validation == "NOT_INHERITED" for p in register.paths)
    # Read-only reanalysis of a checkpointed synthetic DB copy, no migrations or raw writes.
    import shutil

    store.db.execute("CHECKPOINT")
    target = tmp_path / "historical-workspace"
    shutil.copytree(store.workspace, target)
    hashes = {
        p.relative_to(target): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in target.rglob("*")
        if p.is_file()
    }
    reanalyze(target, run_id, tmp_path / "isolated-v2")
    assert hashes == {
        p.relative_to(target): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in target.rglob("*")
        if p.is_file()
    }
    with Store(target, read_only=True) as readonly:
        with pytest.raises(Exception, match="read-only"):
            readonly.db.execute("DELETE FROM findings")


def test_distinct_technical_chains_survive_root_cause_grouping():
    branch = f"branch@{PROJECT}.iam.gserviceaccount.com"
    end = f"end@{PROJECT}.iam.gserviceaccount.com"
    endpoint = f"projects/{PROJECT}/serviceAccounts/{end}"
    result = run(
        [
            binding(subject=f"projects/{PROJECT}"),
            account(),
            account(branch),
            account(end),
            credentials_api(),
            binding(subject=endpoint, member="serviceAccount:" + SA),
            binding(subject=endpoint, member="serviceAccount:" + branch),
        ],
        limits=DiscoveryLimits(max_depth=12),
    )
    paths = [
        p
        for p in result.paths
        if p.entry_point == USER
        and p.identity == end
        and p.mechanism == "identity-chain/access-token"
    ]
    assert len(paths) == 2
    assert len({p.path_id for p in paths}) == 2
    assert len({p.root_cause_id for p in paths}) == 1


def test_unmatched_legacy_paths_are_explicit_and_never_approved(tmp_path):
    legacy = [{"path_id": "old-ambiguous", "proof_status": "PROVEN"}]
    result = run([binding(), account()], legacy_paths=legacy)
    write_register(result, tmp_path / "isolated", legacy_paths=legacy)
    reconciliation = json.loads((tmp_path / "isolated/legacy-reconciliation.json").read_text())
    assert reconciliation[0]["match_status"] == "UNMATCHED"
    assert reconciliation[0]["prior_status"] == "PROVEN"
    assert all(p.analyst_review == "UNREVIEWED" for p in result.paths)


def test_invalid_principal_cannot_support_access_and_csv_is_literal(tmp_path):
    malicious = "=SUM(1,1)"
    result = run([binding(member=malicious), account(), credentials_api()])
    assert result.paths and all(p.classification == "UNSUPPORTED" for p in result.paths)
    write_register(result, tmp_path / "literal")
    with (tmp_path / "literal/active-attack-paths.csv").open() as stream:
        rows = list(csv.reader(stream))
    assert all(row[COLUMNS.index("Entry point")] == "'" + malicious for row in rows[1:])
    for public in ("allUsers", "allAuthenticatedUsers"):
        paths = run([binding(member=public), account(), credentials_api()]).paths
        assert paths and all(p.classification == "INSUFFICIENT_EVIDENCE" for p in paths)
    with pytest.raises(ValueError, match="LEGACY_PATH_COMPARISON_LIMIT"):
        run(
            [binding(), account()],
            limits=DiscoveryLimits(max_candidates=1),
            legacy_paths=[{"path_id": "one"}, {"path_id": "two"}],
        )


def test_inactive_custom_roles_scope_and_empty_conditions_fail_closed():
    role = f"projects/{PROJECT}/roles/inactive"
    disabled = obs(
        "GCP::CustomRole",
        {"name": role, "stage": "DISABLED", "includedPermissions": [ACCESS_TOKEN]},
        operation="gcp:iam.roles.get",
    )
    index = PermissionIndex([binding(role), disabled], context())
    assert index.evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT).allow_state != "AVAILABLE"
    foreign = "projects/another-project/roles/custom"
    detail = obs(
        "GCP::CustomRole",
        {"name": foreign, "includedPermissions": [ACCESS_TOKEN]},
        operation="gcp:iam.roles.get",
    )
    assert (
        PermissionIndex([binding(foreign), detail], context())
        .evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT)
        .state
        != "AVAILABLE"
    )
    assert (
        PermissionIndex([binding(condition={})], context())
        .evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT)
        .state
        == "CONDITIONAL"
    )
    incomplete_deny = deny().model_copy(
        update={
            "configuration": {
                **deny().configuration,
                "rules": [
                    {
                        "denyRule": {
                            **deny().configuration["rules"][0]["denyRule"],
                            "denialCondition": {},
                        }
                    }
                ],
            }
        }
    )
    assert (
        PermissionIndex([binding(), incomplete_deny], context())
        .evaluate(USER, ACCESS_TOKEN, SUBJECT, PROJECT)
        .state
        == "UNCOLLECTED"
    )


def test_mixed_date_composition_does_not_treat_historical_blockers_as_current():
    disabled = obs("GCP::ServiceAccount", {"email": SA, "disabled": True}, SUBJECT)
    observations = [binding(), disabled, credentials_api()]
    assert all(p.classification == "BLOCKED" for p in run(observations).paths)
    sources = context()
    for source in sources:
        source["gcp_metadata"]["composition"] = {"temporally_mixed": True}
    result = run(observations, sources)
    assert result.paths and all(p.classification == "INSUFFICIENT_EVIDENCE" for p in result.paths)
    assert any(
        "Historical blocking evidence" in c.reason for p in result.paths for c in p.prerequisites
    )
    assert all(p.exploitation_verification == "UNVERIFIED" for p in result.paths)


def test_engine_patch_pins_new_results_and_retains_200_history_compatibility():
    result = run([binding(), account(), credentials_api()])
    assert result.engine_version == "2.0.1"
    assert all(p.engine_version == "2.0.1" for p in result.paths)
    legacy = result.model_dump(mode="json")
    legacy["engine_version"] = "2.0.0"
    for path in legacy["paths"]:
        path["engine_version"] = "2.0.0"
    assert GCPAttackPathRegister.model_validate(legacy).engine_version == "2.0.0"
