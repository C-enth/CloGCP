"""Scenario inventory for all executable GCP rules, including explicitly manual criteria."""

import pytest

from offline_analyzer.contracts.models import EvidenceRef
from offline_analyzer.rules.gcp import GCP_RULES, evaluate
from offline_analyzer.rules.gcp_identity import Scope
from offline_analyzer.rules.gcp_org import ORG_RULES, manual_reviews, matches, provider_state
from tests.test_clogcp_domains import CASES as DOMAIN_CASES
from tests.test_clogcp_domains import NUMBER, PROJECT, obs
from tests.test_gcp_config import CASES as CONFIG_CASES

SCOPE = Scope(PROJECT, NUMBER, {PROJECT: NUMBER})
API = {
    "serverKeyRestrictions": {"allowedIps": ["192.0.2.0/24"]},
    "apiTargets": [{"service": "example.googleapis.com"}],
}
KEY = f"projects/{PROJECT}/serviceAccounts/worker@{PROJECT}.iam.gserviceaccount.com/keys/key"
BASE = {r: (g, b, [], [], "sample", "PASS", "FAIL") for r, g, b in CONFIG_CASES}


def add(
    rid,
    good,
    bad,
    good_context=(),
    bad_context=(),
    native="sample",
    good_status="PASS",
    bad_status="FAIL",
):
    BASE["GCP-" + rid] = (
        good,
        bad,
        list(good_context),
        list(bad_context),
        native,
        good_status,
        bad_status,
    )


add("API-APP", {"restrictions": API}, {"restrictions": {"apiTargets": API["apiTargets"]}})
add(
    "API-API",
    {"restrictions": API},
    {"restrictions": {"serverKeyRestrictions": API["serverKeyRestrictions"]}},
)
add("API-BOTH", {"restrictions": API}, {"restrictions": {}})
add(
    "KEY-PERSISTENT",
    {"keyType": "USER_MANAGED", "disabled": True},
    {"keyType": "USER_MANAGED", "disabled": False},
    native=KEY,
    good_status="NOT_APPLICABLE",
)
add(
    "KEY-AGE",
    {"keyType": "USER_MANAGED", "validAfterTime": "2026-10-22T00:00:00Z"},
    {"keyType": "USER_MANAGED", "validAfterTime": "2020-01-01T00:00:00Z"},
    native=KEY,
)
PRIVILEGED = obs(
    "IAMBinding",
    {
        "role": "roles/editor",
        "members": [f"serviceAccount:worker@{PROJECT}.iam.gserviceaccount.com"],
    },
)
add(
    "KEY-PRIVILEGED",
    {"keyType": "USER_MANAGED"},
    {"keyType": "USER_MANAGED"},
    bad_context=[PRIVILEGED],
    native=KEY,
)
add(
    "IAM-BASIC",
    {
        "subject": f"projects/{PROJECT}",
        "role": "roles/viewer",
        "members": ["user:admin@example.com"],
    },
    {
        "subject": f"projects/{PROJECT}",
        "role": "roles/editor",
        "members": ["user:admin@example.com"],
    },
)
add(
    "IAM-PUBLIC",
    {"role": "roles/owner", "members": ["user:admin@example.com"]},
    {"role": "roles/owner", "members": ["allUsers"]},
)
add(
    "IAM-IMPERSONATION",
    {
        "subject": f"projects/{PROJECT}/serviceAccounts/worker@{PROJECT}.iam.gserviceaccount.com",
        "role": "roles/iam.serviceAccountTokenCreator",
        "members": ["user:operator@example.com"],
    },
    {
        "subject": f"projects/{PROJECT}",
        "role": "roles/iam.serviceAccountTokenCreator",
        "members": ["group:operators@example.com"],
    },
)
add(
    "IAM-CROSSPROJECT",
    {
        "role": "roles/editor",
        "members": [f"serviceAccount:worker@{PROJECT}.iam.gserviceaccount.com"],
    },
    {
        "role": "roles/editor",
        "members": ["serviceAccount:worker@synth-foreign.iam.gserviceaccount.com"],
    },
)
add(
    "GOV-KEYS",
    {
        "constraint": "constraints/iam.disableServiceAccountKeyCreation",
        "booleanPolicy": {"enforced": True},
        "_parameters": {"effective": True},
    },
    {
        "constraint": "constraints/iam.disableServiceAccountKeyCreation",
        "booleanPolicy": {"enforced": False},
        "_parameters": {"effective": True},
    },
)
add(
    "LOG-AUDIT",
    {"subject": f"projects/{PROJECT}", "auditConfigs": []},
    {
        "subject": f"projects/{PROJECT}",
        "auditConfigs": [
            {
                "service": "allServices",
                "auditLogConfigs": [
                    {"logType": "DATA_READ", "exemptedMembers": ["user:exempt@example.com"]}
                ],
            }
        ],
    },
)
add(
    "LOG-EXCLUSION",
    {"disabled": False, "filter": 'logName="projects/synth/logs/application"'},
    {"disabled": False, "filter": 'log_id("cloudaudit.googleapis.com/data_access")'},
)
add(
    "SCC-OBSERVATION",
    {"state": "INACTIVE"},
    {
        "state": "ACTIVE",
        "category": "SYNTHETIC_CONFIGURATION",
        "resourceName": (
            f"//compute.googleapis.com/projects/{PROJECT}/zones/us-central1-a/instances/vm"
        ),
    },
    good_status="NOT_APPLICABLE",
)
BUCKET = obs("Bucket", {"iamConfiguration": {"publicAccessPrevention": "inherited"}}, "bucket")
POLICY = obs(
    "OrgPolicy",
    {
        "constraint": "constraints/storage.publicAccessPrevention",
        "booleanPolicy": {"enforced": False},
        "_parameters": {"effective": True},
    },
)
add(
    "STORAGE-PAP",
    {"iamConfiguration": {"publicAccessPrevention": "enforced"}},
    {"iamConfiguration": {"publicAccessPrevention": "inherited"}},
    bad_context=[POLICY],
)
add(
    "STORAGE-PUBLIC",
    {
        "subject": "buckets/bucket",
        "role": "roles/storage.objectViewer",
        "members": ["user:reader@example.com"],
    },
    {"subject": "buckets/bucket", "role": "roles/storage.objectViewer", "members": ["allUsers"]},
    bad_context=[BUCKET, POLICY],
)
add(
    "LOG-RETENTION",
    {"name": "application", "retentionDays": 365},
    {"name": "application", "retentionDays": 1},
    good_status="MANUAL_VALIDATION_REQUIRED",
    bad_status="MANUAL_VALIDATION_REQUIRED",
)
RULES = {r.rule_id: r for r in GCP_RULES}


def test_each_gcp_rule_is_in_the_three_scenario_inventory():
    assert set(BASE) | set(DOMAIN_CASES) == set(RULES)
    assert len({r.rule_id for r in (*GCP_RULES, *ORG_RULES)}) == 77


@pytest.mark.parametrize("rid", sorted(BASE))
@pytest.mark.parametrize("scenario", ["good", "bad", "ambiguous"])
def test_existing_rule_scenarios(rid, scenario):
    good, bad, gc, bc, native, gs, bs = BASE[rid]
    r = RULES[rid]
    data = good if scenario == "good" else bad if scenario == "bad" else {}
    context = gc if scenario == "good" else bc if scenario == "bad" else []
    o = obs(r.resource_type.removeprefix("GCP::"), data, native=native, operation=r.operation)
    v = evaluate(rid, o, context, SCOPE, (True, ""))
    if scenario == "ambiguous":
        assert v.outcome not in {"PASS", "FAIL"}, (rid, v)
    else:
        assert v.outcome == (gs if scenario == "good" else bs), (rid, v)
    assert v.reasoning
    assert o.evidence.artifact_id == "synthetic" and o.evidence.locator == "/0"


ORG_CASES = {
    "GCP-ORG-PUBLIC-SERVERLESS": ("run.googleapis.com/Service", "roles/run.invoker", "allUsers"),
    "GCP-ORG-PUBLIC-DATA": (
        "bigquery.googleapis.com/Dataset",
        "roles/bigquery.dataViewer",
        "allUsers",
    ),
    "GCP-ORG-PUBLIC-OTHER": ("compute.googleapis.com/Instance", "roles/compute.admin", "allUsers"),
    "GCP-ORG-BASIC-ROLE": (
        "cloudresourcemanager.googleapis.com/Project",
        "roles/editor",
        "user:admin@example.com",
    ),
    "GCP-ORG-SA-PRIVILEGED": (
        "cloudresourcemanager.googleapis.com/Project",
        "roles/editor",
        f"serviceAccount:worker@{PROJECT}.iam.gserviceaccount.com",
    ),
    "GCP-ORG-IMPERSONATION": (
        "cloudresourcemanager.googleapis.com/Project",
        "roles/iam.serviceAccountTokenCreator",
        "group:operators@example.com",
    ),
    "GCP-ORG-CROSSPROJECT-SA": (
        "cloudresourcemanager.googleapis.com/Project",
        "roles/editor",
        "serviceAccount:worker@synth-foreign.iam.gserviceaccount.com",
    ),
    "GCP-ORG-DELETED-PRINCIPAL": (
        "cloudresourcemanager.googleapis.com/Project",
        "roles/viewer",
        "deleted:user:old@example.com?uid=123",
    ),
}


@pytest.mark.parametrize("rid", sorted(ORG_CASES))
@pytest.mark.parametrize("scenario", ["good", "bad", "ambiguous"])
def test_org_selector_does_not_hide_ambiguous_policy(rid, scenario):
    kind, role, member = ORG_CASES[rid]
    config = {
        "assetType": kind,
        "resource": "//cloudresourcemanager.googleapis.com/projects/" + PROJECT,
        "policy": {"bindings": [{"role": role, "members": [member]}]},
    }
    if scenario == "good":
        config["policy"]["bindings"] = [
            {"role": "roles/viewer", "members": ["user:reader@example.com"]}
        ]
    if scenario == "ambiguous":
        config.pop("policy")
    notes = {}
    hits = matches(rid, config, PROJECT, SCOPE, notes)
    assert bool(hits) is (scenario == "bad")
    if scenario == "ambiguous":
        assert notes.get("policy_unknown")


@pytest.mark.parametrize("scenario", ["good", "bad", "ambiguous"])
def test_federation_provider_states(scenario):
    provider = obs(
        "WorkloadIdentityProvider", {"disabled": scenario == "good", "attributeCondition": ""}
    )
    info = None if scenario == "ambiguous" else {"items": [provider], "complete": True}
    v, reason, _refs = provider_state([{"attribute": "*"}], info)
    assert v == {"good": "PASS", "bad": "FAIL", "ambiguous": "MANUAL_VALIDATION_REQUIRED"}[scenario]
    assert reason


@pytest.mark.parametrize("scenario", ["good", "bad", "ambiguous"])
def test_domain_review_does_not_invent_org_owned_domains(scenario, monkeypatch):
    recorded = []
    monkeypatch.setattr(
        "offline_analyzer.rules.engine.persist_result",
        lambda store, run, result: recorded.append(result),
    )
    member = {
        "good": "user:reader@corp.example.com",
        "bad": "user:reader@vendor.example.com",
        "ambiguous": "user:unstructured",
    }[scenario]
    o = obs(
        "AssetIAMSearchResult",
        {
            "resource": "//cloudresourcemanager.googleapis.com/projects/" + PROJECT,
            "project": "projects/" + NUMBER,
            "assetType": "cloudresourcemanager.googleapis.com/Project",
            "policy": {"bindings": [{"role": "roles/viewer", "members": [member]}]},
        },
    )

    class Reader:
        def refs(self, run, ids):
            return (EvidenceRef(artifact_id="synthetic", locator="/0"),)

    manual_reviews(Reader(), "synthetic-run", [o], {NUMBER: PROJECT}, PROJECT, o.collected_at)
    rows = [r for r in recorded if r.rule_id == "GCP-ORG-EXTERNAL-DOMAIN"]
    if scenario == "ambiguous":
        assert not rows  # No parseable domain; this is not a passing assessment.
    else:
        assert len(rows) == 1 and rows[0].outcome == "MANUAL_VALIDATION_REQUIRED"
        assert rows[0].evidence and rows[0].evidence_needed
