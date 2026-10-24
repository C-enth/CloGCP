"""GCP collector 2.2.7 (static reading of the PowerShell source; nothing is executed) and
the analyzer changes: effective org-policy shapes for GCP-GOV-KEYS, API_DISABLED versus
QUOTA_PROJECT_DENIED presentation, and an end-to-end synthetic 2.2.7 package."""

import json
import re
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_gcp_collector_226 import SCRIPT, classifier, function_body, package
from test_gcp_coverage_notes import fail, rewrite, sources

from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.reporting.assessment_report import model
from offline_analyzer.reporting.cloud import dashboard
from offline_analyzer.rules.engine import assess
from offline_analyzer.rules.gcp import GCP_RULES, governance
from offline_analyzer.rules.registry import PROVIDER_RULES
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import TIME

TARGET = "123456789012"  # synthetic target project number
QUOTA = "333333333333"  # a different (quota/client) project number


# ---------------------------------------------------------------- C and E: classification
@pytest.mark.parametrize(
    ("stderr", "target", "status"),
    [
        (
            f"ERROR: API [cloudasset.googleapis.com] not enabled on project [{QUOTA}].",
            TARGET,
            "QUOTA_PROJECT_DENIED",
        ),
        (
            f"Cloud Asset API has not been used in project {QUOTA} before or it is disabled.",
            TARGET,
            "QUOTA_PROJECT_DENIED",
        ),
        (
            f"Cloud Asset API has not been used in project {TARGET} before or it is disabled.",
            TARGET,
            "API_DISABLED",
        ),
        (
            f"Cloud Asset API has not been used in project {QUOTA} before or it is disabled.",
            "",
            "API_DISABLED",
        ),  # target number unresolved: kept, with a note
        ("API [run.googleapis.com] SERVICE_DISABLED", TARGET, "API_DISABLED"),  # no number
        (
            "ERROR: (gcloud.run.services.list) argument --region: Must be specified.",
            TARGET,
            "COMMAND_ERROR",
        ),
        ("ERROR: (gcloud.x) HTTPError 403: Forbidden", TARGET, "ACCESS_DENIED"),
    ],
)
def test_service_disabled_names_the_project(stderr, target, status):
    assert classifier(target)(stderr) == status


def test_rest_and_note_paths_use_the_same_resolution():
    rest = function_body("Get-HttpStatusCategory")
    assert "return (Resolve-DisabledService $Body)" in rest
    resolver = function_body("Resolve-DisabledService")
    assert "Kept API_DISABLED" in resolver and "the quota/billing project" in resolver
    # The note is kept with the dataset (gcloud stderr file / REST error message).
    assert "[void]$retryNotes.Add($script:ClassificationNote)" in SCRIPT
    assert "$script:RestNote = $script:ClassificationNote" in SCRIPT
    # Target number: the selected inventory record, refined from the collected project.
    assert SCRIPT.index("$TargetProjectNumber = ''") < SCRIPT.index(
        "function Resolve-DisabledService"
    )
    assert "$TargetProjectNumber = [string]$described.projectNumber" in SCRIPT


# ---------------------------------------------------------------- A: pre-check exemption
EXEMPT = {
    "iam.googleapis.com",
    "orgpolicy.googleapis.com",
    "recommender.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "securitycenter.googleapis.com",
    "cloudasset.googleapis.com",
    "logging.googleapis.com",
}


def precheck():
    exempt = set(
        re.findall(
            r"'([a-z.]+\.googleapis\.com)'",
            re.search(r"\$PrecheckExempt = @\(([^)]*)\)", SCRIPT)[1],
        )
    )

    def skipped(required: str, enabled: set[str]) -> bool:
        return bool(required) and required not in enabled and required not in exempt

    return exempt, skipped


def test_identity_governance_security_apis_are_always_attempted():
    exempt, skipped = precheck()
    assert exempt == EXEMPT
    for body in ("Invoke-Collection", "Invoke-RestEvidence"):
        assert "if (Test-PrecheckSkip $RequiredApi) {" in function_body(body)
    enabled = {"compute.googleapis.com", "storage.googleapis.com"}  # orgpolicy, iam absent
    calls = {
        name: api
        for name, api in re.findall(
            r"^\s*(?:Run|RestList)\s+'[a-z]+'\s+'([a-z_0-9]+)'.*?'([a-z]+\.googleapis\.com)'",
            SCRIPT,
            re.MULTILINE,
        )
    }
    assert calls["project_org_policy_v2"] == "orgpolicy.googleapis.com"
    assert calls["service_account_keys_inventory"] == "iam.googleapis.com"
    for name in ("project_org_policy_v2", "service_account_keys_inventory", "iam_recommendations"):
        assert not skipped(calls[name], enabled), name
    assert skipped(calls["cloud_sql"], enabled)  # resource services are still pre-checked
    assert not skipped(calls["instances"], enabled)


# ---------------------------------------------------------------- B: effective policies
BASELINE = [
    "iam.disableServiceAccountKeyCreation",
    "iam.disableServiceAccountKeyUpload",
    "iam.allowedPolicyMemberDomains",
    "compute.requireOsLogin",
    "compute.disableSerialPortAccess",
    "compute.vmExternalIpAccess",
    "compute.skipDefaultNetworkCreation",
    "storage.publicAccessPrevention",
    "storage.uniformBucketLevelAccess",
    "sql.restrictPublicIp",
    "gcp.resourceLocations",
]


def normaliser():
    body = function_body("ConvertTo-ConstraintName")
    prefixed, bare = (p.replace("''", "'") for p in re.findall(r"-match '((?:[^']|'')*)'", body))

    def name(value: str) -> str:
        text = (value or "").strip()
        if match := re.search(prefixed, text):
            return match[1]
        return text if re.search(bare, text) else ""

    return name


def planned(listed: list[dict]) -> list[str]:
    """Effective-policy constraints the collector describes, in dataset order."""
    name = normaliser()
    baseline = re.findall(
        r"'([A-Za-z.]+)'", re.search(r"\$EffectivePolicyBaseline = @\(([^)]*)\)", SCRIPT)[1]
    )
    names = list(baseline)
    for policy in listed:
        found = name(policy.get("constraint", "")) or name(policy.get("name", ""))
        if found and found not in names:
            names.append(found)
    return names


def test_effective_policy_names_are_normalised_and_baselined():
    name = normaliser()
    assert name("gcp.resourceLocations") == "gcp.resourceLocations"
    assert name("constraints/compute.requireOsLogin") == "compute.requireOsLogin"
    assert name("projects/sample-project/policies/custom.denyPublicIp") == "custom.denyPublicIp"
    assert name("organizations/123/policies/iam.allowedPolicyMemberDomains") == (
        "iam.allowedPolicyMemberDomains"
    )
    assert name("") == "" and name("not a constraint") == "" and name("projects/x") == ""
    assert planned([]) == BASELINE  # empty inventory still describes the 11 baseline policies
    listed = [
        {"constraint": "gcp.resourceLocations"},  # duplicate of the baseline
        {"constraint": "constraints/custom.denyPublicIp"},
        {"name": "projects/p/policies/compute.restrictVpnPeerIPs"},
        {"name": "projects/p/policies/custom.denyPublicIp"},  # duplicate
        {"constraint": ""},
    ]
    assert planned(listed) == [*BASELINE, "custom.denyPublicIp", "compute.restrictVpnPeerIPs"]
    loop = SCRIPT[SCRIPT.index("$constraintIndex=0") :][:400]
    assert "('effective_policy_'+$constraintIndex)" in loop and "'--effective'" in loop
    assert "MaxDetailItems" not in loop  # unlimited, as in 2.2.6 (no new manifest field)


# ---------------------------------------------------------------- D: fallback suppression
def test_no_fallback_is_recorded_for_an_api_disabled_list(tmp_path):
    helper = function_body("Get-ServerlessTargets")
    stop = helper.index("if ($restStatus -eq 'API_DISABLED') { return ,$targets }")
    assert stop < helper.index("[void]$script:Fallbacks.Add(")

    def disabled(manifest, folder):
        for item in manifest["datasets"]:
            if item["dataset"] in {"run_services_rest", "cloud_run"} or item["dataset"].startswith(
                "run_iam_"
            ):
                if item.get("file"):
                    (folder / item["file"]).unlink()
                item.update(status="API_DISABLED", file=None, record_count=None, exit_code=None)
                item.pop("pages", None)
        manifest["datasets"] = [
            i for i in manifest["datasets"] if not i["dataset"].startswith("run_iam_")
        ]

    folder = rewrite(package(tmp_path, buckets=1, version="2.2.7"), disabled)
    found = sources(folder)
    assert "IAM_TARGETS_UNAVAILABLE" not in found["run_services_rest"]["notes"]
    assert found["run_services_rest"]["error"] == "API_DISABLED_OR_UNAVAILABLE"


# ---------------------------------------------------------------- 3: GCP-GOV-KEYS shapes
KEY = "iam.disableServiceAccountKeyCreation"


def policy(body: dict, constraint: str = KEY, effective=True):
    return SimpleNamespace(
        configuration={**body, "_parameters": {"effective": effective, "constraint": constraint}}
    )


@pytest.mark.parametrize(
    ("body", "outcome"),
    [
        (
            {"name": f"projects/{TARGET}/policies/{KEY}", "spec": {"rules": [{"enforce": True}]}},
            "PASS",
        ),
        (
            {"name": f"projects/{TARGET}/policies/{KEY}", "spec": {"rules": [{"enforce": False}]}},
            "FAIL",
        ),
        ({"constraint": f"constraints/{KEY}", "booleanPolicy": {"enforced": True}}, "PASS"),
        ({"constraint": f"constraints/{KEY}", "booleanPolicy": {"enforced": False}}, "FAIL"),
        ({"name": "x", "spec": {"inheritFromParent": True, "rules": [{"enforce": True}]}}, "PASS"),
        (
            {
                "name": "x",
                "spec": {"rules": [{"enforce": True}]},
                "dryRunSpec": {"rules": [{"enforce": False}]},
            },
            "PASS",
        ),  # dry run never counts
        ({"name": "x", "dryRunSpec": {"rules": [{"enforce": True}]}}, "UNKNOWN"),
        (
            {
                "name": "x",
                "spec": {
                    "rules": [
                        {"enforce": True, "condition": {"expression": "e"}},
                        {"enforce": False},
                    ]
                },
            },
            "UNKNOWN",
        ),
        ({"name": "x", "spec": {"rules": [{"values": {"allowedValues": ["a"]}}]}}, "UNKNOWN"),
        ({"name": "x", "spec": {"rules": [{"enforce": True}, {"enforce": False}]}}, "UNKNOWN"),
        ({"name": "x", "spec": {"reset": True}}, "UNKNOWN"),
        ({"name": "x", "spec": {}}, "UNKNOWN"),
        ({"name": "x"}, "UNKNOWN"),  # unset
        ({}, "UNKNOWN"),
        ({"name": "x", "spec": "garbage"}, "UNKNOWN"),
        ({"constraint": f"constraints/{KEY}", "booleanPolicy": {}}, "UNKNOWN"),
    ],
)
def test_key_governance_effective_shapes(body, outcome):
    assert str(governance(policy(body)).outcome) == outcome


def test_key_governance_scope_and_other_constraints():
    listed = {"name": "x", "spec": {"rules": [{"values": {"deniedValues": ["us-east1"]}}]}}
    other = governance(policy(listed, "gcp.resourceLocations"))
    assert str(other.outcome) == "NOT_APPLICABLE"
    not_effective = policy({"spec": {"rules": [{"enforce": True}]}}, effective=False)
    assert str(governance(not_effective).outcome) == "UNKNOWN"
    assert {"pilot-true": policy({"booleanPolicy": {"enforced": True}}, effective="true")}
    assert (
        str(governance(policy({"booleanPolicy": {"enforced": True}}, effective="true")).outcome)
        == "PASS"
    )
    assert next(r for r in GCP_RULES if r.rule_id == "GCP-GOV-KEYS").version == "1.4.0"


# ---------------------------------------------------------------- end to end
POLICIES = {
    "iam.disableServiceAccountKeyCreation": {"spec": {"rules": [{"enforce": True}]}},
    "iam.disableServiceAccountKeyUpload": {
        "spec": {"inheritFromParent": True, "rules": [{"enforce": False}]}
    },
    "gcp.resourceLocations": {"spec": {"rules": [{"values": {"allowedValues": ["in:eu"]}}]}},
}


def package_227(tmp_path: Path) -> Path:
    def update(manifest, folder):
        manifest["datasets"] = [
            d for d in manifest["datasets"] if not d["dataset"].startswith("effective_policy_")
        ]
        for leftover in folder.glob("governance/effective_policy_*"):
            leftover.unlink()

        def entry(index, constraint, body=None, status="SUCCESS"):
            item = dict(
                domain="governance",
                dataset=f"effective_policy_{index}",
                status=status,
                record_count=1,
                exit_code=0,
                required_api="",
                started_utc=TIME,
                finished_utc=TIME,
                file=f"governance/effective_policy_{index}.json",
                error_file=None,
                command=f"gcloud org-policies describe {constraint} --effective "
                "--project=sample-project --format=json --quiet",
            )
            if body is None:
                fail(item, folder, status, "HTTPError 403: synthetic")
            else:
                (folder / item["file"]).write_text(
                    json.dumps({"name": f"projects/{TARGET}/policies/{constraint}", **body})
                )
            return item

        for index, (constraint, body) in enumerate(POLICIES.items(), 1):
            manifest["datasets"].append(entry(index, constraint, body))
        manifest["datasets"].append(entry(4, "compute.requireOsLogin", status="ACCESS_DENIED"))
        for item in manifest["datasets"]:
            if item["dataset"] == "cloud_sql":
                fail(item, folder, "API_DISABLED", "")
                item["error_file"] = None
                (folder / "data/cloud_sql.stderr.txt").unlink(missing_ok=True)
            if item["dataset"] == "asset_iam_list":
                fail(item, folder, "QUOTA_PROJECT_DENIED", f"has not been used in project {QUOTA}")
            if item["dataset"] == "asset_iam_search":
                search = [
                    {
                        "resource": "//cloudresourcemanager.googleapis.com/projects/sample-project",
                        "assetType": "cloudresourcemanager.googleapis.com/Project",
                        "project": f"projects/{TARGET}",
                        "policy": {
                            "bindings": [
                                {
                                    "role": "roles/viewer",
                                    "members": ["user:analyst@partner.example"],
                                }
                            ]
                        },
                    },
                    {
                        "resource": "//iam.googleapis.com/projects/sample-project/serviceAccounts/"
                        "bridge@sample-project.iam.gserviceaccount.com",
                        "assetType": "iam.googleapis.com/ServiceAccount",
                        "project": f"projects/{TARGET}",
                        "policy": {
                            "bindings": [
                                {
                                    "role": "roles/iam.workloadIdentityUser",
                                    "members": [
                                        f"principalSet://iam.googleapis.com/projects/{TARGET}/locations/"
                                        "global/workloadIdentityPools/ci-pool/attribute.repository/x/y"
                                    ],
                                }
                            ]
                        },
                    },
                ]
                (folder / item["file"]).write_text(json.dumps(search))
                item["record_count"] = len(search)

    return rewrite(package(tmp_path, buckets=2, version="2.2.7"), update)


def test_synthetic_227_package_end_to_end(tmp_path):
    folder = package_227(tmp_path)
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        results = list(store.results(run))
        keys = {
            r.native_id.rsplit("/", 1)[-1]: str(r.outcome)
            for r in results
            if r.rule_id == "GCP-GOV-KEYS" and r.native_id
        }
        assert keys == {
            "iam.disableServiceAccountKeyCreation": "PASS",
            "iam.disableServiceAccountKeyUpload": "FAIL",
            "gcp.resourceLocations": "NOT_APPLICABLE",
        }
        # Every GCP rule is accounted for: at least one resource or collection-scope result.
        gcp = {r.rule_id for r in PROVIDER_RULES if r.provider == "GCP"}
        assert len(gcp) == 77  # 48 existing + 29 CloGCP criteria
        assert gcp <= {r.rule_id for r in results}
        # No PASS from a failed, disabled or quota-denied source.
        failed = {
            s["artifact_id"] for s in store.source_data(run) if s["effective_coverage"] == "ERROR"
        }
        assert not [
            r
            for r in results
            if str(r.outcome) == "PASS" and failed & {e.artifact_id for e in r.evidence}
        ]
        gaps = {g["dataset"]: g for g in dashboard(store, run, "GCP")["gaps"]}
        assert gaps["cloud_sql"]["status"] == "API_DISABLED"
        assert gaps["cloud_sql"]["coverage_reason"].startswith(
            "Service not enabled (per enabled-services evidence)"
        )
        assert "quota/billing project" in gaps["asset_iam_list"]["coverage_reason"]
        assert "denied access" in gaps["effective_policy_4"]["coverage_reason"]
        empty = [g for g in gaps.values() if g["status"] == "EMPTY"]
        assert all(
            g["effective_coverage"] != "ERROR"
            and not g["coverage_reason"].startswith(
                ("Service not enabled", "The quota", "The collector identity")
            )
            for g in empty
        )
        codes = Counter(n["code"] for n in model(store, run)["coverage_notes"])
        assert codes["API_DISABLED_OR_UNAVAILABLE"] and codes["COLLECTION_QUOTA_PROJECT_DENIED"]


@pytest.mark.parametrize("version", ["2.2.4", "2.2.5", "2.2.6", "2.2.8"])
def test_earlier_packages_import_unchanged(tmp_path, version):
    """The same evidence declared as an earlier 2.2.x collector gives the same results."""
    outcomes = []
    for name in (version, "2.2.7"):
        folder = package(tmp_path / name, buckets=2, version=name)
        with Store(tmp_path / name / "workspace") as store:
            run = import_package(store, folder)
            assess(store, run)
            outcomes.append(Counter((r.rule_id, str(r.outcome)) for r in store.results(run)))
    assert outcomes[0] == outcomes[1]
