"""GCP collector 2.2.8: custom role details by bare role ID and scope flag. Static reading of
the PowerShell source (nothing is executed; Windows PowerShell 5.1 behaviour is not verifiable
here) and a synthetic 2.2.8 package through the analyzer."""

import json
import re

import pytest
from test_gcp_collector_226 import SCRIPT, WRITE_VERBS, classifier, function_body, package
from test_gcp_coverage_notes import rewrite

from offline_analyzer.iam.gcp_principals import lookup
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store

ROLE = "projects/sample-project/roles/synthetic.operator_1"
MEMBER = "serviceAccount:worker@sample-project.iam.gserviceaccount.com"


def describe_arguments(name: str) -> list[str] | None:
    """Get-RoleDescribeArguments as PowerShell -match applies it (patterns read from source)."""
    body = function_body("Get-RoleDescribeArguments")
    rules = re.findall(r"if \(\$Name -match '([^']+)'\) \{\s*return ,@\(([^)]*\)[^)]*)\)", body)
    assert len(rules) == 2
    for pattern, built in rules:
        # -match is case-insensitive in PowerShell; IDs are lower-case in GCP, so keep both.
        match = re.search(pattern, name, re.IGNORECASE)
        if match:
            flag = re.search(r"'(--(?:project|organization)=)'", built)[1]
            return ["iam", "roles", "describe", match[2], flag + match[1]]
    return None


def test_version_header_and_contract():
    assert "$CollectorVersion = '2.2.8'" in SCRIPT
    assert "2.2.8: custom role details pass the bare role ID" in SCRIPT


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (ROLE, ["iam", "roles", "describe", "synthetic.operator_1", "--project=sample-project"]),
        (
            "organizations/444444444444/roles/org_reviewer.v2",
            ["iam", "roles", "describe", "org_reviewer.v2", "--organization=444444444444"],
        ),
        (
            "projects/example.com:synthetic-app/roles/legacyRole",
            ["iam", "roles", "describe", "legacyRole", "--project=example.com:synthetic-app"],
        ),
        ("roles/owner", None),  # predefined role name: never described here
        ("projects/sample-project/roles/", None),
        ("projects/sample-project/roles/a/b", None),
        ("organizations/not-a-number/roles/x", None),
        ("folders/12345/roles/x", None),
        ("", None),
        ("projects/sample-project/roles/bad role", None),
    ],
)
def test_role_arguments_for_both_scopes_and_odd_shapes(name, expected):
    assert describe_arguments(name) == expected


def test_arguments_are_parenthesised_and_odd_shapes_skip_without_crashing():
    body = function_body("Get-RoleDescribeArguments")
    assert "('--project=' + $Matches[1])" in body
    assert "('--organization=' + $Matches[1])" in body
    # No unparenthesised concatenation inside an argument array.
    assert not re.search(r",\s*'--[a-z]+='\s*\+", body)
    loop = SCRIPT[SCRIPT.index("foreach ($role in $customRoles) {") :]
    loop = loop[: loop.index("\n}\n")]
    assert "$describeArguments = Get-RoleDescribeArguments ([string]$role.name)" in loop
    assert "if ($null -eq $describeArguments) {" in loop and "continue" in loop
    assert "Run 'identity' ('custom_role_detail_'+$roleIndex) $describeArguments" in loop
    # The counter advances only for described roles; no raw pipeline JSON parsing.
    assert loop.index("$roleIndex++") > loop.index("$describeArguments = ")
    assert not re.search(r"Get-Content[^\n]*\|\s*ConvertFrom-Json", SCRIPT)
    assert "([string]$role.name))" not in loop.split("Write-Host")[0]


def test_the_prefix_message_is_a_command_error():
    message = (
        "ERROR: (gcloud.iam.roles.describe) INVALID_ARGUMENT: The role id should not include "
        "any 'projects/' or 'organizations/' prefix."
    )
    assert classifier()(message) == "COMMAND_ERROR"


def test_no_write_verbs_in_the_new_code():
    for text in (function_body("Get-RoleDescribeArguments"),):
        for line in text.splitlines():
            tokens = set(re.findall(r"'([a-z-]+)'", line))
            assert not tokens & WRITE_VERBS, line


def package_228(tmp_path):
    """Synthetic 2.2.8 package whose custom_role_detail_1 succeeds and whose project IAM binds
    the custom role to a service account."""

    def update(manifest, folder):
        manifest["collector_version"] = "2.2.8"
        for item in manifest["datasets"]:
            if item["dataset"] == "custom_role_detail_1":
                if item.get("error_file"):
                    (folder / item["error_file"]).unlink(missing_ok=True)
                item.update(
                    status="SUCCESS",
                    file="identity/custom_role_detail_1.json",
                    error_file=None,
                    record_count=1,
                    exit_code=0,
                    command="gcloud iam roles describe synthetic.operator_1 "
                    "--project=sample-project --format=json --quiet",
                )
                (folder / item["file"]).write_text(
                    json.dumps(
                        {
                            "name": ROLE,
                            "title": "Synthetic operator",
                            "includedPermissions": [
                                "compute.instances.get",
                                "compute.instances.list",
                            ],
                            "stage": "GA",
                        }
                    )
                )
            elif item["dataset"] == "project_iam" and item.get("file"):
                path = folder / item["file"]
                policy = json.loads(path.read_text())
                policy.setdefault("bindings", []).append({"role": ROLE, "members": [MEMBER]})
                path.write_text(json.dumps(policy))

    return rewrite(package(tmp_path, buckets=1, version="2.2.8"), update)


def test_synthetic_228_package_resolves_custom_role_permissions(tmp_path):
    folder = package_228(tmp_path)
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        detail = [
            s
            for s in store.source_data(run)
            if (s.get("gcp_metadata") or {}).get("dataset") == "custom_role_detail_1"
        ]
        assert detail and detail[0]["effective_coverage"] != "ERROR"
        rows = [b for b in lookup(store, run, MEMBER)["bindings"] if b["role"] == ROLE]
        assert rows and rows[0]["role_status"] == "RESOLVED"
        assert rows[0]["permissions"] == ["compute.instances.get", "compute.instances.list"]
