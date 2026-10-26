"""Phase A (AWS batch readiness): access design, read-only guarantees and the pre-flight probe.
Synthetic data only: the probe runs against tools/fixtures/aws_fake_cloud.py."""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tools import aws_access_policy as access
from tools.fixtures import aws_fake_cloud as fake

AWS = Path("collectors/aws")
SCRIPTS = ("assessment.py", "fleet.py", "preflight.py", "batch.py")
# Method calls that are not AWS APIs (boto3 session configuration, local helpers).
LOCAL_CALLS = {
    "set_config_variable",
    "run_prowler",
    "add_argument",
    "add_parser",
    "add_subparsers",
    "run_pool",
}
WRITE_VERB = re.compile(
    r"\.(?:put|create|delete|update|modify|attach|detach|tag|untag|start|stop|terminate|run|"
    r"invoke|send|enable|disable|associate|disassociate|reboot|restore|copy|import|register|"
    r"deregister|authorize|revoke|accept|reject|cancel|set|add|remove|replace|reset|"
    r"subscribe|unsubscribe|publish|purge|batch_write|batch_delete)_[a-z0-9_]+\("
)


def test_access_design_is_current():
    result = subprocess.run(
        [sys.executable, "tools/aws_access_policy.py", "--check"],
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": "src:."},
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        Path("docs/AWS_COLLECTION_ACCESS.md").read_text()
        == (AWS / "AWS_COLLECTION_ACCESS.md").read_text()
    )


def test_collector_calls_are_read_only():
    calls = [(r["service"], r["method"]) for r in access.collector_calls()]
    calls += access.probe_calls()
    assert len(calls) > 100
    offending = [
        f"{s}.{m}"
        for s, m in calls
        if not access.READ_VERB.fullmatch(m) and (s, m) != ("sts", "get_caller_identity")
    ]
    assert offending == []
    for name in SCRIPTS:
        source = (AWS / name).read_text(encoding="utf-8")
        found = {m.group()[1:-1] for m in WRITE_VERB.finditer(source)} - LOCAL_CALLS
        assert found == set(), name


def test_every_api_call_site_uses_a_registered_operation():
    """api(..., "<service>", <operation>, ...) call sites: literal operations must be
    registered; loop variables must iterate a registry list or a tuple of registered names."""
    tree = ast.parse((AWS / "assessment.py").read_text(encoding="utf-8"))
    registered = {(r["service"], r["method"]) for r in access.collector_calls()}
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def loop_source(node, name):
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.For) and getattr(node.target, "id", None) == name:
                return node.iter
        raise AssertionError(f"operation variable {name} is not a loop variable")

    checked = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "api"):
            continue
        service, operation = node.args[3], node.args[4]
        if not isinstance(service, ast.Constant):
            continue  # registry loops: (service, op) both come from GLOBAL/REGIONAL
        if isinstance(operation, ast.Constant):
            assert (service.value, operation.value) in registered
        else:
            source = loop_source(node, operation.id)
            if isinstance(source, ast.Tuple):
                names = [e.value for e in source.elts]
                assert all((service.value, n) in registered for n in names), names
            else:
                assert isinstance(source, ast.Subscript) and source.value.id == "DEPENDENT"
        checked += 1
    assert checked >= 10


def policy(name):
    return json.loads((AWS / "policies" / name).read_text())


def allowed_actions(document):
    return [
        a
        for s in document["Statement"]
        if s["Effect"] == "Allow"
        for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
    ]


def test_policies_are_read_only_and_cover_every_call():
    supplement = policy("member-supplement-policy.json")
    management = policy("management-organizations-read-policy.json")
    for document in (supplement, management):
        for action in allowed_actions(document):
            verb = action.split(":", 1)[1]
            assert re.match(r"(Get|List|Describe|Search)", verb), action
    deny = [s for s in supplement["Statement"] if s["Effect"] == "Deny"]
    assert deny and {"s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt"} <= set(
        deny[0]["Action"]
    )
    snapshot = access.snapshot()["policies"]["SecurityAudit"]["actions"]
    granted = set(allowed_actions(supplement))
    for row in access.matrix():
        if row["requires_permission"]:
            assert access.grants(row["action"], snapshot) or row["action"] in granted, row
    hub = policy("hub-operator-policy.json")
    assert set(allowed_actions(hub)) == {"sts:AssumeRole", "organizations:ListAccounts"}


def test_stackset_role_is_read_only_and_organization_bound():
    template = policy("member-role-stackset.cfn.json")
    role = template["Resources"]["CollectorRole"]["Properties"]
    assert role["ManagedPolicyArns"] == [
        {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/SecurityAudit"}
    ]
    trust = role["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust["Action"] == "sts:AssumeRole"
    assert set(trust["Condition"]) == {"ArnLike", "StringEquals"}
    assert "aws:PrincipalOrgID" in trust["Condition"]["StringEquals"]
    assert template["Parameters"]["MaxSessionDuration"]["Default"] == 3600
    assert role["Policies"][0]["PolicyDocument"] == policy("member-supplement-policy.json")
    text = json.dumps(template)
    assert "AdministratorAccess" not in text and "PowerUser" not in text


def test_probe_families_use_the_designed_actions():
    tree = ast.parse((AWS / "preflight.py").read_text(encoding="utf-8"))
    families = access.literal(tree, {"FAMILIES"})["FAMILIES"]
    assert len({f[0] for f in families}) == len(families)
    for name, service, method, _scope, _params, action in families:
        assert access.iam_action(service, method) == action, name


@pytest.fixture
def probed(tmp_path, capsys):
    cloud = fake.fleet(3)
    first, second, third = (fake.fleet_account(i) for i in range(3))
    cloud.accounts[third].assume_error = "AccessDenied"
    cloud.faults += [
        fake.Fault("guardduty", "list_detectors", "AccessDeniedException", account=first),
        fake.Fault("guardduty", "list_detectors", "AccessDeniedException", account=second),
        fake.Fault("kms", "list_keys", "ThrottlingException", account=first, times=1),
        fake.Fault("macie2", "get_macie_session", "ReadTimeoutError", account=second, times=9),
    ]
    accounts = tmp_path / "accounts.csv"
    accounts.write_text(
        "account_id,business_group,name\n"
        + "".join(f"{a},Group {i},Synthetic {i}\n" for i, a in enumerate((first, second, third)))
    )
    with fake.installed(cloud, "preflight") as preflight:
        code = preflight.main(
            [
                "--accounts",
                str(accounts),
                "--role",
                "CloSecEvidenceReadOnly",
                "--regions",
                "ap-south-1",
                "me-south-1",
                "--output",
                str(tmp_path / "out"),
                "--max-attempts",
                "2",
            ]
        )
    folder = next((tmp_path / "out").iterdir())
    return {
        "code": code,
        "out": capsys.readouterr().out,
        "summary": json.loads((folder / "fleet-summary.json").read_text()),
        "rows": json.loads((folder / "accounts.json").read_text())["rows"],
        "accounts": (first, second, third),
        "calls": cloud.calls,
    }


def test_probe_classifies_every_family_and_masks_accounts(probed):
    first, second, third = probed["accounts"]
    verdicts = probed["summary"]["account_verdicts"]
    assert verdicts == {first: "ACCESS GAP", second: "ACCESS GAP", third: "ACCESS GAP"}
    rows = {(r["account_id"], r["family"], r["region"]): r for r in probed["rows"]}
    assert rows[(third, "assume-role", "global")]["status"] == "DENIED"
    assert rows[(first, "kms", "ap-south-1")]["status"] == "ALLOWED"
    assert rows[(first, "kms", "ap-south-1")]["attempts"] == 2  # throttled once, retried
    assert rows[(second, "macie", "ap-south-1")]["status"] == "TIMEOUT"
    assert rows[(first, "ec2", "me-south-1")]["status"] == "REGION_NOT_ENABLED"
    assert rows[(first, "organizations-policies", "global")]["status"] == "DENIED"
    assert rows[(first, "s3-account-bpa", "global")]["status"] == "ALLOWED"
    repeated = {(r["family"], r["status"]): r for r in probed["summary"]["repeated"]}
    assert repeated[("guardduty", "DENIED")]["accounts"] == 2
    assert repeated[("organizations-policies", "DENIED")]["expected_in_member_accounts"]
    # Terminal output masks every account ID; the result files keep full IDs.
    for account in probed["accounts"]:
        assert account not in probed["out"]
        assert fake.fleet_account(0)[-4:] in probed["out"]
    assert probed["code"] == 1
    # Read-only at runtime: the fake refuses any non-read method, so reaching here proves it.
    assert all(fake.READ.fullmatch(m) for _a, _s, m, _r in probed["calls"])
