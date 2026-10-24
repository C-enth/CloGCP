"""SRE validation track, stages, per-account workbooks and the Finalized report (ADR-008)."""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook

from offline_analyzer.api.app import create_app
from tests.test_api import ORIGIN, TOKEN, authenticated, await_job, upload_package
from tools.fixtures.r12_demo import build


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    root = tmp_path_factory.mktemp("sre")
    build(root / "package")
    with TestClient(
        create_app(root / "work", origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN
    ) as c:
        headers = authenticated(c)
        upload_id = upload_package(c, headers, root / "package").json()["upload_id"]
        run_id = await_job(
            c, c.post("/api/import", headers=headers, json={"upload_id": upload_id})
        )["run_id"]
        await_job(c, c.post(f"/api/runs/{run_id}/assess", headers=headers, json={}))
        yield c, headers, run_id


def findings(client, run_id, **params):
    return client.get(
        f"/api/runs/{run_id}/records/findings", params={"limit": 100, **params}
    ).json()


def stage_counts(client, run_id):
    facets = client.get(f"/api/runs/{run_id}/finding-facets").json()
    return {f["value"]: f["count"] for f in facets["stage"]}, facets


def assert_sql_stage_matches_python(client, run_id):
    counts, _ = stage_counts(client, run_id)
    for value, count in counts.items():
        page = findings(client, run_id, stage=value)
        assert page["total"] == count
        assert {f["stage"] for f in page["items"]} == {value}


def test_sre_workflow_reaches_confirmed_vulnerability_only_with_both_reviews(run):
    client, headers, run_id = run
    items = findings(client, run_id)["items"]
    assert {f["stage"] for f in items} == {"TRIAGE"}
    account = items[0]["account_id"]
    open_in_account = [f for f in items if f["account_id"] == account]

    # Bulk: every open finding of one account is sent to SRE.
    sent = client.post(
        f"/api/runs/{run_id}/sre",
        headers=headers,
        json={
            "verdict": "SENT_TO_SRE",
            "analyst": "analyst-a",
            "provider": "AWS",
            "scope": account,
        },
    )
    assert sent.status_code == 200 and sent.json()["recorded"] == len(open_in_account)
    assert_sql_stage_matches_python(client, run_id)

    first, second, third = (f["finding_id"] for f in open_in_account[:3])
    # A BAU conclusion must carry the SRE's justification.
    rejected = client.post(
        f"/api/runs/{run_id}/sre",
        headers=headers,
        json={"verdict": "NO_GAP_BAU", "analyst": "analyst-a", "finding_ids": [first]},
    )
    assert rejected.status_code == 400
    for fid, verdict, reason in (
        (first, "GAP_CONFIRMED", '=HYPERLINK("x") not intended'),
        (second, "GAP_CONFIRMED", ""),
        (third, "NO_GAP_BAU", "Approved break-glass role"),
    ):
        response = client.post(
            f"/api/runs/{run_id}/sre",
            headers=headers,
            json={
                "verdict": verdict,
                "analyst": "analyst-a",
                "sre_contact": "sre-team",
                "reason": reason,
                "finding_ids": [fid],
            },
        )
        assert response.status_code == 200, response.text
    # Only the analyst's own confirmation makes the SRE-confirmed gap a vulnerability.
    review = client.post(
        f"/api/runs/{run_id}/review/{first}",
        headers=headers,
        json={"status": "CONFIRMED", "analyst": "analyst-a", "note": "SRE confirmed"},
    )
    assert review.status_code == 200
    by_id = {f["finding_id"]: f for f in findings(client, run_id)["items"]}
    assert by_id[first]["stage"] == "CONFIRMED_VULNERABILITY"
    assert by_id[second]["stage"] == "SRE_CONFIRMED_GAP"
    assert by_id[third]["stage"] == "NO_GAP_BAU"
    assert by_id[third]["sre"]["reason"] == "Approved break-glass role"
    assert by_id[first]["analyst_status"] == "CONFIRMED"
    assert_sql_stage_matches_python(client, run_id)

    final = client.get(f"/api/runs/{run_id}/finalized").json()
    assert [f["id"] for f in final["findings"]] == [first]
    assert final["findings"][0]["misuse"] and final["findings"][0]["recommendation"]
    assert final["accounts"][0]["total"] == 1

    workbook = client.get(f"/api/runs/{run_id}/finalized.xlsx")
    assert workbook.status_code == 200
    wb = load_workbook(io.BytesIO(workbook.content))
    assert wb.sheetnames == [
        "Executive Summary",
        "Technical Findings",
        "Attack Paths",
        "Findings Validation",
    ]
    sheet = wb["Technical Findings"]
    header = [c.value for c in sheet[1]]
    assert sheet.max_row == 2 and sheet.cell(2, 1).value == first
    row = dict(zip(header, [c.value for c in sheet[2]], strict=True))
    assert row["SRE response"].startswith("Gap confirmed by sre-team")
    assert row["Confirmed by"] == "analyst-a"
    assert {"Why this is flagged", "How it can be misused", "Impact", "Recommendation"} <= set(
        header
    )
    # Untrusted text never becomes a spreadsheet formula.
    assert not any(c.data_type == "f" for ws in wb.worksheets for r in ws.iter_rows() for c in r)
    report = client.get(f"/api/runs/{run_id}/finalized.rtf")
    assert report.status_code == 200 and first.encode() in report.content
    text = report.content.decode("ascii")
    assert text.index("1. Executive summary") < text.index("2. Technical findings")
    assert text.index("2. Technical findings") < text.index("3. Attack paths")
    assert "Confirmed Vulnerabilities Report" in text and "How it can be misused" in text
    pdf = client.get(f"/api/runs/{run_id}/finalized.pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-1.4") and first.encode() in pdf.content


def test_per_account_sre_workbooks_list_open_findings_with_verdict_choices(run):
    client, headers, run_id = run
    _, facets = stage_counts(client, run_id)
    archive = zipfile.ZipFile(
        io.BytesIO(client.get(f"/api/runs/{run_id}/sre-workbooks.zip").content)
    )
    names = archive.namelist()
    open_stages = {"TRIAGE", "WITH_SRE", "SRE_REVALIDATION"}
    accounts = [a for a in facets["accounts"] if any(a["stage"].get(s) for s in open_stages)]
    assert len(names) == len(accounts)
    account = accounts[0]
    response = client.get(
        f"/api/runs/{run_id}/sre-workbook.xlsx",
        params={"provider": account["provider"], "scope": account["scope"]},
    )
    assert response.status_code == 200
    wb = load_workbook(io.BytesIO(response.content))
    assert wb.sheetnames == ["Read me", "Findings for SRE"]
    sheet = wb["Findings for SRE"]
    assert sheet.max_row - 1 == sum(account["stage"].get(s, 0) for s in open_stages)
    header = [c.value for c in sheet[1]]
    assert header[header.index("SRE verdict")] == "SRE verdict"
    choices = sheet.data_validations.dataValidation[0]
    assert "Gap confirmed" in choices.formula1 and "No gap (BAU)" in choices.formula1
    assert (
        client.get(
            f"/api/runs/{run_id}/sre-workbook.xlsx", params={"provider": "X", "scope": "1"}
        ).status_code
        == 400
    )


def assessment_report(client, headers, run_id, **options):
    job = await_job(
        client,
        client.post(
            f"/api/runs/{run_id}/reports", headers=headers, json={"kind": "assessment", **options}
        ),
    )
    archive = zipfile.ZipFile(io.BytesIO(client.get(f"/api/reports/{job['id']}/download").content))
    xlsx = next(n for n in archive.namelist() if n.endswith(".xlsx"))
    book = load_workbook(io.BytesIO(archive.read(xlsx)))
    # One template: executive summary, technical findings, attack paths last.
    assert book.sheetnames == [
        "Executive Summary",
        "Technical Findings",
        "Attack Paths",
        "Findings Validation",
    ]
    sheet = book["Technical Findings"]
    from xml.etree.ElementTree import fromstring

    with zipfile.ZipFile(
        io.BytesIO(archive.read(next(n for n in archive.namelist() if n.endswith(".docx"))))
    ) as word:
        document = fromstring(word.read("word/document.xml"))
        rtf = "\n".join(document.itertext())
    sections = [
        rtf.index(t) for t in ("1 Executive summary", "2 Technical findings", "3 Attack paths")
    ]
    assert sections == sorted(sections)
    return {row[0] for row in sheet.iter_rows(min_row=2, values_only=True)}, rtf


def test_bulk_marking_drives_report_contents_and_per_account_reports(run):
    client, headers, run_id = run
    items = findings(client, run_id)["items"]
    ids = {f["finding_id"] for f in items}
    candidates = [f["finding_id"] for f in items if f["analyst_status"] == "CANDIDATE"]
    rejected = candidates[:2]
    response = client.post(
        f"/api/runs/{run_id}/review-bulk",
        headers=headers,
        json={
            "status": "REJECTED",
            "analyst": "analyst-a",
            "note": "Known; accepted",
            "finding_ids": rejected,
        },
    )
    assert response.status_code == 200 and response.json()["recorded"] == 2
    # All-or-nothing: an unknown ID records nothing.
    assert (
        client.post(
            f"/api/runs/{run_id}/review-bulk",
            headers=headers,
            json={"status": "CONFIRMED", "analyst": "a", "finding_ids": [candidates[2], "nope"]},
        ).status_code
        == 400
    )
    assert findings(client, run_id, validation="CONFIRMED")["total"] == 1
    stages = {f["finding_id"]: f["stage"] for f in findings(client, run_id)["items"]}
    excluded = {fid for fid, stage in stages.items() if stage in {"REJECTED", "NO_GAP_BAU"}}
    assert set(rejected) <= excluded

    valid, rtf = assessment_report(client, headers, run_id)
    assert valid == ids - excluded and "Findings included" in rtf and "All findings except" in rtf
    everything, _ = assessment_report(client, headers, run_id, include="all")
    assert everything == ids
    confirmed, _ = assessment_report(client, headers, run_id, include="confirmed")
    assert confirmed == {
        f["finding_id"] for f in findings(client, run_id, validation="CONFIRMED")["items"]
    }

    account = items[0]["account_id"]
    scoped, scoped_rtf = assessment_report(
        client, headers, run_id, include="all", provider="AWS", scope=account
    )
    assert scoped == {f["finding_id"] for f in items if f["account_id"] == account}
    assert (
        client.post(
            f"/api/runs/{run_id}/reports", headers=headers, json={"kind": "excel", "include": "all"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/runs/{run_id}/reports",
            headers=headers,
            json={"kind": "assessment", "scope": account},
        ).status_code
        == 400
    )

    final = client.get(
        f"/api/runs/{run_id}/finalized", params={"provider": "AWS", "scope": account}
    ).json()
    other = client.get(
        f"/api/runs/{run_id}/finalized", params={"provider": "AWS", "scope": "000000000000"}
    ).json()
    assert len(final["findings"]) == 1 and other["findings"] == []


def test_attack_paths_carry_a_resource_chain_diagram(run):
    client, _, run_id = run
    paths = client.get(f"/api/runs/{run_id}/cloud/paths").json()["items"]
    assert paths
    for path in paths:
        chart = path["diagram"]
        assert chart["nodes"] and len(chart["edges"]) == len(chart["nodes"]) - 1
        assert chart["nodes"][0]["label"]
    # AWS prerequisite paths name the rule that evidences each prerequisite.
    assert any(n["rules"] for p in paths for n in p["diagram"]["nodes"])


def test_diagram_text_for_each_path_shape():
    from offline_analyzer.attack_paths.diagram import diagram_text

    assert (
        diagram_text(
            {
                "transitions": [
                    {
                        "source": "key/a",
                        "destination": "sa/b",
                        "relationship": "authenticates as",
                        "status": "POTENTIAL",
                    },
                    {
                        "source": "sa/b",
                        "destination": "projects/p",
                        "relationship": "roles/owner",
                        "status": "SUPPORTED",
                    },
                ]
            }
        )
        == "key/a -[authenticates as (POTENTIAL)]-> sa/b -[roles/owner (SUPPORTED)]-> projects/p"
    )
    assert diagram_text({"steps": ["A", "B", "C"]}) == "A -> B -> C"
    text = diagram_text(
        {"attack_path": "AP-05", "anchor": "bucket-x", "prerequisites": {"AP-05.P1": "VERIFIED"}}
    )
    assert text.startswith("bucket-x -> Account-level Block Public Access")
    assert "[VERIFIED; rule R1-S3-ACCOUNT-BPA]" in text


def test_assessor_confirmation_alone_finalizes_and_needs_no_typed_name(run):
    client, headers, run_id = run
    identity = client.get("/api/identity").json()["analyst"]
    assert identity
    triage = (
        findings(client, run_id, stage="TRIAGE")["items"]
        or findings(client, run_id, stage="WITH_SRE")["items"]
    )
    fid = triage[0]["finding_id"]
    response = client.post(
        f"/api/runs/{run_id}/review/{fid}", headers=headers, json={"status": "CONFIRMED"}
    )
    assert response.status_code == 200
    item = next(f for f in findings(client, run_id)["items"] if f["finding_id"] == fid)
    assert item["stage"] == "CONFIRMED_VULNERABILITY" and item["decision"]["analyst"] == identity
    assert fid in {f["id"] for f in client.get(f"/api/runs/{run_id}/finalized").json()["findings"]}


def test_finding_detail_is_built_from_collected_evidence(run):
    client, _, run_id = run
    wildcard = next(
        f for f in findings(client, run_id)["items"] if f["rule_id"] == "SEC-IAM-ROLE-WILDCARD"
    )
    d = client.get(f"/api/runs/{run_id}/findings/{wildcard['finding_id']}/detail").json()
    assert d["overview"]["finding_id"] == wildcard["finding_id"]
    evidence = d["evidence"][0]
    assert evidence["integrity_verified"] and evidence["snippet"] and evidence["locator"]
    assert evidence["operation"] != "unrecorded" and evidence["collected_at"]
    assert '"Action": "*"' in evidence["snippet"] and "Action" in evidence["highlight"]
    action = d["observed"]["parameters"][0]
    assert action["field"] == "Action" and "= *" in action["actual"]
    assert "AssumeRolePolicyDocument" not in action["actual"]
    assert d["gap"]["principle_violated"] == "Least privilege"
    for section in ("misuse", "impact", "remediation", "validation", "completeness"):
        assert d[section]
    text = d["technical_finding"]
    for label in (
        "Observation:",
        "Actual configuration:",
        "Security gap:",
        "Supporting evidence:",
        "Recommended remediation:",
        "Validation:",
        "subject to analyst review",
    ):
        assert label in text
    assert client.get(f"/api/runs/{run_id}/findings/nope/detail").status_code == 400


def test_evidence_snippet_masks_credentials_but_keeps_policy_evidence():
    from offline_analyzer.findings.detail import MASK, _decoded, _masked

    raw = {
        "AccessKeyId": "AKIAABCDEFGHIJKLMNOP",
        "Password": "hunter2",
        "Note": "AIza" + "a" * 35,
        "AssumeRolePolicyDocument": "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A"
        "%22Allow%22%7D%5D%7D",
        "members": ["user:alice@example.com"],
    }
    masked = _decoded(_masked(raw))
    assert masked["AccessKeyId"] == masked["Password"] == masked["Note"] == MASK
    assert masked["AssumeRolePolicyDocument"] == {"Statement": [{"Effect": "Allow"}]}
    assert masked["members"] == ["user:alice@example.com"]
