"""Methodology audit on a synthetic workbook, plus a local-only check of the private one."""

import json
from pathlib import Path

import pytest
from openpyxl import Workbook

from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.methodology.audit import LAYOUT, LayoutError, audit, audit_workbook, main
from offline_analyzer.methodology.coverage_spec import REVIEWED_METHODOLOGY_SHA256

SENTINEL = "synthetic-sentinel-requirement-text"
PRIVATE = Path(__file__).parents[1] / "data" / "private"


def control(cid, source="original-checklist", passed=SENTINEL, ap="AP-01", threat="#1"):
    row = dict.fromkeys(LAYOUT["controls"][2], "x")
    row.update(
        {
            "Control ID": cid,
            "Source": source,
            "Pass Criteria": passed,
            "Fail Indicator": "shared",
            "Validation Instructions": "generic",
            "Linked Attack Path": ap,
            "Linked STRIDE #": threat,
            "SEBI Ref": None,
            "Inherent Severity": "High",
            "Priority Tier": "P2 — High",
        }
    )
    return row


def synthetic_workbook(path: Path, headers_override=None) -> Path:
    tables = {
        "controls": [control("9.1.1"), control("9.1.3"), control("AWS-99", "added", "own")],
        "threats": [{"Threat Ref": "TS-01", "STRIDE": "Spoofing", "Checklist IDs": None,
                     "Attack Path": "AP-01"}],
        "paths": [
            {"AP Code": "AP-01", "Linked Controls / Checklist": "9.1.1", "Linked Threats": "#1"},
            {"AP Code": "AP-02", "Linked Controls / Checklist": None, "Linked Threats": None},
        ],
        "scenarios": [{"Scenario ID": "AS-01", "Attack Path": "XD-09"}],
        "sebi": [{"#": 1, "Source Ref": "D9-001", "STRIDE": "Spoofing"}],
        "accounts": [{"Account ID": "ACCT-001"}],
        "dictionary": [{"Sheet": "STRIDE Validation", "Field / Column": "Validation Status",
                        "Allowed values / format": "Pending/Done"}],
    }  # fmt: skip
    workbook = Workbook()
    workbook.remove(workbook.active)
    for key, (name, _header_row, headers) in LAYOUT.items():
        sheet = workbook.create_sheet(name)
        if key == "lists":
            sheet.append(["ValidationStatus"])
            sheet.append(["Pending"])
            sheet.append(["Validated - Done"])
            continue
        sheet.append([f"{len(tables.get(key, []))} synthetic records"])
        sheet.append(["caption"])
        headers = (headers_override or {}).get(key, headers)
        sheet.append(list(headers))
        for record in tables.get(key, []):
            sheet.append([record.get(h) for h in headers])
    workbook.save(path)
    return path


def test_synthetic_audit_detects_structural_defects(tmp_path, capsys):
    source = synthetic_workbook(tmp_path / "synthetic.xlsx")
    before = sha256_file(source)
    output = tmp_path / "private-audit"
    assert main([str(source), str(output)]) == 0
    printed = capsys.readouterr().out
    assert SENTINEL not in printed
    assert sha256_file(source) == before
    findings = {f["id"]: f for f in json.loads((output / "audit.json").read_text())}
    assert findings["AUD-01"]["affected"] == ["9.1.1", "9.1.3"]
    assert findings["AUD-02"]["detail"] == {"distinct_validation_texts": 1}
    assert findings["AUD-04"]["affected"] == ["TS-01"]
    assert findings["AUD-08"]["affected"] == ["AP-02"]
    assert findings["AUD-09"]["affected"] == ["AP-02"]
    assert findings["AUD-11"]["detail"] == {"scenario_path": ["XD-09"]}
    assert findings["AUD-12"]["detail"]["gaps"] == ["9.1.2"]
    assert "STRIDE Validation:Validation Status" in findings["AUD-16"]["detail"]
    # Synthetic IDs cannot reconcile with the reviewed specification: reported, not hidden.
    assert findings["AUD-19"]["detail"]["reviewed_hash_matches"] is False
    assert "AUD-13" not in findings  # captions declare the actual counts
    inventory = json.loads((output / "inventory.json").read_text())
    assert inventory["controls"] == 3 and inventory["source_sha256"] == before
    assert (output / "methodology-audit.xlsx").exists()
    with pytest.raises(FileExistsError):
        audit(source, output)


def test_layout_change_fails_closed_without_content(tmp_path, capsys):
    headers = list(LAYOUT["controls"][2])
    headers[3] = "Renamed"
    source = synthetic_workbook(tmp_path / "changed.xlsx", {"controls": headers})
    with pytest.raises(LayoutError, match="LAYOUT_HEADER_MISMATCH:controls"):
        audit_workbook(source)
    assert main([str(source), str(tmp_path / "out")]) == 1
    error = capsys.readouterr().err
    assert "LAYOUT_HEADER_MISMATCH:controls" in error and SENTINEL not in error
    assert not (tmp_path / "out").exists()


@pytest.mark.skipif(
    not any(PRIVATE.glob("*.xlsx")), reason="private methodology workbook not present"
)
def test_private_methodology_reconciles_with_tracked_specification():
    """Local-only: asserts counts/IDs; never prints or persists workbook content."""
    (source,) = [p for p in PRIVATE.glob("*.xlsx") if sha256_file(p) == REVIEWED_METHODOLOGY_SHA256]
    _, findings, inventory = audit_workbook(source)
    assert sha256_file(source) == REVIEWED_METHODOLOGY_SHA256
    assert inventory["controls_by_source"] == {"original-checklist": 176, "added-main-prompt": 28}
    assert (inventory["threats"], inventory["attack_paths"], inventory["adversary_scenarios"]) == (
        20,
        30,
        22,
    )
    codes = {f["id"] for f in findings}
    assert "AUD-19" not in codes  # IDs, links, STRIDE categories and severities reconcile
    assert "AUD-13" not in codes  # declared counts equal derived counts
