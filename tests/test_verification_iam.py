"""Synthetic field diagnostics for the R1.2 verifier profiles."""

from types import SimpleNamespace

import pytest

from offline_analyzer.contracts.r0 import AWS_OPERATIONS
from offline_analyzer.verification import REQUIRED_AWS, Structure, verify_package


def test_all_supported_operations_have_verifier_profiles():
    assert set(AWS_OPERATIONS) == set(REQUIRED_AWS)


@pytest.mark.parametrize(
    "operation", [k for k in REQUIRED_AWS if k.startswith(("iam:", "organizations:"))]
)
def test_required_fields_detect_absent_and_null_without_values(operation):
    for parent, names in REQUIRED_AWS[operation].items():
        structure = Structure()
        structure.observe(parent, "start_map", None)
        path = f"{parent}.{names[0]}" if parent else names[0]
        structure.observe(path, "null", None)
        structure.observe(parent, "end_map", None)
        report = structure.report(SimpleNamespace(format="aws-json-v1", operation=operation))
        for index, name in enumerate(names):
            path = f"{parent}.{name}" if parent else name
            assert report["required_fields"][path] == {
                "expected_records": 1,
                "present": int(index == 0),
                "null": int(index == 0),
                "absent": int(index != 0),
            }


def test_verifier_accepts_r12_synthetic_package(tmp_path):
    from tools.fixtures.r12_demo import build

    build(tmp_path / "input")
    report = verify_package(tmp_path / "input", origin="synthetic")
    assert report["sources"]
    assert all(source["parser_accepted"] for source in report["sources"])
    assert all("required_fields" in source for source in report["sources"])
    # Every supplied operation reaches its field diagnostics without a missing profile.
    import json

    serialized = json.dumps(report)
    assert "SYNTHETIC_NOT_REAL_EXPORT_VALIDATION" in serialized
    assert "required_fields" in serialized
    assert "PolicyDocument" in serialized
    assert "synthetic-analyst" not in serialized
