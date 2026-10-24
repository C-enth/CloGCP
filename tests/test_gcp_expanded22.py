"""GCP collector 2.2 contract, field outcome distribution and gap semantics."""

import json
import re
from pathlib import Path

import pytest

from offline_analyzer.contracts.gcp_expanded_catalog import EXTENSIONS_22
from offline_analyzer.ingestion.gcp import inspect_package
from offline_analyzer.ingestion.gcp_legacy import integrity_acknowledgment_required
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import FIELD_DISTRIBUTION, expanded22, field_distribution

COLLECTOR = Path("collectors/gcp/GCP_Security_Evidence_Collector.ps1")


def test_catalog_extension_lines_match_corrected_collector():
    lines = COLLECTOR.read_text(encoding="utf-8").splitlines()
    for row in EXTENSIONS_22:
        assert f'"{row["family"]}_$idx"' in lines[row["collector_line"] - 1]


def test_field_distribution_is_preserved_and_never_passes(tmp_path):
    folder = field_distribution(tmp_path / "collection")
    _, summary = inspect_package(folder)
    assert summary["original_status_totals"] == FIELD_DISTRIBUTION
    assert sum(FIELD_DISTRIBUTION.values()) == 145
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        coverage = dict(
            store.rows(
                "SELECT json_extract_string(data,'$.gcp_metadata.status'), count(*) FROM sources "
                "WHERE run_id=? GROUP BY 1",
                [run],
            )
        )
        failed_pass = list(
            store.rows(
                "SELECT count(*) FROM evaluations e WHERE run_id=? AND outcome='PASS' "
                "AND NOT EXISTS("
                "SELECT 1 FROM sources s WHERE s.run_id=e.run_id AND "
                "json_extract_string(s.data,'$.gcp_metadata.status') IN ('SUCCESS','EMPTY'))",
                [run],
            )
        )
    assert coverage == FIELD_DISTRIBUTION
    assert failed_pass == [(0,)]


def test_expanded22_imports_with_verified_checksums(tmp_path):
    folder = expanded22(tmp_path / "collection")
    assert not integrity_acknowledgment_required(folder)
    package, summary = inspect_package(folder)
    assert summary["adapter_profile"] == "gcp-expanded-2.2-adapter-1"
    assert summary["source_checksum_verified"] is True
    gaps = {
        s.gcp_metadata["dataset"]: (s.coverage, s.errors)
        for s in package.sources
        if s.gcp_metadata["dataset"].startswith("discovery_")
    }
    assert gaps["discovery_engines_2"] == ("ERROR", ("COLLECTION_QUOTA_PROJECT_DENIED",))
    assert gaps["discovery_datastores_2"][1] == ("COLLECTION_UNEXPECTED_RESPONSE_SCHEMA",)
    assert gaps["discovery_unsupported_1"][1] == ("COLLECTION_UNSUPPORTED_ENDPOINT",)
    assert gaps["discovery_engines_1"][0] == "PARTIAL"
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)


@pytest.mark.parametrize(
    "version", ["2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8"]
)
def test_collector_221_and_222_manifests_are_accepted(tmp_path, version):
    """2.2.1 adds project discovery, 2.2.2 a sign-in check; the evidence format is 2.2."""
    import hashlib

    folder = expanded22(tmp_path / "collection")
    manifest = folder / "collection_manifest.json"
    data = json.loads(manifest.read_text())
    data["collector_version"] = version
    manifest.write_text(json.dumps(data))
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(folder).as_posix()}"
        for p in sorted(
            p for p in folder.rglob("*") if p.is_file() and p.name != "checksums.sha256"
        )
    ]
    (folder / "checksums.sha256").write_text("\n".join(lines) + "\n")
    _, summary = inspect_package(folder)
    assert summary["adapter_profile"] == "gcp-expanded-2.2-adapter-1"
    with Store(tmp_path / "workspace") as store:
        assess(store, import_package(store, folder))


def test_expanded22_interrupted_collection_is_limited(tmp_path):
    folder = expanded22(tmp_path / "collection", interrupted=True)
    package, summary = inspect_package(folder)
    assert summary["collection_status"] == "INTERRUPTED"
    assert all(
        "COLLECTION_INTERRUPTED" in s.gcp_metadata["completeness_limitations"]
        for s in package.sources
    )


@pytest.mark.parametrize("tamper", ["modify", "unlisted", "missing-index"])
def test_expanded22_checksums_fail_closed(tmp_path, tamper):
    folder = expanded22(tmp_path / "collection")
    if tamper == "modify":
        target = folder / "inventory/project.json"
        target.write_text(target.read_text().replace("sample-project", "sample-projecx"))
    elif tamper == "unlisted":
        (folder / "inventory/extra.json").write_text("[]")
    else:
        (folder / "checksums.sha256").unlink()
    with pytest.raises(InputError, match="CHECKSUM|SOURCE_CHECKSUMS_REQUIRED|MISMATCH"):
        inspect_package(folder)


def test_expanded21_still_requires_integrity_acknowledgment(tmp_path):
    from tools.fixtures.gcp_expanded import expanded

    folder = expanded(tmp_path / "collection")
    assert integrity_acknowledgment_required(folder)
    manifest = json.loads((folder / "collection_manifest.json").read_text())
    assert re.fullmatch(r"assessment-expanded-2\.1", manifest["schema_version"])


def test_collector_checks_gcloud_sign_in_before_collecting():
    """Static check (no PowerShell here): sign-in is verified before any output exists."""
    script = Path("collectors/gcp/GCP_Security_Evidence_Collector.ps1").read_text(
        encoding="utf-8-sig"
    )
    check = script.index("$sessionProblem = Test-GcloudSession")
    assert check < script.index("$root = Join-Path $OutputRoot")
    assert check > script.index("Type YES to collect read-only metadata")
    body = script[script.index("function Test-GcloudSession") : check]
    assert "auth print-access-token --quiet" in body and "$token = $null" in body
    assert (
        "Write-AtomicText" not in body
        and "Out-File" not in body
        and "Write-Host $token" not in body
    )
    assert "throw 'gcloud sign-in required before collection" in script
    assert "$authFailures" in script and "do not import this package" in script


def test_collector_searches_beyond_the_project_only_when_opted_in():
    """ADR-010: folder/organization IAM searches return other projects' bindings."""
    script = Path("collectors/gcp/GCP_Security_Evidence_Collector.ps1").read_text(
        encoding="utf-8-sig"
    )
    for dataset in (
        "($nodeDataset + '_iam_search')",
        "('organization_' + $node.id + '_iam_search')",
    ):
        start = script.index(dataset)
        guard = script.rfind("if ($IncludeOrganizationSearch) {", 0, start)
        assert guard != -1 and start - guard < 120
    assert "Type ORG to confirm org-level review is authorized" in script
    assert "[switch]$IncludeOrganizationSearch" in script
    # The project-scope search is unconditional.
    project = script.index("'asset_iam_search' @('asset','search-all-iam-policies'")
    assert "IncludeOrganizationSearch" not in script[project - 200 : project]


def test_collector_lists_only_the_projects_own_images():
    """ADR-010: Google's public image catalog belongs to other projects."""
    script = COLLECTOR.read_text(encoding="utf-8-sig")
    line = next(x for x in script.splitlines() if x.startswith("Run 'compute' 'images'"))
    assert "'--no-standard-images'" in line and "$CollectorVersion = '2.2.8'" in script


def test_organization_listings_send_the_required_parent():
    """workforcePools.list and accessPolicies.list reject requests without a parent."""
    script = COLLECTOR.read_text(encoding="utf-8-sig")
    assert "$OrgParent=$(if ($OrgNode.Count -gt 0) { '&parent='+(E ('organizations/'" in script
    assert script.index("$OrgParent=") > script.index("$parentNodes = New-Object")
    for dataset in ("'workforce_pools'", "'access_context_policies'"):
        line = next(x for x in script.splitlines() if dataset in x)
        assert "?pageSize=1000'+$OrgParent)" in line


def test_collector_argument_arrays_keep_each_concatenated_flag_whole():
    """PowerShell's comma binds tighter than +: `,'--region='+$r,` splits into two arguments."""
    script = COLLECTOR.read_text(encoding="utf-8-sig")
    for line in script.splitlines():
        if line.lstrip().startswith(("Run ", "Invoke-Collection")) and "@(" in line:
            args = line[line.index("@(") :]
            assert not re.search(r"(?:@\(|,)\s*'[^']*'\s*\+", args), line
    for dataset in ("run_iam_", "function_iam_"):
        line = next(x for x in script.splitlines() if f"('{dataset}'+$ix)" in x)
        assert "('--region='+$target.region)" in line and "('--project='+$ProjectId)" in line


def test_collector_omits_rest_lists_that_reject_the_location_wildcard():
    script = COLLECTOR.read_text(encoding="utf-8-sig")
    assert "/locations/-/jobs" not in script and "/locations/-/repositories" not in script
    assert "'cloud_run_jobs' @('run','jobs','list'" in script
    assert "'artifact_repositories' @('artifacts','repositories','list'" in script
