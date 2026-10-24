"""GCP collector 2.2.6: static checks of the PowerShell source (no PowerShell runs here) and
synthetic packages through the analyzer. Windows PowerShell 5.1 behaviour itself (array
non-enumeration, ZIP entry names, console encoding) is not executed by these tests."""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from offline_analyzer.ingestion.errors import explanation
from offline_analyzer.ingestion.gcp import inspect_package
from offline_analyzer.ingestion.gcp_legacy import GCP_COLLECTOR_VERSIONS_22, manifest_detection
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from tools.fixtures.gcp_expanded import TIME, expanded22

COLLECTOR = Path("collectors/gcp/GCP_Security_Evidence_Collector.ps1")
SCRIPT = COLLECTOR.read_text(encoding="utf-8-sig")
LIMIT_KEYS = ("service_accounts", "buckets", "api_keys", "custom_roles", "kms")
STORAGE_RULES = (
    "GCP-STORAGE-PUBLIC",
    "GCP-STORAGE-PAP",
    "GCP-STORAGE-UBLA",
    "GCP-STORAGE-VERSIONING",
)


# ---------------------------------------------------------------- static source checks
def function_body(name: str) -> str:
    start = SCRIPT.index(f"function {name}")
    return SCRIPT[start : SCRIPT.index("\n}\n", start)]


def test_version_and_no_pipeline_json_parsing():
    assert "$CollectorVersion = '2.2.8'" in SCRIPT
    # `Get-Content -Raw | ConvertFrom-Json` emits a JSON array as ONE object under PS 5.1.
    assert not re.search(r"\|\s*ConvertFrom-Json", SCRIPT)
    for path in ("api/api_keys.json", "storage/buckets.json"):
        assert f"@(Read-EvidenceArray '{path}')" in SCRIPT
    # Read-EvidenceArray parses with -InputObject and re-emits array items one by one.
    helper = function_body("Read-EvidenceArray")
    assert (
        "ConvertFrom-Json -InputObject" in helper and "Write-Output -NoEnumerate $entry" in helper
    )


@pytest.mark.parametrize(
    ("loop", "limit"),
    [
        ("foreach ($key in $keys) {", "api_keys"),
        ("foreach ($bucket in $buckets) {", "buckets"),
        ("foreach ($sa in $saRecords) {", "service_accounts"),
        ("foreach ($role in $customRoles) {", "custom_roles"),
    ],
)
def test_detail_counters_advance_only_after_the_name_check(loop, limit):
    body = SCRIPT[SCRIPT.index(loop) :][:700]
    lines = [x.strip() for x in body.splitlines()[1:9]]
    skip = next(i for i, x in enumerate(lines) if "continue" in x)
    stop = next(i for i, x in enumerate(lines) if f"$DetailLimits['{limit}'] = $true" in x)
    count = next(i for i, x in enumerate(lines) if re.fullmatch(r"\$\w+\+\+", x))
    assert skip < stop < count


def test_detail_limits_and_fallbacks_are_reported():
    keys = re.search(r"\$DetailLimits = \[ordered\]@\{([^}]*)\}", SCRIPT)[1]
    assert [k.split("=")[0].strip() for k in keys.split(";")] == list(LIMIT_KEYS)
    assert SCRIPT.count("$DetailLimits['kms']=$true") == 2
    assert "detail_limits_reached=[pscustomobject]$DetailLimits;" in SCRIPT
    assert "dependency_fallbacks=@($Fallbacks.ToArray());" in SCRIPT
    # Trackers exist before collection starts, so an interrupted run still writes them.
    assert SCRIPT.index("$Fallbacks = New-Object") < SCRIPT.index(
        "try {\nRun 'inventory' 'project'"
    )


def test_run_and_function_iam_fall_back_to_gcloud_lists():
    helper = function_body("Get-ServerlessTargets")
    assert "Get-ManifestStatus 'serverless' $RestDataset" in helper
    assert "Get-ManifestStatus 'serverless' $GcloudDataset" in helper
    assert "[void]$script:Fallbacks.Add(" in helper
    for field in ("dataset_family=", "failed_dependency=", "failed_status=", "fallback_source="):
        assert field in helper
    assert "'cloud.googleapis.com/location'" in helper  # Knative-style gcloud run list
    assert "Get-ServerlessTargets 'run_iam' 'run_services_rest' 'cloud_run'" in SCRIPT
    assert "Get-ServerlessTargets 'function_iam' 'functions_rest' 'functions'" in SCRIPT


WRITE_VERBS = {
    "create",
    "delete",
    "update",
    "patch",
    "deploy",
    "enable",
    "disable",
    "undelete",
    "destroy",
    "set-iam-policy",
    "add-iam-policy-binding",
    "remove-iam-policy-binding",
    "import",
    "restore",
}


def test_collector_stays_read_only():
    calls = [x for x in SCRIPT.splitlines() if re.match(r"\s*Run\s+'", x) and "@(" in x]
    assert len(calls) > 60
    for line in calls:
        tokens = set(re.findall(r"'([a-z-]+)'", line[line.index("@(") :]))
        assert not tokens & WRITE_VERBS, line
    assert re.search(r"\.(?:Post|Put|Delete|Patch|Send)Async\(", SCRIPT) is None
    assert "GetAsync($Url)" in SCRIPT
    assert not re.search(r"Invoke-(?:WebRequest|RestMethod)", SCRIPT)


def test_zip_uses_explicit_forward_slash_entries_and_records_its_digest():
    helper = function_body("New-EvidenceZip")
    assert "CreateEntryFromFile($archive, $file.FullName, $entryName" in helper
    assert "-replace '\\\\','/'" in helper
    assert "$_.FullName.Contains('\\')" in helper and 'throw "ZIP verification failed' in helper
    code = [x for x in SCRIPT.splitlines() if not x.lstrip().startswith("#")]
    assert not any("Compress-Archive" in x for x in code)
    assert 'Write-AtomicText "$zip.sha256"' in SCRIPT and "ZIP SHA-256:" in SCRIPT


def test_gcloud_output_is_read_as_utf8_everywhere():
    helper = function_body("Set-Utf8Process")
    for setting in (
        "StandardOutputEncoding",
        "StandardErrorEncoding",
        "['PYTHONIOENCODING'] = 'utf-8'",
        "['PYTHONUTF8'] = '1'",
    ):
        assert setting in helper
    # Every process start (sign-in check, REST token, each collection) uses it.
    assert SCRIPT.count("[void]$proc.Start()") + SCRIPT.count("[void]$process.Start()") == 3
    assert SCRIPT.count("Set-Utf8Process $psi") == 3
    discovery = function_body("Get-DiscoveredProjects")
    assert "[Console]::OutputEncoding = $savedEncoding" in discovery


def test_metadata_files_are_written_atomically_as_arrays():
    assert (
        "Write-AtomicText (Join-Path $root 'iam_parent_hierarchy_attempted.json') "
        "(ConvertTo-Json -InputObject @($parentNodes.ToArray()) -Depth 6)"
    ) in SCRIPT
    assert "Set-Content" not in SCRIPT
    assert "ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($folderDetailsPath))" in (
        SCRIPT
    )
    assert "VM startup scripts and instance metadata" in SCRIPT
    assert "Cloud Build substitutions" in SCRIPT


# ---------------------------------------------------------------- classification table
def classifier(target_number: str = ""):
    """The Get-GcloudFailureStatus rules, in order, as PowerShell -match would apply them.
    A disabled-service match is resolved like Resolve-DisabledService (2.2.7): a message that
    names another project number than the target's is QUOTA_PROJECT_DENIED."""
    rules = []
    for pattern, status in re.findall(
        r"if \(\$Text -match '((?:[^']|'')*)'\) \{ return "
        r"(?:'([A-Z_]+)'|\(Resolve-DisabledService \$Text\)) \}",
        function_body("Get-GcloudFailureStatus"),
    ):
        # PowerShell single-quoted strings double the quote; -match ignores case by default.
        rules.append((re.compile(pattern.replace("''", "'"), re.IGNORECASE), status or "RESOLVE"))
    assert len(rules) == 8
    named = re.compile(
        re.search(
            r"\[regex\]::Match\(\$Text, '((?:[^']|'')*)'\)",
            function_body("Resolve-DisabledService"),
        )[1].replace("''", "'")
    )

    def resolve(text: str) -> str:
        found = named.search(text)
        if not found or not target_number:
            return "API_DISABLED"
        return "QUOTA_PROJECT_DENIED" if found[1] != target_number else "API_DISABLED"

    def classify(text: str) -> str:
        status = next((status for regex, status in rules if regex.search(text)), "FAILED")
        return resolve(text) if status == "RESOLVE" else status

    return classify


@pytest.mark.parametrize(
    ("stderr", "status"),
    [
        ("ERROR: (gcloud.storage.buckets.list) HTTPError 429: Too Many Requests", "RATE_LIMITED"),
        (
            "ERROR: RESOURCE_EXHAUSTED: Quota exceeded for quota metric 'Read requests'",
            "RATE_LIMITED",
        ),
        (
            "Quota exceeded for quota metric 'Queries' and limit 'Queries per minute'",
            "RATE_LIMITED",
        ),
        (
            "ERROR: (gcloud.run.services.get-iam-policy) There was a problem refreshing your "
            "current auth tokens: Reauthentication failed. cannot prompt during non-interactive "
            "execution.",
            "AUTH_ERROR",
        ),
        ("Please run:\n\n  $ gcloud auth login\n\nto obtain new credentials.", "AUTH_ERROR"),
        ("ERROR: (gcloud.iam.roles.describe) HTTPError 403: Forbidden", "ACCESS_DENIED"),
        ("ERROR: (gcloud.x) PERMISSION_DENIED: Permission 'iam.roles.get' denied", "ACCESS_DENIED"),
        ("ERROR: (gcloud.x) [403] request rejected", "ACCESS_DENIED"),
        (
            "ERROR: (gcloud.functions.get-iam-policy) NOT_FOUND: Resource 'x' was not found",
            "NOT_FOUND",
        ),
        ("ERROR: (gcloud.x) HTTPError 404: Not Found", "NOT_FOUND"),
        ("ERROR: (gcloud.x) UNAVAILABLE: The service is currently unavailable.", "SERVER_ERROR"),
        ("ERROR: (gcloud.x) HTTPError 503: Service Unavailable", "SERVER_ERROR"),
        ("API [run.googleapis.com] SERVICE_DISABLED", "API_DISABLED"),
        ("ERROR: (gcloud) Invalid choice: 'servicez'.", "COMMAND_ERROR"),
        # Bare numbers in unrelated text are not status codes.
        ("ERROR: (gcloud.x) unexpected response for bucket synthetic-403-logs", "FAILED"),
        ("Listed 404 items before the stream closed", "FAILED"),
        ("the internal network answered slowly", "FAILED"),
        ("ERROR: something else went wrong", "FAILED"),
    ],
)
def test_gcloud_failure_classification(stderr, status):
    assert classifier()(stderr) == status


def test_only_transient_failures_are_retried_a_bounded_number_of_times():
    assert "$GcloudTransientRetries = 3" in SCRIPT
    transient = function_body("Test-TransientStatus")
    assert set(re.findall(r"-eq '([A-Z_]+)'", transient)) == {"RATE_LIMITED", "SERVER_ERROR"}
    loop = function_body("Invoke-Collection")
    assert "(Test-TransientStatus $status) -and $attempt -le $GcloudTransientRetries" in loop
    assert "[Math]::Min(30, [Math]::Pow(2, $attempt))" in loop
    # The retried command is the unchanged read-only argument list.
    assert loop.count("$quoted = ") == 1 and loop.index("$quoted = ") < loop.index("while ($true)")


# ---------------------------------------------------------------- synthetic packages
def _entry(folder: Path, domain: str, name: str, body, command: str, status="SUCCESS") -> dict:
    item = dict(
        domain=domain,
        dataset=name,
        status=status,
        record_count=None,
        exit_code=0 if status in {"SUCCESS", "EMPTY"} else 1,
        required_api="",
        started_utc=TIME,
        finished_utc=TIME,
        file=None,
        error_file=None,
        command=command,
    )
    if body is not None:
        item["file"] = f"{domain}/{name}.json"
        (folder / item["file"]).parent.mkdir(parents=True, exist_ok=True)
        (folder / item["file"]).write_text(json.dumps(body))
        item["record_count"] = len(body) if isinstance(body, list) else 1
        if item["record_count"] == 0:
            item["status"] = "EMPTY"
    else:
        item["error_file"] = f"{domain}/{name}.stderr.txt"
        (folder / item["error_file"]).parent.mkdir(parents=True, exist_ok=True)
        (folder / item["error_file"]).write_text("Synthetic collection gap")
    return item


def package(
    root: Path,
    *,
    buckets: int = 0,
    collapsed: bool = False,
    fallback: bool = False,
    version: str = "2.2.6",
    manifest_extra: dict | None = None,
) -> Path:
    folder = expanded22(root / "collection")
    manifest = json.loads((folder / "collection_manifest.json").read_text())
    replaced = {"storage"} | ({"serverless"} if fallback else set())
    kept = []
    for item in manifest["datasets"]:
        if item["domain"] in replaced and (
            item["domain"] == "storage" or item["dataset"].startswith(("run_", "cloud_run"))
        ):
            for key in ("file", "error_file"):
                if item.get(key):
                    (folder / item[key]).unlink(missing_ok=True)
            continue
        kept.append(item)
    names = [f"synthetic-bucket-{i}" for i in range(1, buckets + 1)]
    listing = [
        {
            "name": name,
            "storage_url": f"gs://{name}/",
            "uniform_bucket_level_access": True,
            "public_access_prevention": "enforced",
            "versioning_enabled": True,
        }
        for name in names
    ]
    list_command = "gcloud storage buckets list --project=sample-project --format=json --quiet"
    kept.append(_entry(folder, "storage", "buckets", listing, list_command))
    if collapsed and names:
        # 2.2.5 under PS 5.1: one call for every name joined by spaces, which fails.
        joined = "gs://" + " ".join(names)
        kept.append(
            _entry(
                folder,
                "storage",
                "bucket_iam_1",
                None,
                f"gcloud storage buckets get-iam-policy {joined!r} --format=json",
                status="FAILED",
            )
        )
    else:
        for i, name in enumerate(names, 1):
            policy = {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["serviceAccount:worker@sample-project.iam.gserviceaccount.com"],
                    }
                ],
                "etag": "synthetic",
            }
            kept.append(
                _entry(
                    folder,
                    "storage",
                    f"bucket_iam_{i}",
                    policy,
                    f"gcloud storage buckets get-iam-policy gs://{name} --format=json --quiet",
                )
            )
            kept.append(
                _entry(
                    folder,
                    "storage",
                    f"bucket_details_{i}",
                    listing[i - 1],
                    f"gcloud storage buckets describe gs://{name} --format=json --quiet",
                )
            )
    if fallback:
        rest = _entry(
            folder,
            "serverless",
            "run_services_rest",
            None,
            "GET https://run.googleapis.com/v2/projects/sample-project/locations/-/services",
            status="SERVER_ERROR",
        )
        rest["exit_code"] = None
        kept.append(rest)
        knative = [
            {
                "apiVersion": "serving.knative.dev/v1",
                "kind": "Service",
                "metadata": {
                    "name": "synthetic-service",
                    "namespace": "123456789012",
                    "labels": {"cloud.googleapis.com/location": "us-central1"},
                },
            }
        ]
        kept.append(
            _entry(
                folder,
                "serverless",
                "cloud_run",
                knative,
                "gcloud run services list --project=sample-project --format=json --quiet",
            )
        )
        policy = {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}], "etag": "e"}
        kept.append(
            _entry(
                folder,
                "serverless",
                "run_iam_1",
                policy,
                "gcloud run services get-iam-policy synthetic-service --region=us-central1 "
                "--project=sample-project --format=json --quiet",
            )
        )
    manifest.update(
        datasets=kept,
        collector_version=version,
        detail_limits_reached={key: False for key in LIMIT_KEYS},
        dependency_fallbacks=[
            {
                "dataset_family": "run_iam",
                "failed_dependency": "serverless/run_services_rest",
                "failed_status": "SERVER_ERROR",
                "fallback_source": "serverless/cloud_run",
                "fallback_status": "SUCCESS",
                "targets": 1,
            }
        ]
        if fallback
        else [],
    )
    manifest.update(manifest_extra or {})
    (folder / "collection_manifest.json").write_text(json.dumps(manifest))
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(folder).as_posix()}"
        for p in sorted(
            p for p in folder.rglob("*") if p.is_file() and p.name != "checksums.sha256"
        )
    ]
    (folder / "checksums.sha256").write_text("\n".join(lines) + "\n")
    return folder


def storage_results(store, run) -> Counter:
    return Counter(
        (r.rule_id, r.native_id.split("/bindings/")[0].removeprefix("buckets/"))
        for r in store.results(run)
        if r.rule_id in STORAGE_RULES and r.evaluation_scope == "RESOURCE"
    )


@pytest.mark.parametrize("buckets", [0, 2, 3])
def test_every_bucket_gets_its_own_iam_and_storage_evaluations(tmp_path, buckets):
    folder = package(tmp_path, buckets=buckets)
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        datasets = Counter(
            re.sub(r"_\d+$", "", d)
            for (d,) in store.rows(
                "SELECT json_extract_string(data,'$.gcp_metadata.dataset') FROM sources "
                "WHERE run_id=? AND json_extract_string(data,'$.gcp_metadata.domain')='storage'",
                [run],
            )
        )
        results = storage_results(store, run)
        outcomes = {
            str(r.outcome)
            for r in store.results(run)
            if r.rule_id in STORAGE_RULES and r.evaluation_scope == "RESOURCE"
        }
    assert datasets["bucket_iam"] == buckets and datasets["bucket_details"] == buckets
    names = {f"synthetic-bucket-{i}" for i in range(1, buckets + 1)}
    for rule in STORAGE_RULES:
        assert {b for (r, b) in results if r == rule} == names, rule
    assert all(n == 1 for n in results.values())
    assert outcomes <= {"PASS"}  # private, enforced, uniform, versioned: nothing unresolved


def test_collapsed_bucket_listing_leaves_the_public_access_rule_without_buckets(tmp_path):
    """What 2.2.5 produced under PS 5.1 for 3 buckets: the gap 2.2.6 closes."""
    folder = package(tmp_path, buckets=3, collapsed=True)
    with Store(tmp_path / "workspace") as store:
        run = import_package(store, folder)
        assess(store, run)
        results = storage_results(store, run)
    assert not any(rule == "GCP-STORAGE-PUBLIC" for rule, _ in results)
    assert (
        sum(rule == "GCP-STORAGE-UBLA" for rule, _ in results) == 3
    )  # list-based rules unaffected


def test_run_iam_fallback_is_recorded_and_imported(tmp_path):
    folder = package(tmp_path, fallback=True)
    package_, summary = inspect_package(folder)
    subjects = [
        (s.request_parameters or {}).get("subject")
        for s in package_.sources
        if s.gcp_metadata["dataset"] == "run_iam_1"
    ]
    assert subjects == ["projects/sample-project/locations/us-central1/services/synthetic-service"]
    statuses = {s.gcp_metadata["dataset"]: s.gcp_metadata["status"] for s in package_.sources}
    assert statuses["run_services_rest"] == "SERVER_ERROR" and statuses["cloud_run"] == "SUCCESS"
    manifest = json.loads((folder / "collection_manifest.json").read_text())
    assert manifest["dependency_fallbacks"][0]["fallback_source"] == "serverless/cloud_run"
    with Store(tmp_path / "workspace") as store:
        assess(store, import_package(store, folder))


@pytest.mark.parametrize("version", ["2.2.4", "2.2.5", "2.2.6"])
def test_supported_collector_versions_import(tmp_path, version):
    folder = package(tmp_path, buckets=2, version=version)
    with Store(tmp_path / "workspace") as store:
        assess(store, import_package(store, folder))


@pytest.mark.parametrize("version", ["2.3.0", "2.2.9", "", None])
def test_unsupported_collector_version_is_named_with_the_accepted_range(tmp_path, version):
    folder = package(tmp_path, buckets=2, manifest_extra={"collector_version": version})
    with pytest.raises(InputError, match="GCP_COLLECTOR_VERSION_UNSUPPORTED"):
        inspect_package(folder)
    accepted = f"{GCP_COLLECTOR_VERSIONS_22[0]} to {GCP_COLLECTOR_VERSIONS_22[-1]}"
    assert accepted == "2.2.0 to 2.2.8"
    assert accepted in explanation("GCP_COLLECTOR_VERSION_UNSUPPORTED")["message"]
    detection = manifest_detection(folder)
    assert accepted in detection["rejection_condition"] and detection["corrective_action"]
    assert "pilot-1.2.2" not in explanation("LEGACY_GCP_MANIFEST_INVALID")["message"]


@pytest.mark.parametrize(
    "extra",
    [
        {"detail_limits_reached": {key: False for key in (*LIMIT_KEYS, "extra")}},
        {"detail_limits_reached": {key: "no" for key in LIMIT_KEYS}},
        {"dependency_fallbacks": [{"dataset_family": "bucket_iam", "targets": 1}]},
    ],
)
def test_malformed_226_summary_fields_fail_closed(tmp_path, extra):
    folder = package(tmp_path, buckets=2, manifest_extra=extra)
    with pytest.raises(InputError, match="LEGACY_GCP_MANIFEST_INVALID"):
        inspect_package(folder)


def test_detail_limits_reached_are_accepted(tmp_path):
    limits = {key: key == "buckets" for key in LIMIT_KEYS}
    folder = package(tmp_path, buckets=2, manifest_extra={"detail_limits_reached": limits})
    _, summary = inspect_package(folder)
    assert summary["adapter_profile"] == "gcp-expanded-2.2-adapter-1"
