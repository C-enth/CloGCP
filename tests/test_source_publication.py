"""Synthetic index/history publication regressions; no real credentials or evidence."""

import subprocess

from tools import source_release


def repository(tmp_path, monkeypatch):
    monkeypatch.setattr(source_release, "ROOT", tmp_path)

    def git(*args):
        return subprocess.run(
            [
                "git",
                "-c",
                "user.name=Synthetic",
                "-c",
                "user.email=synthetic@example.invalid",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    git("init", "-b", "feature/offline-security-analyzer")
    (tmp_path / "README.md").write_text("Synthetic publication test\n")
    git("add", "README.md")
    git("commit", "-m", "Synthetic baseline")
    return git


def test_publication_checks_actual_index_not_only_worktree(tmp_path, monkeypatch):
    git = repository(tmp_path, monkeypatch)
    source = tmp_path / "README.md"
    source.write_text("Synthetic credential signature: " + "AKIA" + "A" * 16)
    git("add", "README.md")
    source.write_text("Sanitized current file\n")
    report, _ = source_release.audit()
    categories = {r["category"] for r in report["findings"]}
    assert {"aws_access_key", "index_worktree_mismatch"} <= categories
    assert report["result"] == "REVIEW_REQUIRED"


def test_publication_checks_history_paths_even_for_reused_blobs(tmp_path, monkeypatch):
    git = repository(tmp_path, monkeypatch)
    (tmp_path / "data/private").mkdir(parents=True)
    git("mv", "README.md", "data/private/customer.json")
    git("commit", "-m", "Synthetic prohibited path")
    git("mv", "data/private/customer.json", "README.md")
    git("commit", "-m", "Synthetic source path restored")
    report, _ = source_release.audit()
    assert report["history_commits_reviewed"] == 3
    assert {"path": "data/private/customer.json", "category": "forbidden_history_path"} in report[
        "findings"
    ]


def test_publication_account_diagnostics_do_not_print_values():
    value = "012345" * 2
    issues = source_release.findings("README.md", ("Account: " + value).encode())
    assert issues == [{"path": "README.md", "line": 1, "category": "unreviewed_account_identifier"}]
    assert value not in str(issues)


def test_generated_evidence_is_never_allowed_in_current_source():
    for path in (
        "examples/r12/golden/manifest.json",
        "tests/generated/evidence.json",
        "frontend/customer-evidence.json",
        "src/offline_analyzer/raw/source.json",
        "artifacts/build.zip",
        "packaging/windows/CloSec.exe",
    ):
        assert not source_release.allowed(path)
        assert source_release.category(path) is None


def test_build_hash_digits_are_not_accounts_but_other_values_still_are():
    import json

    digits = "012345" * 2
    digest = "a" * 52 + digits
    path = "src/offline_analyzer/api/assets/build-info.json"
    data = json.dumps({"frontend_build_id": digest}).encode()
    assert not source_release.findings(path, data)
    assert source_release.findings("README.md", data)
    assert source_release.findings(path, json.dumps({"frontend_build_id": digits}).encode())
    with_account = json.dumps({"frontend_build_id": digest, "account": digits}).encode()
    assert len(source_release.findings(path, with_account)) == 1
    credential = (
        "const b={frontend_build_id: '" + digest + "'}; const k='AKIA" + "A" * 16 + "';"
    ).encode()
    issues = source_release.findings("src/offline_analyzer/api/assets/assets/app.js", credential)
    assert [i["category"] for i in issues] == ["aws_access_key"]


def test_new_evidence_history_is_not_exempted(tmp_path, monkeypatch):
    git = repository(tmp_path, monkeypatch)
    evidence = tmp_path / "examples/new-evidence.json"
    evidence.parent.mkdir()
    evidence.write_text("{}")
    git("add", str(evidence))
    git("commit", "-m", "Synthetic newly forbidden evidence")
    report, _ = source_release.audit()
    assert {"path": "examples/new-evidence.json", "category": "forbidden_history_path"} in (
        report["findings"]
    )
    assert not report["historical_synthetic_paths"]
