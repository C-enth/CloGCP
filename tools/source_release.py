"""Read-only publication audit of an explicit application-source allowlist.

Writes reviewable paths/hashes and a NUL-separated staging list; never stages or pushes.
No customer artifact directories, raw evidence or credentials are read or printed.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP = {
    ".gitignore",
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "ARCHITECTURE.md",
    "CHANGELOG.md",
    "EVIDENCE_SCHEMA.md",
    "IMPLEMENTATION_ROADMAP.md",
    "METHODOLOGY_COVERAGE.md",
    "TEST_PLAN.md",
    "pyproject.toml",
    "requirements.txt",
}
SUFFIXES = {
    "src": {".py", ".html", ".css", ".js", ".json"},
    "tests": {".py"},
    "tools": {".py"},
    "docs": {".md"},
    "packaging": {".py", ".ps1", ".sh", ".md", ".spec", ".manifest", ".txt", ".json"},
    "frontend": {".tsx", ".ts", ".css", ".html", ".json", ".js"},
    # Versioned read-only collectors and their machine-readable analyzer contract.
    "collectors": {".py", ".ps1", ".md", ".json", ".txt"},
}
PATTERNS = {
    "aws_access_key": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "credential_url": re.compile(r"https?://[^\s/:'\"]+:[^\s/'\"]+@"),
    "assigned_secret": re.compile(
        r"(?i)(?:aws_secret_access_key|aws_session_token|client_secret|github_token|"
        r"api_key|access_token)\s*[=:]\s*['\"][A-Za-z0-9/+_=.-]{24,}['\"]"
    ),
    "google_api_key": re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    "google_access_token": re.compile(r"ya29\.[A-Za-z0-9_-]{30,}"),
    "private_host_url": re.compile(
        r"https?://[A-Za-z0-9_.-]+\.(?:internal|corp|local)(?=[:/\s\"'])"
    ),
}
# Only documented synthetic identities may occur in published source. Values from
# customer packages never enter this list or the diagnostic output.
SYNTHETIC_ACCOUNTS = {
    "111111111111",
    "222222222222",
    "333333333333",
    "444444444444",
    "555555555555",
    "666666666666",
    "777777777777",
    "999999999999",
    "800000000000",
    "899999999999",
    "000000000001",
    "123456789012",
}
ACCOUNT = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def allowed(name: str) -> bool:
    path = Path(name)
    if name in TOP or name == "frontend/.npmrc":
        return True
    if any(
        p
        in {
            "node_modules",
            "__pycache__",
            "private",
            "raw",
            "uploads",
            "artifacts",
            "data",
            "reports",
            "workspaces",
        }
        for p in path.parts
    ):
        return False
    if path.parent.as_posix() == "src/offline_analyzer/contracts/schemas":
        return path.suffix == ".json"
    if path.parts[0] not in SUFFIXES or path.suffix not in SUFFIXES[path.parts[0]]:
        return False
    if path.parts[0] == "src":
        if name == "src/offline_analyzer/api/assets/build-info.json":
            return True
        return path.suffix == ".py" or (
            name.startswith("src/offline_analyzer/api/assets/")
            and path.suffix in {".html", ".css", ".js"}
        )
    if path.parts[0] == "frontend":
        return (
            name.startswith("frontend/src/") and path.suffix in {".tsx", ".ts", ".css"}
        ) or name in {
            "frontend/index.html",
            "frontend/package.json",
            "frontend/package-lock.json",
            "frontend/tsconfig.json",
            "frontend/vite.config.ts",
            # Pre-paint theme initialiser, copied verbatim into the compiled assets.
            "frontend/public/theme-init.js",
        }
    return path.parts[0] != "packaging" or path.parts[1] == "portable"


def category(name: str) -> str | None:
    """Every current path needs a maintained source/build/operations justification."""
    if not allowed(name):
        return None
    if name.endswith((".test.ts", ".test.tsx")):
        return "Automated tests and generators"
    if name.startswith(("src/offline_analyzer/rules/", "src/offline_analyzer/contracts/")):
        return "Security rules and schemas"
    if name.startswith(("src/", "frontend/src/", "frontend/public/")):
        return "Application source"
    if name.startswith(("tests/", "tools/fixtures/")) or name in {
        "tools/collector_fixture.py",
        "tools/collector_v030_fixture.py",
        "tools/gcp_fixture.py",
        "tools/multicloud_scale.py",
        "tools/scale_security_check.py",
    }:
        return "Automated tests and generators"
    if name.startswith(("packaging/", "tools/")):
        return "Build/packaging"
    if name.endswith(".md"):
        return "Essential documentation"
    return "Dependency/configuration"


# Reviewed delivery source retired by ADR-007 (PyInstaller kit, pilot GCP collector).
# Accepted only in history, still secret-scanned; forbidden in the current tree/index.
RETIRED_HISTORY_PREFIXES = ("packaging/windows/", "packaging/gcp/")


def historical_synthetic_blobs() -> set[tuple[str, str]]:
    """Recognize only the exact non-sensitive examples reviewed before cleanup.

    Old examples remain in shared history and main; never exempt newly introduced
    evidence paths. All of their historical bytes still undergo the secret scan.
    """
    baseline = "9387e9ae10257639c31b5df8b6cfb2f8386ccf41"
    result = subprocess.run(
        ["git", "rev-list", baseline],
        cwd=ROOT,
        capture_output=True,
    )
    if result.returncode:
        return set()
    blobs = set()
    for revision in result.stdout.decode().splitlines():
        rows = git("ls-tree", "-r", "-z", revision, "--", "examples/").decode().split("\0")
        for row in filter(None, rows):
            metadata, name = row.split("\t", 1)
            _, kind, oid = metadata.split()
            if kind == "blob":
                blobs.add((name, oid))
    return blobs


def findings(name: str, data: bytes) -> list[dict]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [{"path": name, "category": "unexpected_binary"}]
    # The compiled UI and its build-info JSON contain a generated SHA-256 identity.
    # A numeric substring of that exact field is not an AWS account. Keep all
    # credential signatures active and scan every other value, including malformed IDs.
    build_hashes = (
        [
            match.span(1)
            for match in re.finditer(
                r"""\bfrontend_build_id["']?\s*:\s*["']([0-9a-f]{64})["']""", text
            )
        ]
        if name.startswith("src/offline_analyzer/api/assets/")
        else []
    )
    issues = [
        {"path": name, "line": text.count("\n", 0, match.start()) + 1, "category": category}
        for category, pattern in PATTERNS.items()
        for match in pattern.finditer(text)
    ]
    issues.extend(
        {
            "path": name,
            "line": text.count("\n", 0, match.start()) + 1,
            "category": "unreviewed_account_identifier",
        }
        for match in ACCOUNT.finditer(text)
        if match.group() not in SYNTHETIC_ACCOUNTS
        and not any(start <= match.start() and match.end() <= end for start, end in build_hashes)
    )
    return issues


def audit() -> tuple[dict, list[str]]:
    names = sorted(
        set(
            git("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")
        )
        - {""}
    )
    selected = [n for n in names if allowed(n)]
    issues, inventory = [], []
    for name in selected:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            issues.append({"path": name, "category": "unsafe_or_large_source"})
            continue
        data = path.read_bytes()
        issues.extend(findings(name, data))
        inventory.append(
            {
                "path": name,
                "category": category(name),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    staged = git("ls-files", "--stage", "-z").decode().split("\0")
    staged_inventory = []
    for row in filter(None, staged):
        metadata, name = row.split("\t", 1)
        mode, oid, stage = metadata.split()
        if not allowed(name):
            issues.append({"path": name, "category": "forbidden_staged_path"})
        if mode != "100644" or stage != "0":
            issues.append({"path": name, "category": "unsafe_index_mode_or_conflict"})
        data = git("cat-file", "blob", oid)
        issues.extend(findings(name, data))
        staged_inventory.append({"path": name, "sha256": hashlib.sha256(data).hexdigest()})
        path = ROOT / name
        if not path.is_file() or path.is_symlink() or path.read_bytes() != data:
            issues.append({"path": name, "category": "index_worktree_mismatch"})
    history = []
    seen = set()
    legacy_examples = historical_synthetic_blobs()
    historical_synthetic = set()
    retired = set()
    # Inspect each revision's complete tree, including reused blobs under renamed
    # paths. rev-list --objects alone reports only one path for a shared blob.
    commits = git("rev-list", "--all").decode().splitlines()
    for commit in commits:
        for row in filter(None, git("ls-tree", "-r", "-z", commit).decode().split("\0")):
            metadata, name = row.split("\t", 1)
            mode, kind, oid = metadata.split()
            if (name, oid, mode) in seen:
                continue
            seen.add((name, oid, mode))
            if (name, oid) in legacy_examples:
                historical_synthetic.add(name)
            elif name.startswith(RETIRED_HISTORY_PREFIXES):
                retired.add(name)
            elif not allowed(name):
                issues.append({"path": name, "category": "forbidden_history_path"})
            if kind != "blob" or mode != "100644":
                issues.append({"path": name, "category": "unsafe_history_mode"})
                continue
            history.append({"path": name, "object": oid})
            issues.extend(findings(name, git("cat-file", "blob", oid)))
    return {
        "schema": "closec-source-review-1",
        "branch": git("branch", "--show-current").decode().strip(),
        "result": "PASS" if not issues else "REVIEW_REQUIRED",
        "files": inventory,
        "history_blobs_reviewed": history,
        "history_commits_reviewed": len(commits),
        "historical_synthetic_paths": sorted(historical_synthetic),
        "retired_history_paths": sorted(retired),
        "history_notice": (
            "Reviewed non-sensitive synthetic examples remain in historical commits; "
            "cleanup does not erase history. No history rewriting is performed."
        ),
        "index_files_reviewed": staged_inventory,
        "findings": issues,
        "excluded_untracked_paths": [n for n in names if not allowed(n)],
        "scanner": (
            "Source/index/all revision trees; credential/account signatures. Human review required."
        ),
        "customer_directories_read": False,
        "credentials_printed": False,
    }, selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report, paths = audit()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "source-review.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output / "approved-source-paths.txt").write_text("\n".join(paths) + "\n")
    (args.output / "approved-source-paths.nul").write_bytes(
        b"\0".join(p.encode() for p in paths) + b"\0"
    )
    print(
        json.dumps(
            {
                "result": report["result"],
                "selected_files": len(paths),
                "issues": report["findings"],
                "history_blobs": len(report["history_blobs_reviewed"]),
            }
        )
    )
    return 0 if report["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
