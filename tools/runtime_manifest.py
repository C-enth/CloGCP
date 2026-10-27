"""Runtime file selection and RUNTIME_MANIFEST.json, shared by a source clone and the release.

A clone plus its launcher runs exactly the files a release ZIP contains, minus the bundled
wheels: the same selection, the same bytes, the same manifest. Release archives are build
outputs attached to tags, never committed.

    python -m tools.runtime_manifest --write   # after changing runtime files
    python -m tools.runtime_manifest --check   # fails when the committed manifest drifts
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from tools.source_release import allowed

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "RUNTIME_MANIFEST.json"
SCHEMA = "clogcp-runtime-1"
ENTRY_FILES = (
    "CloGCP.cmd",
    "CloGCP.command",
    "check-windows.py",
    "setup-windows.ps1",
    "setup-macos.sh",
    "verify.py",
    "CLOGCP_VERSION.json",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
)
PACKAGES = ("src/offline_analyzer/", "src/clogcp_delta/", "src/clogcp_report_finalizer/")
COLLECTORS = ("collectors/gcp/GCP_Security_Evidence_Collector.ps1", "collectors/gcp/README.md")
LOCKS = ("locks/macos-arm64.txt", "locks/macos-x86_64.txt", "locks/windows-x64.txt")


def selected(name: str) -> bool:
    """Application runtime: packages, launchers, docs, GCP collector, finalizer and locks."""
    if name.startswith(PACKAGES):
        return allowed(name)
    if name.startswith("docs/") and name.endswith(".md"):
        return allowed(name)
    return name in ENTRY_FILES or name in COLLECTORS or name in LOCKS


def source_names(root: Path = ROOT) -> list[str]:
    """Tracked and untracked-but-not-ignored files that exist in the working tree."""
    names = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return sorted({n for n in names.split("\0") if n and (root / n).is_file()})


def runtime_files(root: Path = ROOT) -> dict[str, bytes]:
    files = {}
    for name in source_names(root):
        if not selected(name):
            continue
        path = root / name
        if path.is_symlink():
            raise ValueError("SYMLINK_IN_RUNTIME: " + name)
        files[name] = path.read_bytes()
    missing = [n for n in (*ENTRY_FILES, *COLLECTORS, *LOCKS) if n not in files]
    if missing:
        raise ValueError("REQUIRED_RUNTIME_FILE_MISSING: " + ", ".join(missing))
    return files


def manifest(files: dict[str, bytes]) -> bytes:
    data = {
        "schema": SCHEMA,
        "product": "CloGCP",
        "version": json.loads(files["CLOGCP_VERSION.json"])["version"],
        "files": [
            {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(files.items())
        ],
    }
    return (json.dumps(data, indent=1) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = manifest(runtime_files())
    target = ROOT / MANIFEST
    if args.write:
        target.write_bytes(expected)
        print(f"{MANIFEST}: {len(json.loads(expected)['files'])} files")
        return 0
    if not target.is_file() or target.read_bytes() != expected:
        print(f"{MANIFEST} is out of date; run python -m tools.runtime_manifest --write")
        return 1
    print(f"{MANIFEST}: current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
