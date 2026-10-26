"""Build CloGCP from committed current source and verified offline dependency wheels."""

import argparse
import hashlib
import json
import stat
import subprocess
import zipfile
from pathlib import Path

from tools.portable_release import dependencies
from tools.source_release import allowed, findings

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.8.5-clogcp.1"
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
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_zip(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("UNSAFE_RELEASE_PATH")
            info = zipfile.ZipInfo("CloGCP/" + name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if name.endswith((".sh", ".command")) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, data)
    with zipfile.ZipFile(path) as archive:
        if archive.testzip():
            raise ValueError("RELEASE_CRC_FAILURE")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    runtime = {}
    for name in names:
        if not name:
            continue
        selected = name.startswith(("src/offline_analyzer/", "src/clogcp_delta/")) and allowed(name)
        selected |= name.startswith("docs/") and Path(name).suffix == ".md" and allowed(name)
        selected |= name in ENTRY_FILES or name == "README.md"
        selected |= name in {
            "collectors/gcp/GCP_Security_Evidence_Collector.ps1",
            "collectors/gcp/README.md",
        }
        if not selected:
            continue
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or findings(name, path.read_bytes()):
            raise ValueError("SOURCE_SECURITY_REVIEW_REQUIRED: " + name)
        runtime[name] = path.read_bytes()
    if not set(ENTRY_FILES) <= runtime.keys():
        raise ValueError("REQUIRED_APPLICATION_COMPONENT_MISSING")
    for name, path in dependencies(args.wheelhouse).items():
        runtime[name] = path.read_bytes()
    snapshot = digest(
        b"".join(
            name.encode() + b"\0" + hashlib.sha256(data).digest()
            for name, data in sorted(runtime.items())
        )
    )
    metadata = {
        "product": "CloGCP",
        "version": VERSION,
        "application_version": "0.8.5rc1",
        "engine_version": "2.0.1",
        "git_revision": revision,
        "working_tree_modified": False,
        "source_kind": "COMMITTED_SOURCE",
        "source_snapshot": snapshot,
        "customer_data_included": False,
        "native_windows_acceptance": "PENDING",
        "desktop_excel_acceptance": "PENDING",
        "authorized_client_acceptance": "PENDING",
        "python_system_prerequisite": "CPython 3.12",
    }
    runtime["src/offline_analyzer/api/assets/release-info.json"] = json.dumps(
        metadata, indent=2
    ).encode()
    manifest = {
        "schema": "clogcp-portable-1",
        **metadata,
        "files": [
            {"path": name, "bytes": len(data), "sha256": digest(data)}
            for name, data in sorted(runtime.items())
        ],
    }
    runtime["portable-manifest.json"] = json.dumps(manifest, indent=2).encode()
    args.output.mkdir(parents=True, exist_ok=False)
    write_zip(args.output / "CloGCP.zip", runtime)
    # Source comes directly from this checkout, never a previous delivery archive.
    source = {}
    extra = {*ENTRY_FILES, "run-portable.py", "CloSec.cmd", "CloSec.command"}
    for name in names:
        if not name or not (allowed(name) or name in extra):
            continue
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            continue
        source[name] = path.read_bytes()
    source["SOURCE_BUILD.json"] = json.dumps(metadata, indent=2).encode()
    write_zip(args.output / "CloGCP-source.zip", source)
    print(json.dumps({**metadata, "runtime_members": len(runtime), "source_members": len(source)}))


if __name__ == "__main__":
    main()
