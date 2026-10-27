"""Build CloGCP from the runtime selection of a clone and verified offline dependency wheels.

The ZIP equals a clone's RUNTIME_MANIFEST.json files plus wheels, release-info.json and
portable-manifest.json. An uncommitted working tree is recorded as WORKING_TREE_SNAPSHOT.
"""

import argparse
import hashlib
import json
import stat
import subprocess
import zipfile
from pathlib import Path

from tools.portable_release import dependencies
from tools.runtime_manifest import MANIFEST, manifest, runtime_files, source_names
from tools.source_release import allowed, findings

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.8.5-clogcp.3"


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
    modified = bool(
        subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).decode().strip()
    )
    names = source_names(ROOT)
    # The clone's runtime selection, byte for byte; the committed manifest must be current.
    runtime = runtime_files(ROOT)
    if (ROOT / MANIFEST).read_bytes() != manifest(runtime):
        raise ValueError("RUNTIME_MANIFEST_OUT_OF_DATE")
    for name, data in runtime.items():
        if findings(name, data):
            raise ValueError("SOURCE_SECURITY_REVIEW_REQUIRED: " + name)
    runtime[MANIFEST] = (ROOT / MANIFEST).read_bytes()
    for name, path in dependencies(args.wheelhouse).items():
        if name.startswith("locks/"):
            # Wheels are added; the committed hash locks are never replaced by the wheelhouse.
            if path.read_bytes() != runtime[name]:
                raise ValueError("WHEELHOUSE_LOCK_DIFFERS_FROM_COMMITTED_LOCK: " + name)
            continue
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
        "application_version": "0.8.5rc3",
        "engine_version": "2.0.1",
        "git_revision": revision,
        "working_tree_modified": modified,
        "source_kind": "WORKING_TREE_SNAPSHOT" if modified else "COMMITTED_SOURCE",
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
    portable = {
        "schema": "clogcp-portable-1",
        **metadata,
        "files": [
            {"path": name, "bytes": len(data), "sha256": digest(data)}
            for name, data in sorted(runtime.items())
        ],
    }
    runtime["portable-manifest.json"] = json.dumps(portable, indent=2).encode()
    args.output.mkdir(parents=True, exist_ok=False)
    write_zip(args.output / "CloGCP.zip", runtime)
    # Source comes directly from this checkout, never a previous delivery archive.
    source = {}
    extra = {*runtime, "CloSec.cmd", "CloSec.command"}
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
