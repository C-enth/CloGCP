"""Build a separate allowlisted CloGCP portable/source release from a validated baseline.

Never changes the baseline, original install or client workspaces. No Git/network mutation.
"""

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

NEW_RUNTIME = (
    "clogcp.py",
    "clogcp_profile.py",
    "findings/clogcp_reconcile.py",
    "reporting/clogcp_assurance.py",
    "rules/gcp_context.py",
    "rules/gcp_domains.py",
    "rules/gcp_public_context.py",
)
EXCLUDED_PARTS = {
    "__pycache__",
    ".venv",
    "node_modules",
    ".git",
    "artifacts",
    "data",
    ".pytest_cache",
}
VERSION = "0.8.4-clogcp.1"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_zip(path: Path, files: dict[str, bytes]) -> None:
    with ZipFile(path, "x", compression=ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in sorted(files.items()):
            rel = Path(name)
            if rel.is_absolute() or ".." in rel.parts or EXCLUDED_PARTS.intersection(rel.parts):
                raise ValueError("Unapproved release path")
            info = ZipInfo("CloGCP/" + name, (2026, 10, 23, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = (
                0o100755 if name.endswith((".sh", ".command")) else 0o100644
            ) << 16
            z.writestr(info, data)
    with ZipFile(path) as z:
        if z.testzip():
            raise ValueError("ZIP CRC failure")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    a.output.mkdir(parents=True, exist_ok=False)
    base = json.loads((a.baseline / "portable-manifest.json").read_text())
    runtime = {}
    changed = []
    for entry in base["files"]:
        name = entry["path"]
        old = (a.baseline / name).read_bytes()
        if digest(old) != entry["sha256"]:
            raise ValueError("Baseline integrity mismatch")
        # Portable app: runtime + existing dependencies, no collectors or frontend development.
        if name.startswith(("src/", "wheelhouse/", "locks/")) or name in {
            "pyproject.toml",
            "requirements.txt",
            "setup-macos.sh",
            "setup-windows.ps1",
        }:
            current = root / name
            runtime[name] = current.read_bytes() if name.startswith("src/") else old
            if name == "setup-macos.sh":
                runtime[name] = old.replace(
                    b"CloSec setup complete. Run: bash start-macos.sh",
                    b"CloGCP setup complete. Run: sh CloGCP.command",
                )
            elif name == "setup-windows.ps1":
                runtime[name] = old.replace(
                    b"CloSec setup complete. Run: .\\start-windows.ps1",
                    b"CloGCP setup complete. Run: .\\CloGCP.cmd",
                )
            if runtime[name] != old:
                changed.append(name)
    for name in NEW_RUNTIME:
        relative = "src/offline_analyzer/" + name
        runtime[relative] = (root / relative).read_bytes()
        changed.append(relative)
    for name in ("CloGCP.command", "CloGCP.cmd", "README.md"):
        runtime[name] = (root / name).read_bytes()
        changed.append(name)
    for name in (
        "docs/ADR-CLOGCP-001.md",
        "docs/GCP_COLLECTOR_CONTRACT.md",
        "docs/GCP_EXCEL_REGISTER.md",
    ):
        runtime[name] = (root / name).read_bytes()
    for path in sorted((root / "docs/clogcp").rglob("*")):
        if path.is_file():
            runtime[path.relative_to(root).as_posix()] = path.read_bytes()
    verifier = (
        (a.baseline / "verify.py")
        .read_text()
        .replace("CloSec", "CloGCP")
        .replace("closec-portable-1", "clogcp-portable-1")
    )
    runtime["verify.py"] = verifier.encode()
    snapshot = digest(
        b"".join(
            n.encode() + b"\0" + hashlib.sha256(v).digest()
            for n, v in sorted(runtime.items())
            if not n.startswith(("wheelhouse/", "locks/"))
        )
    )
    metadata = {
        "product": "CloGCP",
        "version": VERSION,
        "status": "RELEASE_CANDIDATE",
        "base_source_revision": base["git_revision"],
        "source_kind": "WORKING_TREE_SNAPSHOT",
        "source_snapshot": snapshot,
        "source_branch": "clogcp/correction-0.8.4",
        "base_zip_sha256": "9050e2f34d861065c58c8d96709b4adc4d4cc20047f1b12026a5db8acae59dd8",
        "customer_data_included": False,
        "production_assessment_validated": False,
        "native_windows_acceptance": "PENDING",
        "desktop_excel_acceptance": "PENDING",
    }
    runtime["CLOGCP_VERSION.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    manifest = {
        "schema": "clogcp-portable-1",
        "product": "CloGCP",
        "git_revision": base["git_revision"],
        **metadata,
        "files": [
            {"path": n, "sha256": digest(v), "bytes": len(v)} for n, v in sorted(runtime.items())
        ],
    }
    runtime["portable-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    portable = a.output / "CloGCP.zip"
    write_zip(portable, runtime)
    source = dict(runtime)
    source = {n: v for n, v in source.items() if not n.startswith(("wheelhouse/", "locks/"))}
    for directory in ("tests", "tools", "frontend", "collectors"):
        for path in sorted((root / directory).rglob("*")):
            if (
                path.is_file()
                and not path.is_symlink()
                and not EXCLUDED_PARTS.intersection(path.relative_to(root).parts)
            ):
                if path.suffix in {".pyc", ".log"}:
                    continue
                source[path.relative_to(root).as_posix()] = path.read_bytes()
    for name in (
        "AGENTS.md",
        "ARCHITECTURE.md",
        "EVIDENCE_SCHEMA.md",
        "METHODOLOGY_COVERAGE.md",
        "IMPLEMENTATION_ROADMAP.md",
        "TEST_PLAN.md",
        "pyproject.toml",
    ):
        source[name] = (root / name).read_bytes()
    source["SOURCE_README.txt"] = (
        b"CloGCP source and synthetic tests. Portable ZIP supplies wheelhouse and locks "
        b"for offline setup. Source is an uncommitted working-tree snapshot.\n"
    )
    source.pop("portable-manifest.json")
    source["SOURCE_SHA256SUMS.txt"] = "".join(
        f"{digest(v)}  {n}\n" for n, v in sorted(source.items())
    ).encode()
    write_zip(a.output / "CloGCP-source.zip", source)
    files = {
        p.name: {"sha256": digest(p.read_bytes()), "bytes": p.stat().st_size}
        for p in (portable, a.output / "CloGCP-source.zip")
    }
    for name, entry in files.items():
        (a.output / (name + ".sha256")).write_text(entry["sha256"] + "  " + name + "\n")
    (a.output / "VERSION.json").write_text(
        json.dumps({**metadata, "assets": files}, indent=2) + "\n"
    )
    (a.output / "APPLICATION_CHANGES.json").write_text(
        json.dumps(sorted(set(changed)), indent=2) + "\n"
    )
    print(json.dumps({"source_snapshot": snapshot, "assets": files}, indent=2))


if __name__ == "__main__":
    main()
