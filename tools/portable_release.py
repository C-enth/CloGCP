"""One source application ZIP for macOS/Windows x64; no evidence or executable build."""

import argparse
import hashlib
import json
import stat
import subprocess
import time
import tomllib
import zipfile
from pathlib import Path

from tools.source_release import allowed, findings

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    "setup-macos.sh",
    "start-macos.sh",
    "setup-windows.ps1",
    "start-windows.ps1",
    "verify.py",
)
EXECUTABLES = frozenset({"CloSec.command", "setup-macos.sh", "start-macos.sh"})


DOCUMENTS = (
    "GCP_ATTACK_ENGINE.md",
    "GCP_FINAL_WORKFLOW.md",
    "OPERATOR_GUIDE.md",
    "ASSESSMENT_COVERAGE.md",
    "RELEASE_0.7.0.md",
    "SPRINT_ASSESSMENT_CHANGELOG.md",
    "ADR-011-assessment-finalisation.md",
)
COLLECTORS = (
    "collectors/aws/assessment.py",
    "collectors/aws/README.md",
    "collectors/aws/config.example.json",
    "collectors/aws/approved_accounts.example.txt",
    "collectors/gcp/GCP_Security_Evidence_Collector.ps1",
    "collectors/gcp/README.md",
    "collectors/collector-analyzer-contract.json",
)
TARGETS = ("windows-x64", "macos-arm64", "macos-x86_64")


def dependencies(wheelhouse: Path) -> dict[str, Path]:
    """Prepared offline wheels and hash locks; every target must be complete."""
    paths = {}
    for target in TARGETS:
        lock = wheelhouse / "locks" / f"{target}.txt"
        wheels = sorted((wheelhouse / "wheelhouse" / target).glob("*.whl"))
        if not lock.is_file() or not wheels:
            raise ValueError(f"Incomplete wheelhouse for {target}")
        paths[f"locks/{target}.txt"] = lock
        for wheel in wheels:
            if wheel.is_symlink() or wheel.stat().st_size > 64 * 1024 * 1024:
                raise ValueError(f"Unsafe wheel: {wheel.name}")
            paths[f"wheelhouse/{target}/{wheel.name}"] = wheel
    return paths


def candidates(root: Path, *, working_tree: bool = False) -> dict[str, Path]:
    paths = {name: root / name for name in ("pyproject.toml", "requirements.txt")}
    tracked = (
        subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
        .stdout.decode()
        .split("\0")
    )
    for name in filter(None, tracked):
        if name.startswith(("src/offline_analyzer/", "src/clogcp_delta/", "frontend/")) and allowed(
            name
        ):
            if name.startswith("src/offline_analyzer/api/assets/"):
                # Current compiled assets are indexed below, independently of git staging.
                continue
            paths[name] = root / name
    for path in (root / "src/offline_analyzer/api/assets").rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_file() and allowed(name):
            paths[name] = path
    if working_tree:
        # Explicit source-only inventory; never enumerate private/workspace/artifact trees.
        for directory in (
            "src/offline_analyzer",
            "src/clogcp_delta",
            "frontend/src",
            "frontend/public",
        ):
            for path in (root / directory).rglob("*"):
                name = path.relative_to(root).as_posix()
                if path.is_file() and allowed(name):
                    paths[name] = path
    for name in SCRIPTS:
        paths[name] = root / "packaging/portable" / name
    for name in ("CloSec.command", "CloSec.cmd"):  # One launcher per OS for every layout.
        paths[name] = root / name
    paths["README.md"] = root / "packaging/portable/README.md"
    paths["OPERATIONS.md"] = root / "docs/OPERATIONS_0.5.1.md"
    paths["GCP_COLLECTOR_CONTRACT.md"] = root / "docs/GCP_COLLECTOR_CONTRACT.md"
    for name in DOCUMENTS:
        paths[name] = root / "docs" / name
    for name in COLLECTORS:
        paths[name] = root / name
    for name, path in paths.items():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError(f"Unsafe or missing application source: {name}")
        if findings(path.relative_to(root).as_posix(), path.read_bytes()):
            raise ValueError(f"Source security review required: {name}")
    return paths


def assemble(
    root: Path,
    output: Path,
    *,
    revision: str,
    wheelhouse: Path | None = None,
    working_tree: bool = False,
) -> Path:
    paths = candidates(root, working_tree=working_tree)
    if wheelhouse is not None:
        paths.update(dependencies(wheelhouse))
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    output.mkdir(parents=True, exist_ok=False)
    contents = {name: path.read_bytes() for name, path in paths.items()}
    fingerprint = hashlib.sha256(
        "\n".join(
            f"{name}:{hashlib.sha256(data).hexdigest()}" for name, data in sorted(contents.items())
        ).encode()
    ).hexdigest()
    contents["src/offline_analyzer/api/assets/release-info.json"] = json.dumps(
        {
            "git_revision": revision,
            "working_tree_modified": working_tree,
            "application_version": version,
            "source_snapshot": fingerprint,
        },
        indent=2,
    ).encode()
    manifest = {
        "schema": "closec-portable-1",
        "product": "CloSec",
        "application_version": version,
        "git_revision": revision,
        "working_tree_modified": working_tree,
        "source_kind": "WORKING_TREE_SNAPSHOT" if working_tree else "COMMITTED_SOURCE",
        "source_snapshot": fingerprint,
        "python": "3.12",
        "platforms": ["macOS", "Windows x64"],
        "status": "SOURCE_APPLICATION_WINDOWS_NATIVE_ACCEPTANCE_PENDING",
        "customer_evidence_included": False,
        "offline_dependencies": sorted(
            target for target in TARGETS if f"locks/{target}.txt" in paths
        ),
        "files": [
            {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(contents.items())
        ],
    }
    contents["portable-manifest.json"] = json.dumps(manifest, indent=2).encode()
    snapshot = (
        "-update-" + time.strftime("%Y%m%d") + "-sprint-" + fingerprint[:12] if working_tree else ""
    )
    target = output / f"CloSec-{version}{snapshot}-portable-source.zip"
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=time.localtime()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix modes, so macOS keeps launchers double-clickable.
            mode = 0o755 if name in EXECUTABLES else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, data)
    (output / "portable-manifest.json").write_bytes(contents["portable-manifest.json"])
    (output / "SHA256SUMS.txt").write_text(
        f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n"
    )
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--wheelhouse", type=Path, help="tools/build_wheelhouse.py output (offline installs)"
    )
    parser.add_argument(
        "--working-tree",
        action="store_true",
        help="Explicitly package pending source changes with truthful snapshot metadata",
    )
    args = parser.parse_args()
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    if status and not args.working_tree:
        raise SystemExit("Commit the reviewed source before preparing a portable release.")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    target = assemble(
        ROOT,
        args.output.resolve(),
        revision=revision,
        wheelhouse=args.wheelhouse.resolve() if args.wheelhouse else None,
        working_tree=args.working_tree,
    )
    print(json.dumps({"distribution": str(target), "git_revision": revision}))


if __name__ == "__main__":
    main()
