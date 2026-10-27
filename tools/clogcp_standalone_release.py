"""Positive-allowlist source packages for independent finalizer and delta collector."""

import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path

from tools.source_release import findings

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = {
    "clogcp_report_finalizer": {
        "pydantic",
        "pydantic-core",
        "annotated-types",
        "typing-extensions",
        "typing-inspection",
        "openpyxl",
        "et-xmlfile",
        "defusedxml",
    },
    "clogcp_delta": {
        "pydantic",
        "pydantic-core",
        "annotated-types",
        "typing-extensions",
        "typing-inspection",
    },
}

# Each package's version comes from its own source, never from this packager.
VERSION_SOURCES = {
    "clogcp_report_finalizer": ("src/clogcp_report_finalizer/schema.py", r'^VERSION = "([^"]+)"'),
    "clogcp_delta": (
        "src/clogcp_delta/models.py",
        r'collector_version: Literal\["gcp-delta-([^"]+)"\]',
    ),
}


def version(package: str) -> str:
    path, pattern = VERSION_SOURCES[package]
    return re.search(pattern, (ROOT / path).read_text(encoding="utf-8"), re.M)[1]


def assemble(package: str, output: Path, wheelhouse: Path) -> Path:
    if package not in DEPENDENCIES or output.exists():
        raise ValueError("SUPPORTED_PACKAGE_AND_NEW_OUTPUT_REQUIRED")
    files = {}
    for path in sorted((ROOT / "src" / package).glob("*.py")):
        if path.is_symlink() or findings(path.relative_to(ROOT).as_posix(), path.read_bytes()):
            raise ValueError("SOURCE_REVIEW_REQUIRED")
        files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    dependencies = DEPENDENCIES[package]
    for lock in sorted((wheelhouse / "locks").glob("*.txt")):
        lines = []
        selected = set()
        for line in lock.read_text().splitlines():
            if "==" not in line:
                continue
            name = line.split("==")[0].lower().replace("_", "-")
            if name not in dependencies:
                continue
            selected.add(name)
            lines.append(line)
            digest = re.search(r"--hash=sha256:([0-9a-f]{64})", line)[1]
            matches = [
                p
                for p in (wheelhouse / "wheelhouse" / lock.stem).glob("*.whl")
                if hashlib.sha256(p.read_bytes()).hexdigest() == digest
            ]
            if len(matches) != 1:
                raise ValueError("DEPENDENCY_HASH_OR_INVENTORY_MISMATCH")
            wheel = matches[0]
            files[f"wheelhouse/{lock.stem}/{wheel.name}"] = wheel.read_bytes()
        if selected != dependencies:
            raise ValueError("DEPENDENCY_CLOSURE_INCOMPLETE")
        files[f"locks/{lock.name}"] = ("\n".join(lines) + "\n").encode()
    files["GCP_FINAL_WORKFLOW.md"] = (ROOT / "docs/GCP_FINAL_WORKFLOW.md").read_bytes()
    display = (
        "CloGCP Report Finalizer"
        if package == "clogcp_report_finalizer"
        else "CloGCP Missing-Evidence Collector"
    )
    gui = " --gui" if package == "clogcp_report_finalizer" else " --help"
    release = version(package)
    files["README.md"] = f"""# {display} {release}

Separate offline source candidate. No analyzer backend, database or client evidence included.
Requires an existing Python 3.12 runtime; installing this tool does not reinstall CloGCP.
The finalizer reads only explicitly selected report exports. The separate collector can
contact GCP only after an approved plan and explicit --execute; defaults to dry-run.

Offline setup (choose macos-arm64, macos-x86_64 or windows-x64):

```
python3.12 -m venv .venv
.venv/bin/python -m pip install --no-index --only-binary=:all: --require-hashes \
  --find-links wheelhouse/macos-x86_64 -r locks/macos-x86_64.txt
```

On Windows use `.venv\\Scripts\\python.exe` and `wheelhouse/windows-x64` with its lock.
Reuse the existing compatible CloGCP Python without installing anything:

```
CLOGCP_PYTHON=/path/to/CloGCP/.venv/bin/python sh start-macos.sh{gui}
```

On Windows set `CLOGCP_PYTHON` to the existing compatible python.exe and run
`start-windows.cmd{gui}`. These launchers set PYTHONPATH to this package only.
Set PYTHONPATH to this directory's src and run `python -m {package}{gui}`.
Alternatively copy only src/{package} into an existing compatible Python runtime's
site-packages after verifying source-manifest.json; no analyzer code is required.

Run `python verify.py` before using the package. See GCP_FINAL_WORKFLOW.md for the exact
scope, inputs, approvals, limitations and workflow. The finalizer's standard output is a
new review copy plus a separate Assessor QA / Exceptions register. No technical decision
or human approval is invented. Native Windows, native Excel and customer acceptance are
pending; this package is not a Windows executable or an embedded Python runtime.
""".encode()
    files["verify.py"] = b"""import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'source-manifest.json').read_text())
for record in manifest['files']:
    path=root/record['path']
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=record['sha256']:
        raise SystemExit('PACKAGE_INTEGRITY_FAILURE')
print('PASS: package integrity verified')
"""
    files["start-macos.sh"] = f"""#!/bin/sh
set -eu
CLOGCP_TOOL_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONPATH="$CLOGCP_TOOL_ROOT/src"
CLOGCP_TOOL_PYTHON=${{CLOGCP_PYTHON:-$CLOGCP_TOOL_ROOT/.venv/bin/python}}
exec "$CLOGCP_TOOL_PYTHON" -m {package} "$@"
""".encode()
    files["start-windows.cmd"] = f"""@echo off
set "PYTHONPATH=%~dp0src"
if defined CLOGCP_PYTHON (
  "%CLOGCP_PYTHON%" -m {package} %*
) else (
  "%~dp0.venv\\Scripts\\python.exe" -m {package} %*
)
""".replace("\n", "\r\n").encode()
    manifest = {
        "schema_version": "clogcp-standalone-source-1",
        "package": package,
        "version": release,
        "customer_evidence_included": False,
        "native_windows_acceptance": "PENDING",
        "native_excel_acceptance": "PENDING",
        "files": [
            {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in sorted(files.items())
        ],
    }
    files["source-manifest.json"] = json.dumps(manifest, indent=2).encode()
    output.mkdir(parents=True)
    target = output / (package.replace("_", "-") + f"-{release}-source.zip")
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if name.endswith(".sh") else 0o644)) << 16
            archive.writestr(info, data)
    (output / "SHA256SUMS.txt").write_text(
        f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n"
    )
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", choices=DEPENDENCIES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    args = parser.parse_args()
    print(assemble(args.package, args.output, args.wheelhouse).name)


if __name__ == "__main__":
    main()
