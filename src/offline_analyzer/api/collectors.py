"""Serve the bundled, versioned collectors for download from the local application.

Fixed allowlist only: no request-supplied paths. Files come from the application's own
`collectors/` directory (source checkout or extracted portable release) and are hashed on
every listing. Each collector ships as one ZIP named after the collector: a top-level folder
with the script, its README, the analyzer contract and the empty working subfolders the
script uses by default (AWS `evidence/`; GCP `organization/` and `projects/`).
"""

import hashlib
import io
import json
import zipfile
from pathlib import Path

from offline_analyzer.ingestion.json_input import InputError

ROOT = Path(__file__).resolve().parents[3] / "collectors"
FIXED_TIME = (2026, 1, 1, 0, 0, 0)
AWS_FILES = (
    "aws/assessment.py",
    "aws/README.md",
    "aws/config.example.json",
    "aws/approved_accounts.example.txt",
    "collector-analyzer-contract.json",
)
GCP_FILES = (
    "gcp/GCP_Security_Evidence_Collector.ps1",
    "gcp/README.md",
    "collector-analyzer-contract.json",
)
KITS = {
    "aws": ("CloSec_AWS_Collector", AWS_FILES, ("evidence",)),
    "gcp": ("CloSec_GCP_Collector", GCP_FILES, ("organization", "projects")),
}


def _read(relative: str) -> bytes:
    path = ROOT / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
        raise InputError("COLLECTOR_BUNDLE_UNAVAILABLE")
    return path.read_bytes()


def _kit_zip(key: str) -> bytes:
    folder, files, subfolders = KITS[key]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            # Deterministic bytes: fixed timestamps and order.
            info = zipfile.ZipInfo(f"{folder}/{Path(relative).name}", FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, _read(relative))
        for sub in subfolders:
            archive.writestr(zipfile.ZipInfo(f"{folder}/{sub}/", FIXED_TIME), b"")
    return buffer.getvalue()


def _versions() -> dict:
    contract = json.loads(_read("collector-analyzer-contract.json"))
    aws, gcp = contract["providers"]
    return {
        "AWS": aws["collector_version"],
        "GCP": gcp["collector_version"],
        "AWS and GCP": contract["contract_version"],
    }


def bundles() -> dict[str, tuple[str, str, callable]]:
    versions = _versions()
    return {
        "aws": (
            f"CloSec_AWS_Collector_v{versions['AWS']}.zip",
            "application/zip",
            lambda: _kit_zip("aws"),
        ),
        "gcp": (
            f"CloSec_GCP_Collector_v{versions['GCP']}.zip",
            "application/zip",
            lambda: _kit_zip("gcp"),
        ),
        "contract": (
            "collector-analyzer-contract.json",
            "application/json",
            lambda: _read("collector-analyzer-contract.json"),
        ),
    }


def listing() -> list[dict]:
    versions = _versions()
    descriptions = {
        "aws": (
            "AWS",
            "Python/boto3, read-only. Folder with assessment.py, README and evidence/",
        ),
        "gcp": (
            "GCP",
            "PowerShell 5.1 + gcloud, read-only. Folder with script, README, "
            "organization/ and projects/",
        ),
        "contract": ("AWS and GCP", "Collector-to-analyzer contract (machine-readable)"),
    }
    result = []
    for key, (name, _, produce) in bundles().items():
        data = produce()
        provider, description = descriptions[key]
        result.append(
            {
                "id": key,
                "name": name,
                "provider": provider,
                "version": versions.get(provider),
                "description": description,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return result


def download(key: str) -> tuple[str, str, bytes]:
    entry = bundles().get(key)
    if entry is None:
        raise InputError("COLLECTOR_BUNDLE_UNAVAILABLE")
    name, media, produce = entry
    return name, media, produce()
