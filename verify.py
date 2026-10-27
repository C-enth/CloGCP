"""Standard-library integrity check of the runtime files; never reads assessment data.

A release ZIP carries portable-manifest.json (runtime files plus bundled wheels). A source
clone carries RUNTIME_MANIFEST.json, the same runtime selection without wheels. Both list
SHA-256 and size for every file; any difference stops the launcher.
"""

import hashlib
import json
from pathlib import Path

MANIFESTS = (
    ("portable-manifest.json", "clogcp-portable-1"),
    ("RUNTIME_MANIFEST.json", "clogcp-runtime-1"),
)


def verify(root: Path) -> dict:
    root = root.resolve()
    found = [(name, schema) for name, schema in MANIFESTS if (root / name).is_file()]
    if not found:
        raise ValueError("No runtime manifest")
    name, schema = found[0]
    manifest = json.loads((root / name).read_text(encoding="utf-8"))
    if manifest.get("product") != "CloGCP" or manifest.get("schema") != schema:
        raise ValueError("Invalid runtime manifest")
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe manifest path")
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Unsafe source path")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            raise ValueError("Runtime file integrity mismatch")
    return {
        "result": "PASS",
        "product": "CloGCP",
        "mode": "release" if schema == "clogcp-portable-1" else "source-clone",
        "version": manifest.get("version"),
        "git_revision": manifest.get("git_revision"),
        "files": len(manifest["files"]),
    }


if __name__ == "__main__":
    try:
        print(json.dumps(verify(Path(__file__).resolve().parent)))
    except (OSError, ValueError, KeyError):
        raise SystemExit(
            "Runtime integrity check failed; re-extract the release or re-clone the tag."
        ) from None
