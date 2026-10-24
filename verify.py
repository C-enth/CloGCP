"""Standard-library portable source integrity check; never reads assessment data."""

import hashlib
import json
from pathlib import Path


def verify(root: Path) -> dict:
    root = root.resolve()
    manifest = json.loads((root / "portable-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("product") != "CloGCP" or manifest.get("schema") != "clogcp-portable-1":
        raise ValueError("Invalid portable manifest")
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
            raise ValueError("Portable source integrity mismatch")
    return {
        "result": "PASS",
        "product": "CloGCP",
        "git_revision": manifest["git_revision"],
        "files": len(manifest["files"]),
    }


if __name__ == "__main__":
    try:
        print(json.dumps(verify(Path(__file__).resolve().parent)))
    except (OSError, ValueError, KeyError):
        raise SystemExit(
            "Portable source integrity check failed; re-extract the original distribution."
        ) from None
