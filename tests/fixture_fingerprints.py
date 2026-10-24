"""Pin historical synthetic byte contracts without retaining generated evidence."""

import hashlib
from pathlib import Path


def package_fingerprint(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.iterdir()):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()
