"""Bounded input helpers. No general archive extraction is implemented."""

import hashlib
import re
from pathlib import Path, PurePosixPath


def validate_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or "\x00" in value
        or ".." in path.parts
        or value == "."
    ):
        raise ValueError("unsafe relative path")


def resolve_under(root: Path, relative: str) -> Path:
    validate_relative_path(relative)
    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("path escapes workspace")
    return target


def sha256_file(path: Path, max_bytes: int = 64 * 1024 * 1024) -> str:
    from offline_analyzer.provenance.execution import checkpoint

    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            checkpoint()
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("file exceeds byte budget")
            digest.update(chunk)
    return digest.hexdigest()


FORMULA_LEAD = re.compile(r"^[\s\x00-\x1f]*[=+@-]")


def excel_literal(value: str) -> str:
    """Report exporters must additionally write strings, never formula cell types."""
    if FORMULA_LEAD.match(value):
        return "'" + value
    return value


def verify_artifact(root: Path, artifact) -> Path:
    """Check declared size and digest before an adapter opens the raw file.

    Callers must protect the workspace from concurrent writers; this does not
    eliminate TOCTOU races or authenticate the collector.
    """
    target = resolve_under(root, artifact.relative_path)
    if not target.is_file() or target.stat().st_size != artifact.size_bytes:
        raise ValueError("artifact size mismatch")
    if sha256_file(target) != artifact.sha256:
        raise ValueError("artifact checksum mismatch")
    return target
