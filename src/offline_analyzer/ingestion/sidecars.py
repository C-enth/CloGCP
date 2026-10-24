"""Bounded OS metadata, never cloud evidence or an executable input."""

from pathlib import Path, PurePosixPath

from offline_analyzer.ingestion.json_input import MAX_PACKAGE_FILES, InputError

MAX_METADATA_BYTES = 64 * 1024
MAX_METADATA_TOTAL = 1024 * 1024


def is_os_metadata(name: str) -> bool:
    return PurePosixPath(name.replace("\\", "/")).name == ".DS_Store"


def check_metadata_size(size: int) -> None:
    if size > MAX_METADATA_BYTES:
        raise InputError(
            "OS_METADATA_BYTE_LIMIT",
            limit={
                "name": "os_metadata_file_bytes",
                "allowed": MAX_METADATA_BYTES,
                "observed": size,
            },
        )


def metadata_names(directory: Path) -> set[str]:
    """Ignore only exact known names after normal link and size protections."""
    names, total, file_count = set(), 0, 0
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise InputError("UNSAFE_ARCHIVE_MEMBER")
        if not path.is_file():
            continue
        file_count += 1
        if file_count > MAX_PACKAGE_FILES + 75:
            raise InputError("ARCHIVE_MEMBER_LIMIT")
        if is_os_metadata(path.name):
            check_metadata_size(path.stat().st_size)
            total += path.stat().st_size
            if total > MAX_METADATA_TOTAL or len(names) >= 128:
                raise InputError("OS_METADATA_PACKAGE_LIMIT")
            names.add(path.relative_to(directory).as_posix())
    return names
