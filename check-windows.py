"""Standard-library Windows preflight, invoked as a file before offline installation."""

import platform
import struct
import sys


def compatible(os_name: str, version: tuple[int, ...], machine: str, bits: int) -> bool:
    return (
        os_name == "win32"
        and version[:2] == (3, 12)
        and machine.upper() in {"AMD64", "X86_64"}
        and bits == 64
    )


def main() -> int:
    if not compatible(
        sys.platform, tuple(sys.version_info[:2]), platform.machine(), struct.calcsize("P") * 8
    ):
        print("Windows x64 Python 3.12 is required.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
