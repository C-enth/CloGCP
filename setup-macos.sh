#!/bin/sh
# Offline setup: installs only hash-locked wheels (locks/<platform>.txt). Never downloads.
# Release ZIP: wheels are bundled in wheelhouse/. Source clone: set CLOGCP_WHEELHOUSE to a
# folder holding <platform>/ wheels, e.g. the wheelhouse folder of the matching release ZIP.
set -eu
CLOSEC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLOSEC_PYTHON=${CLOSEC_PYTHON:-python3.12}
"$CLOSEC_PYTHON" -c 'import sys; assert sys.platform == "darwin" and sys.version_info[:2] == (3,12), "Install macOS Python 3.12 first"'
case "$("$CLOSEC_PYTHON" -c 'import platform; print(platform.machine())')" in
    arm64) CLOSEC_PLATFORM=macos-arm64 ;;
    x86_64) CLOSEC_PLATFORM=macos-x86_64 ;;
    *) printf '%s\n' 'Unsupported macOS architecture.' >&2; exit 1 ;;
esac
"$CLOSEC_PYTHON" "$CLOSEC_ROOT/verify.py"
CLOSEC_WHEELS="$CLOSEC_ROOT/wheelhouse/$CLOSEC_PLATFORM"
if [ ! -d "$CLOSEC_WHEELS" ] && [ -n "${CLOGCP_WHEELHOUSE:-}" ]; then
    CLOSEC_WHEELS="$CLOGCP_WHEELHOUSE/$CLOSEC_PLATFORM"
fi
if [ ! -d "$CLOSEC_WHEELS" ]; then
    printf '%s\n' "Wheels for $CLOSEC_PLATFORM not found. Use the release ZIP, or set CLOGCP_WHEELHOUSE to its wheelhouse folder." >&2
    exit 1
fi
"$CLOSEC_PYTHON" -m venv "$CLOSEC_ROOT/.venv"
"$CLOSEC_ROOT/.venv/bin/python" -m pip install --no-index --only-binary=:all: \
    --find-links "$CLOSEC_WHEELS" --require-hashes \
    -r "$CLOSEC_ROOT/locks/$CLOSEC_PLATFORM.txt"
"$CLOSEC_ROOT/.venv/bin/python" -m pip check
printf '%s\n' 'CloGCP setup complete. Run: sh CloGCP.command'
