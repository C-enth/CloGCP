#!/bin/sh
# Offline setup: installs only the bundled, hash-locked wheels. Never downloads packages.
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
if [ ! -d "$CLOSEC_ROOT/wheelhouse/$CLOSEC_PLATFORM" ]; then
    printf '%s\n' "Bundled wheelhouse/$CLOSEC_PLATFORM is missing; use the complete release ZIP." >&2
    exit 1
fi
"$CLOSEC_PYTHON" -m venv "$CLOSEC_ROOT/.venv"
"$CLOSEC_ROOT/.venv/bin/python" -m pip install --no-index --only-binary=:all: \
    --find-links "$CLOSEC_ROOT/wheelhouse/$CLOSEC_PLATFORM" --require-hashes \
    -r "$CLOSEC_ROOT/locks/$CLOSEC_PLATFORM.txt"
"$CLOSEC_ROOT/.venv/bin/python" -m pip check
printf '%s\n' 'CloSec setup complete. Run: bash start-macos.sh'
