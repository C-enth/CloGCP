#!/bin/sh
set -eu
CLOSEC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLOSEC_PYTHON="$CLOSEC_ROOT/.venv/bin/python"
if [ ! -x "$CLOSEC_PYTHON" ]; then
    printf '%s\n' 'Run bash setup-macos.sh first.' >&2
    exit 1
fi
"$CLOSEC_PYTHON" -c 'import sys; assert sys.platform == "darwin" and sys.version_info[:2] == (3,12), "macOS Python 3.12 is required"'
"$CLOSEC_PYTHON" "$CLOSEC_ROOT/verify.py"
export PYTHONPATH="$CLOSEC_ROOT/src"
# Workspace: a folder given as the first argument, else CLOSEC_WORKSPACE, else the location
# remembered in CloSec (Workspace location screen), else the default below. Quoted
# throughout, so spaces and non-ASCII characters in paths are kept intact.
CLOSEC_DEFAULT_WORKSPACE="$HOME/Library/Application Support/OfflineAWSAnalyzer/workspace"
if [ -n "${1:-}" ]; then
    exec "$CLOSEC_PYTHON" -m offline_analyzer.launcher --workspace "$1" --default-workspace "$CLOSEC_DEFAULT_WORKSPACE" --environment "${CLOSEC_ENVIRONMENT:-assessment}" --port 0
fi
exec "$CLOSEC_PYTHON" -m offline_analyzer.launcher --default-workspace "$CLOSEC_DEFAULT_WORKSPACE" --environment "${CLOSEC_ENVIRONMENT:-assessment}" --port 0
