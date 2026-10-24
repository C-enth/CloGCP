#!/bin/sh
# Independent CloGCP distribution. All assessment storage is selected by its profile.
set -eu
CLOGCP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x "$CLOGCP_ROOT/.venv/bin/python" ]; then
    if [ -n "${CLOGCP_PYTHON:-}" ]; then
        CLOSEC_PYTHON=$CLOGCP_PYTHON
    else
        CLOSEC_PYTHON=$(command -v python3.12) || {
            printf '%s\n' 'Install Python 3.12, then run CloGCP.command again.' >&2
            exit 1
        }
    fi
    export CLOSEC_PYTHON
    sh "$CLOGCP_ROOT/setup-macos.sh"
fi
"$CLOGCP_ROOT/.venv/bin/python" "$CLOGCP_ROOT/verify.py"
export PYTHONPATH="$CLOGCP_ROOT/src"
exec "$CLOGCP_ROOT/.venv/bin/python" -m offline_analyzer.clogcp \
    --environment "${CLOGCP_ENVIRONMENT:-assessment}" --port 0 "$@"
