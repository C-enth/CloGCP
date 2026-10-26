#!/bin/sh
# Double-click on macOS to start CloSec; close this window to stop it. The same file works in
# three places: next to a bundled release/ ZIP it extracts that once and starts it; in an
# extracted release it performs the offline setup on first use; in a developer checkout it
# uses the existing .venv.
set -eu
CLOSEC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fail() {
    printf '%s\n' "$@" >&2
    printf '%s' 'Press Return to close.' >&2
    read -r _
    exit 1
}

CLOSEC_RELEASE=$(ls "$CLOSEC_ROOT"/release/CloSec-*-portable-source.zip 2>/dev/null | tail -n 1)
if [ -n "$CLOSEC_RELEASE" ]; then
    # One folder per release ZIP, so a newer release is extracted and set up afresh.
    CLOSEC_APP="$CLOSEC_ROOT/release/$(basename "$CLOSEC_RELEASE" .zip)-app"
    if [ ! -f "$CLOSEC_APP/CloSec.command" ]; then
        printf '%s\n' 'First start: extracting the bundled CloSec release...'
        rm -rf "$CLOSEC_APP.partial"
        ditto -x -k "$CLOSEC_RELEASE" "$CLOSEC_APP.partial" || fail 'Could not extract the release.'
        mv "$CLOSEC_APP.partial" "$CLOSEC_APP"
    fi
    exec sh "$CLOSEC_APP/CloSec.command" "$@"
fi

if [ ! -x "$CLOSEC_ROOT/.venv/bin/python" ]; then
    [ -f "$CLOSEC_ROOT/setup-macos.sh" ] || fail \
        'This checkout has no bundled release and no .venv; see README.md to set it up.'
    for candidate in python3.12 /Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12 \
        /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12; do
        if command -v "$candidate" >/dev/null 2>&1; then
            CLOSEC_PYTHON=${CLOSEC_PYTHON:-$(command -v "$candidate")}
            break
        fi
    done
    [ -n "${CLOSEC_PYTHON:-}" ] || fail 'Python 3.12 is required. Install it from python.org' \
        '(macOS 64-bit universal2 installer), then double-click CloSec.command again.'
    export CLOSEC_PYTHON
    printf '%s\n' 'First start: installing CloSec offline from the bundled packages...'
    if ! sh "$CLOSEC_ROOT/setup-macos.sh"; then
        rm -rf "$CLOSEC_ROOT/.venv"  # A partial environment must not skip setup next time.
        fail 'CloSec setup failed; review the messages above.'
    fi
fi

if [ -f "$CLOSEC_ROOT/start-macos.sh" ]; then
    exec sh "$CLOSEC_ROOT/start-macos.sh" "$@"
fi
export PYTHONPATH="$CLOSEC_ROOT/src"
# Developer checkout: a folder argument, else CLOSEC_WORKSPACE / the remembered location /
# the default, resolved by the launcher.
CLOSEC_DEFAULT_WORKSPACE="$HOME/Library/Application Support/OfflineAWSAnalyzer/workspace"
if [ -n "${1:-}" ]; then
    exec "$CLOSEC_ROOT/.venv/bin/python" -m offline_analyzer.launcher --workspace "$1" \
        --default-workspace "$CLOSEC_DEFAULT_WORKSPACE" \
        --environment "${CLOSEC_ENVIRONMENT:-assessment}" --port 0
fi
exec "$CLOSEC_ROOT/.venv/bin/python" -m offline_analyzer.launcher \
    --default-workspace "$CLOSEC_DEFAULT_WORKSPACE" \
    --environment "${CLOSEC_ENVIRONMENT:-assessment}" --port 0
