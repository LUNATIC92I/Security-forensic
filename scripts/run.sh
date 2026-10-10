#!/usr/bin/env bash
# Launch the desktop application (use "cli" as first argument for the command line).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && . .venv/bin/activate
if [ "${1:-}" = "cli" ]; then shift; exec python -m lunatic_forensics "$@"; fi
exec python -m lunatic_forensics gui
