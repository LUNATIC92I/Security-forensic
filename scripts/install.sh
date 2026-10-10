#!/usr/bin/env bash
# Installation script (Linux / macOS). Creates a virtual environment and installs the application.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
"$PY" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[api,dev]"
echo
echo "Installed. Next steps:"
echo "  . .venv/bin/activate"
echo "  export LUNATIC_MASTER_PASSPHRASE='...'   # recommended: wraps the data-encryption key"
echo "  ./scripts/run.sh                          # GUI (first run creates the administrator)"
echo "  python -m pytest                          # validation suite"
echo "Linux note: Qt needs libegl1 libgl1 libxkbcommon0 libfontconfig1 (apt) for the GUI."
