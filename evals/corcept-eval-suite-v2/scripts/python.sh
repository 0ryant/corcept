#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -x .venv/bin/python ]]; then
  export PYTHON="${PYTHON:-.venv/bin/python}"
else
  export PYTHON="${PYTHON:-$(command -v python3 || command -v python)}"
fi
exec "$PYTHON" "$@"
