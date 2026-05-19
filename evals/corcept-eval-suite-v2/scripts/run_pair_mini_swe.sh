#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASELINE_CMD:?Set BASELINE_CMD}"
: "${CORCEPT_CMD:?Set CORCEPT_CMD}"
PLUGIN_DIR="${PLUGIN_DIR:-}"
./scripts/python.sh -m corcept_eval run-pair --baseline-cmd "$BASELINE_CMD" --corcept-cmd "$CORCEPT_CMD" --plugin-dir "$PLUGIN_DIR" --out results/paired-mini-swe
