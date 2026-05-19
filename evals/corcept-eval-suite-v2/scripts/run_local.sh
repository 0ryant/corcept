#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/python.sh -m corcept_eval run-local --out results/local
./scripts/python.sh -m corcept_eval preflight --out results/preflight.json
