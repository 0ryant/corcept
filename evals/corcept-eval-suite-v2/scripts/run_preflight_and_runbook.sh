#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/python.sh -m corcept_eval preflight --out results/preflight.json
./scripts/python.sh -m corcept_eval list-benchmarks --out results/benchmark-registry.json
./scripts/python.sh -m corcept_eval write-runbook --out results/external-runbook.md
