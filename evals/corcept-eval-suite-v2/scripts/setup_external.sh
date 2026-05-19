#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/setup_env.sh

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running. Start Docker Desktop or colima, then re-run." >&2
  exit 1
fi

echo "Pulling SWE-bench evaluation base image..."
docker pull python:3.11-slim

echo "Installing SWE-bench harness packages in eval venv..."
.venv/bin/pip install -q swebench datasets huggingface_hub

echo "Verifying docker can run isolated containers..."
docker run --rm python:3.11-slim python -c "print('docker-ok')"

./scripts/python.sh -m corcept_eval preflight --out results/preflight.json
./scripts/python.sh -m corcept_eval list-benchmarks --out results/benchmark-registry.json
./scripts/python.sh -m corcept_eval write-runbook --out results/external-runbook.md

echo "External benchmark stack ready. See results/preflight.json for availability."
