#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/setup_env.sh

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running." >&2
  exit 1
fi

OUT="${1:-results/external-smoke}"
mkdir -p "$OUT"

echo "Running SWE-bench mini dataset smoke import..."
./scripts/python.sh <<'PY'
from datasets import load_dataset

rows = load_dataset("MariusHobbhahn/swe-bench-verified-mini", split="test")
print(f"swe-bench-verified-mini rows: {len(rows)}")
print(f"sample instance: {rows[0]['instance_id']}")
PY

docker run --rm python:3.11-slim python -c "print('container verifier ok')" | tee "$OUT/docker-smoke.txt"
./scripts/python.sh -m corcept_eval preflight --out "$OUT/preflight.json"

echo "Smoke complete: $OUT"
