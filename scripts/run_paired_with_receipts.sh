#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVAL="$ROOT/evals/corcept-eval-suite-v2"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/results/paired-${STAMP}"
LOG="$OUT/run.log"
mkdir -p "$OUT"

exec > >(tee -a "$LOG") 2>&1
echo "=== corcept paired benchmarks with receipts ==="
echo "out=$OUT"
echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "$EVAL"
./scripts/setup_env.sh
./scripts/python.sh -m corcept_eval run-paired-all \
  --out "$OUT" \
  --repo-root "$ROOT" \
  --plugin-dir "$ROOT/plugins/corcept"

echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "manifest=$OUT/MANIFEST.json"
echo "summary=$OUT/WITH-VS-WITHOUT.md"
