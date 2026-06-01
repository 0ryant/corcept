#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ROOT
OUT="$ROOT/results/full-benchmark"
EVAL="$ROOT/evals/corcept-eval-suite-v2"
PYTHON="$EVAL/scripts/python.sh"
PLUGIN="$(cd "$ROOT/plugins/corcept" && pwd)"
LOG="$OUT/resume.log"
BASELINE_CMD='claude --print "$CORCEPT_TASK_PROMPT"'
CORCEPT_CMD='claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'

exec >>"$LOG" 2>&1
echo "=== resume $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# Retry mini-SWE task 3 CORCEPT only (prior run hit API 529)
cd "$EVAL"
"$PYTHON" <<'PY'
import json, os, subprocess, time
from pathlib import Path
from corcept_eval.mini_swe import TASKS, make_task_repo, run_pytest
from corcept_eval.pair import run_agent_command

repo_root = Path(os.environ["ROOT"])
root = repo_root / "results/full-benchmark/paired-mini-swe"
plugin = str(repo_root / "plugins/corcept")
task = next(t for t in TASKS if t["id"] == "mini_003_redact_nested")
cmd = 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'
repo = make_task_repo(task, root / "repos" / "corcept-retry")
agent = run_agent_command(cmd, repo, task, "corcept", plugin)
tests = run_pytest(repo)
row = {"task_id": task["id"], "mode": "corcept-retry", "agent": agent, "tests": tests, "passed": tests["passed"]}
retry_path = root / "mini_003_corcept_retry.json"
retry_path.write_text(json.dumps(row, indent=2), encoding="utf-8")
results = json.loads((root / "results.json").read_text(encoding="utf-8"))
for i, r in enumerate(results["rows"]):
    if r["task_id"] == task["id"] and r["mode"] == "corcept":
        results["rows"][i] = {**row, "mode": "corcept", "note": "retried after 529"}
        break
passed = sum(1 for r in results["rows"] if r["mode"] == "corcept" and r["passed"])
results["summary"]["corcept_pass_rate"] = passed / 3
results["summary"]["delta"] = results["summary"]["corcept_pass_rate"] - results["summary"]["baseline_pass_rate"]
(root / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print("mini-swe retry:", row["passed"], "->", retry_path)
PY

# Paired mini-reasoning (all 4 tasks)
"$PYTHON" -m corcept_eval run-pair \
  --suite mini-reasoning \
  --baseline-cmd "$BASELINE_CMD" \
  --corcept-cmd "$CORCEPT_CMD" \
  --plugin-dir "$PLUGIN" \
  --out "$OUT/paired-mini-reasoning"

# Harbor terminal-bench (3 tasks)
mkdir -p "$OUT/harbor"
harbor run --dataset terminal-bench@2.0 --n-tasks 3 \
  --jobs-dir "$OUT/harbor" --job-name terminal-bench-oracle --agent oracle

harbor run --dataset terminal-bench@2.0 --n-tasks 3 \
  --jobs-dir "$OUT/harbor" --job-name terminal-bench-baseline --agent claude-code

# Final aggregate
cd "$ROOT"
"$PYTHON" "$ROOT/scripts/finalize_benchmark_report.py"
echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
