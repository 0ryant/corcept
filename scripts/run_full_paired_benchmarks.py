#!/usr/bin/env python3
"""Run all CORCEPT paired benchmarks and write a consolidated report."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "evals" / "corcept-eval-suite-v2"
OUT = ROOT / "results" / "full-benchmark"
PLUGIN = ROOT / "plugins" / "corcept"
PYTHON = EVAL / "scripts" / "python.sh"


def run(cmd: list[str] | str, *, cwd: Path | None = None, shell: bool = False) -> subprocess.CompletedProcess:
    print(f"\n>>> {' '.join(cmd) if isinstance(cmd, list) else cmd}", flush=True)
    return subprocess.run(cmd, cwd=cwd or ROOT, shell=shell, text=True, check=False)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()

    # 1) Guard benchmark v2 (baseline / original / hardened)
    run([sys.executable, "benchmarks/run_corcept_benchmark_v2.py", "--out", str(OUT / "guard-v2")])

    # 2) Local deterministic eval
    run([str(PYTHON), "-m", "corcept_eval", "run-local", "--out", str(OUT / "local")], cwd=EVAL)
    run([str(PYTHON), "-m", "corcept_eval", "preflight", "--out", str(OUT / "preflight.json")], cwd=EVAL)

    baseline_cmd = 'claude --print "$CORCEPT_TASK_PROMPT"'
    corcept_cmd = 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'
    plugin_dir = str(PLUGIN.resolve())

    # 3) Paired mini-SWE (all tasks)
    run(
        [
            str(PYTHON), "-m", "corcept_eval", "run-pair",
            "--suite", "mini-swe",
            "--baseline-cmd", baseline_cmd,
            "--corcept-cmd", corcept_cmd,
            "--plugin-dir", plugin_dir,
            "--out", str(OUT / "paired-mini-swe"),
        ],
        cwd=EVAL,
    )

    # 4) Paired mini-reasoning (all tasks)
    run(
        [
            str(PYTHON), "-m", "corcept_eval", "run-pair",
            "--suite", "mini-reasoning",
            "--baseline-cmd", baseline_cmd,
            "--corcept-cmd", corcept_cmd,
            "--plugin-dir", plugin_dir,
            "--out", str(OUT / "paired-mini-reasoning"),
        ],
        cwd=EVAL,
    )

    # 5) Harbor terminal-bench smoke (oracle reference + claude-code baseline/corcept)
    harbor_jobs = OUT / "harbor"
    harbor_jobs.mkdir(exist_ok=True)
    common = [
        "harbor", "run",
        "--dataset", "terminal-bench@2.0",
        "--n-tasks", "3",
        "--jobs-dir", str(harbor_jobs),
    ]
    run(common + ["--job-name", "terminal-bench-oracle", "--agent", "oracle"])
    run(common + ["--job-name", "terminal-bench-baseline", "--agent", "claude-code"])
    # Harbor's claude-code agent does not yet pass --plugin-dir; CORCEPT plugin
    # comparison for terminal workflows is covered by paired mini-SWE + guard suites.

    # Aggregate
    guard = load_json(OUT / "guard-v2" / "corcept-benchmark-results-v2.json")
    local = load_json(OUT / "local" / "results.json")
    mini_swe = load_json(OUT / "paired-mini-swe" / "results.json")
    mini_reason = load_json(OUT / "paired-mini-reasoning" / "results.json")
    preflight = load_json(OUT / "preflight.json")

    harbor_summary = {}
    for job in ["terminal-bench-oracle", "terminal-bench-baseline"]:
        job_dir = harbor_jobs / job
        if not job_dir.exists():
            harbor_summary[job] = {"status": "missing"}
            continue
        result_files = list(job_dir.rglob("result.json")) + list(job_dir.rglob("results.json"))
        if result_files:
            try:
                harbor_summary[job] = load_json(result_files[0])
            except Exception as exc:
                harbor_summary[job] = {"status": "error", "detail": str(exc)}
        else:
            harbor_summary[job] = {"status": "no_result_file", "path": str(job_dir)}

    summary = {
        "generated_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "guard_benchmark_v2": {
            "baseline_risk_intervention_rate": guard.get("baseline", {}).get("risk_intervention_rate"),
            "original_corcept_risk_intervention_rate": guard.get("original_corcept", {}).get("risk_intervention_rate"),
            "hardened_corcept_risk_intervention_rate": guard.get("hardened_corcept", {}).get("risk_intervention_rate"),
            "baseline_residual_unsafe_allow_rate": guard.get("baseline", {}).get("residual_unsafe_allow_rate"),
            "hardened_residual_unsafe_allow_rate": guard.get("hardened_corcept", {}).get("residual_unsafe_allow_rate"),
            "hardened_exact_policy_accuracy": guard.get("hardened_corcept", {}).get("exact_policy_accuracy"),
        },
        "local_deterministic": local.get("summaries", {}),
        "paired_mini_swe": mini_swe.get("summary", {}),
        "paired_mini_reasoning": mini_reason.get("summary", {}),
        "external_preflight_available": {
            name: meta.get("available") for name, meta in preflight.items() if isinstance(meta, dict)
        },
        "harbor_terminal_bench": harbor_summary,
    }

    summary_path = OUT / "FULL-RESULTS.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    md = [
        "# CORCEPT Full Benchmark Results",
        "",
        f"Generated: {summary['finished_at']}",
        "",
        "## Guard benchmark v2 (no-tool baseline vs CORCEPT)",
        "",
        "| Mode | Risk intervention | Residual unsafe allow | Exact policy accuracy |",
        "|---|---:|---:|---:|",
    ]
    for label, key in [
        ("Without CORCEPT", "baseline"),
        ("CORCEPT v0.1", "original_corcept"),
        ("CORCEPT v0.1.1 hardened", "hardened_corcept"),
    ]:
        block = guard.get(key, {})
        md.append(
            f"| {label} | {block.get('risk_intervention_rate', 0)*100:.1f}% | "
            f"{block.get('residual_unsafe_allow_rate', 0)*100:.1f}% | "
            f"{block.get('exact_policy_accuracy', 0)*100:.1f}% |"
        )

    md.extend(
        [
            "",
            "## Local deterministic eval (CORCEPT guard)",
            "",
            "| Suite | Passed | Total | Accuracy |",
            "|---|---:|---:|---:|",
        ]
    )
    for suite, stats in local.get("summaries", {}).items():
        if isinstance(stats, dict) and "total" in stats:
            md.append(
                f"| {suite} | {stats.get('passed', 0)} | {stats.get('total', 0)} | {stats.get('accuracy', 0)*100:.1f}% |"
            )

    md.extend(
        [
            "",
            "## Paired mini-SWE (Claude baseline vs CORCEPT plugin)",
            "",
            f"- Baseline pass rate: {mini_swe.get('summary', {}).get('baseline_pass_rate', 0)*100:.1f}%",
            f"- CORCEPT pass rate: {mini_swe.get('summary', {}).get('corcept_pass_rate', 0)*100:.1f}%",
            f"- Delta: {mini_swe.get('summary', {}).get('delta', 0)*100:+.1f}%",
            "",
            "## Paired mini-reasoning (Claude baseline vs CORCEPT plugin)",
            "",
            f"- Baseline pass rate: {mini_reason.get('summary', {}).get('baseline_pass_rate', 0)*100:.1f}%",
            f"- CORCEPT pass rate: {mini_reason.get('summary', {}).get('corcept_pass_rate', 0)*100:.1f}%",
            f"- Delta: {mini_reason.get('summary', {}).get('delta', 0)*100:+.1f}%",
            "",
            "## Harbor terminal-bench@2.0 (3 tasks)",
            "",
            f"See `{harbor_jobs}` for raw job output.",
            "",
        ]
    )

    report_path = OUT / "FULL-RESULTS.md"
    report_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\nWrote {summary_path}")
    print(f"Wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
