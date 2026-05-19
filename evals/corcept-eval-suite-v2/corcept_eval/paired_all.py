from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import guard as guard_mod
from .local import run_local, _pretool_cases, run_stop_cases
from .mini_reasoning import TASKS as REASON_TASKS, parse_answer, run_agent as run_reason_agent
from .mini_swe import TASKS as SWE_TASKS, make_task_repo, run_pytest
from .pair import run_agent_command
from .receipts import ReceiptWriter, utc_now
from .report import write_report


BASELINE_CMD = 'claude --print "$CORCEPT_TASK_PROMPT"'
CORCEPT_CMD = 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'


def run_guard_benchmark(repo_root: Path, out: Path) -> dict:
    script = repo_root / "benchmarks" / "run_corcept_benchmark_v2.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--out", str(out)],
        cwd=repo_root,
        text=True,
        capture_output=True,
        timeout=600,
    )
    results_path = out / "corcept-benchmark-results-v2.json"
    data = json.loads(results_path.read_text(encoding="utf-8")) if results_path.exists() else {}
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "results_path": str(results_path),
        "summary": {
            "baseline_unsafe_allow_rate": data.get("baseline", {}).get("residual_unsafe_allow_rate"),
            "hardened_unsafe_allow_rate": data.get("corcept_v0_1_1_hardened", {}).get("residual_unsafe_allow_rate"),
            "hardened_policy_accuracy": data.get("corcept_v0_1_1_hardened", {}).get("exact_policy_accuracy"),
        },
    }


def run_pretool_live_paired(rw: ReceiptWriter, bench: dict) -> dict:
    rows = []
    for case in _pretool_cases():
        event = {"tool": case["tool"], **case["input"]}
        baseline = {"decision": "allow", "reason": "No CORCEPT hook installed.", "category": "unprotected"}
        corcept = guard_mod.classify_tool(case["tool"], case["input"])
        row = {
            "id": case["id"],
            "expected": case["expected"],
            "baseline": baseline["decision"],
            "corcept": corcept.decision,
            "baseline_ok": baseline["decision"] == case["expected"],
            "corcept_ok": corcept.decision == case["expected"],
        }
        rows.append(row)
        rw.write_receipt(
            bench,
            mode="baseline",
            case_id=case["id"],
            command=f"noop-pretool {case['tool']}",
            payload={"decision": baseline["decision"], "expected": case["expected"], "passed": row["baseline_ok"]},
        )
        rw.write_receipt(
            bench,
            mode="corcept",
            case_id=case["id"],
            command=f"corcept-guard {case['tool']}",
            payload={
                "decision": corcept.decision,
                "reason": corcept.reason,
                "expected": case["expected"],
                "passed": row["corcept_ok"],
            },
        )
    baseline_acc = sum(1 for r in rows if r["baseline_ok"]) / len(rows)
    corcept_acc = sum(1 for r in rows if r["corcept_ok"]) / len(rows)
    risky = [r for r in rows if r["expected"] in {"deny", "ask", "block"}]
    baseline_unsafe_allow = sum(1 for r in risky if r["baseline"] == "allow") / len(risky)
    corcept_unsafe_allow = sum(1 for r in risky if r["corcept"] == "allow") / len(risky)
    summary = {
        "cases": len(rows),
        "baseline_policy_accuracy": baseline_acc,
        "corcept_policy_accuracy": corcept_acc,
        "delta_accuracy": corcept_acc - baseline_acc,
        "baseline_unsafe_allow_rate": baseline_unsafe_allow,
        "corcept_unsafe_allow_rate": corcept_unsafe_allow,
    }
    out = rw.run_root / "pretool-live"
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "results.json"
    result_path.write_text(json.dumps({"suite": "pretool-live-paired", "rows": rows, "summary": summary}, indent=2), encoding="utf-8")
    rw.write_suite_result(bench, result_path, summary)
    return summary


def run_mini_swe_paired(rw: ReceiptWriter, bench: dict, plugin_dir: str, limit: int | None) -> dict:
    out = rw.run_root / "paired-mini-swe"
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    tasks = SWE_TASKS[:limit] if limit else SWE_TASKS
    for task in tasks:
        for mode, cmd in [("baseline", BASELINE_CMD), ("corcept", CORCEPT_CMD)]:
            repo = make_task_repo(task, out / "repos" / mode / task["id"])
            agent = run_agent_command(cmd, repo, task, mode, plugin_dir)
            tests = run_pytest(repo)
            passed = tests["passed"]
            rows.append({"task_id": task["id"], "mode": mode, "agent": agent, "tests": tests, "passed": passed})
            rw.write_receipt(
                bench,
                mode=mode,
                case_id=task["id"],
                command=cmd,
                payload={"passed": passed, "tests": tests, "duration_s": agent["duration_s"], "exit_code": agent["exit_code"]},
                stdout=agent.get("output", ""),
            )
    def rate(mode: str) -> float:
        subset = [r for r in rows if r["mode"] == mode]
        return sum(1 for r in subset if r["passed"]) / len(subset) if subset else 0.0
    summary = {
        "tasks": len(tasks),
        "baseline_pass_rate": rate("baseline"),
        "corcept_pass_rate": rate("corcept"),
        "delta": rate("corcept") - rate("baseline"),
        "baseline_mean_duration_s": _mean([r["agent"]["duration_s"] for r in rows if r["mode"] == "baseline"]),
        "corcept_mean_duration_s": _mean([r["agent"]["duration_s"] for r in rows if r["mode"] == "corcept"]),
    }
    result_path = out / "results.json"
    result_path.write_text(json.dumps({"suite": "paired-mini-swe", "rows": rows, "summary": summary}, indent=2), encoding="utf-8")
    write_report(result_path, out / "report.md")
    rw.write_suite_result(bench, result_path, summary)
    return summary


def run_mini_reasoning_paired(rw: ReceiptWriter, bench: dict, plugin_dir: str, limit: int | None) -> dict:
    out = rw.run_root / "paired-mini-reasoning"
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    tasks = REASON_TASKS[:limit] if limit else REASON_TASKS
    for task in tasks:
        for mode, cmd in [("baseline", BASELINE_CMD), ("corcept", CORCEPT_CMD)]:
            agent = run_reason_agent(cmd, task, mode, plugin_dir, out / "runs" / task["id"] / mode)
            passed = agent["answer"] == task["expected"]
            rows.append(
                {
                    "task_id": task["id"],
                    "kind": task["kind"],
                    "mode": mode,
                    "expected": task["expected"],
                    "agent": agent,
                    "passed": passed,
                }
            )
            rw.write_receipt(
                bench,
                mode=mode,
                case_id=task["id"],
                command=cmd,
                payload={
                    "passed": passed,
                    "expected": task["expected"],
                    "answer": agent.get("answer"),
                    "duration_s": agent["duration_s"],
                    "exit_code": agent["exit_code"],
                },
                stdout=agent.get("output", ""),
            )
    def rate(mode: str) -> float:
        subset = [r for r in rows if r["mode"] == mode]
        return sum(1 for r in subset if r["passed"]) / len(subset) if subset else 0.0
    summary = {
        "tasks": len(tasks),
        "baseline_pass_rate": rate("baseline"),
        "corcept_pass_rate": rate("corcept"),
        "delta": rate("corcept") - rate("baseline"),
    }
    result_path = out / "results.json"
    result_path.write_text(json.dumps({"suite": "paired-mini-code-reasoning", "rows": rows, "summary": summary}, indent=2), encoding="utf-8")
    write_report(result_path, out / "report.md")
    rw.write_suite_result(bench, result_path, summary)
    return summary


def run_stop_gate_paired(rw: ReceiptWriter, bench: dict) -> dict:
    rows = []
    for case in run_stop_cases():
        baseline = "allow"
        corcept = case["actual"]
        rows.append(
            {
                "id": case["id"],
                "expected": case["expected"],
                "baseline": baseline,
                "corcept": corcept,
                "baseline_ok": baseline == case["expected"],
                "corcept_ok": corcept == case["expected"],
            }
        )
        rw.write_receipt(
            bench,
            mode="baseline",
            case_id=case["id"],
            command="noop-stop-gate",
            payload={"decision": baseline, "expected": case["expected"], "passed": baseline == case["expected"]},
        )
        rw.write_receipt(
            bench,
            mode="corcept",
            case_id=case["id"],
            command="corcept-stop-gate",
            payload={"decision": corcept, "expected": case["expected"], "passed": corcept == case["expected"]},
        )
    summary = {
        "cases": len(rows),
        "baseline_accuracy": sum(1 for r in rows if r["baseline_ok"]) / len(rows),
        "corcept_accuracy": sum(1 for r in rows if r["corcept_ok"]) / len(rows),
    }
    out = rw.run_root / "stop-gate-paired"
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "results.json"
    result_path.write_text(json.dumps({"suite": "stop-gate-paired", "rows": rows, "summary": summary}, indent=2), encoding="utf-8")
    rw.write_suite_result(bench, result_path, summary)
    return summary


def run_swe_bench_mini_prompt_paired(rw: ReceiptWriter, bench: dict, plugin_dir: str, limit: int = 3) -> dict:
    from datasets import load_dataset

    ds = load_dataset("MariusHobbhahn/swe-bench-verified-mini", split="test")
    rows = []
    out = rw.run_root / "swe-bench-mini-prompt-paired"
    out.mkdir(parents=True, exist_ok=True)
    for i, row in enumerate(ds):
        if i >= limit:
            break
        instance_id = row["instance_id"]
        prompt = (
            f"You are fixing GitHub issue {instance_id} in {row['repo']}.\n"
            f"Problem:\n{row['problem_statement'][:4000]}\n\n"
            "Return a concise unified diff patch only."
        )
        task = {"id": instance_id, "prompt": prompt}
        for mode, cmd in [("baseline", BASELINE_CMD), ("corcept", CORCEPT_CMD)]:
            t0 = time.time()
            env_task = {**task, "prompt": prompt}
            agent = run_reason_agent(cmd, env_task, mode, plugin_dir, out / "runs" / instance_id / mode, timeout_s=600)
            has_patch = "diff --git" in agent.get("output", "") or "@@" in agent.get("output", "")
            receipt_row = {
                "instance_id": instance_id,
                "repo": row["repo"],
                "mode": mode,
                "has_patch_like_output": has_patch,
                "duration_s": agent["duration_s"],
                "exit_code": agent["exit_code"],
            }
            rows.append(receipt_row)
            rw.write_receipt(
                bench,
                mode=mode,
                case_id=instance_id,
                command=cmd,
                payload=receipt_row,
                stdout=agent.get("output", ""),
            )
    def rate(mode: str) -> float:
        subset = [r for r in rows if r["mode"] == mode]
        return sum(1 for r in subset if r["has_patch_like_output"]) / len(subset) if subset else 0.0
    summary = {
        "instances": limit,
        "baseline_patch_like_rate": rate("baseline"),
        "corcept_patch_like_rate": rate("corcept"),
        "delta": rate("corcept") - rate("baseline"),
        "note": "Prompt-level paired run; not full SWE-bench container verification.",
    }
    result_path = out / "results.json"
    result_path.write_text(json.dumps({"suite": "swe-bench-mini-prompt-paired", "rows": rows, "summary": summary}, indent=2), encoding="utf-8")
    rw.write_suite_result(bench, result_path, summary)
    return summary


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def run_all_paired(
    repo_root: Path,
    run_root: Path,
    *,
    plugin_dir: str,
    skip_agent: bool = False,
    skip_swe_mini: bool = False,
    skip_deterministic: bool = False,
    skip_mini_swe: bool = False,
    skip_mini_reasoning: bool = False,
    limit: int | None = None,
) -> Path:
    rw = ReceiptWriter(run_root, repo_root)
    aggregate: dict[str, Any] = {"started_at": utc_now(), "benchmarks": {}}

    existing_summary = run_root / "SUMMARY.json"
    if skip_deterministic and existing_summary.exists():
        prior = json.loads(existing_summary.read_text(encoding="utf-8"))
        aggregate["benchmarks"] = dict(prior.get("benchmarks", {}))
        aggregate["started_at"] = prior.get("started_at", aggregate["started_at"])

    if not skip_deterministic:
        # Guard v2 proxy benchmark
        b = rw.begin_benchmark(
            "guard-v2",
            baseline_label="without_corcept",
            corcept_label="corcept_v0_1_1_hardened",
            meta={"type": "deterministic-proxy"},
        )
        guard_out = run_root / "guard-v2"
        guard_out.mkdir(parents=True, exist_ok=True)
        guard_summary = run_guard_benchmark(repo_root, guard_out)
        rw.write_suite_result(b, guard_out / "corcept-benchmark-results-v2.json", guard_summary["summary"])
        aggregate["benchmarks"]["guard-v2"] = guard_summary["summary"]

        # Local eval (CORCEPT correctness receipt)
        local_out = run_root / "local-deterministic"
        run_local(repo_root / "evals" / "corcept-eval-suite-v2", local_out)
        local_data = json.loads((local_out / "results.json").read_text(encoding="utf-8"))
        b = rw.begin_benchmark("local-deterministic", baseline_label="n/a", corcept_label="corcept_guard", meta={"type": "corcept-only"})
        rw.write_suite_result(b, local_out / "results.json", local_data.get("summaries", {}))
        aggregate["benchmarks"]["local-deterministic"] = local_data.get("summaries", {})

        # PreTool live paired
        b = rw.begin_benchmark("pretool-live", baseline_label="without_corcept", corcept_label="corcept_guard")
        aggregate["benchmarks"]["pretool-live"] = run_pretool_live_paired(rw, b)

        # Stop gate paired
        b = rw.begin_benchmark("stop-gate", baseline_label="without_corcept", corcept_label="corcept_stop_gate")
        aggregate["benchmarks"]["stop-gate"] = run_stop_gate_paired(rw, b)

    if not skip_agent:
        if not skip_mini_swe:
            b = rw.begin_benchmark("mini-swe", baseline_label="claude_no_plugin", corcept_label="claude_corcept_plugin")
            aggregate["benchmarks"]["mini-swe"] = run_mini_swe_paired(rw, b, plugin_dir, limit)
        elif (run_root / "paired-mini-swe" / "results.json").exists():
            mini_swe_data = json.loads((run_root / "paired-mini-swe" / "results.json").read_text(encoding="utf-8"))
            aggregate["benchmarks"]["mini-swe"] = mini_swe_data.get("summary", {})

        b = rw.begin_benchmark("mini-reasoning", baseline_label="claude_no_plugin", corcept_label="claude_corcept_plugin")
        if not skip_mini_reasoning:
            aggregate["benchmarks"]["mini-reasoning"] = run_mini_reasoning_paired(rw, b, plugin_dir, limit)
        elif (run_root / "paired-mini-reasoning" / "results.json").exists():
            reason_data = json.loads((run_root / "paired-mini-reasoning" / "results.json").read_text(encoding="utf-8"))
            aggregate["benchmarks"]["mini-reasoning"] = reason_data.get("summary", {})

        if not skip_swe_mini:
            b = rw.begin_benchmark(
                "swe-bench-mini-prompt",
                baseline_label="claude_no_plugin",
                corcept_label="claude_corcept_plugin",
                meta={"instances": limit or 3},
            )
            aggregate["benchmarks"]["swe-bench-mini-prompt"] = run_swe_bench_mini_prompt_paired(
                rw, b, plugin_dir, limit=limit or 3
            )

    aggregate["finished_at"] = utc_now()
    manifest = rw.finalize(run_root / "SUMMARY.json", aggregate)
    _write_with_vs_without_md(run_root, aggregate)
    return manifest


def _write_with_vs_without_md(run_root: Path, aggregate: dict) -> None:
    lines = [
        "# CORCEPT With vs Without — Full Receipt Run",
        "",
        f"Generated: {aggregate.get('finished_at', utc_now())}",
        "",
        "Receipts: `receipts/<benchmark>/<mode>/<case_id>/`",
        "Manifest: `MANIFEST.json`",
        "",
        "## Summary",
        "",
        "| Benchmark | Without | With CORCEPT | Delta / note |",
        "|---|---:|---:|---|",
    ]
    for name, data in aggregate.get("benchmarks", {}).items():
        if "baseline_pass_rate" in data:
            lines.append(
                f"| {name} | {data['baseline_pass_rate']*100:.1f}% | {data['corcept_pass_rate']*100:.1f}% | {data.get('delta',0)*100:+.1f}% |"
            )
        elif "baseline_policy_accuracy" in data:
            lines.append(
                f"| {name} | acc {data['baseline_policy_accuracy']*100:.1f}%, unsafe allow {data['baseline_unsafe_allow_rate']*100:.1f}% | "
                f"acc {data['corcept_policy_accuracy']*100:.1f}%, unsafe allow {data['corcept_unsafe_allow_rate']*100:.1f}% | "
                f"Δacc {data.get('delta_accuracy',0)*100:+.1f}% |"
            )
        elif "baseline_unsafe_allow_rate" in data:
            lines.append(
                f"| {name} | unsafe allow {data['baseline_unsafe_allow_rate']*100:.1f}% | "
                f"unsafe allow {data['hardened_unsafe_allow_rate']*100:.1f}% | hardened acc {data.get('hardened_policy_accuracy',0)*100:.1f}% |"
            )
        elif "baseline_accuracy" in data:
            lines.append(
                f"| {name} | {data['baseline_accuracy']*100:.1f}% | {data['corcept_accuracy']*100:.1f}% | stop gate |"
            )
        elif "baseline_patch_like_rate" in data:
            lines.append(
                f"| {name} | patch-like {data['baseline_patch_like_rate']*100:.1f}% | "
                f"patch-like {data['corcept_patch_like_rate']*100:.1f}% | prompt-level, not verified |"
            )
        else:
            lines.append(f"| {name} | — | CORCEPT-only | governance receipt |")
    (run_root / "WITH-VS-WITHOUT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
