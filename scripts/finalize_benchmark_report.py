#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "full-benchmark"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def harbor_job_summary(jobs_dir: Path, job_name: str) -> dict:
    job_dir = jobs_dir / job_name
    if not job_dir.exists():
        return {"status": "missing"}
    for pattern in ("result.json", "results.json", "summary.json"):
        matches = list(job_dir.rglob(pattern))
        if matches:
            try:
                data = load(matches[0])
                return {"status": "ok", "path": str(matches[0]), "data": data}
            except Exception as exc:
                return {"status": "parse_error", "detail": str(exc)}
    # harbor often writes job-level artifacts under dated folders
    children = [p.name for p in job_dir.iterdir()] if job_dir.is_dir() else []
    return {"status": "no_result_file", "children": children[:20]}


def main() -> None:
    guard = load(OUT / "guard-v2" / "corcept-benchmark-results-v2.json")
    local = load(OUT / "local" / "results.json")
    mini_swe = load(OUT / "paired-mini-swe" / "results.json")
    preflight = load(OUT / "preflight.json")

    mini_reason_path = OUT / "paired-mini-reasoning" / "results.json"
    mini_reason = load(mini_reason_path) if mini_reason_path.exists() else None

    harbor_dir = OUT / "harbor"
    harbor = {
        "terminal-bench-oracle": harbor_job_summary(harbor_dir, "terminal-bench-oracle"),
        "terminal-bench-baseline": harbor_job_summary(harbor_dir, "terminal-bench-baseline"),
    }

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "guard_benchmark_v2": {
            "without_corcept": {
                "risk_intervention_rate": guard["baseline"]["risk_intervention_rate"],
                "residual_unsafe_allow_rate": guard["baseline"]["residual_unsafe_allow_rate"],
                "exact_policy_accuracy": guard["baseline"]["exact_policy_accuracy"],
            },
            "corcept_v0_1": {
                "risk_intervention_rate": guard["corcept_v0_1_original"]["risk_intervention_rate"],
                "residual_unsafe_allow_rate": guard["corcept_v0_1_original"]["residual_unsafe_allow_rate"],
                "exact_policy_accuracy": guard["corcept_v0_1_original"]["exact_policy_accuracy"],
            },
            "corcept_v0_1_1_hardened": {
                "risk_intervention_rate": guard["corcept_v0_1_1_hardened"]["risk_intervention_rate"],
                "residual_unsafe_allow_rate": guard["corcept_v0_1_1_hardened"]["residual_unsafe_allow_rate"],
                "exact_policy_accuracy": guard["corcept_v0_1_1_hardened"]["exact_policy_accuracy"],
            },
        },
        "local_deterministic": local.get("summaries", {}),
        "paired_mini_swe": mini_swe.get("summary", {}),
        "paired_mini_reasoning": mini_reason.get("summary") if mini_reason else None,
        "harbor_terminal_bench": harbor,
        "external_preflight": {
            name: meta.get("available")
            for name, meta in preflight.items()
            if isinstance(meta, dict) and "available" in meta
        },
    }

    (OUT / "FULL-RESULTS.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# CORCEPT Full Benchmark Results",
        "",
        f"Updated: {summary['generated_at']}",
        "",
        "## 1. Guard benchmark v2 (without vs CORCEPT)",
        "",
        "| Mode | Risk intervention | Residual unsafe allow | Policy accuracy |",
        "|---|---:|---:|---:|",
    ]
    for label, key in [
        ("Without CORCEPT", "baseline"),
        ("CORCEPT v0.1", "corcept_v0_1_original"),
        ("CORCEPT v0.1.1 hardened", "corcept_v0_1_1_hardened"),
    ]:
        b = guard[key]
        lines.append(
            f"| {label} | {b['risk_intervention_rate']*100:.1f}% | "
            f"{b['residual_unsafe_allow_rate']*100:.1f}% | {b['exact_policy_accuracy']*100:.1f}% |"
        )

    lines += [
        "",
        "## 2. Local deterministic eval (CORCEPT guard)",
        "",
        "| Suite | Passed | Total | Accuracy |",
        "|---|---:|---:|---:|",
    ]
    for suite, stats in local.get("summaries", {}).items():
        if isinstance(stats, dict) and "total" in stats:
            lines.append(
                f"| {suite} | {stats.get('passed', stats.get('oracle_passed', '-'))} | "
                f"{stats.get('total', stats.get('tasks', '-'))} | "
                f"{stats.get('accuracy', stats.get('oracle_expected_pass_rate', 0))*100:.1f}% |"
            )

    ms = mini_swe.get("summary", {})
    lines += [
        "",
        "## 3. Paired mini-SWE (Claude baseline vs CORCEPT plugin)",
        "",
        f"- Tasks: {ms.get('tasks', 3)}",
        f"- Baseline pass rate: **{ms.get('baseline_pass_rate', 0)*100:.1f}%**",
        f"- CORCEPT pass rate: **{ms.get('corcept_pass_rate', 0)*100:.1f}%**",
        f"- Delta: {ms.get('delta', 0)*100:+.1f}%",
        "",
        "| Task | Baseline | CORCEPT |",
        "|---|---|---|",
    ]
    rows = {r["task_id"]: {} for r in mini_swe.get("rows", [])}
    for r in mini_swe.get("rows", []):
        rows[r["task_id"]][r["mode"]] = "PASS" if r["passed"] else "FAIL"
    for tid, modes in rows.items():
        lines.append(f"| {tid} | {modes.get('baseline', '-')} | {modes.get('corcept', '-')} |")

    if mini_reason:
        mr = mini_reason.get("summary", {})
        lines += [
            "",
            "## 4. Paired mini-reasoning (Claude baseline vs CORCEPT plugin)",
            "",
            f"- Baseline pass rate: **{mr.get('baseline_pass_rate', 0)*100:.1f}%**",
            f"- CORCEPT pass rate: **{mr.get('corcept_pass_rate', 0)*100:.1f}%**",
            f"- Delta: {mr.get('delta', 0)*100:+.1f}%",
            "",
            "| Task | Baseline | CORCEPT |",
            "|---|---|---|",
        ]
        rmap: dict[str, dict] = {}
        for r in mini_reason.get("rows", []):
            rmap.setdefault(r["task_id"], {})[r["mode"]] = "PASS" if r["passed"] else "FAIL"
        for tid, modes in rmap.items():
            lines.append(f"| {tid} | {modes.get('baseline', '-')} | {modes.get('corcept', '-')} |")
    else:
        lines += ["", "## 4. Paired mini-reasoning", "", "_Pending — run in progress._"]

    lines += [
        "",
        "## 5. Harbor terminal-bench@2.0 (3 tasks)",
        "",
    ]
    for job, meta in harbor.items():
        lines.append(f"- **{job}**: {meta.get('status')}")

    lines += [
        "",
        "## Raw artifacts",
        "",
        f"- `{OUT / 'guard-v2'}`",
        f"- `{OUT / 'local'}`",
        f"- `{OUT / 'paired-mini-swe'}`",
        f"- `{OUT / 'paired-mini-reasoning'}`",
        f"- `{OUT / 'harbor'}`",
        "",
    ]
    (OUT / "FULL-RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT / 'FULL-RESULTS.md'}")


if __name__ == "__main__":
    main()
