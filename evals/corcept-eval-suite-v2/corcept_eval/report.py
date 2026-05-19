from __future__ import annotations
import json
from pathlib import Path


def pct(x): return f"{100*x:.1f}%"

def write_report(input_path: Path, out: Path):
    data=json.loads(input_path.read_text(encoding="utf-8"))
    lines=[]
    lines.append("# CORCEPT Eval Report")
    lines.append("")
    lines.append(f"Source: `{input_path}`")
    lines.append("")
    if "summaries" in data:
        lines.append("## Local deterministic results")
        lines.append("")
        lines.append("| Suite | Total | Passed | Failed | Accuracy |")
        lines.append("|---|---:|---:|---:|---:|")
        for name, s in data["summaries"].items():
            if "total" in s:
                lines.append(f"| {name} | {s['total']} | {s['passed']} | {s['failed']} | {pct(s['accuracy'])} |")
            else:
                lines.append(f"| {name} | {s.get('tasks','')} | oracle {s.get('oracle_passed','')} | noop {s.get('noop_passed','')} | oracle {pct(s.get('oracle_expected_pass_rate',0))} |")
        lat=data.get("latency",{})
        if lat:
            lines.append("")
            lines.append("## Guard latency")
            lines.append("")
            lines.append(f"Calls: `{lat.get('calls')}`; median `{lat.get('median_us'):.3f} µs`; p95 `{lat.get('p95_us'):.3f} µs`.")
        lines.append("")
        lines.append("## Interpretation")
        lines.append("")
        lines.append("The local benchmark is a policy and harness correctness benchmark, not a model-reasoning benchmark. It verifies that CORCEPT's deterministic guard, stop, memory, and doctrine rules classify the current fixture set correctly, and that the mini-SWE harness can distinguish failing initial states from passing oracle patches.")
    elif data.get("suite") in {"paired-mini-swe", "paired-mini-code-reasoning"}:
        s=data["summary"]
        title = "Paired mini-SWE results" if data.get("suite") == "paired-mini-swe" else "Paired mini code-reasoning results"
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"Baseline pass rate: **{pct(s['baseline_pass_rate'])}**")
        lines.append(f"CORCEPT pass rate: **{pct(s['corcept_pass_rate'])}**")
        lines.append(f"Delta: **{pct(s['delta'])}**")
    lines.append("")
    lines.append("## External benchmark status")
    lines.append("")
    lines.append("SWE-Skills-Bench, SWE-bench, Terminal-Bench, LiveCodeBench, BigCodeBench, EvalPlus, CRUXEval, BFCL, tau-bench, MLE-bench, RepoBench and CodeClash adapters are included but require external infrastructure: Docker where applicable, the benchmark package/checkouts, and an agent/model command. They were not executed in this sandbox.")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines)+"\n", encoding="utf-8")
