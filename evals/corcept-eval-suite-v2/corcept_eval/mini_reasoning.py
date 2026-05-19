from __future__ import annotations
import json, os, subprocess, time
from pathlib import Path

TASKS = [
    {
        "id": "reason_001_output_prediction",
        "kind": "output_prediction",
        "prompt": "Given Python code `def f(xs):\n    out=[]\n    for x in xs:\n        if x % 2:\n            out.append(x*3)\n        else:\n            out.append(x//2)\n    return out` and input `[1,2,5,8]`, return only JSON {\"answer\": ...} with the function output.",
        "expected": [3,1,15,4],
    },
    {
        "id": "reason_002_edge_case",
        "kind": "output_prediction",
        "prompt": "Given Python code `def g(s):\n    return ''.join(sorted(set(s.lower())))` and input `\"BaNaNa!\"`, return only JSON {\"answer\": ...} with the output string.",
        "expected": "!abn",
    },
    {
        "id": "reason_003_bug_localization",
        "kind": "bug_localization",
        "prompt": "A function should return the first duplicate item preserving order. Code: `def first_dup(xs):\n    seen=set()\n    for x in xs:\n        if x in seen:\n            return x\n        seen.add(xs)\n    return None`. Return only JSON {\"answer\": \"...\"} naming the minimal buggy expression.",
        "expected": "seen.add(xs)",
    },
    {
        "id": "reason_004_invariant",
        "kind": "invariant",
        "prompt": "Code: `def clamp(x, lo, hi): return max(lo, min(x, hi))`. Return only JSON {\"answer\": true/false} answering whether output is always between lo and hi when lo <= hi.",
        "expected": True,
    },
]

def parse_answer(text: str):
    candidates: list[str] = []
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        depth = 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[i : j + 1])
                    break
    for raw in reversed(candidates):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "answer" in obj:
            return obj["answer"]
    return None

def run_agent(cmd: str, task: dict, mode: str, plugin_dir: str, out: Path, *, timeout_s: int = 300) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({
        "CORCEPT_TASK_ID": task["id"],
        "CORCEPT_TASK_PROMPT": task["prompt"],
        "CORCEPT_MODE": mode,
        "CORCEPT_PLUGIN_DIR": plugin_dir,
    })
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=out,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=timeout_s,
        )
        output = proc.stdout
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + "\n[timeout]"
        exit_code = 124
        timed_out = True
    answer = parse_answer(output)
    return {
        "exit_code": exit_code,
        "duration_s": time.time() - t0,
        "output": output[-4000:],
        "answer": answer,
        "timed_out": timed_out,
    }

def run_pair_reasoning(out: Path, baseline_cmd: str, corcept_cmd: str, plugin_dir: str = "", limit: int | None = None) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    tasks = TASKS[:limit] if limit else TASKS
    for task in tasks:
        for mode, cmd in [("baseline", baseline_cmd), ("corcept", corcept_cmd)]:
            agent = run_agent(cmd, task, mode, plugin_dir, out)
            passed = agent["answer"] == task["expected"]
            rows.append({"task_id": task["id"], "kind": task["kind"], "mode": mode, "expected": task["expected"], "agent": agent, "passed": passed})
    def rate(mode: str) -> float:
        subset = [r for r in rows if r["mode"] == mode]
        return sum(1 for r in subset if r["passed"]) / len(subset) if subset else 0.0
    results = {"suite": "paired-mini-code-reasoning", "rows": rows, "summary": {"tasks": len(tasks), "baseline_pass_rate": rate("baseline"), "corcept_pass_rate": rate("corcept"), "delta": rate("corcept") - rate("baseline")}}
    result_path = out / "results.json"
    result_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return result_path
