from __future__ import annotations
import json, os, shutil, subprocess, time, shlex
from pathlib import Path
from .mini_swe import TASKS, make_task_repo, run_pytest
from .mini_reasoning import run_pair_reasoning


def run_agent_command(cmd: str, repo: Path, task: dict, mode: str, plugin_dir: str) -> dict:
    env=os.environ.copy()
    env.update({
        "CORCEPT_TASK_ID": task["id"],
        "CORCEPT_TASK_PROMPT": task["prompt"],
        "CORCEPT_MODE": mode,
        "CORCEPT_REPO": str(repo),
        "CORCEPT_PLUGIN_DIR": plugin_dir,
    })
    t0=time.time()
    proc=subprocess.run(cmd, cwd=repo, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=900)
    return {"exit_code":proc.returncode, "duration_s":time.time()-t0, "output":proc.stdout[-8000:]}


def run_pair(suite_root: Path, out: Path, baseline_cmd: str, corcept_cmd: str, plugin_dir: str = "", limit: int | None = None, suite: str = "mini-swe") -> Path:
    if suite == "mini-reasoning":
        return run_pair_reasoning(out=out, baseline_cmd=baseline_cmd, corcept_cmd=corcept_cmd, plugin_dir=plugin_dir, limit=limit)
    out.mkdir(parents=True, exist_ok=True)
    rows=[]
    tasks=TASKS[:limit] if limit else TASKS
    for task in tasks:
        for mode, cmd in [("baseline", baseline_cmd), ("corcept", corcept_cmd)]:
            repo=make_task_repo(task, out / "repos" / mode)
            agent=run_agent_command(cmd, repo, task, mode, plugin_dir)
            tests=run_pytest(repo)
            rows.append({"task_id":task["id"], "mode":mode, "agent":agent, "tests":tests, "passed":tests["passed"]})
    def rate(mode):
        subset=[r for r in rows if r["mode"]==mode]
        return sum(1 for r in subset if r["passed"])/len(subset) if subset else 0
    results={"suite":"paired-mini-swe", "rows":rows, "summary":{"tasks":len(tasks), "baseline_pass_rate":rate("baseline"), "corcept_pass_rate":rate("corcept"), "delta":rate("corcept")-rate("baseline")}}
    result_path=out/"results.json"
    result_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return result_path
