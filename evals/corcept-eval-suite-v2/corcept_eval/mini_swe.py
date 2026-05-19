from __future__ import annotations
import json, os, shutil, subprocess, sys, time
from pathlib import Path

TASKS = [
    {
        "id":"mini_001_slugify_unicode",
        "prompt":"Fix slugify so accented Latin letters normalize to ASCII, punctuation collapses to single hyphens, and empty results return 'untitled'.",
        "files":{"slugify.py":"""
import re

def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    return text.strip('-')
""",
        "test_slugify.py":"""
from slugify import slugify

def test_slugify_normalizes_accents():
    assert slugify('Café déjà vu!') == 'cafe-deja-vu'

def test_slugify_empty_is_untitled():
    assert slugify('!!!') == 'untitled'
"""},
        "oracle":{"slugify.py":"""
import re
import unicodedata

def slugify(text: str) -> str:
    normalized = unicodedata.normalize('NFKD', text)
    ascii_text = normalized.encode('ascii', 'ignore').decode('ascii')
    ascii_text = ascii_text.lower().strip()
    ascii_text = re.sub(r'[^a-z0-9]+', '-', ascii_text).strip('-')
    return ascii_text or 'untitled'
"""}
    },
    {
        "id":"mini_002_rate_limiter_boundary",
        "prompt":"Fix the fixed-window rate limiter so the Nth request inside the window is allowed and the N+1th request is blocked.",
        "files":{"rate_limiter.py":"""
class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self.events = {}

    def allow(self, user: str, now: int) -> bool:
        window_start = now - self.window_seconds
        events = [t for t in self.events.get(user, []) if t > window_start]
        if len(events) >= self.limit - 1:
            self.events[user] = events
            return False
        events.append(now)
        self.events[user] = events
        return True
""",
        "test_rate_limiter.py":"""
from rate_limiter import RateLimiter

def test_nth_request_allowed_and_next_blocked():
    rl = RateLimiter(limit=3, window_seconds=10)
    assert rl.allow('u', 100) is True
    assert rl.allow('u', 101) is True
    assert rl.allow('u', 102) is True
    assert rl.allow('u', 103) is False

def test_old_events_expire():
    rl = RateLimiter(limit=2, window_seconds=10)
    assert rl.allow('u', 0) is True
    assert rl.allow('u', 1) is True
    assert rl.allow('u', 11) is True
"""},
        "oracle":{"rate_limiter.py":"""
class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self.events = {}

    def allow(self, user: str, now: int) -> bool:
        window_start = now - self.window_seconds
        events = [t for t in self.events.get(user, []) if t > window_start]
        if len(events) >= self.limit:
            self.events[user] = events
            return False
        events.append(now)
        self.events[user] = events
        return True
"""}
    },
    {
        "id":"mini_003_redact_nested",
        "prompt":"Fix redact() so it recursively redacts secret/token/password/api_key values in nested dictionaries and lists without mutating the input.",
        "files":{"redact.py":"""
SENSITIVE = {'secret', 'token', 'password', 'api_key'}

def redact(value):
    if isinstance(value, dict):
        return {k: ('<redacted>' if k in SENSITIVE else v) for k, v in value.items()}
    return value
""",
        "test_redact.py":"""
from redact import redact

def test_nested_redaction_and_no_mutation():
    original = {'user': {'token': 'abc', 'name': 'ryan'}, 'items': [{'password': 'x'}]}
    out = redact(original)
    assert out['user']['token'] == '<redacted>'
    assert out['items'][0]['password'] == '<redacted>'
    assert original['user']['token'] == 'abc'

def test_case_insensitive_key():
    assert redact({'API_KEY': 'abc'})['API_KEY'] == '<redacted>'
"""},
        "oracle":{"redact.py":"""
SENSITIVE = {'secret', 'token', 'password', 'api_key'}

def redact(value):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in SENSITIVE:
                out[k] = '<redacted>'
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
"""}
    }
]


def make_task_repo(task, root: Path) -> Path:
    repo = root / task["id"]
    if repo.exists(): shutil.rmtree(repo)
    repo.mkdir(parents=True)
    for rel, content in task["files"].items():
        p = repo / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content.strip()+"\n", encoding="utf-8")
    (repo / "PROMPT.md").write_text(task["prompt"]+"\n", encoding="utf-8")
    return repo


def run_pytest(repo: Path) -> dict:
    t0=time.time()
    env=os.environ.copy(); env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"]="1"
    proc=subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, env=env)
    return {"exit_code":proc.returncode, "passed":proc.returncode==0, "duration_s":time.time()-t0, "output":proc.stdout[-4000:]}


def apply_oracle(task, repo: Path):
    for rel, content in task["oracle"].items():
        (repo/rel).write_text(content.strip()+"\n", encoding="utf-8")


def run_mini_swe_oracle_noop(suite_root: Path, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    rows=[]
    for task in TASKS:
        for mode in ["noop", "oracle"]:
            repo=make_task_repo(task, out / mode)
            if mode=="oracle": apply_oracle(task, repo)
            result=run_pytest(repo)
            rows.append({"task_id":task["id"], "mode":mode, **result})
    summary={
        "tasks":len(TASKS),
        "noop_passed":sum(1 for r in rows if r["mode"]=="noop" and r["passed"]),
        "oracle_passed":sum(1 for r in rows if r["mode"]=="oracle" and r["passed"]),
        "oracle_expected_pass_rate":sum(1 for r in rows if r["mode"]=="oracle" and r["passed"])/len(TASKS),
        "noop_expected_fail_rate":sum(1 for r in rows if r["mode"]=="noop" and not r["passed"])/len(TASKS),
    }
    (out/"mini_swe_results.json").write_text(json.dumps({"summary":summary,"rows":rows}, indent=2), encoding="utf-8")
    return {"summary":summary, "rows":rows}
