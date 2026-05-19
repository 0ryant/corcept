from __future__ import annotations
import re
from pathlib import PurePosixPath
from dataclasses import dataclass

@dataclass
class Decision:
    decision: str  # allow | ask | deny
    reason: str
    category: str = "uncategorized"

PROTECTED_PATTERNS = [
    r"(^|/)\.env(\.|$)", r"(^|/)\.env$", r"\.pem$", r"\.key$", r"id_rsa", r"id_ed25519",
    r"(^|/)\.aws(/|$)", r"(^|/)\.gcp(/|$)", r"(^|/)\.azure(/|$)", r"(^|/)\.git(/|$)",
    r"secret", r"token", r"credential", r"private[_-]?key"
]

HARD_DENY_PATTERNS = [
    (r"(^|[;&|\s])sudo\s+rm\s+-[a-zA-Z]*r[f]?\s+(/|~|\$HOME)(\s|$)", "root_or_home_recursive_delete"),
    (r"(^|[;&|\s])rm\s+-[a-zA-Z]*r[f]?\s+(/|~|\$HOME)(\s|$)", "root_or_home_recursive_delete"),
    (r"(^|[;&|\s])chmod\s+-R\s+777\b", "world_writable_recursive_chmod"),
    (r"curl\b[^|;]*\|\s*(sh|bash|zsh|fish)\b", "pipe_to_shell"),
    (r"wget\b[^|;]*\|\s*(sh|bash|zsh|fish)\b", "pipe_to_shell"),
    (r"(sh|bash|zsh|fish)\s*<\s*\(\s*(curl|wget)\b", "process_substitution_remote_exec"),
    (r"\b(cat|less|more|head|tail|grep|awk|sed)\b[^;&|]*(\.env|secret|token|credential|private[_-]?key)", "secret_read_or_exfil"),
    (r"\b(printenv|env|set)\b.*\b(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)", "sensitive_env_exfil"),
]

ASK_PATTERNS = [
    (r"\b(npm|pnpm|yarn|bun)\s+(install|i|add)\b", "package_install"),
    (r"\b(pip|pip3|uv)\s+install\b", "package_install"),
    (r"\bpython\s+-m\s+pip\s+install\b", "package_install"),
    (r"\bcargo\s+add\b", "package_install"),
    (r"\bgo\s+get\b", "package_install"),
    (r"\bgit\s+push\b", "git_remote_side_effect"),
    (r"\bgit\s+reset\s+--hard\b", "destructive_git"),
    (r"\bgit\s+clean\s+-", "destructive_git"),
    (r"\brm\s+-[a-zA-Z]*r[f]?\s+(\.|\.\/|[^/\s][^\s]*)", "recursive_delete"),
    (r"\b(kubectl|terraform|pulumi|aws|gcloud|az)\b", "infra_or_cloud_side_effect"),
    (r"\b(deploy|vercel|netlify|flyctl|railway|wrangler)\b", "deploy_side_effect"),
    (r"\bdocker\s+(run|compose|build|push)\b", "container_side_effect"),
]

def protected_path(path: str) -> bool:
    norm = str(PurePosixPath(path.replace('\\', '/')))
    return any(re.search(p, norm, re.I) for p in PROTECTED_PATTERNS)

def classify_bash(command: str) -> Decision:
    normalized = re.sub(r"\s+", " ", command.strip())
    compact = re.sub(r"\s+", "", command.strip())
    # No-space remote shell variant.
    if re.search(r"(curl|wget)[^|;]*\|(?:sh|bash|zsh|fish)\b", compact, re.I):
        return Decision("deny", "Remote pipe-to-shell execution is blocked.", "pipe_to_shell")
    for pat, cat in HARD_DENY_PATTERNS:
        if re.search(pat, normalized, re.I):
            return Decision("deny", f"Blocked high-risk shell command: {cat}.", cat)
    for pat, cat in ASK_PATTERNS:
        if re.search(pat, normalized, re.I):
            return Decision("ask", f"Command requires explicit approval: {cat}.", cat)
    return Decision("allow", "No CORCEPT guard matched.", "safe_or_unclassified")

def classify_corcept_controlled_write(path: str) -> Decision | None:
    norm = path.replace('\\', '/').lower()
    if '/.corcept/memory/accepted/' in norm or norm.startswith('.corcept/memory/accepted/'):
        return Decision("deny", f"Accepted memory mutation blocked without promotion flow: {path}", "accepted_memory_mutation")
    if '/.corcept/doctrine/' in norm or norm.startswith('.corcept/doctrine/'):
        return Decision("ask", f"Doctrine mutation requires explicit approval: {path}", "doctrine_mutation")
    if norm == '.corcept/config.yaml' or norm.endswith('/.corcept/config.yaml'):
        return Decision("ask", "CORCEPT policy config mutation requires approval.", "config_mutation")
    if norm == '.corcept/ledger/events.jsonl' or norm.endswith('/.corcept/ledger/events.jsonl'):
        return Decision("ask", "Direct ledger mutation requires approval.", "ledger_mutation")
    return None


def classify_tool(tool_name: str, tool_input: dict) -> Decision:
    if tool_name == "Bash":
        return classify_bash(str(tool_input.get("command", "")))
    if tool_name in {"Read", "Edit", "Write", "Grep", "Glob"}:
        path = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("glob") or tool_input.get("pattern") or "")
        if path and protected_path(path):
            return Decision("deny", f"Protected path or secret-like path is blocked: {path}", "protected_path")
        if tool_name in {"Edit", "Write"}:
            policy = classify_corcept_controlled_write(path)
            if policy:
                return policy
            if path.startswith("/") and not path.startswith("/tmp/"):
                return Decision("deny", "Write outside repo root is blocked.", "outside_repo_write")
    return Decision("allow", "Tool request allowed.", "safe_or_unclassified")
