from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Dict


def resolve_python() -> str:
    for candidate in ("python3", "python"):
        path = shutil.which(candidate)
        if path:
            return path
    return sys.executable


def check_python() -> bool:
    try:
        proc = subprocess.run(
            [resolve_python(), "-c", "import sys; assert sys.version_info >= (3, 10)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def check_docker() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def check_git() -> bool:
    return bool(shutil.which("git"))


def check_harbor() -> bool:
    return bool(shutil.which("harbor"))


def check_claude() -> bool:
    return bool(shutil.which("claude"))


def check_cargo() -> bool:
    return bool(shutil.which("cargo"))


def resolve_requirement(name: str) -> bool:
    if name == "python":
        return check_python()
    if name == "docker":
        return check_docker()
    if name == "git":
        return check_git()
    if name == "harbor":
        return check_harbor()
    return bool(shutil.which(name))


def requirement_status(requires: list[str]) -> Dict[str, bool]:
    return {name: resolve_requirement(name) for name in requires}


def environment_notes() -> dict:
    return {
        "python": resolve_python(),
        "docker_available": check_docker(),
        "claude_code_available": check_claude(),
        "cargo_available": check_cargo(),
        "external_benchmarks_run": False,
    }
