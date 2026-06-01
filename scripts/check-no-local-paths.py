#!/usr/bin/env python3
"""Fail when tracked source files contain one developer's local home paths."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FORBIDDEN = (
    "C:" + "/Users/0ryant",
    "C:" + "\\Users\\0ryant",
    "/Users/" + "rytilcock",
    "/mnt/c/Users/" + "0ryant",
)

TEXT_SUFFIXES = {
    ".rs",
    ".toml",
    ".json",
    ".jsonl",
    ".md",
    ".sh",
    ".py",
    ".yml",
    ".yaml",
}
TEXT_NAMES = {"Cargo.toml", "README", "LICENSE"}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [Path(line) for line in result.stdout.splitlines() if line]


def should_scan(path: Path) -> bool:
    if any(part in {".git", "target", "target-w3-corcept"} for part in path.parts):
        return False
    return path.name in TEXT_NAMES or path.suffix in TEXT_SUFFIXES


def main() -> int:
    findings: list[str] = []
    for path in tracked_files():
        if not should_scan(path) or not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(pattern in line for pattern in FORBIDDEN):
                findings.append(f"{path}:{lineno}: {line.strip()}")

    if findings:
        print("local path guard: found non-portable developer-local paths", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print("local path guard: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
