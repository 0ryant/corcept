from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .runtime import environment_notes, resolve_python


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_head(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def environment_snapshot(root: Path) -> dict[str, Any]:
    claude_version = None
    if shutil.which("claude"):
        try:
            proc = subprocess.run(["claude", "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
            claude_version = proc.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    harbor_version = None
    if shutil.which("harbor"):
        try:
            proc = subprocess.run(["harbor", "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
            harbor_version = proc.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return {
        "captured_at": utc_now(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": resolve_python(),
        "claude_version": claude_version,
        "harbor_version": harbor_version,
        "corcept_eval_notes": environment_notes(),
        "git_head": git_head(root),
    }


class ReceiptWriter:
    def __init__(self, run_root: Path, repo_root: Path):
        self.run_root = run_root
        self.repo_root = repo_root
        self.receipts_dir = run_root / "receipts"
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        self.manifest: dict[str, Any] = {
            "schema": "corcept-paired-receipts/v1",
            "started_at": utc_now(),
            "repo_root": str(repo_root),
            "run_root": str(run_root),
            "environment": environment_snapshot(repo_root),
            "benchmarks": [],
            "artifacts": [],
        }

    def begin_benchmark(self, name: str, *, baseline_label: str, corcept_label: str, meta: dict | None = None) -> dict:
        entry = {
            "name": name,
            "baseline_label": baseline_label,
            "corcept_label": corcept_label,
            "started_at": utc_now(),
            "meta": meta or {},
            "receipts": [],
        }
        self.manifest["benchmarks"].append(entry)
        return entry

    def write_receipt(
        self,
        bench: dict,
        *,
        mode: str,
        case_id: str,
        command: str,
        payload: dict,
        stdout: str = "",
        stderr: str = "",
    ) -> Path:
        case_dir = self.receipts_dir / bench["name"] / mode / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        receipt = {
            "schema": "corcept-case-receipt/v1",
            "benchmark": bench["name"],
            "mode": mode,
            "case_id": case_id,
            "command": command,
            "captured_at": utc_now(),
            "payload": payload,
        }
        receipt_path = case_dir / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        if stdout:
            (case_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
        if stderr:
            (case_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
        bench["receipts"].append(
            {
                "mode": mode,
                "case_id": case_id,
                "receipt": str(receipt_path.relative_to(self.run_root)),
                "passed": payload.get("passed"),
            }
        )
        self._register_artifact(receipt_path)
        return receipt_path

    def write_suite_result(self, bench: dict, result_path: Path, summary: dict) -> None:
        bench["finished_at"] = utc_now()
        bench["summary"] = summary
        bench["results_path"] = str(result_path.relative_to(self.run_root))
        self._register_artifact(result_path)

    def _register_artifact(self, path: Path) -> None:
        if not path.exists():
            return
        self.manifest["artifacts"].append(
            {
                "path": str(path.relative_to(self.run_root)),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )

    def finalize(self, summary_path: Path, summary: dict) -> Path:
        self.manifest["finished_at"] = utc_now()
        self.manifest["summary"] = summary
        manifest_path = self.run_root / "MANIFEST.json"
        manifest_path.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        self._register_artifact(manifest_path)
        return manifest_path
