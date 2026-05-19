from __future__ import annotations
import argparse
import json
from pathlib import Path
from .local import run_local
from .report import write_report
from .pair import run_pair
from .adapters import preflight_external, list_external, write_external_runbook
from .paired_all import run_all_paired


def main() -> int:
    parser = argparse.ArgumentParser(prog="corcept-eval", description="CORCEPT benchmark harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_local = sub.add_parser("run-local", help="Run local deterministic governance/stop/memory benchmarks")
    p_local.add_argument("--out", default="results/local")
    p_local.add_argument("--suite-root", default=".")

    p_pair = sub.add_parser("run-pair", help="Run paired baseline vs CORCEPT agent on mini-SWE tasks")
    p_pair.add_argument("--suite", choices=["mini-swe", "mini-reasoning"], default="mini-swe")
    p_pair.add_argument("--baseline-cmd", required=True)
    p_pair.add_argument("--corcept-cmd", required=True)
    p_pair.add_argument("--plugin-dir", default="")
    p_pair.add_argument("--out", default="results/paired")
    p_pair.add_argument("--suite-root", default=".")
    p_pair.add_argument("--limit", type=int, default=0)

    p_report = sub.add_parser("report", help="Write markdown report from JSON results")
    p_report.add_argument("--input", required=True)
    p_report.add_argument("--out", required=True)

    p_pre = sub.add_parser("preflight", help="Check availability of external benchmark tools")
    p_pre.add_argument("--out", default="results/preflight.json")

    p_list = sub.add_parser("list-benchmarks", help="Print the external benchmark registry")
    p_list.add_argument("--out", default="")

    p_runbook = sub.add_parser("write-runbook", help="Write an external benchmark runbook")
    p_runbook.add_argument("--out", default="results/external-runbook.md")

    p_all = sub.add_parser("run-paired-all", help="Run all with/without CORCEPT benchmarks with receipts")
    p_all.add_argument("--out", default="results/paired-v1")
    p_all.add_argument("--repo-root", default="../..")
    p_all.add_argument("--plugin-dir", default="../../plugins/corcept")
    p_all.add_argument("--skip-agent", action="store_true")
    p_all.add_argument("--skip-swe-mini", action="store_true")
    p_all.add_argument("--skip-deterministic", action="store_true", help="Reuse prior SUMMARY benchmarks; skip guard/local/pretool/stop")
    p_all.add_argument("--skip-mini-swe", action="store_true", help="Reuse paired-mini-swe/results.json if present")
    p_all.add_argument("--skip-mini-reasoning", action="store_true", help="Reuse paired-mini-reasoning/results.json if present")
    p_all.add_argument("--limit", type=int, default=0)

    args = parser.parse_args()
    if args.cmd == "run-local":
        result_path = run_local(Path(args.suite_root), Path(args.out))
        report_path = Path(args.out) / "report.md"
        write_report(result_path, report_path)
        print(result_path)
        print(report_path)
    elif args.cmd == "run-pair":
        result_path = run_pair(
            suite_root=Path(args.suite_root),
            out=Path(args.out),
            baseline_cmd=args.baseline_cmd,
            corcept_cmd=args.corcept_cmd,
            plugin_dir=args.plugin_dir,
            limit=args.limit or None,
            suite=args.suite,
        )
        report_path = Path(args.out) / "report.md"
        write_report(result_path, report_path)
        print(result_path)
        print(report_path)
    elif args.cmd == "report":
        write_report(Path(args.input), Path(args.out))
        print(args.out)
    elif args.cmd == "preflight":
        preflight_external(Path(args.out))
        print(args.out)
    elif args.cmd == "list-benchmarks":
        payload = list_external()
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(args.out)
        else:
            print(json.dumps(payload, indent=2))
    elif args.cmd == "write-runbook":
        write_external_runbook(Path(args.out))
        print(args.out)
    elif args.cmd == "run-paired-all":
        manifest = run_all_paired(
            repo_root=Path(args.repo_root).resolve(),
            run_root=Path(args.out).resolve(),
            plugin_dir=str(Path(args.plugin_dir).resolve()),
            skip_agent=args.skip_agent,
            skip_swe_mini=args.skip_swe_mini,
            skip_deterministic=args.skip_deterministic,
            skip_mini_swe=args.skip_mini_swe,
            skip_mini_reasoning=args.skip_mini_reasoning,
            limit=args.limit or None,
        )
        print(manifest)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
