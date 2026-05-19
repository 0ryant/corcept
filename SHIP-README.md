# Corcept Fullship v4

This is the single shippable archive for Corcept.

## Contents

- `corcept/` — full Rust workspace, Claude Code plugin, docs, ADRs, subtasks, schemas and eval suite.
- `dist/corcept-plugin-v4.zip` — standalone Claude Code plugin archive regenerated from `corcept/plugins/corcept`.
- `dist/corcept-eval-suite-v2.zip` — standalone eval suite archive.
- `results/local/` — deterministic local benchmark run for the current package.
- `release-manifest.json` — package manifest, file counts, versions and caveats.
- `checksums.sha256` — SHA256 checksums for shippable nested artifacts.

## What is not claimed

The local deterministic results do not prove model reasoning improvement. They prove that the policy/eval harness is internally consistent. Public reasoning/correctness claims require paired model runs on the external benchmark stack.

## First local commands

```bash
cd corcept
cd evals/corcept-eval-suite-v2
python -m corcept_eval run-local --out results/local
cd ../..
cargo test --workspace
```

Use the Python command form below if the package is installed/editable:

```bash
cd corcept/evals/corcept-eval-suite-v2
python -m corcept_eval run-local --out results/local
python -m corcept_eval list-benchmarks --out results/benchmark-registry.json
python -m corcept_eval write-runbook --out results/external-runbook.md
```
