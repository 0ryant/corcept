# CORCEPT Eval Suite v0.2

CORCEPT Eval Suite is a paired benchmark harness for measuring whether CORCEPT improves agentic software-engineering behaviour rather than merely adding prompt surface.

## What it measures

- deterministic governance/tool-call policy correctness
- stop-gate correctness
- memory/doctrine mutation policy
- mini-SWE smoke tasks
- mini code-reasoning paired tasks
- external benchmark readiness and runbooks
- with/without CORCEPT deltas on public benchmarks

## Local deterministic run

```bash
python -m corcept_eval run-local --out results/local
python -m corcept_eval preflight --out results/preflight.json
python -m corcept_eval list-benchmarks --out results/benchmark-registry.json
python -m corcept_eval write-runbook --out results/external-runbook.md
```

## Paired mini-SWE run

```bash
python -m corcept_eval run-pair   --suite mini-swe   --baseline-cmd 'claude --print "$CORCEPT_TASK_PROMPT"'   --corcept-cmd 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'   --plugin-dir /path/to/corcept-plugin   --out results/paired-mini-swe
```

## Paired code-reasoning control

```bash
python -m corcept_eval run-pair   --suite mini-reasoning   --baseline-cmd 'claude --print "$CORCEPT_TASK_PROMPT"'   --corcept-cmd 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'   --plugin-dir /path/to/corcept-plugin   --out results/paired-mini-reasoning
```

The code-reasoning control is intentionally not the main product proof. It is a regression detector: CORCEPT should not degrade raw code reasoning through irrelevant instruction overhead.
