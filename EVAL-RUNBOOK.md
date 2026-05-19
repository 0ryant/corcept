# CORCEPT Eval Runbook

## Local deterministic suite

```bash
cd evals/corcept-eval-suite-v2
python -m corcept_eval run-local --out results/local
python -m corcept_eval preflight --out results/preflight.json
python -m corcept_eval list-benchmarks --out results/benchmark-registry.json
python -m corcept_eval write-runbook --out results/external-runbook.md
```

## Paired mini-SWE

```bash
python -m corcept_eval run-pair   --suite mini-swe   --baseline-cmd 'claude --print "$CORCEPT_TASK_PROMPT"'   --corcept-cmd 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'   --plugin-dir ../../plugins/corcept   --out results/paired-mini-swe
```

## Paired mini-reasoning

```bash
python -m corcept_eval run-pair   --suite mini-reasoning   --baseline-cmd 'claude --print "$CORCEPT_TASK_PROMPT"'   --corcept-cmd 'claude --plugin-dir "$CORCEPT_PLUGIN_DIR" --print "$CORCEPT_TASK_PROMPT"'   --plugin-dir ../../plugins/corcept   --out results/paired-mini-reasoning
```

## External benchmark policy

Do not mix harnesses. Run baseline and CORCEPT with the same model, same timeout, same temperature, same container image, same verifier and same task subset.
