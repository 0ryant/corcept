# Terminal-Bench / Harbor adapter

Terminal-Bench is the runtime-layer benchmark. Use it to test whether CORCEPT improves real terminal workflows, not just toy command classification.

Expected local preflight:

```bash
harbor datasets list
```

Experiment:

```text
baseline agent command: no CORCEPT plugin/hooks
CORCEPT agent command: CORCEPT plugin/hooks enabled
```

Report task success and command-safety metrics together.
