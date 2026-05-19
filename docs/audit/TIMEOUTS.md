# Wait states and timeouts (ST-035 / ADR-0019 supplement)

| Component | Default | Escalation | Receipt field |
| --- | --- | --- | --- |
| Hook stdin read | 30s | fail hook with block output | — |
| PreTool guard eval | 5s | deny (fail closed) | — |
| Stop gate eval | 5s | allow with warn logged | — |
| Eval agent subprocess | 600s | mark `timed_out: true`, continue aggregate | `timed_out` |
| Mini-reasoning agent | 300s | same | `timed_out` |
| Ledger append lock | 10s | hook fails (authority sink) | — |
| Git metadata probe | 5s | skip silently | — |

Stop gate when no passing test after source change: **block** with reason
`Source files changed after the last recorded passing test run.`

Future: `corcept.event.timeout.v1` when agent-bound timeouts become ledger events.
