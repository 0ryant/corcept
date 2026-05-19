# Runtime logging vs audit ledger (ST-049)

## Authority boundary

| Output | Role | Authority | Failure mode |
| --- | --- | --- | --- |
| **Ledger** (`.corcept/ledger/events.jsonl`) | Tamper-evident audit evidence | **Yes** | Hook fails if append fails |
| **Telemetry** (`{state}/telemetry/events.jsonl`) | Ops metrics, timing | No | Best-effort skip |
| **Debug log** (`{state}/logs/corcept.log`) | Operator diagnostics | No | Best-effort skip |
| **CloudEvents export** | SIEM/projection | No | Best-effort skip |

The audit ledger is the proof boundary (ADR-0021). Debug and telemetry outputs are **not** SIEM authority.

## Hook hot path

Default dispatcher: **LedgerSink only** — zero extra I/O unless explicitly enabled.

| Env | Effect |
| --- | --- |
| `CORCEPT_TELEMETRY=1` | Enable TelemetrySink + DebugLogSink |
| `CORCEPT_LOG=debug` | Enable DebugLogSink |
| `CORCEPT_CE_OUT=/path/ce.jsonl` | Enable CloudEventsSink |
| `CORCEPT_RECEIPTS=1` | Enable ReceiptSink |

When logging is off, hook path adds negligible overhead (single ledger append).

## Redaction

Debug log lines include: `ts`, `correlation_id`, `event_type`, `outcome` only.

Never written: tool_input secrets, env vars, full prompts, API keys.

## Future: structured tracing

Full `tracing` JSON lines (level, target, span) may follow in a later release; current `DebugLogSink` is the phase-1 operator tail.

## See also

- [STORAGE-LAYOUT.md](./STORAGE-LAYOUT.md)
- [ADR-0026](../adr/0026-log-sink-architecture.md)
