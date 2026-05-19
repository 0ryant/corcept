# CORCEPT wire contracts

Schema IDs: `https://schemas.corcept.dev/<name>`

| Schema | File | Authority |
| --- | --- | --- |
| Ledger event v1 | `schemas/corcept-ledger-event-v1.schema.json` | Yes — hash-chained JSONL |
| Hook input v1 | `schemas/corcept-hook-input-v1.schema.json` | Hook stdin |
| Sink record v1 | `schemas/corcept-sink-record-v1.schema.json` | Internal dispatch |
| CloudEvents audit v1 | `schemas/corcept-cloudevent-audit-v1.schema.json` | Projection only |
| Boundary execution receipt v1 | `schemas/corcept-boundary-execution-receipt-v1.schema.json` | Admission stub (ADR-0023) |

Examples in `examples/` are validated in CI via `scripts/validate-contracts.sh` and `corcept-contract` tests.

## Cross-surface parity

| Surface | Authority | Stable join keys |
| --- | --- | --- |
| Ledger JSONL | Yes | `id`, `session_id`, `event_type` |
| CloudEvents JSONL | Projection | `id` = ledger `id`, `correlationid` = `session_id`, `corcepteventfingerprint` |
| Eval case receipt | Regression artifact | `payload.decision`, benchmark `case_id` |

Changing CloudEvents projection must not mutate ledger lines. Fingerprint algorithm: `corcept-sink-cloudevents::event_fingerprint`.

Compatibility: additive changes only within `v1`; breaking changes require new schema id + ADR.
