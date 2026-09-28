# CORCEPT wire contracts

Schema IDs: `https://schemas.corcept.dev/<name>`

| Schema | File | Authority |
| --- | --- | --- |
| Ledger event v1 | `schemas/corcept-ledger-event-v1.schema.json` | Yes — hash-chained JSONL |
| Hook input v1 | `schemas/corcept-hook-input-v1.schema.json` | Hook stdin |
| Delegation envelope v1 | `schemas/corcept-delegation-v1.schema.json` | Candidate references; signed authority snapshot required |
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

## Delegated invocation contract

The optional `delegation` object in Hook Input v1 uses
`corcept.delegation.v1`. It is a provisional Corcept consumer format;
McPact issue [#45](https://github.com/0ryant/McPact/issues/45) is an upstream
proposal, not an interoperability or upstream schema-compliance guarantee.

The envelope requires opaque caller, agent, user, organisation, target service,
capability, action, resource, grant, and correlation references. References are
1 to 128 ASCII characters from `[A-Za-z0-9_.:-]`; `approval_id` is optional
and null means absent. Unknown fields and verification markers are rejected.
Credentials, email addresses, URLs, and raw resource paths do not belong in
this envelope. Unrecognised fields in the surrounding native hook remain
permitted for host compatibility.

[delegation-allow.json](examples/delegation-allow.json) demonstrates a candidate
MCP `PreToolUse` payload. Its filename describes an allow scenario; the fixture
alone cannot authorize anything. Schema validation proves its structure. The
guard must still verify an operator-pinned signed snapshot, bind the actual
invocation, apply all policy ceilings, consume replay state, and append signed
decision evidence before returning allow.

The contract validator registers the committed delegation schema locally, so
references do not require a schema-host network lookup. Both the contract hook
schema and `../schemas/hook-input.schema.json` share the same envelope contract.
See [the operator guide](../docs/DELEGATED_AUTHORITY.md) and
[ADR-0028](../docs/adr/0028-delegated-authority.md) for admission and trust limits.
