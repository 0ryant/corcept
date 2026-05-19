# ADR-0022: Audit events and CloudEvents boundary

Status: accepted  
Date: 2026-05-18  
Subtask: ST-039  
Tags: parity, contracts, backlog

## Context

No export envelope for SIEM/automation. Doctrine standardizes CloudEvents 1.0 at boundaries.

## Decision

`.corcept/ledger/events.jsonl` is authority. CloudEvents JSONL is derived projection only. No secrets in CE `data`.

### Mapping

| Ledger `event_type` | CloudEvents `type` |
| --- | --- |
| `corcept.event.session_started.v1` | `io.corcept.hook.session_started.v1` |
| `corcept.event.tool_requested.v1` | `io.corcept.hook.tool_requested.v1` |
| … | … |

Export: `corcept export cloudevents --ledger PATH --out PATH`

## Consequences

Export CLI can rebuild CE from ledger. Contract tests validate projection separately from authority.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
