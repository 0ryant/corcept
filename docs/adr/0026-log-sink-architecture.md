# ADR-0026: Log sink architecture and failure modes

Status: accepted  
Date: 2026-05-18  
Subtask: ST-051  
Tags: parity, contracts, backlog

## Context

Ledger append is inline; no unified dispatch for telemetry, debug logs, CE projection, or eval receipts.

## Decision

`SinkDispatcher` + `LogSink` trait. LedgerSink required; all other sinks best-effort. Hook default: ledger only.

## Consequences

No scattered fs::write for observability. Cross-surface contract tests share SinkRecord.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
