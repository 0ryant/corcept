# ADR-0018: Versioned ledger event types

Status: accepted  
Date: 2026-05-18  
Subtask: ST-032  
Tags: parity, contracts, backlog

## Context

Ledger events use free-form `event_type` strings. Sibling repos (cortex) use stable wire strings `corcept.event.<semantic>.v1` with snapshot tests.

## Decision

Introduce `LedgerEventType` enum, `schema: corcept.ledger_event.v1` on every line, and snapshot tests forbidding silent wire renames.

## Consequences

Breaking renames require ADR + schema bump. Consumers can bind to versioned types.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
