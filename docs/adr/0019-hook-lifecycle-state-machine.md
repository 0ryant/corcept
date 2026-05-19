# ADR-0019: Hook lifecycle state machine

Status: accepted  
Date: 2026-05-18  
Subtask: ST-033  
Tags: parity, contracts, backlog

## Context

Hook flow (PreTool → PostTool → Stop) is implicit in corcept-runtime. Doctrine requires explicit states, transitions, and event-type mapping.

## Decision

Document FSM with states, triggers, preconditions, terminal states, recovery, and idempotency. Map committed transitions to ADR-0018 event types.

## Consequences

Reviewers can trace hook behavior without reading all runtime code. Benchmark receipts can cite transition IDs.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
