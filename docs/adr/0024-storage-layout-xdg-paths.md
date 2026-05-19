# ADR-0024: Storage layout and XDG operator paths

Status: accepted  
Date: 2026-05-18  
Subtask: ST-047  
Tags: parity, contracts, backlog

## Context

All state lives in repo `.corcept/`. Operator-scoped artifacts (telemetry, keys, debug logs) should use XDG like cortex/taudit.

## Decision

Project scope: `.corcept/` (doctrine, memory, ledger). Operator scope: XDG data/state/config with env overrides. CI skips operator paths when HOME unset.

## Consequences

Two-tier layout documented. `corcept doctor --validate-perms` checks 0700 on sensitive dirs.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
