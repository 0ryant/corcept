# ADR-0025: Signed ledger rows and verification modes

Status: accepted  
Date: 2026-05-18  
Subtask: ST-048  
Tags: parity, contracts, backlog

## Context

Hash chain detects tamper but does not provide non-repudiation. Cortex uses Ed25519 per-row signatures.

## Decision

Optional `signature` field on ledger lines. Modes: verify (hash only), verify --signed (require Ed25519), trusted-history append. No HMAC fallback.

## Consequences

Key rotation via `corcept keygen`. Unsigned rows fail `--signed` with typed reason.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
