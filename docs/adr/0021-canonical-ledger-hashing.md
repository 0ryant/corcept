# ADR-0021: Canonical ledger hashing

Status: accepted  
Date: 2026-05-18  
Subtask: ST-036  
Tags: parity, contracts, backlog

## Context

Current SHA-256 over serde_json string is malleable. Cortex uses domain-separated canonical preimages.

## Decision

Phase A: domain prefix + sorted-key canonical JSON. Phase B (optional): BLAKE3 + domain tags with migration path.

## Consequences

Verify rejects tamper that reorders JSON keys. Legacy ledgers need dual-verify or migration tool.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
