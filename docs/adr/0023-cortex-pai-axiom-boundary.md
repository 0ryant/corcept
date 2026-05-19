# ADR-0023: Cortex and pai-axiom boundary stubs

Status: accepted  
Date: 2026-05-18  
Subtask: ST-046  
Tags: parity, contracts, backlog

## Context

Future integration with Cortex memory admission and AXIOM execution receipts needs typed envelopes, not ad-hoc JSON.

## Decision

Define schema-only boundary types (`corcept.boundary.execution_receipt.v1`) and fixtures in `contracts/`. No runtime dependency until requested.

### Outcome values

| Outcome | Meaning |
| --- | --- |
| `candidate` | Eval/agent output; not admitted to trusted memory |
| `quarantine` | Held pending human or admission gate review |
| `accepted` | Promoted to trusted substrate |
| `rejected` | Failed admission; retained for audit only |

## Consequences

Eval receipts can align with ecosystem admission model when integration lands.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
