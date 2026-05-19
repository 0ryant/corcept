# ADR-0020: Guard and stop-gate composition lattice

Status: accepted  
Date: 2026-05-18  
Subtask: ST-034  
Tags: parity, contracts, backlog

## Context

Multiple classifiers (bash, path, secret, stop) can disagree. No documented total order.

## Decision

PreTool: Allow < Ask < Deny (strictest wins). Stop: AllowStop < BlockStop. Document pairwise composition and property-test the lattice.

## Consequences

Benchmark suites become normative for policy behavior.

## References

- `docs/PARITY-TASKS.md`
- Engineering doctrine: event-contracts, state-machines, audit-logging, testing-strategy
