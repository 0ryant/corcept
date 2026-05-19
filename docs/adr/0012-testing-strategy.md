---
title: Testing strategy
description: Use crate unit tests, hook fixtures, runtime integration tests, and CI gates.
seo:
  title: Testing strategy - Corcept ADR
  description: Use crate unit tests, hook fixtures, runtime integration tests, and CI gates.
  keywords: ['adr', 'testing', 'ci', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'testing', 'ci']
status: accepted
---


# Testing strategy

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Use a three-layer test pyramid enforced in CI:

| Layer | Target share | Scope | CI |
| --- | ---: | --- | --- |
| Fast unit | ~70% | `corcept-types`, `corcept-guards`, `corcept-ledger`, `corcept-sink` | `cargo test` in `quality.yml` |
| Contract / integration | ~25% | `corcept-contract`, hook fixtures, adversarial corpus, cross-sink | `validate-contracts.sh`, `cargo test` |
| E2E regression | ~5% | eval harness deterministic paired run | `quality.yml`, `eval-regression.yml` |

Property tests (`proptest`) cover policy lattice, event wire roundtrip, and hash-chain append invariants.

See `tests/README.md` and `docs/doctrine-adoption-map.md` for module mapping.

## Consequences

Positive:

- The runtime has a clear trust model.
- Behavior can be verified with tests and ledger evidence.
- Plugin assets stay small and reviewable.
- Security-sensitive behavior lives in Rust instead of prompt prose.

Trade-offs:

- The scaffold is more engineering-heavy than a prompt pack.
- Users must build or install the CLI for hooks to execute.
- Policy tuning requires schema-aware changes rather than casual prompt edits.

## Completion

This ADR is implemented in the scaffold and linked to completed subtasks in `TASKS.md`.
