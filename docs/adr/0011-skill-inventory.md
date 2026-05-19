---
title: Small canonical skill inventory
description: Prefer a compact set of high-signal skills over a giant catalogue.
seo:
  title: Small canonical skill inventory - Corcept ADR
  description: Prefer a compact set of high-signal skills over a giant catalogue.
  keywords: ['adr', 'skills', 'product', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'skills', 'product']
status: accepted
---


# Small canonical skill inventory

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Prefer a compact set of high-signal skills over a giant catalogue.

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
