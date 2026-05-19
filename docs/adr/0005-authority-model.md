---
title: Authority model
description: Adopt L0-L4 authority levels for observe, propose, modify, execute, and external side effects.
seo:
  title: Authority model - Corcept ADR
  description: Adopt L0-L4 authority levels for observe, propose, modify, execute, and external side effects.
  keywords: ['adr', 'authority', 'governance', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'authority', 'governance']
status: accepted
---


# Authority model

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Adopt L0-L4 authority levels for observe, propose, modify, execute, and external side effects.

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
