---
title: Rust workspace
description: Use Rust for the CLI, hooks, guard evaluation, ledger, memory, and doctrine runtime.
seo:
  title: Rust workspace - Corcept ADR
  description: Use Rust for the CLI, hooks, guard evaluation, ledger, memory, and doctrine runtime.
  keywords: ['adr', 'rust', 'workspace', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'rust', 'workspace']
status: accepted
---


# Rust workspace

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Use Rust for the CLI, hooks, guard evaluation, ledger, memory, and doctrine runtime.

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
