---
title: Command hooks over HTTP hooks
description: Use command hooks that read JSON from stdin instead of default HTTP hooks.
seo:
  title: Command hooks over HTTP hooks - Corcept ADR
  description: Use command hooks that read JSON from stdin instead of default HTTP hooks.
  keywords: ['adr', 'hooks', 'security', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'hooks', 'security']
status: accepted
---


# Command hooks over HTTP hooks

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Use command hooks that read JSON from stdin instead of default HTTP hooks.

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
