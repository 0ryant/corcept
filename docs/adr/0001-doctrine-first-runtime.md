---
title: Doctrine-first runtime
description: Choose doctrine and audit as the primary product surface instead of a large prompt catalogue.
seo:
  title: Doctrine-first runtime - Corcept ADR
  description: Choose doctrine and audit as the primary product surface instead of a large prompt catalogue.
  keywords: ['adr', 'doctrine', 'governance', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'doctrine', 'governance']
status: accepted
---


# Doctrine-first runtime

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Choose doctrine and audit as the primary product surface instead of a large prompt catalogue.

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
