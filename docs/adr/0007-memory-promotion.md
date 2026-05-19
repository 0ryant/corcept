---
title: Evidence-backed memory promotion
description: Separate observations, candidates, accepted memory, and doctrine.
seo:
  title: Evidence-backed memory promotion - Corcept ADR
  description: Separate observations, candidates, accepted memory, and doctrine.
  keywords: ['adr', 'memory', 'evidence', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'memory', 'evidence']
status: accepted
---


# Evidence-backed memory promotion

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Separate observations, candidates, accepted memory, and doctrine.

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
