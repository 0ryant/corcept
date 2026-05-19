---
title: Claude Code plugin layout
description: Use root-level plugin components with `.claude-plugin/plugin.json`, skills, agents, hooks, bin, and settings.
seo:
  title: Claude Code plugin layout - Corcept ADR
  description: Use root-level plugin components with `.claude-plugin/plugin.json`, skills, agents, hooks, bin, and settings.
  keywords: ['adr', 'plugin', 'claude-code', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'plugin', 'claude-code']
status: accepted
---


# Claude Code plugin layout

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace. The system must be inspectable, project-local by default, testable, and auditable.

## Decision

Use root-level plugin components with `.claude-plugin/plugin.json`, skills, agents, hooks, bin, and settings.

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
