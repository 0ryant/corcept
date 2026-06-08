---
title: No default MCP install; bounded opt-in serve only
description: Do not install Corcept as an MCP server by default; ship only a bounded opt-in local stdio entrypoint.
seo:
  title: No default MCP install - Corcept ADR
  description: Do not install Corcept as an MCP server by default; ship only a bounded opt-in local stdio entrypoint.
  keywords: ['adr', 'mcp', 'security', 'Corcept', 'ADR', 'Claude Code', 'Rust']
tags: ['adr', 'mcp', 'security']
status: accepted
---


# No default MCP install; bounded opt-in serve only

## Status

Accepted.

## Context

Corcept is intended to be a governed Claude Code runtime, not a broad prompt marketplace or generic shell bridge. The system must be inspectable, project-local by default, testable, and auditable.

Some operators still need a first-party MCP story for Codex and other MCP-aware clients. That story must preserve Corcept's trust boundaries instead of bypassing them.

## Decision

Do not install Corcept as an MCP server by default.

Ship an explicit opt-in stdio entrypoint only. The original v1 surface was
`corcept serve`, bounded to read-mostly tools tied to a single project root:

- doctor report
- audit report
- doctrine validation
- candidate memory listing
- CloudEvents preview

The bounded MCP surface must not expose:

- raw hook execution
- direct ledger mutation
- memory promotion
- broad shell or filesystem bridging
- automatic default connector installation

Supersession note, 2026-06-01: `corcept serve` remains available during the
deprecation window, but the canonical first-party MCP entrypoint is now the
McPact-generated `corcept-mcp` adapter. The no-default-install boundary still
applies. Any mutation-capable tool must carry explicit authority, trust-ceiling,
path-scope, and approval-gate metadata.

## Consequences

Positive:

- The runtime keeps a clear trust model while still supporting first-party MCP clients.
- Behavior can be verified with tests and ledger evidence.
- Operators get one explicit local entrypoint without default connector install.
- Plugin assets stay small and reviewable.
- Security-sensitive behavior lives in Rust instead of prompt prose.

Trade-offs:

- The server is intentionally less flexible than generic MCP shell bridges.
- Users must build or install the CLI and opt in explicitly.
- Policy tuning requires schema-aware changes rather than casual prompt edits.
- Future MCP expansion now requires explicit review against this boundary.

## Completion

This ADR is implemented in the scaffold and linked to completed subtasks in `TASKS.md`.
