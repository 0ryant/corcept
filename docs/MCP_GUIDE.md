---
title: Corcept MCP guide
description: How to run the opt-in bounded Corcept MCP server safely.
seo:
  title: Corcept MCP guide
  description: Run Corcept as an opt-in bounded MCP server with a narrow read-mostly tool surface.
  keywords: [Corcept, MCP, stdio, Codex, Claude Code, audit]
tags: [mcp, docs, corcept]
status: complete
---

# Corcept MCP guide

> **Deprecation notice.** `corcept serve` (this hand-rolled, read-only surface)
> is **deprecated** and superseded by the McPact-generated **`corcept-mcp`**
> adapter, which is now the canonical first-party MCP entrypoint. `corcept-mcp`
> exposes the full governed tool surface (hooks, audit verify, key generation)
> with policy, trust-ceiling, and audit-sink enforcement. Both surfaces now
> negotiate the **same** MCP protocol revision (`2025-11-25`) during the
> deprecation window; prefer `corcept-mcp`. `corcept serve` will be removed in a
> future release.

`corcept serve` is the legacy opt-in MCP entrypoint for Corcept.

It is intentionally opt-in:

- No default installation into editors or agents.
- No broad shell bridge.
- No direct ledger mutation, hook execution, or memory promotion in v1.
- One bound project root per server process.

## Bounded tool surface

| Tool | Purpose | Mutates state |
| --- | --- | --- |
| `doctor_report` | Project health and doctrine/ledger checks | No |
| `audit_report` | Ledger summary plus verification result | No |
| `doctrine_validate` | Doctrine validation warnings | No |
| `candidate_memory_list` | Read-only candidate memory listing | No |
| `cloudevents_preview` | Derived CloudEvents preview from the authority ledger | No |

## Start locally

```bash
cargo run -p corcept-cli -- serve --path /path/to/repo
```

or after installing the binary:

```bash
corcept serve --path /path/to/repo
```

The server uses newline-delimited JSON-RPC 2.0 over stdio, matching the MCP stdio transport for protocol version `2025-11-25` (converged with the canonical `corcept-mcp` adapter). The `initialize` handshake negotiates: a client proposing an older revision such as `2025-06-18` receives `2025-11-25` in the response and decides whether to proceed.

## Expected lifecycle

1. Send `initialize`.
2. Send `notifications/initialized`.
3. Call `tools/list`.
4. Call one of the bounded tools.

## Example initialize request

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"local-smoke","version":"0.1.0"}}}
```

## Trust boundaries

- `.corcept/ledger/events.jsonl` remains the authority surface.
- `cloudevents_preview` is derived output only.
- The server never auto-discovers other repos; `--path` fixes the working root.
- Validation and argument mistakes are returned as typed tool errors so clients can recover without hidden side effects.

## Smoke paths

- Installed binary smoke: `scripts/smoke-installed-mcp.ps1`
- Codex hotload runbook: `scripts/smoke-codex-corcept-connector.md`
