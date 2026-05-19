---
title: Architecture
description: System architecture for Corcept Runtime.
seo:
  title: Architecture - Corcept Runtime
  description: System architecture for Corcept Runtime.
  keywords: ['architecture', 'runtime', 'hooks', 'ledger', 'memory', 'doctrine', 'Corcept', 'Claude Code', 'Rust']
tags: ['architecture', 'runtime', 'hooks', 'ledger', 'memory', 'doctrine']
status: complete
---


# Architecture

Corcept is divided into four operational layers.

## 1. Claude Code plugin layer

Located at `plugins/corcept/`, this layer contains:

- `.claude-plugin/plugin.json` manifest.
- `skills/*/SKILL.md` namespaced skills.
- `agents/*.md` bounded subagents.
- `hooks/hooks.json` lifecycle wiring.
- `bin/*` wrapper scripts that delegate to the Rust CLI.

## 2. Rust runtime layer

The Rust workspace implements deterministic behavior that should not be left to prompts:

- `corcept-types`: shared config, hook, event, memory, and doctrine types.
- `corcept-ledger`: JSONL audit ledger and hash-chain verification.
- `corcept-guards`: bash/filesystem/secret/stop policy evaluation.
- `corcept-doctrine`: doctrine loading and validation.
- `corcept-memory`: candidate and accepted memory lifecycle.
- `corcept-runtime`: project init, doctor, audit, and hook orchestration.
- `corcept-cli`: operator CLI and hook entrypoint.
- `create-corcept`: dedicated installer binary.

## 3. Project governance layer

Generated projects receive:

```text
.claude/CLAUDE.md
.claude/settings.json
.corcept/config.yaml
.corcept/doctrine/*.md
.corcept/memory/{accepted,candidates,rejected}/
.corcept/ledger/events.jsonl
.corcept/reports/
```

## 4. Evidence layer

Every meaningful operation becomes structured evidence:

- prompt received
- task classified
- tool requested
- tool allowed/asked/denied
- file modified
- command executed
- test run
- audit completed
- memory proposed/promoted
- doctrine changed

This is the core difference between CORCEPT and a prompt bundle. The runtime must be able to reconstruct what happened from the ledger.
