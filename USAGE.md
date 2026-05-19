---
title: Usage
description: Operational usage patterns for CORCEPT CLI, hooks, skills, agents, memory, and doctrine.
seo:
  title: Usage - Corcept Runtime
  description: Operational usage patterns for CORCEPT CLI, hooks, skills, agents, memory, and doctrine.
  keywords: ['usage', 'cli', 'skills', 'agents', 'hooks', 'Corcept', 'Claude Code', 'Rust']
tags: ['usage', 'cli', 'skills', 'agents', 'hooks']
status: complete
---


# Usage

## CLI

```bash
corcept init --path . --dry-run
corcept doctor --path .
corcept audit --path .
corcept memory propose --path . --title "Convention" --claim "Claim text" --evidence "src/lib.rs:10"
corcept memory promote --path . --id mem_...
corcept doctrine validate --path .
```

## Claude Code skills

Use the plugin with:

```bash
claude --plugin-dir ./plugins/corcept
```

Then invoke:

```text
/corcept:intake
/corcept:map-codebase
/corcept:plan-change
/corcept:implement
/corcept:review
/corcept:test
/corcept:threat-model
/corcept:audit
/corcept:ship
```

## Hook behavior

- `PreToolUse` blocks or asks before risky actions.
- `PostToolUse` records tool results and marks tests.
- `Stop` blocks premature completion if source changed after tests.
- `UserPromptSubmit` injects scoped governance reminders.
- `SessionStart` loads doctrine/memory context.

## Memory

Memory is never promoted directly from model output. It moves through:

```text
observation -> candidate -> accepted memory -> doctrine, if explicitly approved
```
