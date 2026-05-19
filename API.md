---
title: API Reference
description: Public Rust crate API and CLI command reference.
seo:
  title: API Reference - Corcept Runtime
  description: Public Rust crate API and CLI command reference.
  keywords: ['api', 'rust', 'cli', 'runtime', 'Corcept', 'Claude Code', 'Rust']
tags: ['api', 'rust', 'cli', 'runtime']
status: complete
---


# API Reference

## `corcept-types`

Shared data types:

- `CorceptConfig`
- `HookEnvelope`
- `HookOutput`
- `PermissionDecision`
- `LedgerEvent`
- `MemoryCandidate`
- `AcceptedMemory`
- `DoctrineRule`

## `corcept-ledger`

- `append_event(root, event)`
- `read_events(root)`
- `verify_hash_chain(root)`
- `last_hash(root)`

## `corcept-guards`

- `evaluate_pre_tool(input, config)`
- `evaluate_stop(root, stop_hook_active)`
- `extract_path(tool_input)`
- `extract_command(tool_input)`

## `corcept-runtime`

- `init_project(options)`
- `doctor(path)`
- `audit(path)`
- `handle_hook(raw_json, command)`

## CLI commands

```bash
corcept init
corcept doctor
corcept audit
corcept hook
corcept memory propose
corcept memory promote
corcept doctrine validate
```
