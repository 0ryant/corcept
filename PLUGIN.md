---
title: Claude Code Plugin
description: Plugin layout, hooks, skills, agents, and packaging rules.
seo:
  title: Claude Code Plugin - Corcept Runtime
  description: Plugin layout, hooks, skills, agents, and packaging rules.
  keywords: ['plugin', 'claude-code', 'hooks', 'skills', 'agents', 'Corcept', 'Claude Code', 'Rust']
tags: ['plugin', 'claude-code', 'hooks', 'skills', 'agents']
status: complete
---


# Claude Code Plugin

The plugin is rooted at `plugins/corcept/`.

```text
plugins/corcept/
  .claude-plugin/plugin.json
  skills/*/SKILL.md
  agents/*.md
  hooks/hooks.json
  bin/*
  settings.json
```

## Hook wrappers

The plugin does not embed policy in shell. Every wrapper delegates to Rust:

```text
corcept-session-start       -> corcept hook session-start
corcept-user-prompt-submit  -> corcept hook user-prompt-submit
corcept-pretool-guard       -> corcept hook pretool-guard
corcept-posttool-audit      -> corcept hook posttool-audit
corcept-stop-check          -> corcept hook stop-check
```

## Skill policy

Side-effect skills use `disable-model-invocation: true`. This includes:

- `ship`
- `memory-promote`
- `doctrine-add`
- `audit`

## Agent policy

Agents declare:

- `name`
- `description`
- `model`
- `effort`
- `maxTurns`
- `tools` or `disallowedTools`

Plugin agents avoid unsupported plugin-agent fields and keep permission enforcement in hooks.
