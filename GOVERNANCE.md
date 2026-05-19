---
title: Governance
description: Authority model, doctrine precedence, memory promotion rules, and audit controls.
seo:
  title: Governance - Corcept Runtime
  description: Authority model, doctrine precedence, memory promotion rules, and audit controls.
  keywords: ['governance', 'authority', 'doctrine', 'memory', 'audit', 'Corcept', 'Claude Code', 'Rust']
tags: ['governance', 'authority', 'doctrine', 'memory', 'audit']
status: complete
---


# Governance

## Authority levels

```text
L0 observe
L1 propose
L2 modify local
L3 execute local
L4 external side effect
```

Default policy allows L0-L1, checks scope for L2, gates commands for L3, and requires explicit user invocation for L4.

## Precedence

```text
direct user instruction
> active doctrine
> accepted memory
> project CLAUDE.md
> skill or agent instructions
> model preference
```

Direct instruction does not bypass hard safety gates such as secret protection or destructive shell command denial.

## Memory promotion

Memory promotion requires evidence and approval. Accepted memory is project-scoped, reviewable, and demotable. Doctrine changes require explicit doctrine command invocation.
