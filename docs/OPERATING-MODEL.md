---
title: Operating Model
description: CORCEPT operating model for Claude Code governed execution.
seo:
  title: Corcept operating model
  description: Operating model for doctrine, memory, agents, hooks, and audit in Corcept.
  keywords: [CORCEPT, Claude Code, operating model, governance, memory, audit]
tags: [operating-model, governance, hooks, memory]
status: complete
---

# Operating Model

Corcept treats Claude Code as an execution partner that needs boundaries. The model is:

```text
user intent -> intake -> plan -> bounded implementation -> test -> review -> audit -> ship
```

The runtime enforces hard boundaries through hooks and records evidence through the ledger.
