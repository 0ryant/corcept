---
id: ST-024
title: Align Rust guard with memory/doctrine benchmark
status: completed
date: 2026-05-18
tags: [guards, memory, doctrine, correctness, tests]
---

# ST-024: Align Rust guard with memory/doctrine benchmark

Completed:

- Protected writes now hard-deny instead of ask.
- Accepted memory mutation hard-denies unless routed through promotion flow.
- Doctrine mutation requires explicit approval.
- Direct ledger/config mutation requires approval.
- Added Rust tests for protected writes, accepted memory and doctrine mutation.
- Updated Python benchmark proxy to match Rust policy.
