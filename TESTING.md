---
title: Testing
description: Unit, fixture, integration, hook, and plugin validation strategy.
seo:
  title: Testing - Corcept Runtime
  description: Unit, fixture, integration, hook, and plugin validation strategy.
  keywords: ['testing', 'rust', 'fixtures', 'hooks', 'Corcept', 'Claude Code', 'Rust']
tags: ['testing', 'rust', 'fixtures', 'hooks']
status: complete
---


# Testing

The workspace contains unit tests in each crate and fixture-driven examples under `examples/fixtures/`.

Recommended CI gate:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Critical scenarios

- PreToolUse denies destructive bash.
- PreToolUse asks for package installation.
- PreToolUse denies secret-like reads.
- PreToolUse asks for protected writes.
- PostToolUse appends ledger events.
- Stop blocks stale tests.
- Memory candidate must include evidence.
- Doctrine directory validates.
- Installer dry-run writes nothing.
