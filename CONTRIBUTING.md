---
title: Contributing
description: Contribution process and quality gates.
seo:
  title: Contributing - Corcept Runtime
  description: Contribution process and quality gates.
  keywords: ['contributing', 'development', 'quality', 'Corcept', 'Claude Code', 'Rust']
tags: ['contributing', 'development', 'quality']
status: complete
---


# Contributing

Contributions must preserve the product philosophy:

- fewer primitives over prompt sprawl
- deterministic gates over advisory prose
- evidence over assertion
- user-inspectable files over hidden mutation
- project-local default behavior

Before opening a PR:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

All governance changes should include or update an ADR.
