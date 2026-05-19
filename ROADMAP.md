---
title: Roadmap
description: Versioned roadmap for Corcept Runtime.
seo:
  title: Roadmap - Corcept Runtime
  description: Versioned roadmap for Corcept Runtime.
  keywords: ['roadmap', 'mvp', 'runtime', 'Corcept', 'Claude Code', 'Rust']
tags: ['roadmap', 'mvp', 'runtime']
status: complete
---


# Roadmap

## v0.1 scaffold-complete

- [x] Rust workspace.
- [x] CLI and installer crates.
- [x] Hook runtime.
- [x] Ledger, guard, memory, doctrine crates.
- [x] Claude Code plugin assets.
- [x] Root docs, ADRs, and subtasks.

## v0.5 doctrine parity (active)

See [`docs/BACKLOG.md`](docs/BACKLOG.md) for ST-027–ST-051 and sprint plan.

- [ ] Contracts-first ledger events + JSON Schema CI.
- [ ] Hook lifecycle FSM + policy lattice ADRs.
- [ ] CloudEvents export + log sink dispatcher.
- [ ] XDG operator paths + optional Ed25519 row signing.
- [ ] Root CI + governance workflows.

## v0.2 verification hardening

- [ ] Run full CI in Rust-enabled environment.
- [ ] Add property tests for guard pattern matching.
- [ ] Add signed artifact release.
- [ ] Add marketplace manifest once distribution path is chosen.

## v0.3 team mode

- [ ] Team policy packs.
- [ ] Read-only MCP profiles.
- [ ] Audit report renderer.
- [ ] Memory expiry enforcement.
