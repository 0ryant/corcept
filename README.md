---
title: Corcept Runtime
description: Doctrine-first Claude Code governance runtime with Rust hooks, bounded agents, audit ledger, memory promotion, and plugin packaging.
seo:
  title: Corcept Runtime - governed Claude Code hooks, agents, memory, and audit ledger
  description: A Rust workspace and Claude Code plugin scaffold for safe agentic development: PreToolUse guards, PostToolUse audit, Stop gates, doctrine, memory promotion, and bounded subagents.
  keywords:
    - Claude Code plugin
    - Claude Code hooks
    - AI coding governance
    - agent audit ledger
    - Rust CLI scaffold
    - doctrine memory runtime
tags: [claude-code, rust, hooks, agents, plugin, governance, audit-ledger, memory, doctrine, corcept]
status: v0.5-code-complete
---

# Corcept Runtime

Corcept is a governed Claude Code runtime: a Rust workspace plus a Claude Code plugin scaffold that turns raw agentic coding into a bounded, auditable, doctrine-backed workflow.

It is intentionally not a giant prompt pack. The system is built around a smaller set of enforceable primitives:

- **PreToolUse guards** for filesystem, bash, secret, production-risk policy, package mutation, shell-mediated secret reads, and adversarial command variants.
- **PostToolUse audit** that records tool calls, file mutations, and test evidence.
- **Stop gates** that prevent premature completion when tests are stale or evidence is missing.
- **Doctrine** as explicit authority.
- **Memory promotion** as evidence-backed continuity, not model vibes.
- **Bounded agents** with jurisdiction, model choice, effort, and tool restrictions.
- **Namespaced Claude Code skills** for structured workflows.

## Repository shape

```text
corcept/
  Cargo.toml                  # Rust workspace
  crates/                     # Runtime, guards, ledger, memory, doctrine, CLI, installer
  plugins/corcept/         # Claude Code plugin scaffold
  schemas/                    # JSON schemas for config, events, memory, doctrine, hook IO
  docs/adr/                   # Architecture decision records
  docs/subtasks/              # Completed implementation subtasks
  docs/                       # Product, architecture, API, plugin, security docs
  examples/                   # Hook input fixtures and example generated project
  tests/                      # Integration fixture notes
```

## Build

```bash
make check                  # fmt + clippy + test + contracts (CI parity)
cargo build --release -p corcept-cli
```

Released binaries are named `corcept` (see `.github/workflows/release.yml`).

## v0.5 — doctrine parity (code complete)

- Versioned ledger events (`corcept.event.*.v1`) + JSON Schema contracts
- Hook FSM transition IDs, policy lattice, hardened hash chain
- CloudEvents export, multi-sink dispatch (ledger authority + best-effort ops sinks)
- XDG operator paths, Ed25519 signed ledger rows (`corcept audit verify --signed`)
- CI: `quality.yml`, `governance.yml`, `eval-regression.yml`, tag-triggered `release.yml`

```bash
corcept doctor --strict
corcept audit verify
corcept audit verify --signed
corcept export cloudevents --ledger .corcept/ledger/events.jsonl --out /tmp/ce.jsonl
corcept key generate
```

## Install into a target repo

```bash
cargo run -p create-corcept -- --path /path/to/repo --dry-run
cargo run -p create-corcept -- --path /path/to/repo
```

or with the CLI:

```bash
cargo run -p corcept-cli -- init --path /path/to/repo --dry-run
cargo run -p corcept-cli -- init --path /path/to/repo
```

## Test the plugin locally

```bash
claude --plugin-dir ./plugins/corcept
```

Plugin skills are namespaced, for example:

```text
/corcept:intake
/corcept:plan-change
/corcept:review
/corcept:ship
```

## Hook contract

The hook binaries in `plugins/corcept/bin/` delegate to the `corcept` CLI:

```text
SessionStart      -> corcept hook session-start
UserPromptSubmit  -> corcept hook user-prompt-submit
PreToolUse        -> corcept hook pretool-guard
PostToolUse       -> corcept hook posttool-audit
Stop              -> corcept hook stop-check
```

Each hook reads Claude Code hook JSON from stdin and writes Claude Code hook JSON to stdout.

## Release

Tag `v0.5.0` (or later `v*.*.*`) triggers `.github/workflows/release.yml`:

- Quality gate (`make check`)
- Platform binaries + plugin zip + `SHA256SUMS`
- Optional minisign when `MINISIGN_SECRET_KEY` is set (see `docs/release-trust.md`)
