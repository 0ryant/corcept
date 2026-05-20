# Corcept Runtime

> Doctrine-first Claude Code governance runtime with Rust hooks, bounded
> agents, audit ledger, memory promotion, and plugin packaging.

**Status:** `v0.5-code-complete`

Corcept is a governed Claude Code runtime: a Rust workspace plus a Claude Code plugin scaffold that turns raw agentic coding into a bounded, auditable, doctrine-backed workflow.

It is intentionally not a giant prompt pack. The system is built around a smaller set of enforceable primitives:

- **PreToolUse guards** for filesystem, bash, secret, production-risk policy, package mutation, shell-mediated secret reads, and adversarial command variants.
- **PostToolUse audit** that records tool calls, file mutations, and test evidence.
- **Stop gates** that prevent premature completion when tests are stale or evidence is missing.
- **Doctrine** as explicit authority.
- **Memory promotion** as evidence-backed continuity, not model vibes.
- **Opt-in bounded MCP** via `corcept serve`, exposing only read-mostly reports and previews.
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

## Opt-in MCP server

`corcept serve` starts a local stdio MCP server bound to one project root:

```bash
corcept serve --path /path/to/repo
```

The first-party MCP surface is intentionally narrow:

- `doctor_report`
- `audit_report`
- `doctrine_validate`
- `candidate_memory_list`
- `cloudevents_preview`

It is not installed by default, it does not expose a shell bridge, and v1 does not permit hook execution, direct ledger mutation, or memory promotion over MCP.

See `docs/MCP_GUIDE.md` for setup, trust boundaries, and smoke steps.

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

## License (Gated tier)

This is a gated-tier product. It is licensed under the Business Source License
1.1 (BUSL-1.1), with the following parameters:

- **Change Date:** 2030-05-20 — on this date, this work converts to the
  Apache License, Version 2.0.
- **Additional Use Grant:** You may make production use of the Licensed Work,
  provided such use does not include offering the Licensed Work to third
  parties on a hosted or embedded basis in order to compete with the
  Licensor's paid service offerings.
- **OSS-tier alternatives:** The OSS distribution of corcept's bare verbs is
  available at https://crates.io/crates/corcept under the standard dual
  MIT OR Apache-2.0 license (pre-v0.6.0 versions).

See LICENSE for the full BUSL-1.1 text. See
`ecosystem-catalog/commercial/license-matrix.md` for the ecosystem-wide
license decision rationale. Pre-v0.6.0 LICENSE preserved at LICENSE.old.
