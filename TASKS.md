---
title: Completed Tasks
description: Completed subtasks for the generated scaffold.
seo:
  title: Completed Tasks - Corcept Runtime
  description: Completed subtasks for the generated scaffold.
  keywords: ['tasks', 'completed', 'subtasks', 'Corcept', 'Claude Code', 'Rust']
tags: ['tasks', 'completed', 'subtasks']
status: complete
---


# Completed Tasks

| ID | Task | Status | Artifact |
|---|---|---:|---|
| ST-001 | Define governance product shape | complete | `docs/adr/0001-doctrine-first-runtime.md` |
| ST-002 | Create Rust workspace | complete | `Cargo.toml`, `crates/*` |
| ST-003 | Implement shared types | complete | `crates/corcept-types` |
| ST-004 | Implement ledger hash chain | complete | `crates/corcept-ledger` |
| ST-005 | Implement pre-tool guards | complete | `crates/corcept-guards` |
| ST-006 | Implement doctrine loader | complete | `crates/corcept-doctrine` |
| ST-007 | Implement memory promotion | complete | `crates/corcept-memory` |
| ST-008 | Implement runtime orchestration | complete | `crates/corcept-runtime` |
| ST-009 | Implement CLI | complete | `crates/corcept-cli` |
| ST-010 | Implement installer binary | complete | `crates/create-corcept` |
| ST-011 | Write plugin manifest | complete | `plugins/corcept/.claude-plugin/plugin.json` |
| ST-012 | Write Claude Code skills | complete | `plugins/corcept/skills/*` |
| ST-013 | Write bounded agents | complete | `plugins/corcept/agents/*` |
| ST-014 | Wire hooks | complete | `plugins/corcept/hooks/hooks.json` |
| ST-015 | Write hook wrappers | complete | `plugins/corcept/bin/*` |
| ST-016 | Write schemas | complete | `schemas/*` |
| ST-017 | Write root docs | complete | root `*.md` |
| ST-018 | Write ADRs | complete | `docs/adr/*` |
| ST-019 | Write subtask files | complete | `docs/subtasks/*` |
| ST-020 | Package scaffold zip | complete | generated artifact |
| ST-021 | Harden guard classifiers and ledger append path | complete | `docs/adr/0013-hardened-command-classification.md`, `crates/corcept-guards`, `crates/corcept-ledger` |


## Completed in v0.4.0-fullship

- ST-022 evaluation suite — completed (`docs/subtasks/ST-022-evaluation-suite.md`, paired benchmarks in `results/paired-latest/`).
- ST-023 expanded external benchmark adapters — completed.
- ST-024 policy-aligned guard benchmark — completed.
- ST-025 single fullship zip — completed.
- ST-026 corcept release rename — completed.

## Completed in v0.5 doctrine parity (code complete)

Full plan: [`docs/BACKLOG.md`](docs/BACKLOG.md) · [`docs/PARITY-TASKS.md`](docs/PARITY-TASKS.md)

| ID | Task | Status | Artifact |
|---|---|---:|---|
| ST-027 | Vendored minimum viable doctrine | complete | `.doctrine/`, `docs/doctrine-adoption-map.md` |
| ST-028 | Root CI quality workflow | complete | `.github/workflows/quality.yml` |
| ST-029 | Governance supply-chain workflow | complete | `.github/workflows/governance.yml`, `docs/RELEASE_GATES.md` |
| ST-030 | contracts/ tree and examples | complete | `contracts/` |
| ST-031 | Runtime schema validation | complete | `corcept-contract` |
| ST-032 | Versioned event type registry | complete | ADR-0018, `corcept-types` |
| ST-033 | Hook lifecycle FSM | complete | ADR-0019 |
| ST-034 | Policy composition lattice | complete | ADR-0020, `corcept-guards` |
| ST-035 | Wait states and timeouts | complete | `docs/audit/TIMEOUTS.md` |
| ST-036 | Canonical hash hardening | complete | ADR-0021, `corcept-ledger` |
| ST-037 | Ledger contract test suite | complete | `tests/fixtures/hooks/` |
| ST-038 | Audit operation registry | complete | `docs/audit/operations.yaml` |
| ST-039 | CloudEvents boundary ADR | complete | ADR-0022 |
| ST-040 | CloudEvents sink crate | complete | `corcept-sink-cloudevents` |
| ST-041 | Cross-surface contract tests | complete | `corcept-sink-cloudevents/tests/` |
| ST-042 | Testing ADR enforceable matrix | complete | ADR-0012 revision |
| ST-043 | Adversarial abuse-case corpus | complete | `tests/adversarial/` |
| ST-044 | Eval harness contract gate | complete | `eval-regression.yml` |
| ST-045 | Property-based tests | complete | proptest |
| ST-046 | Cortex/pai-axiom boundary stubs | complete | ADR-0023 |
| ST-047 | XDG path layout | complete | ADR-0024, `paths.rs` |
| ST-048 | Ed25519 signed ledger rows | complete | ADR-0025 |
| ST-049 | Runtime logging vs audit ledger | complete | `docs/audit/LOGGING.md`, DebugLogSink |
| ST-050 | Release artifact signing | complete | `docs/release-trust.md` |
| ST-051 | Log sink architecture | complete | ADR-0026, `corcept-sink` |
