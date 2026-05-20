---
title: Changelog
description: Changelog for scaffold versions.
seo:
  title: Changelog - Corcept Runtime
  description: Changelog for scaffold versions.
  keywords: ['changelog', 'release-notes', 'Corcept', 'Claude Code', 'Rust']
tags: ['changelog', 'release-notes']
status: complete
---


# Changelog

## Unreleased

- Added `detect_interpreter_wrapper` to close failure-mode CC-2: shell-mediated
  indirection patterns (`bash -c`, `sh -c`, `zsh -c`, `powershell -Command`,
  `cmd /c`) now produce a Deny verdict regardless of inner intent. Wired at
  the head of `evaluate_bash` so it runs before all per-token guards.
  Adversarial corpus expanded with 5 wrapper scenarios. New tests:
  `tests::test_interpreter_wrapper_class_is_blocked` and
  `tests::test_interpreter_wrapper_does_not_overmatch_safe_commands`.
  Reference: value-sheet/18-cross-product-test/v2/results/per-tool-failure-mode-tests-results/composite.md.

## 0.1.1 - hardened-scaffold

- Hardened Bash guard classification for adversarial command variants.
- Added dependency alias, Git side-effect, recursive-delete, env-dump, and shell-mediated secret-read gates.
- Expanded secret-ish protected path detection.
- Changed ledger previous-hash lookup from full-file parse to tail-line read.
- Added ADR-0013 and ST-021 hardening records.
- Added benchmark v2 script and results.

## 0.1.0 - scaffold-complete

- Added Rust workspace with eight crates.
- Added CLI, installer, runtime, guards, ledger, memory, and doctrine implementations.
- Added Claude Code plugin scaffold with skills, agents, hooks, and binaries.
- Added JSON schemas, ADRs, completed subtasks, root docs, examples, and CI wiring.


## 0.1.2 - Evaluation suite

- Added CORCEPT Eval Suite v0.1.
- Added paired baseline-vs-CORCEPT harness.
- Added external benchmark adapters and local deterministic results.


## v0.5.0 — 2026-05-19

Doctrine parity code-complete release (ST-027–ST-051).

- Versioned ledger events, FSM, policy lattice, canonical hash, adversarial corpus.
- CloudEvents + receipt sinks with XDG data-home layout (`corcept-sink`, `corcept-types/paths`).
- Ed25519 row signing (`RowSignature`), operator key management, `corcept audit verify --signed`.
- Contract validation in `corcept doctor --strict`; eval regression CI gate.
- Governance workflows (gitleaks, cargo-audit, supply-chain gate).
- Tag-triggered release workflow: multi-platform CLI, plugin zip, SHA256SUMS, optional minisign.

## v0.4.0-fullship — 2026-05-18

- Added CORCEPT Eval Suite v0.2 with expanded benchmark registry.
- Added mini code-reasoning paired harness.
- Added benchmark runbook and list-benchmarks CLI.
- Hardened Rust write guards for protected files, accepted memory, doctrine, config and ledger.
- Added ADR-0015 and ADR-0016.
- Added ST-023, ST-024 and ST-025.
- Consolidated all shippable artifacts into one fullship archive.
