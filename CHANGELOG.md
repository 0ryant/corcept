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


## v0.4.0-fullship — 2026-05-18

- Added CORCEPT Eval Suite v0.2 with expanded benchmark registry.
- Added mini code-reasoning paired harness.
- Added benchmark runbook and list-benchmarks CLI.
- Hardened Rust write guards for protected files, accepted memory, doctrine, config and ledger.
- Added ADR-0015 and ADR-0016.
- Added ST-023, ST-024 and ST-025.
- Consolidated all shippable artifacts into one fullship archive.
