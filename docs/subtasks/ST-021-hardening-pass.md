---
title: ST-021 Hardening pass
status: complete
completed_at: 2026-05-18
seo:
  title: Corcept hardening pass completed
  description: Completed subtask covering command classification, secret path heuristics, adversarial guard tests, and fast ledger append.
  keywords: [Corcept, hardening, Claude Code hooks, benchmark, Rust guards]
tags: [subtask, complete, hardening, security, benchmark]
---

# ST-021: Hardening pass

## Status

Complete.

## Completed work

- Replaced exact-string Bash matching with classifier-based guard evaluation.
- Added pipe-to-shell detection for no-space and process-substitution variants.
- Added shell-mediated protected file read blocking.
- Added dependency alias approval gates.
- Added force-push and external Git side-effect approval gates.
- Added recursive-delete approval gating and root/protected recursive-delete hard blocking.
- Added secret-ish filename detection.
- Added adversarial guard tests.
- Replaced full-ledger previous-hash lookup with a last-hash sidecar and tail-line fallback.
- Added benchmark v2 artifacts.

## Evidence

- `crates/corcept-guards/src/lib.rs`
- `crates/corcept-ledger/src/lib.rs`
- `docs/adr/0013-hardened-command-classification.md`
- `benchmarks/run_corcept_benchmark_v2.py`
- `benchmarks/corcept-benchmark-report-v2.md`
- `benchmarks/corcept-benchmark-results-v2.json`
