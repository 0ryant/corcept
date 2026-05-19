---
title: ADR-0013 Hardened Command Classification
status: accepted
date: 2026-05-18
seo:
  title: Hardened command classification for Corcept guards
  description: Decision record for adversarial shell parsing, package mutation gates, protected path detection, and fast ledger append semantics.
  keywords: [Corcept, Claude Code hooks, PreToolUse, shell guard, command classification, security]
tags: [adr, security, hooks, pretooluse, command-classification, benchmark]
---

# ADR-0013: Hardened Command Classification

## Context

The first benchmark showed that the original guard logic blocked obvious unsafe operations but missed shell-mediated variants: `sudo rm -rf /`, no-space pipe-to-shell, package-manager aliases, force-push variants, shell reads of `.env`, and secret-ish filenames such as `secrets.env`.

The ledger path also read the entire JSONL file to find the previous hash before every append, creating O(n) append growth.

## Decision

CORCEPT now treats Bash commands as a classified shell surface rather than exact strings only.

The guard layer adds deterministic classifiers for:

- remote pipe-to-shell execution with or without whitespace,
- `bash <(curl ...)` / shell command-substitution fetch execution,
- recursive deletes, distinguishing root/protected targets from local deletes,
- world-writable recursive `chmod`,
- shell-mediated reads of protected paths via `cat`, `grep`, `sed`, `awk`, `head`, `tail`, etc.,
- package-manager mutations and aliases such as `npm i`, `cargo add`, `uv pip install`,
- git external/destructive actions such as `git push`, `git reset`, and `git clean`,
- infra/container commands such as `kubectl`, `terraform`, `docker`, and `helm`,
- privilege escalation through `sudo`, `doas`, or `su`,
- secret-ish filenames beyond exact `.env` matching.

The ledger `last_hash` implementation now uses a `last_hash` sidecar for normal appends and falls back to reading the last non-empty JSONL line if the sidecar is missing. It no longer parses the full ledger on each append.

## Consequences

The guard path becomes more conservative around side effects and secret disclosure while keeping routine local inspection commands allowed. Recursive local deletes now require approval instead of being silently allowed. Direct reads of secret-ish files are denied. Protected writes remain approval-gated rather than denied so users can intentionally edit local env templates or credential placeholders when explicitly approved.

The runtime keeps the hash-chain ledger semantics but removes the previous O(n) append growth. Verification still reads the whole ledger by design and refreshes the sidecar after a valid chain check.
