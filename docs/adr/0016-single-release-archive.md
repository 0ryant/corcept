---
id: ADR-0016
title: Single release archive
status: accepted
date: 2026-05-18
tags: [release, packaging, zip, artifact, distribution]
seo:
  title: CORCEPT single release archive packaging
  description: Defines one canonical fullship zip containing source, plugin, evals, docs, manifests, checksums and local results.
---

# ADR-0016: Single release archive

## Decision

Ship one canonical archive named `corcept-fullship-v4.zip`.

It contains:

- full Rust workspace scaffold
- Claude Code plugin directory
- standalone plugin zip
- eval suite v0.2
- deterministic local eval results
- benchmark registry and runbook
- release manifest
- checksums
- ADRs, subtasks and root docs

## Rationale

A single archive prevents artifact drift. Earlier standalone scaffold/plugin/eval zips were useful during iteration, but shipping requires one inspectable source of truth.

## Consequence

All nested artifacts must be regenerated from the same source tree before final packaging. Checksums are generated last.
