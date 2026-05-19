---
title: Corcept release identity
status: accepted
date: 2026-05-18
tags: [corcept, rename, brand, release, governance]
seo:
  title: Corcept release identity architecture decision
  description: Records the repository-wide Corcept identity and package naming convention.
---

# ADR-0017: Corcept release identity

## Decision

The shipped product identity is **Corcept**. All public surfaces use the `corcept` namespace unless a lower-level runtime requires another spelling convention.

## Scope

The Corcept identity applies to:

- repository root
- Rust crate names and imports
- Claude Code plugin namespace
- skills, agents, hooks, and hook binaries
- project state directory `.corcept/`
- CLI and environment variable naming
- benchmark and eval package naming
- distribution zips
- docs, metadata, SEO tags, and search tags

## Rationale

A single identity reduces search fragmentation, package ambiguity, and operator confusion. The architecture remains doctrine-first, hook-gated, audit-ledger-backed, and benchmarkable.

## Consequences

Existing local project state should be migrated to `.corcept/`. External documentation, package names, and future release artifacts should use Corcept naming consistently.
