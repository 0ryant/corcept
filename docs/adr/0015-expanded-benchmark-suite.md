---
id: ADR-0015
title: Expanded benchmark stack
status: accepted
date: 2026-05-18
tags: [evaluation, swe-bench, terminal-bench, reasoning, correctness, benchmark]
seo:
  title: Expanded CORCEPT benchmark stack
  description: Adds SWE, terminal, reasoning, tool-use, policy-following and ML-engineering benchmark adapters.
---

# ADR-0015: Expanded benchmark stack

## Decision

CORCEPT will ship a layered benchmark stack instead of relying on a single headline benchmark.

The minimum credible public run is:

1. SWE-Skills-Bench for skill marginal utility.
2. SWE-bench Lite for cheap issue-patching iteration.
3. Terminal-Bench for terminal/runtime behaviour.
4. SWE-bench Verified for public credibility.

The extended stack includes SWE-bench Pro/Public, SWE-bench Multilingual, LiveCodeBench, BigCodeBench, EvalPlus, CRUXEval, BFCL, τ-bench, MLE-bench, RepoBench and CodeClash.

## Rationale

CORCEPT is not only a patch generator. It is a governance runtime. Public SWE benchmarks measure patch success, but they do not fully measure memory poisoning, doctrine mutation, unsafe tools, false-success completions, stale-test completions or audit quality.

## Consequence

Benchmark reports must separate:

- model reasoning/coding capability
- CORCEPT deterministic governance correctness
- CORCEPT with/without model-agent deltas
- cost/latency overhead
- safety false positives and false negatives
