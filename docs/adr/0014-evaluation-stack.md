# ADR-0014: Paired evaluation stack

Status: accepted  
Date: 2026-05-18  
Tags: benchmark, evaluation, SWE-bench, Terminal-Bench, SWE-Skills-Bench, CORCEPT, governance, correctness, reasoning

## Context

CORCEPT cannot be validated by guard fixtures alone. The runtime claims are broader: improved correctness, fewer false completions, fewer unsafe tool operations, better evidence discipline, and lower memory/doctrine poisoning risk.

## Decision

Ship an evaluation suite with:

1. local deterministic governance benchmarks;
2. mini-SWE correctness tasks;
3. paired with/without command harness;
4. external adapters for SWE-Skills-Bench, SWE-bench Verified/Mini, Terminal-Bench/Harbor, LiveCodeBench, and BFCL;
5. metrics that include false success, unsafe action, stale-test completion, and cost per verified solve.

## Consequences

CORCEPT's public claims must be tied to paired benchmark results. Solve rate alone is insufficient. A result that improves solve rate while increasing unsafe operations is not considered a governance win.
