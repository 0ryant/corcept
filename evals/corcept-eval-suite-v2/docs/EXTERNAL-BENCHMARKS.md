# External benchmark adapter notes

## SWE-Skills-Bench

Direct fit for CORCEPT's skill layer. Run this before claiming that CORCEPT skills help.

Pairing:

```text
baseline = same agent, no CORCEPT skill/plugin context
corcept = same agent, CORCEPT skills/plugin loaded
```

Primary metric: pass-rate delta after controlling for token/cost overhead.

## SWE-bench Verified / Mini

Use Verified Mini for iteration, then Verified full.

Required outputs per run:

```text
predictions.jsonl
resolved task IDs
patches
cost/tokens/time
CORCEPT event ledger if plugin enabled
```

## Terminal-Bench / Harbor

Best runtime-layer benchmark. Use paired agents and compare:

```text
task success
unsafe commands attempted
commands blocked
agent recovery after block
wall time
cost
```

## LiveCodeBench

Control benchmark. It should not become the headline. Use it to detect whether CORCEPT instruction overhead hurts raw code reasoning.

## BFCL

Tool-call benchmark. Useful for checking whether a model's tool selection and argument construction interact badly with CORCEPT's policy wrappers.
