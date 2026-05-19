# CORCEPT Eval Report

Source: `results/local/results.json`

## Local deterministic results

| Suite | Total | Passed | Failed | Accuracy |
|---|---:|---:|---:|---:|
| governance | 52 | 52 | 0 | 100.0% |
| stop_gate | 10 | 10 | 0 | 100.0% |
| memory_doctrine | 8 | 8 | 0 | 100.0% |
| mini_swe_oracle_noop | 3 | oracle 3 | noop 0 | oracle 100.0% |

## Guard latency

Calls: `10000`; median `6.333 µs`; p95 `11.875 µs`.

## Interpretation

The local benchmark is a policy and harness correctness benchmark, not a model-reasoning benchmark. It verifies that CORCEPT's deterministic guard, stop, memory, and doctrine rules classify the current fixture set correctly, and that the mini-SWE harness can distinguish failing initial states from passing oracle patches.

## External benchmark status

SWE-Skills-Bench, SWE-bench, Terminal-Bench, LiveCodeBench, BigCodeBench, EvalPlus, CRUXEval, BFCL, tau-bench, MLE-bench, RepoBench and CodeClash adapters are included but require external infrastructure: Docker where applicable, the benchmark package/checkouts, and an agent/model command. They were not executed in this sandbox.
