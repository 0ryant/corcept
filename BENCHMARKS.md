# CORCEPT Benchmark Plan

CORCEPT must be evaluated as a runtime, not just a coding prompt.

## Minimum credible stack

1. SWE-Skills-Bench — skill marginal utility.
2. SWE-bench Lite — cheap real issue patching.
3. Terminal-Bench — terminal/runtime behaviour.
4. SWE-bench Verified — public headline patching result.

## Extended controls

- SWE-bench Pro/Public for long-horizon enterprise-like issues.
- SWE-bench Multilingual for language generalisation.
- LiveCodeBench, BigCodeBench, EvalPlus and CRUXEval for code reasoning/correctness controls.
- BFCL for tool-calling correctness.
- τ-bench for policy-following with tools.
- MLE-bench for ML-engineering/research workflows.
- RepoBench for repository-level context selection.
- CodeClash for iterative goal-oriented development.

## Metrics

- verified pass rate
- false-success rate
- stale-test completion rate
- unsafe action rate
- scope-violation rate
- policy false-positive rate
- token/cost per successful task
- wall-time per successful task
- tool calls per successful task
- audit completeness
- memory/doctrine mutation violations

## Rule

Any public result must report exact model, agent harness, benchmark commit/version, task subset, random seed if relevant, cost, verifier, and CORCEPT version.
