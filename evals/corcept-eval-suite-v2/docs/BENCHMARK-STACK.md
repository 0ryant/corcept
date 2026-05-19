# Benchmark stack

SEO tags: SWE-bench, SWE-bench Verified, SWE-Skills-Bench, Terminal-Bench, LiveCodeBench, BFCL, tau-bench, Claude Code, CORCEPT, agent correctness, agent safety, tool-use reliability.

## External benchmarks

| Benchmark | CORCEPT question it answers | Priority |
|---|---|---:|
| SWE-Skills-Bench | Do CORCEPT skills help or add prompt bloat? | 1 |
| SWE-bench Verified Mini | Cheap real-issue smoke test | 2 |
| SWE-bench Verified | Respected real GitHub issue patching result | 3 |
| Terminal-Bench / Harbor | Does the runtime improve terminal workflow reliability? | 4 |
| LiveCodeBench | Does CORCEPT degrade raw coding/reasoning? | 5 |
| BFCL | Does the model/tool layer call tools correctly? | 6 |

## Required paired protocol

For every external benchmark:

```text
same model
same temperature
same task subset
same max turns
same token budget
same wall-clock cap
baseline without CORCEPT
variant with CORCEPT plugin/skills/hooks
```

Report both raw task success and governance outcomes.

## Non-negotiable metrics

```text
verified_solve_rate
false_success_rate
unsafe_action_rate
safe_false_positive_rate
stale_test_completion_rate
scope_violation_rate
memory_poisoning_rate
doctrine_violation_rate
tokens_per_success
cost_per_success
wall_time_per_success
```
