# CORCEPT External Benchmark Runbook

Run every benchmark paired where possible: same model, same task, same repository/container, same verifier; only CORCEPT changes.

Primary metrics: verified pass rate, false-success rate, unsafe action rate, stale-test completion rate, token/cost per success, latency, scope-violation rate.

| Priority | Benchmark | Signal | Paired | Best for |
|---:|---|---|---|---|
| 1 | `swe_skills_bench` | skill_marginal_utility | true | skills, prompt_bloat_detection, with_without_corcept_delta |
| 2 | `swe_bench_lite` | real_issue_patch_success_cheap_iteration | true | iteration, patch_correctness, cost_control |
| 3 | `swe_bench_verified` | public_credibility_repo_patch_success | true | headline_result, patch_correctness |
| 4 | `swe_bench_multilingual` | multi_language_repo_patch_success | true | language_generalisation |
| 5 | `swe_bench_pro_public` | long_horizon_enterprise_swe | true | long_horizon, large_codebase, scope_control |
| 6 | `terminal_bench` | terminal_agent_runtime_reliability | true | hooks, bash_policy, runtime_workflows, recovery |
| 7 | `livecodebench` | fresh_code_reasoning_control | true | reasoning_regression, self_repair_control |
| 8 | `bigcodebench` | practical_function_level_code_generation | true | code_generation_control, tool_like_function_reasoning |
| 9 | `evalplus` | robust_unit_test_correctness | true | unit_correctness_regression, prompt_bloat_detection |
| 10 | `cruxeval` | code_reasoning_execution_understanding | true | reasoning_control, execution_understanding |
| 11 | `bfcl` | tool_call_correctness | false | tool_use_control, schema_following |
| 12 | `tau_bench` | policy_following_tool_agent_reliability | true | doctrine, authority, policy_following |
| 13 | `mle_bench` | ml_engineering_long_horizon | true | research_engineering, experiment_discipline |
| 14 | `repobench` | repository_level_retrieval_completion | true | context_selection, repo_reasoning_control |
| 15 | `codeclash` | goal_oriented_iterative_swe | true | longitudinal_agents, memory, iteration |

## Minimum credible public run

1. SWE-Skills-Bench: tests whether the CORCEPT skill layer helps or hurts.
2. SWE-bench Lite: cheap repo-patching iteration.
3. Terminal-Bench: tests the runtime/hook layer under real terminal workflows.
4. SWE-bench Verified: public headline once the harness is stable.

## Do not report

- Local guard-suite accuracy as model reasoning improvement.
- Any external benchmark result without exact model, harness, commit, task subset, cost, and verifier version.
