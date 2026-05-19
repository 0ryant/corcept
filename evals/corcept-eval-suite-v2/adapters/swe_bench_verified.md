# SWE-bench Verified adapter

Recommended first external sequence:

1. Run `MariusHobbhahn/swe-bench-verified-mini` for a 50-task smoke test.
2. Run `princeton-nlp/SWE-bench_Verified` for the 500-task headline benchmark.
3. Report baseline vs CORCEPT with the same model, temperature, max turns, and budget.

Collect:

- prediction patch
- task resolved or unresolved
- test output
- generated token count
- wall time
- CORCEPT ledger summary
- unsafe actions attempted/blocked
- stale-test completion events
