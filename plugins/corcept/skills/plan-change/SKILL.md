---
description: Create a bounded implementation plan with scope, risks, test plan, and rollback path.
disable-model-invocation: true
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT plan-change

Create a plan for `$ARGUMENTS`. Include files_in_scope, files_out_of_scope, acceptance_criteria, steps, test_plan, rollback_plan, and approval_needed. Do not edit files.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
