---
description: Audit current work for evidence, tests, doctrine, memory, risks, and completion.
disable-model-invocation: true
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT audit

Run an evidence audit. Return pass/fail/conditional, acceptance criteria evidence, changed files, tests, stale-test status, doctrine/memory validity, and required next action.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
