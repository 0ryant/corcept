---
description: Final readiness gate before PR, release, merge, or deployment.
disable-model-invocation: true
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT ship

Perform final readiness check. Shipping is not allowed without explicit evidence for tests, changed files, unresolved risks, and acceptance criteria.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
