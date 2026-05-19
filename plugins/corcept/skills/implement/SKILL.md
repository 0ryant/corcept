---
description: Execute an approved CORCEPT plan with bounded local edits and evidence tracking.
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT implement

Implement only an approved plan. Keep diffs bounded. Do not change doctrine, memory, secrets, CI, dependencies, or deploy config unless explicitly in scope.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
