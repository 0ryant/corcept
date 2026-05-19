---
description: Perform adversarial security and prompt-injection review for a change.
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT threat-model

Review secrets, auth, authorization, input validation, data leakage, network calls, dependencies, prompt injection, and production side effects.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
