---
description: Validate CORCEPT installation, hooks, config, doctrine, memory, and ledger.
disable-model-invocation: true
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT doctor

Validate CORCEPT installation and report missing config, hooks, doctrine, memory, ledger, and plugin wiring.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
