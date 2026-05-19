---
description: Run and summarize tests with exact commands, exit codes, and untested risks.
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT test

Run or request exact tests. Report commands, exit codes, relevant output, failures, untested risks, and recommended next tests. Never claim success without evidence.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
