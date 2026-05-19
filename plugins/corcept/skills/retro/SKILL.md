---
description: Produce a retrospective from ledger evidence and propose follow-up improvements.
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT retro

Use the ledger to identify what happened, what worked, what failed, what memory candidates are justified, and what doctrine changes are not justified.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
