---
description: Classify a task, identify authority level, risks, likely files, agents, and acceptance criteria.
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(corcept *) Bash(cargo test *) Bash(npm test *) Bash(pnpm test *)
---

# CORCEPT intake

Return YAML with task.class, authority_required, likely_files, required_agents, acceptance_criteria, risks, and unknowns. Do not implement.

## Output discipline

- Surface assumptions and uncertainty.
- Prefer YAML or concise structured sections.
- Cite ledger, file, command, or test evidence when making completion claims.
- Do not claim tests passed unless the command was actually run or provided by the user.
