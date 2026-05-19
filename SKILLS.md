# Skills — corcept

> Golden agent-facing recipes for the doctrine-first Claude Code governance
> runtime. Audience: AI agents (Claude / Cursor / Codex / etc.) and the
> humans configuring them.

## When to reach for this repo

Reach for corcept when an agent session needs **hook-level governance** over
Claude Code: PreToolUse deny on destructive operations, PostToolUse audit
emission to an append-only ledger, Stop-gate enforcement of test/evidence
freshness, and bounded sub-agent launches. Do NOT reach for corcept when you
just need memory recall (use cortex), context packing (use cordance), or
doctrine lookup (use doctrine-mcp). Corcept is the **runtime hook surface** —
the other repos supply the memory, context, and authority that hooks consume.

## Skills index

- [install-hooks-first](#skill-install-hooks-first) — bootstrap hooks into a target repo before any governed session
- [pretool-deny-pattern](#skill-pretool-deny-pattern) — configure PreToolUse to deny destructive operations
- [posttool-audit-emission](#skill-posttool-audit-emission) — every tool call generates a `corcept.event.tool_use.v1` ledger row
- [stop-check-with-evidence](#skill-stop-check-with-evidence) — Stop hook blocks premature completion when tests are stale
- [bounded-subagent-launch](#skill-bounded-subagent-launch) — sub-agents launch with jurisdiction / model / effort / tool restrictions

---

## Skill: install-hooks-first

**When:** Starting work in a target repo that has not yet been initialised with
corcept hooks. This is the prerequisite for every other skill in this file —
without it, no PreToolUse / PostToolUse / Stop hook fires and there is no
ledger row to verify against.

**How (golden invocation):**

```bash
cargo run -p corcept-cli -- init --path /path/to/repo --dry-run
cargo run -p corcept-cli -- init --path /path/to/repo
```

The dry-run prints the file plan (hook binaries, `plugins/corcept/hooks/hooks.json`,
`.corcept/` ledger directory, schemas) without writing. The second invocation
applies it.

**Expected output:** A populated `plugins/corcept/` directory with `hooks/hooks.json`
wired to the five hook binaries (`corcept-session-start`,
`corcept-user-prompt-submit`, `corcept-pretool-guard`,
`corcept-posttool-audit`, `corcept-stop-check`), plus an empty
`.corcept/ledger/events.jsonl` ready to receive rows.

**Common pitfalls:**
- Running `init` without `--dry-run` first on a repo with pre-existing
  `plugins/corcept/` content — the installer refuses to overwrite protected
  files (ADR 0010). Inspect the dry-run plan before applying.
- Forgetting to commit the generated `plugins/corcept/` scaffold — hooks
  cannot fire from an uncommitted file tree in some Claude Code configurations.

**See also:** `docs/adr/0009-dry-run-installer.md`, `docs/adr/0010-protected-files-policy.md`.

---

## Skill: pretool-deny-pattern

**When:** You need to block specific destructive operations (e.g.
`git push --force`, `rm -rf`, package mutation, shell-mediated secret reads)
before they execute. PreToolUse runs before Claude Code dispatches the tool —
this is the only place to **prevent** an action, not just record it.

**How (golden invocation):**

The matcher in `plugins/corcept/hooks/hooks.json` already covers
`Bash|Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch`.
The guard binary delegates to:

```bash
corcept hook pretool-guard < hook-input.json > hook-output.json
```

To add a new deny rule, extend the guard rules under
`crates/corcept-guards/` (filesystem / bash / secret / production-risk /
package-mutation / shell-mediated-secret / adversarial variants are already
wired) and re-run `make check`.

**Expected output:** Hook JSON on stdout with `"decision": "block"` and a
`reason` field; Claude Code surfaces the reason to the user and does not
dispatch the tool. A `corcept.event.pretool_guard.v1` row is appended to
`.corcept/ledger/events.jsonl` as evidence.

**Common pitfalls:**
- Writing a deny rule without a matching test fixture in
  `examples/hook-inputs/` — the guard FSM transition table (ADR 0019) requires
  a fixture per branch.
- Returning a non-zero exit instead of a `"block"` decision — Claude Code
  treats process-level failure as advisory, not authoritative.

**See also:** `docs/adr/0013-hardened-command-classification.md`,
`docs/adr/0019-hook-lifecycle-state-machine.md`,
`docs/adr/0020-guard-stop-gate-composition.md`.

---

## Skill: posttool-audit-emission

**When:** Every Bash / Edit / Write / MultiEdit / NotebookEdit tool call must
produce a ledger row. PostToolUse fires after Claude Code completes the tool;
the row records the call, any file mutations, and (if Bash) the exit status.

**How (golden invocation):**

The PostToolUse matcher in `plugins/corcept/hooks/hooks.json`
(`Bash|Edit|Write|MultiEdit|NotebookEdit`) routes to:

```bash
corcept hook posttool-audit < hook-input.json > hook-output.json
```

To verify ledger integrity after a session:

```bash
corcept audit verify
corcept audit verify --signed   # if Ed25519 signing is configured
```

**Expected output:** Append-only JSONL row matching
`schemas/corcept.event.tool_use.v1.json` with `event_id`, `tool_name`,
`input_hash`, `mutation_summary`, `prev_hash` (hash chain link), and
optional `signature`. `audit verify` returns success iff the chain is intact.

**Common pitfalls:**
- Tampering with `.corcept/ledger/events.jsonl` by hand — the hash chain
  (ADR 0006) breaks immediately and `audit verify` will fail loudly.
- Running long-running tool calls without rotating the ledger — the file
  grows unbounded. Use `corcept export cloudevents --ledger ... --out ...`
  to emit downstream and archive (see `docs/adr/0018-versioned-ledger-event-types.md`).

**See also:** `docs/adr/0006-event-ledger-hash-chain.md`,
`docs/adr/0018-versioned-ledger-event-types.md`,
`schemas/corcept.event.tool_use.v1.json`.

---

## Skill: stop-check-with-evidence

**When:** Claude Code is about to declare a task complete (the Stop event
fires). Corcept blocks completion when **tests are stale** (no `cargo test`
ledger row newer than the latest source mutation) or **evidence is missing**
(an expected artefact / receipt is not present in the ledger).

**How (golden invocation):**

The Stop matcher in `plugins/corcept/hooks/hooks.json` (empty matcher = all
Stop events) routes to:

```bash
corcept hook stop-check < hook-input.json > hook-output.json
```

Configure evidence requirements via `corcept doctrine` rules; the stop-check
evaluator reads the current doctrine and checks the ledger for the required
event types since the last source mutation.

**Expected output:** Hook JSON with `"decision": "block"` and a `reason`
naming the missing evidence (e.g. `"test run stale: last cargo test row at
event_id 0x42; source mutation at event_id 0x48"`). The agent must run tests
(or generate the missing evidence) and re-emit Stop.

**Common pitfalls:**
- Treating a Stop block as a bug — it is the design. The Stop gate
  (ADR 0020) is the only place that enforces evidence-completeness across an
  entire session. If the block is wrong, fix the doctrine rule, not the gate.
- Running `corcept doctor --strict` and seeing green but Stop still blocks —
  doctor reports static health; Stop reports dynamic ledger state. Both must
  be green before promotion.

**See also:** `docs/adr/0007-memory-promotion.md`,
`docs/adr/0020-guard-stop-gate-composition.md`,
`docs/RELEASE_GATES.md`.

---

## Skill: bounded-subagent-launch

**When:** A complex task needs sub-agents (architect / implementer / auditor /
reviewer / security / test-runner / memory-curator) and each sub-agent must
operate within a **bounded authority surface**: jurisdiction (file/path
scope), model choice, effort budget, and explicit tool allowlist.

**How (golden invocation):**

Sub-agent definitions live in `plugins/corcept/agents/` (one `.md` per agent
role). Launch via the namespaced skill:

```text
/corcept:plan-change       # opens the architect sub-agent
/corcept:implement         # opens the implementer sub-agent
/corcept:review            # opens the reviewer sub-agent
/corcept:audit             # opens the auditor sub-agent
/corcept:threat-model      # opens the security sub-agent
```

Each agent `.md` declares its jurisdiction (e.g. `crates/corcept-guards/`),
its tool allowlist (e.g. `Read | Grep | Edit` but **not** `Bash` or
`WebFetch`), and its effort hint. The principal agent enforces these via
PreToolUse — out-of-scope tool calls are denied by the same guard surface
that blocks destructive operations.

**Expected output:** Sub-agent runs to completion within its bounds; its
tool calls produce ledger rows tagged with the agent role. The principal
receives the sub-agent's final report and decides next steps.

**Common pitfalls:**
- Launching the implementer with `Bash` enabled across the full workspace
  when only one crate is in scope — narrow the jurisdiction in the agent
  `.md` instead of relying on the implementer to self-limit.
- Skipping the auditor / reviewer steps because "the implementer was
  careful" — the audit and review sub-agents read the ledger, not the diff.
  Their findings are independent of implementer prose.

**See also:** `docs/adr/0005-authority-model.md`,
`docs/adr/0011-skill-inventory.md`,
`plugins/corcept/agents/`.

---

## Skills via MCP (mcpact-generated)

corcept-cli is also exposed as an MCP server compiled by mcpact. The MCP tools mirror the CLI subcommands with typed authority classes and policy gates. Spin up the MCP server with:

```bash
corcept mcp serve
```

| Tool | Authority class | Trust ceiling | When |
|------|-----------------|---------------|------|
| corcept_doctor | Observe | Reviewed | Health checks before trusting other tools |
| corcept_hook_session_start | Analyze | Reviewed | Programmatic session-start event ingestion |
| corcept_hook_pretool_guard | Plan | Reviewed | Driver-driven gate decisions |
| corcept_hook_posttool_audit | Mutate | Signed | Driver-driven audit row writes |
| corcept_hook_stop_check | Plan | Reviewed | Completion gating |
| corcept_audit_verify | Observe | Signed | Hash-chain integrity reads |
| corcept_export_cloudevents | Observe | Reviewed | Ledger-to-CloudEvents conversion |
| corcept_key_generate | Credential | Verified | Approval-gated Ed25519 keygen |

The MCP surface is the recommended path for non-Claude-Code agents to drive corcept's governance. Claude Code itself continues to use the hook surface directly.

### Skill: corcept-as-mcp-server-for-agents

**When:** the agent / driver is not Claude Code, but still needs corcept's hook-state and audit chain.

**How (golden invocation):**

```bash
corcept mcp serve --workdir <path> &
# then call via MCP transport:
#   tool: corcept_audit_verify
#   params: { "ledger_path": "<path>/.corcept/ledger" }
```

**Expected output:** JSON-RPC 2.0 over stdio; tools follow `corcept_*` naming; authority classes carried in tool annotations.

**Common pitfalls:**
- Hook-event ingestion via MCP does NOT replace Claude Code hooks; both surfaces are valid and can run in parallel.
- `corcept_key_generate` requires explicit approval gate; will refuse without it.

**See also:** `docs/MCP_GUIDE.md` (if present, otherwise the generated crate's README).

---

## How this repo composes with the ecosystem

Corcept supplies the **runtime hook surface**. Its ledger rows feed taudit's
authority graph as evidence, cortex consumes session-close events for memory
promotion (gated by the trust-exchange admission flow), doctrine-mcp answers
"is this allowed?" queries the guards consult, and tapprove reviews diffs
that corcept's PostToolUse rows attest to. The typical wire is:
`cordance pack → corcept session → cortex memory candidate → tapprove review`.

## What this repo will NOT do

Corcept will not store memories, pack context, lookup doctrine, or review
diffs — those are sibling responsibilities. It will not expose hook
execution, ledger mutation, or memory promotion over its bounded MCP surface
(ADR 0008): `corcept serve` exposes read-mostly reports (`doctor_report`,
`audit_report`, `doctrine_validate`, `candidate_memory_list`,
`cloudevents_preview`) and nothing else. Live runtime writes outside the
hook contract are out of scope.
