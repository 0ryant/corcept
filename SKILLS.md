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
corcept audit verify --signed   # only meaningful when rows were signed at append time
```

**Signing is opt-in, not on-by-default.** Even after `corcept key generate`
provisions an Ed25519 key, ledger rows are appended **unsigned** unless the
append path is explicitly opted in via `CORCEPT_SIGN_LEDGER=1` (the
`should_sign_append()` check in `crates/corcept-ledger/src/lib.rs:159-164`).
`corcept audit verify --signed` then re-checks each row's signature; it does
not retroactively sign unsigned rows. Default v0.5.0 posture is hash-chained
but unsigned — signed rows are an explicit operator opt-in (key generation
plus the env var on the writer).

**Expected output:** Append-only JSONL row matching
`schemas/corcept.event.tool_use.v1.json` with `event_id`, `tool_name`,
`input_hash`, `mutation_summary`, `prev_hash` (hash chain link), and
optional `signature` (present only when `CORCEPT_SIGN_LEDGER=1` was set at
append time). `audit verify` returns success iff the chain is intact.

**Common pitfalls:**
- Assuming signed rows out of the box because `corcept key generate` ran.
  Key provisioning is necessary but not sufficient; the writer process must
  also see `CORCEPT_SIGN_LEDGER=1` in its environment.
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
fires). Corcept blocks completion when **source files have changed after the
last recorded passing test run** — concretely, when a `Bash`/`Edit`/`Write`
mutation to a tracked source path is recorded in the ledger after the most
recent successful `cargo test` (or equivalent test-runner) row.

**Scope is narrower than "evidence completeness."** The v0.5.0 stop-check is
**stale-tests-after-source-change** only. There is **no wired check for
"expected artefact / receipt present in the ledger"** — the broader
evidence-completeness pattern is design intent but not implemented at this
gate today. Configure stale-test detection via `corcept doctrine` rules; do
not assume the gate will fail on a missing tapprove receipt, missing
deploy-attestation, etc. unless you wire it yourself.

**How (golden invocation):**

The Stop matcher in `plugins/corcept/hooks/hooks.json` (empty matcher = all
Stop events) routes to:

```bash
corcept hook stop-check < hook-input.json > hook-output.json
```

The stop-check evaluator reads the current doctrine and checks the ledger
for a successful test-run row newer than the most recent source-mutation row.

**Expected output:** Hook JSON with `"decision": "block"` and a `reason`
naming the staleness (e.g. `"test run stale: last cargo test row at
event_id 0x42; source mutation at event_id 0x48"`). The agent must run tests
and re-emit Stop.

**Common pitfalls:**
- Expecting the gate to block on broader evidence gaps (missing receipts,
  missing artefacts, missing deploy attestations). It will not in v0.5.0 —
  only on stale tests after source change. Other evidence requirements
  belong outside this gate today.
- Treating a Stop block as a bug — it is the design. If the block is wrong,
  fix the doctrine rule, not the gate.
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

## Skills via MCP (mcpact-generated) — multi-client surface

`corcept-mcp` is a Rust MCP server crate generated from `corcept.mcpact.toml`
via `mcpact generate`. It exposes **10 native MCP tools** (v0.6+) to any
MCP-speaking client: Claude Code, Cursor, Codex, and the pai-axiom runtime.

**This is the structural extension that closes the 3 previously uncovered client quadrants.**

### Host registration

| Client | File | Status |
|--------|------|--------|
| Claude Code | `crates/corcept-mcp/.mcpact/hosts/claude.json` | Merge into `~/.claude/claude_desktop_config.json` |
| Cursor | `crates/corcept-mcp/.mcpact/hosts/cursor.json` | Merge into Cursor MCP server config |
| Codex | `crates/corcept-mcp/.mcpact/hosts/codex.toml` | Merge into `~/.codex/config.toml` |
| pai-axiom | `crates/corcept-mcp/.mcpact/hosts/axiom.json` | Merge into `~/.claude/pai-axiom/mcp-servers.json` |

### Coverage matrix

The corcept enforcement model has two tiers:
1. **Claude Code hooks** (`plugins/corcept/` PreToolUse / PostToolUse / Stop) — these
   DENY an LLM tool call before it executes. Only Claude Code fires these.
2. **MCP authority layer** (`crates/corcept-mcp/`) — these surface hook-state and gate
   decisions as MCP authority decisions, visible to all MCP clients.

| Quadrant | Hook enforcement | MCP authority visible |
|----------|-----------------|----------------------|
| Claude Code (primary) | ✓ native PreToolUse deny | ✓ (v0.6+) |
| Cursor | ✗ no native hook | ✓ (v0.6+) |
| Codex | ✗ no native hook | ✓ (v0.6+) |
| pai-axiom runtime | ✗ no native hook | ✓ (v0.6+) |

Honest gap: PreToolUse deny-before-execution is **Claude Code-specific**. The MCP
layer makes corcept's governance decisions visible to Cursor, Codex, and axiom,
but those clients must implement their own pre-execution gate if they want the
equivalent of `"decision": "block"`. The MCP tools expose the information needed
to drive that gate; the gate itself is outside corcept's scope for non-Claude clients.

### MCP tool surface

Start the server:

```bash
cargo run -p corcept-mcp
# or after cargo install:
corcept-mcp
```

| Tool | Authority | Approval | When |
|------|-----------|----------|------|
| `corcept_doctor` | Observe | never | Health checks before trusting other tools |
| `corcept_hook_session_start` | Analyze | never | Programmatic session-start event ingestion |
| `corcept_hook_user_prompt_submit` | Analyze | never | Prompt-injection guard ingestion |
| `corcept_hook_pretool_guard` | Plan | never | Driver-driven gate decisions (returns block/allow) |
| `corcept_hook_posttool_audit` | Mutate | on-mutation | Audit row writes (hash-chained ledger append) |
| `corcept_hook_stop_check` | Plan | never | Completion gating (stale-test detection) |
| `corcept_audit_verify` | Observe | never | Hash-chain ledger integrity reads |
| `corcept_export_cloudevents` | Observe | never | Ledger-to-CloudEvents conversion |
| `corcept_key_generate` | Credential | always | Approval-gated Ed25519 keygen |
| `corcept_memory_promote` | Plan | on-mutation | Promote candidate memory to cortex (gated) |

All `*Args` structs carry `#[serde(deny_unknown_fields)]` to prevent key-rename tamper
attacks at the deserialization boundary (per Wave 71 eval finding §1.2.5). All tool
dispatch uses `mcpact_runtime::SafeCommand` — no `std::process::Command::new` in tool
sources (verified by `test_4_no_direct_command_new_in_tool_sources`).

### Skill: corcept-as-mcp-server-for-agents

**When:** the agent / driver is not Claude Code, but still needs corcept's hook-state
and audit chain. The MCP layer is the correct path. Claude Code continues to use
`plugins/corcept/` hook surface directly; the MCP surface and hook surface can run
in parallel.

**How (golden invocation):**

```bash
# Start the MCP server (stdio transport):
cargo run -p corcept-mcp
# or:
corcept-mcp

# Then call via MCP:
#   tool: corcept_audit_verify
#   params: { "signed": false }

# Approval-gated example (key generation):
#   MCPACT_APPROVED=1 corcept-mcp
#   tool: corcept_key_generate
#   params: {}
```

**Expected output:** JSON-RPC 2.0 over stdio; tools follow `corcept_*` naming;
authority classes carried in tool annotations as `{ "mcpact": { "authority": "...",
"trustCeiling": "...", "shellAccess": false } }`.

**Common pitfalls:**
- Hook-event ingestion via MCP does NOT replace Claude Code hooks; both surfaces
  are valid and can run in parallel.
- `corcept_key_generate` and `corcept_hook_posttool_audit` require operator approval
  (`MCPACT_APPROVED=1`); they will refuse without it.
- `corcept_memory_promote` is approval-gated on mutation. Dry-run (`--dry-run`) does
  not require approval.
- For Cursor: the JSON registration at `.mcpact/hosts/cursor.json` uses the same
  `mcpServers` shape as Claude Code; Cursor's MCP config format is identical.
- For Codex: merge the TOML at `.mcpact/hosts/codex.toml` into `~/.codex/config.toml`
  under `[mcp_servers]`.
- For pai-axiom: merge `.mcpact/hosts/axiom.json` into your axiom runtime MCP config.

**See also:** `crates/corcept-mcp/README.md`, `docs/MCP_GUIDE.md`.

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
