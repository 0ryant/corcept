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
- [verify-ledger-integrity](#skill-verify-ledger-integrity) — the ONE supported way to decide if the ledger is tampered (never hash it yourself)
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

## Skill: verify-ledger-integrity

**When:** You need to answer "is this ledger tampered?" — before trusting any
ledger-derived fact, after copying a `.corcept/ledger/` between machines, or as
a CI gate. This is a verdict you MUST NOT reconstruct by hand.

**This is the ONLY supported way to determine ledger integrity. Do NOT compute
SHA-256 over the rows yourself.** The hash chain is domain-separated under a
**private prefix** (`HASH_DOMAIN` in `crates/corcept-ledger/src/canonical.rs`;
signatures additionally use `SIGN_DOMAIN`), so a naive `sha256(row_bytes)` will
**never** reproduce the committed digest and will **false-flag a clean ledger**.
Run the tool and report its verdict **verbatim**.

**How (golden invocation):**

```bash
# CLI — fail-closed: exits non-zero when tampering is detected.
corcept audit --path /path/to/repo verify           # hash-chain integrity
corcept audit --path /path/to/repo verify --signed  # + Ed25519 on every row
```

```text
# MCP — tool: corcept_audit_verify
#   params: { "path": "/path/to/repo", "signed": false }
```

Note the CLI argument order: `--path` is a flag on the `audit` PARENT command,
so it must come **before** the `verify` subcommand
(`audit --path X verify`, NOT `audit verify --path X`). The MCP wrapper emits
this order for you.

**Expected output:** A structured `VerifyReport`. Read these top-level fields —
do not re-derive them:

- `tamper_detected: bool` — the verdict. `false` = intact, `true` = tampered.
- `tampered_lines: [usize]` — 1-based row numbers that failed (empty when clean).
- `status: "pass" | "fail"`, `hash_chain_valid`, `rows_scanned`, `failures[]`,
  `warnings[]` (non-fatal downgrade notices, e.g. legacy un-domain-separated
  rows when `CORCEPT_ALLOW_LEGACY_HASH=1`).

The process **exits non-zero** when `tamper_detected` is true (mirrors
`doctor --strict`), so the tool is safe to wire directly into a CI gate without
parsing JSON.

**Common pitfalls:**

- Hand-rolling SHA-256 to "double-check" the tool. The private domain prefix
  guarantees your hand-rolled digest disagrees with the committed one — you will
  report a clean ledger as tampered. Trust the tool's verdict.
- Putting `--path` after `verify` on the CLI. clap rejects it
  (`unexpected argument --path`) because `--path` lives on the `audit` parent.
- Reading only stdout text and ignoring the exit code in a script. The exit code
  is the fail-closed signal; `tamper_detected` is its structured twin.

**See also:** `docs/adr/0006-event-ledger-hash-chain.md`,
`docs/adr/0021-hardened-hash-domain-separation.md`,
`crates/corcept-ledger/src/canonical.rs`,
`crates/corcept-ledger/src/signed_row.rs`.

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
