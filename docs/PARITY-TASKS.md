---
title: Doctrine parity tasks
description: Task backlog to align CORCEPT with engineering-doctrine and sibling-repo contract/state-machine/CloudEvents/test patterns.
status: proposed
---

# CORCEPT — full parity task backlog

Align CORCEPT with **engineering-doctrine** ([event-contracts](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/event-contracts.md), [state-machines-and-workflows](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/state-machines-and-workflows.md), [testing-strategy](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/testing-strategy.md)) and proven patterns from **cortex**, **algol**, and **taudit**.

**Parity definition:** every public wire surface (hook I/O, ledger lines, CLI JSON, eval receipts) has a versioned contract, golden fixtures validated in CI, an explicit lifecycle/state model, and optional CloudEvents projection — without replacing the hash-chained ledger as authority.

## Status update — bounded MCP v1

`corcept serve` now exists as an opt-in bounded local MCP server. It is intentionally read-mostly and limited to doctor, audit, doctrine validation, candidate-memory listing, and CloudEvents preview. It is not a default install path, not a shell bridge, and not an alternate authority surface.

Any future MCP expansion should preserve that posture unless a new ADR explicitly widens the trust boundary.

**Current gaps (observed):**

| Area | CORCEPT today | Sibling baseline |
| --- | --- | --- |
| Repo `.doctrine/` | None | `cortex/.doctrine/cortex.md`, `algol/docs/doctrine-adoption-map.md` |
| Event `type` naming | Free strings (`file_modified`, …) | `corcept.event.*.v1` (Cortex) / `io.corcept.*.v1` (taudit CE) |
| CloudEvents | None | algol ADR 0010, `taudit-sink-cloudevents` |
| JSON Schema enforcement | Schemas exist; no `jsonschema` in Rust | taudit `contracts/` + CI; algol `ensure_valid()` |
| Hook lifecycle FSM | Implicit in `corcept-runtime` | algol ADR 0002 explicit states + transitions |
| Contract tests | ~26 inline unit tests | Wire snapshots, fixture dirs, cross-sink parity |
| Root CI | Template in `_compare/` only | `quality.yml` + `governance.yml` (algol/taudit) |
| Policy composition | Guards + stop gate in code | cortex ADR 0026 total order documented |
| **Storage layout (XDG)** | All state in repo `.corcept/` | cortex `paths.rs`, taudit telemetry/receipts/logs split |
| **Log sinks** | Ledger only (inline append) | taudit multi-sink + `ReportSink`; algol CE JSONL projection |
| **Log signing** | SHA-256 hash chain only | cortex Ed25519 `RowSignature` + `verify_signed_chain` |

---

## Lane map

| Lane | Focus | Blocks |
| --- | --- | --- |
| **P0 — Doctrine & CI spine** | `.doctrine/`, workflows, release gates | Everything else |
| **P1 — Contracts & schemas** | `contracts/`, versioned types, validation | P2, P3, P4 |
| **P2 — State machine & policy** | Hook FSM ADR, policy lattice | P3 event mapping |
| **P3 — Ledger & events** | Versioned ledger events, hash ADR, wire tests | P4 CloudEvents |
| **P4 — CloudEvents projection** | CE sink, ecosystem envelope, export CLI | P5 cross-surface |
| **P5 — Test portfolio** | Fixtures, adversarial corpus, eval regression gate | — |
| **P6 — Boundaries (optional)** | Cortex / pai-axiom admission envelopes | After P3 |
| **P7 — Storage & signed audit** | XDG paths, log sinks, Ed25519 rows, release signing | After P3 ST-036 |

---

## P0 — Doctrine & CI spine

### ST-027 — Vendored minimum viable doctrine

**Goal:** Repo-local doctrine index like cortex `corcept.md` + adoption map like algol.

**Tasks:**

1. Add `.doctrine/README.md` (index → canonical library at `~/prj/engineering-doctrine`).
2. Add `.doctrine/corcept.md` — 5–7 principles with BUILD_SPEC/ADR binding table (template: `minimum-viable-doctrine.template.md`).
3. Add `docs/doctrine-adoption-map.md` — principle → ADR → crate → CI job.
4. Add `.doctrine/UPSTREAM.md` — vendored commit SHA + sync procedure.

**Acceptance:**

- [ ] New contributor can read `.doctrine/corcept.md` in &lt;5 min and know which ADRs enforce which principle.
- [ ] Every adopted principle links to one canonical doctrine file (no orphan claims).

**Refs:** `cortex/.doctrine/cortex.md`, `algol/docs/doctrine-adoption-map.md`

---

### ST-028 — Root CI quality workflow

**Goal:** Same local/CI gates as algol/taudit `quality.yml`.

**Tasks:**

1. Promote `_compare/corcept/corcept/.github/workflows/ci.yml` → `.github/workflows/quality.yml`.
2. Jobs: `fmt --check`, `clippy -D warnings`, `cargo test --workspace --all-targets`, `cargo deny`, `cargo audit`.
3. Matrix: `ubuntu-latest` + `macos-latest` (hooks must work on macOS).
4. Add Makefile `check` target as documented blessed path (already partial).

**Acceptance:**

- [ ] PR to `main` runs quality workflow green on clean tree.
- [ ] `make check` locally matches CI job set (document any intentional diff).

**Refs:** `algol/.github/workflows/quality.yml`, `taudit/.github/workflows/quality.yml`

---

### ST-029 — Governance / supply-chain workflow

**Goal:** Separate governance lane (doctrine: merge-path evidence).

**Tasks:**

1. Add `.github/workflows/governance.yml` — gitleaks, trivy (or checkov if IaC added), zizmor on workflows.
2. Optional: `taudit verify` self-scan with `TAUDIT_CORRELATION_ID` (taudit pattern).
3. Add `docs/RELEASE_GATES.md` — P0 blockers on public contract surfaces (schemas, ledger, hook I/O).

**Acceptance:**

- [ ] Governance workflow runs on schedule + PR; failures documented with owner.
- [ ] Release gates doc lists contract-breaking vs additive changes.

**Refs:** `taudit/docs/RELEASE_GATES.md`, `algol/.github/workflows/governance.yml`

---

## P1 — Contracts & schemas

### ST-030 — `contracts/` tree and examples

**Goal:** Published wire contracts live beside code (taudit pattern).

**Tasks:**

1. Create `contracts/schemas/`:
   - `corcept-ledger-event-v1.schema.json` (authority)
   - `corcept-hook-input-v1.schema.json` (from `schemas/hook-input.schema.json`)
   - `corcept-hook-output-v1.schema.json` (new — PreTool/Stop output)
   - `corcept-memory-candidate-v1.schema.json`
   - `corcept-doctrine-frontmatter-v1.schema.json`
2. Create `contracts/examples/` — one valid + one intentionally invalid example per schema.
3. Add `contracts/README.md` — schema ID URIs (`https://schemas.corcept.dev/...`), compatibility rules.
4. Deprecate or alias root `schemas/*` → `contracts/schemas/*` (single source; ADR for cutover).

**Acceptance:**

- [ ] Every schema has ≥1 committed example that validates in CI.
- [ ] `additionalProperties` policy documented per schema (hook input: true; ledger: false).

**Refs:** `taudit/contracts/`, `corcept/schemas/`

---

### ST-031 — Runtime schema validation crate

**Goal:** Fail closed at boundaries (doctrine event-contracts §1).

**Tasks:**

1. Add dev-dep `jsonschema` (or workspace crate `corcept-contract`) loading schemas from `contracts/schemas/`.
2. Validate on: ledger append, hook stdin parse (debug/strict mode), memory candidate write, doctrine load.
3. Add `corcept doctor --strict` flag: verify schemas compile + examples validate + ledger lines validate.
4. Add `ensure_valid()` on `LedgerEvent`, `HookInput`, etc. (algol `model.rs` pattern).

**Acceptance:**

- [ ] Invalid ledger line rejected at append time in strict mode.
- [ ] `cargo test -p corcept-contract` (or ledger tests module) validates all `contracts/examples/*.json`.

**Refs:** `taudit/crates/taudit-sink-cloudevents` tests, `algol/src/model.rs`

---

### ST-032 — Versioned event type registry

**Goal:** Stable wire strings with snapshot tests (cortex `event.rs` pattern).

**Tasks:**

1. ADR **0018 — versioned ledger event types**.
2. Replace free `event_type: String` with `LedgerEventType` enum + `wire_str()` → `corcept.event.<semantic>.v1`.
3. Add `schema: "corcept.ledger_event.v1"` field on every ledger line.
4. Snapshot test: all enum variants → wire string list (forbid silent renames).
5. Update `contracts/schemas/corcept-ledger-event-v1.schema.json` with `event_type` pattern enum.

**Event type catalog (initial):**

| Wire `event_type` | Transition / meaning |
| --- | --- |
| `corcept.event.tool_requested.v1` | PreTool hook entered |
| `corcept.event.tool_decided.v1` | allow / ask / deny emitted |
| `corcept.event.file_modified.v1` | PostTool file change |
| `corcept.event.command_executed.v1` | Bash executed |
| `corcept.event.test_run.v1` | Tests recorded |
| `corcept.event.stop_decided.v1` | Stop gate outcome |
| `corcept.event.memory_proposed.v1` | Candidate created |
| `corcept.event.memory_promoted.v1` | Accepted memory |
| `corcept.event.doctrine_loaded.v1` | Doctrine read |
| `corcept.event.audit_completed.v1` | Audit pass/fail |

**Acceptance:**

- [ ] No runtime code emits unregistered event type strings.
- [ ] Snapshot test fails if wire string changes without ADR.

**Refs:** `cortex/crates/cortex-core/src/event.rs`, doctrine state-machines §3

---

## P2 — State machine & policy

### ST-033 — Hook lifecycle state machine ADR

**Goal:** Explicit FSM per doctrine state-machines-and-workflows §1–§3.

**Tasks:**

1. ADR **0019 — hook lifecycle state machine** with diagram:

```text
SessionStart → TurnActive → PreToolEvaluating → {Allowed|Asked|Denied}
  → ToolExecuting → PostToolAuditing → TurnActive
  → StopEvaluating → {StopAllowed|StopBlocked} → SessionEnd
```

2. Table: state, allowed transitions, trigger (hook name), preconditions, terminal states.
3. Map each **committed** transition to `corcept.event.*.v1` from ST-032.
4. Document recovery: denied tool → agent retry; stop blocked → must run tests.
5. Document idempotency: duplicate PreTool for same `tool_use_id` behavior.

**Acceptance:**

- [ ] ADR reviewed; every hook handler in `corcept-runtime` references a transition ID.
- [ ] Eval benchmark can cite transition IDs in receipts.

**Refs:** `algol/docs/adr/0002-local-lifecycle-state-machine.md`, doctrine state-machines §3

---

### ST-034 — Policy composition lattice ADR

**Goal:** Document total order when multiple guards apply (cortex ADR 0026 analog).

**Tasks:**

1. ADR **0020 — guard and stop-gate composition**.
2. Define outcomes: `Allow < Ask < Deny` for PreTool; `AllowStop < BlockStop` for Stop.
3. Define composition when bash + path + secret classifiers disagree (strictest wins).
4. Add property tests: random classifier inputs → outcome matches lattice.
5. Wire lattice into benchmark expected outcomes (`pretool-live`, `stop-gate`).

**Acceptance:**

- [ ] 100% pretool-live + stop-gate benchmark alignment with documented lattice.
- [ ] `corcept-guards` tests include pairwise composition cases.

**Refs:** `cortex/docs/adr/0026-policy-engine-enforcement-lattice.md`

---

### ST-035 — Wait states and timeouts (hook/agent)

**Goal:** Doctrine state-machines §5.2 — no indefinite pending.

**Tasks:**

1. Document max dwell for: agent subprocess (eval harness), hook wrapper stall, ledger lock.
2. Eval harness: configurable timeout + receipt field `timed_out` (partial — already started).
3. Stop gate: define behavior when tests never run (block + reason code).
4. Metrics hooks (future): `corcept.event.timeout.v1` when agent exceeds bound.

**Acceptance:**

- [ ] ADR lists timeout defaults and escalation (fail hook vs allow with warn).
- [ ] Eval receipts record timeout without crashing aggregate run.

---

## P3 — Ledger & canonical hashing

### ST-036 — Canonical hash ADR and hardening

**Goal:** Tamper-evident ledger aligned with cortex ADR 0022 intent (without full Cortex complexity).

**Tasks:**

1. ADR **0021 — canonical ledger hashing** — document current SHA-256 over `serde_json` and its limits.
2. Phase A (minimal): domain-separated preimage (`corcept:ledger:v1:` + canonical JSON with sorted keys).
3. Phase B (optional parity): BLAKE3 + domain tag like cortex; migration path for existing ledgers.
4. Add negative tests: malleable JSON reorder must not verify on hardened path.
5. `corcept audit verify` documents which hash generation ledger uses.

**Acceptance:**

- [ ] Verify rejects tampered `decision` field on hardened path.
- [ ] Migration tool or dual-verify for legacy `sha256:` lines.

**Refs:** `cortex/docs/adr/0022-canonical-event-envelope-and-hash.md`, `corcept/docs/adr/0006-*`

---

### ST-037 — Ledger contract test suite

**Goal:** algol fixture + taudit jsonschema pattern for authority surface.

**Tasks:**

1. Move `examples/fixtures/` → `tests/fixtures/hooks/` with expected ledger JSONL sidecars.
2. Integration test: run hook CLI against fixture stdin → compare golden ledger lines (hash chain optional in fixture via frozen timestamps).
3. Negative fixtures: broken `prev_hash`, unknown `event_type`, schema violation.
4. Test: `verify_hash_chain()` on golden chain passes; single-byte flip fails.

**Acceptance:**

- [ ] ≥6 hook fixtures (pretool allow/deny, posttool, stop allow/block, memory).
- [ ] CI runs integration tests on ubuntu + macos.

**Refs:** `algol/tests/contract_fixtures.rs`, `corcept/examples/fixtures/`

---

### ST-038 — Audit operation registry

**Goal:** cortex `operations.yaml` — typed ops emitted vs registered set.

**Tasks:**

1. Add `docs/audit/operations.yaml` — op id, event_type, authority level, description.
2. Add `scripts/validate-audit-operations.py` (or Rust) — registry ↔ `LedgerEventType` enum.
3. CI step in quality workflow.

**Acceptance:**

- [ ] Every `LedgerEventType` has a registry entry; CI fails on drift.

**Refs:** `cortex/docs/audit/operations.yaml`, `cortex/scripts/validate-audit-operations.py`

---

## P4 — CloudEvents projection

### ST-039 — CloudEvents boundary ADR

**Goal:** algol ADR 0010 pattern — ledger authority, CE derived.

**Tasks:**

1. ADR **0022 — audit events and CloudEvents boundary**.
2. State explicitly: `.corcept/ledger/events.jsonl` = authority; CloudEvents JSONL = projection/export.
3. No secrets in CE `data`; reference ledger event id + correlation id.
4. Required CE attrs: `specversion`, `id`, `source`, `type`, `time`, `subject` (session_id).
5. `type` pattern: `io.corcept.hook.<semantic>.v1` mapping table from ST-032.

**Acceptance:**

- [ ] ADR merged; BUILD_SPEC/API.md reference export path.

**Refs:** `algol/docs/adr/0010-audit-events-and-cloudevents-boundary.md`, doctrine `tooling/cloudevents.md`

---

### ST-040 — CloudEvents schema and sink crate

**Goal:** taudit `taudit-sink-cloudevents` parity.

**Tasks:**

1. Add `contracts/schemas/corcept-cloudevent-audit-v1.schema.json` (CE 1.0 structured JSON).
2. Reuse or embed `ecosystem-evidence-envelope-v0` extensions: `correlationid`, `provenancerepo`, `provenanceproducer`, `provenanceversion`, `provenancekind` (from taudit).
3. Crate `corcept-sink-cloudevents` (or feature on `corcept-ledger`): `project(ledger_event) -> CloudEvent`.
4. CLI: `corcept export cloudevents --ledger .corcept/ledger/events.jsonl --out audit-ce.jsonl`.
5. Unit tests: every `LedgerEventType` projects to valid CE; jsonschema validates output.

**Acceptance:**

- [ ] Round-trip test: fixture ledger → export → validate against schema + examples.
- [ ] Secret-like substrings in metadata redacted or hashed in projection.

**Refs:** `taudit/contracts/schemas/taudit-cloudevent-finding-v1.schema.json`, `taudit/crates/taudit-sink-cloudevents/`

---

### ST-041 — Cross-surface contract parity test

**Goal:** taudit `cross_sink_contract.rs` — stable ids across outputs.

**Tasks:**

1. If CLI status JSON + ledger + CE export coexist: assert same `id`, `event_type` semantic, correlation id.
2. Fingerprint field for hook outcomes (32 hex) stable across surfaces.
3. Document in `contracts/README.md`.

**Acceptance:**

- [ ] Changing projection does not change ledger line; changing ledger requires ADR + fixture update.

**Refs:** `taudit/crates/taudit-cli/tests/cross_sink_contract.rs`

---

## P5 — Test portfolio

### ST-042 — Expand testing ADR 0012 into enforceable matrix

**Goal:** Doctrine testing-strategy pyramid with CI enforcement.

**Tasks:**

1. Revise `docs/adr/0012-testing-strategy.md` with layer targets:
   - Fast (unit): guards, types, ledger hash — **~70%**
   - Medium (contract/integration): fixtures, schema, hook CLI — **~25%**
   - E2E: paired eval harness smoke — **~5%**
2. Map each crate to layer in `docs/doctrine-adoption-map.md`.
3. Add `tests/README.md` — how to add fixtures, when ADR required.

**Acceptance:**

- [ ] ADR lists concrete test modules per layer; CI covers all listed modules.

---

### ST-043 — Adversarial / abuse-case corpus

**Goal:** Doctrine testing-strategy §5 + cortex ADR 0029 intent.

**Tasks:**

1. Add `tests/adversarial/scenarios/` — YAML or JSON scenario id, hook input, expected decision.
2. Initial scenarios: `rm -rf /`, path traversal, secret in command, prompt injection in tool_response, oversized stdin.
3. CI: run scenarios against `corcept-guards` + hook path; fail on unsafe allow.
4. Link to benchmark `guard-v2` as regression oracle.

**Acceptance:**

- [ ] ≥10 adversarial scenarios; 0% unsafe allow on hardened guard profile.

**Refs:** `cortex/docs/adr/0029-adversarial-eval-harness-regression-corpus.md`, `taudit/crates/taudit-cli/tests/output_injection_corpus.rs`

---

### ST-044 — Eval harness as contract gate

**Goal:** Promote `results/paired-*` pattern to in-repo regression (cortex `eval/` pattern).

**Tasks:**

1. Move eval receipt schema to `contracts/schemas/corcept-paired-receipts-v1.schema.json`.
2. Add `evals/corcept-eval-suite-v2/fixtures/` golden receipts; validate in CI with `--skip-agent`.
3. Optional workflow `.github/workflows/eval-regression.yml` on eval path changes.
4. Pin baseline metrics JSON; fail on guard regression beyond threshold.

**Acceptance:**

- [ ] CI validates receipt schema + deterministic benchmarks without Claude API.
- [ ] Agent benchmarks remain manual/scheduled (document cost).

**Refs:** `cortex/.github/workflows/eval-regression.yml`, `corcept/results/paired-latest/`

---

### ST-045 — Property-based tests for parsers and FSM

**Goal:** Doctrine testing-strategy §6 — proptest for non-obvious invariants.

**Tasks:**

1. `proptest` on: JSON answer parser (`mini_reasoning`), hook input deserialization, hash chain append sequence.
2. FSM: random transition sequences → only legal transitions accepted (model check lite).

**Acceptance:**

- [ ] proptest runs in CI (bounded cases for speed).

---

## P6 — Cross-system boundaries (optional, post-P3)

### ST-046 — Cortex / pai-axiom boundary stubs

**Goal:** Future integration without inventing wire formats ad hoc.

**Tasks:**

1. ADR **0023 — cortex-pai-axiom boundary** (consumer-only stubs if no integration yet).
2. Define `corcept.boundary.execution_receipt.v1` envelope for eval receipts export.
3. Align with `AxiomCortexAdmission` skill constraints — candidate-only memory, quarantine flags.
4. No runtime dependency until explicitly requested; schemas + fixtures only.

**Refs:** `cortex/docs/adr/0040-cortex-pai-axiom-boundary-contract.md`, pai-axiom admission skills

---

| **P7 — Storage & signing** | XDG paths, log sinks, Ed25519 rows, release signing | P3 ledger, P4 CE |

Doctrine [audit-logging.md](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/audit-logging.md) §2: tamper protection is an **estate decision** — hash chaining (have), asymmetric row signing (cortex), or external SIEM. Configuration paths are not in doctrine text but siblings converge on **XDG Base Directory** for operator-scoped artifacts.

**Design split (must be explicit in ADR):**

| Scope | Location | Contents | Rationale |
| --- | --- | --- | --- |
| **Project** (repo) | `.corcept/` | doctrine, memory, ledger, config, reports | GitOps governance; project-local by default (ADR 0001) |
| **Operator** (user) | XDG dirs | install cache, signing keys, CLI telemetry, debug logs, eval run roots | Not committed; avoids dotfile worms (cortex T-SC-6) |
| **Override** | env + flags | same as taudit | CI/minimal containers skip gracefully |

### ST-047 — XDG path layout ADR

**Goal:** Document two-tier storage like cortex + taudit without breaking project-local governance.

**Tasks:**

1. ADR **0024 — storage layout and XDG operator paths**.
2. Define resolution order (taudit pattern):
   - **Ledger (project):** `$CORCEPT_LEDGER` → `.corcept/ledger/events.jsonl` (default, in-repo).
   - **Operator data:** `$CORCEPT_DATA_HOME` → `$XDG_DATA_HOME/corcept` → `$HOME/.local/share/corcept`.
   - **Operator state (logs/telemetry):** `$CORCEPT_STATE_HOME` → `$XDG_STATE_HOME/corcept` → `$HOME/.local/state/corcept`.
   - **Operator config:** `$CORCEPT_CONFIG_HOME` → `$XDG_CONFIG_HOME/corcept` → `$HOME/.config/corcept`.
3. Map artifacts:
   - `state/telemetry.jsonl` — hook timing, doctor runs (optional, skip if no HOME)
   - `state/logs/corcept.log` — structured debug (never secrets)
   - `data/keys/` — Ed25519 operator keys (ST-048)
   - `data/receipts/` — default for `run-paired-all` when not `--out` (optional)
4. Add `crates/corcept-types/src/paths.rs` (or `corcept-runtime/paths.rs`) using `dirs` crate — mirror `cortex/crates/cortex-cli/src/paths.rs`.
5. `corcept doctor --validate-perms`: project `.corcept/ledger` and operator data dir **0700** on Unix (cortex `assert_secure_data_dir`).
6. CI: when `XDG_*` unset, operator artifacts **silently skipped** (taudit README pattern) — hooks must not fail.

**Acceptance:**

- [ ] ADR table lists every path with env override + fallback chain.
- [ ] `cargo test default_operator_data_dir_under_xdg` (or platform equivalent).
- [ ] Project `.corcept/` remains default for init/doctor; XDG only for operator-global state.

**Refs:** `cortex/crates/cortex-cli/src/paths.rs`, `taudit/README.md` §runtime artifacts, `tsafe/docs/features/storage-paths.md`

---

### ST-048 — Ed25519 signed ledger rows (log signing)

**Goal:** Asymmetric **log signing** parity with cortex `signed_row.rs` — optional tier above hash chain.

**Current:** SHA-256 hash chain (ADR 0006) detects tamper **after the fact** if verifier has genesis; no non-repudiation against writer with ledger access.

**Target (cortex Lane 3.D.6):**

1. ADR **0025 — signed ledger rows and verification modes**.
2. Add optional `signature` field on ledger lines:

```json
{
  "schema": "corcept.ledger_event.v1",
  "event_type": "corcept.event.tool_decided.v1",
  "hash": "sha256:…",
  "signature": {
    "schema_version": 1,
    "key_id": "fp:…",
    "signed_at": "2026-05-18T…Z",
    "bytes": "<base64 ed25519>"
  }
}
```

3. Preimage: domain-separated canonical bytes (ST-036 hardened hash — **not** raw JSON string).
4. Key lifecycle:
   - `corcept keygen` → `$CORCEPT_DATA_HOME/keys/active.ed25519` (0600)
   - `corcept key show` → fingerprint for `key_id`
   - Rotation: new key signs `corcept.event.key_rotated.v1`; old rows remain verifiable with historical pubkey registry in `data/keys/trust/` 
5. Verification modes:
   - `corcept audit verify` — hash chain only (default, backward compatible)
   - `corcept audit verify --signed` — require valid Ed25519 on every row (fail on `MissingSignature`)
   - `corcept audit verify --trusted-history` — opt-in signed append on `corcept run` / hook path (cortex `--trusted-history` pattern)
6. Contract: `contracts/schemas/corcept-ledger-event-v1.schema.json` + `corcept-row-signature-v1.schema.json`.
7. Tests: sign → verify pass; flip one byte → fail; unsigned row → `--signed` fails with typed reason.

**Acceptance:**

- [ ] Signed and unsigned rows coexist during migration; ADR documents cutover.
- [ ] No symmetric HMAC fallback (cortex ADR 0010 single asymmetric domain).
- [ ] Secrets never in signature preimage or debug logs.

**Refs:** `cortex/crates/cortex-ledger/src/signed_row.rs`, `cortex/crates/cortex-ledger/src/audit.rs` (`verify_signed_chain`), doctrine audit-logging §2

---

### ST-049 — Runtime logging vs audit ledger

**Goal:** Separate **debug/ops logs** (XDG state, rotatable) from **audit ledger** (project authority).

**Tasks:**

1. Structured logging to `$CORCEPT_STATE_HOME/logs/` via `tracing` (JSON lines, correlation id = session_id).
2. Log fields: level, ts, target, session_id, hook_event — **no** tool_input secrets, env vars, or full prompts (redact/hmac-ref like taudit).
3. `CORCEPT_LOG=off|info|debug` env; default `info` for operator, silent in hook hot path unless `CORCEPT_DEBUG=1`.
4. ADR cross-ref: audit ledger = evidence; debug log = operator diagnostics (not SIEM authority).
5. Optional export: project debug log tail into receipt bundle for eval failures only.

**Acceptance:**

- [ ] Hook path adds &lt;5ms when logging off (benchmark or doc).
- [ ] Log dir follows XDG state home; skipped gracefully in CI without HOME.

**Refs:** doctrine observability.md (correlation), taudit log-dir behavior

---

### ST-050 — Release artifact signing (distinct from log signing)

**Goal:** ROADMAP “signed artifact release” — **binary/release** trust, not ledger rows.

**Tasks:**

1. Document in `docs/RELEASE_GATES.md` (ST-029): minisign/cosign for release tarballs (taudit `docs/release-trust.md` pattern).
2. CI: sign when secrets present; publish unsigned fallback with checksums (tsafe code-signing.md).
3. Do **not** conflate with ST-048 — release signing ≠ audit log signing.

**Acceptance:**

- [ ] Release workflow documents signed vs unsigned artifacts per platform.

**Refs:** `corcept/ROADMAP.md`, `taudit/docs/release-trust.md`, `tsafe/docs/features/code-signing.md`

---

### ST-051 — Log sink architecture (multi-sink dispatch)

**Goal:** One dispatch layer for all observability/audit outputs — taudit `write_runtime_artifacts` + `ReportSink` pattern, not ad-hoc writes scattered in runtime.

**Problem today:** `corcept-ledger` appends directly to `.corcept/ledger/events.jsonl`. Eval harness writes receipts ad hoc. No telemetry, no debug log, no pluggable projection sinks. Hook hot path will sprawl if each output format gets its own `fs::write`.

**Sink taxonomy (authority order):**

| Sink | Format | Default path | Authority? | Best-effort? |
| --- | --- | --- | --- | --- |
| **LedgerSink** | hash-chained JSONL | `.corcept/ledger/events.jsonl` | **Yes** — proof boundary | No — hook fails if append fails |
| **TelemetrySink** | structured JSONL | `$XDG_STATE_HOME/corcept/telemetry/events.jsonl` | No — ops metrics | Yes — skip if no HOME/XDG |
| **DebugLogSink** | plain text | `$XDG_STATE_HOME/corcept/logs/corcept.log` | No — operator debug | Yes |
| **CloudEventsSink** | CE 1.0 JSONL | stdout or `--ce-out` | No — projection | Yes (ST-040) |
| **ReceiptSink** | receipt JSON | `--out` or `$XDG_DATA_HOME/corcept/receipts/` | No — eval/audit bundle | Yes |

```text
Hook / runtime
     │
     ▼
 SinkDispatcher (corcept-runtime)
     │
     ├─► LedgerSink      ── required, project-scoped
     ├─► TelemetrySink   ── optional, XDG state
     ├─► DebugLogSink    ── optional, XDG state
     ├─► CloudEventsSink ── optional, projects from ledger event
     └─► ReceiptSink     ── eval/CLI only
```

**Tasks:**

1. ADR **0026 — log sink architecture and failure modes**.
2. Crate `corcept-sink` (or module in `corcept-runtime`) with trait:

```rust
pub trait LogSink: Send + Sync {
    /// Human-readable sink id: "ledger", "telemetry", "debug", "cloudevents", "receipt"
    fn id(&self) -> &'static str;
    /// False for LedgerSink — all others best-effort
    fn is_authority(&self) -> bool;
    fn emit(&self, record: &SinkRecord) -> Result<()>;
}
```

3. `SinkRecord` fields: `correlation_id` (session_id), `event_type`, `ts`, `outcome`, `hook_event`, `duration_ms`, `redacted_metadata` — **no secrets** (taudit redaction rules).
4. `SinkDispatcher::emit_all(record)` — ledger first; on ledger error propagate; on secondary sink error log to stderr once, continue (tsafe audit best-effort pattern).
5. Path resolution via ST-047 `paths.rs`; CLI/env overrides mirror taudit:
   - `--telemetry-dir`, `--log-dir`, `--ledger` (project override)
   - `$CORCEPT_TELEMETRY_DIR`, `$CORCEPT_LOG_DIR`, `$CORCEPT_LEDGER`
6. Hook default: **LedgerSink only** (zero extra I/O in hot path unless `CORCEPT_TELEMETRY=1` or `CORCEPT_LOG=debug`).
7. `corcept export sinks --ledger .corcept/ledger/events.jsonl --format cloudevents|telemetry-replay` — rebuild projection files from authority.
8. Contract tests: same `SinkRecord` → ledger line + CE line share `id` + `correlation_id` (ST-041 cross-surface).
9. Schema: `contracts/schemas/corcept-sink-record-v1.schema.json`, `corcept-telemetry-event-v1.schema.json`.

**Acceptance:**

- [ ] No direct `fs::write` to ledger outside `LedgerSink`.
- [ ] Telemetry + debug sinks skipped silently when XDG/HOME unset (CI-safe).
- [ ] `cargo test -p corcept-sink` covers dispatcher fail-open vs fail-closed behavior.
- [ ] Eval harness `ReceiptWriter` implements or delegates to `ReceiptSink`.

**Refs:** `taudit/crates/taudit-cli/src/main.rs` (`write_runtime_artifacts`, `resolve_runtime_artifact_paths`), `taudit/crates/taudit-core/src/ports.rs` (`ReportSink`), algol `algol-audit-events.jsonl` projection

---

## Dependency graph

```text
ST-027 ─┬─► ST-028 ─► ST-029
        │
ST-030 ─┴─► ST-031 ─► ST-037
        │
        └─► ST-032 ─► ST-033 ─► ST-038
                 │
                 ├─► ST-036
                 │
                 └─► ST-039 ─► ST-040 ─► ST-041

ST-034 ─► ST-043 (benchmark alignment)
ST-042 ─► ST-044, ST-045
ST-046 (optional, after ST-032)
ST-047 ─► ST-049, ST-051
ST-048 depends on ST-036, ST-047
ST-051 depends on ST-047; feeds ST-040, ST-041
```

---

## Suggested execution order (sprints)

| Sprint | Tasks | Outcome |
| --- | --- | --- |
| **S1** | ST-027, ST-028, ST-030, ST-042 | Doctrine + CI + contracts tree |
| **S2** | ST-031, ST-032, ST-033, ST-037 | Validated versioned ledger + FSM ADR |
| **S3** | ST-034, ST-036, ST-038, ST-043 | Policy lattice + hash hardening + adversarial |
| **S4** | ST-039, ST-040, ST-041, ST-044 | CloudEvents export + eval contract gate |
| **S5** | ST-029, ST-035, ST-045, ST-046 | Governance workflow + property tests + boundaries |
| **S6** | ST-047, ST-049, ST-051 | XDG paths + log sinks + operator debug logging |
| **S7** | ST-048, ST-050 | Ed25519 ledger signing + release artifact signing |

---

## Done when (full parity checklist)

- [ ] `.doctrine/corcept.md` + adoption map committed
- [ ] `.github/workflows/quality.yml` + `governance.yml` green
- [ ] `contracts/schemas/*` + examples validated in CI via jsonschema
- [ ] All ledger events use `corcept.event.*.v1` + snapshot tests
- [ ] Hook lifecycle ADR with transition → event type mapping
- [ ] Policy composition ADR matches benchmark suites
- [ ] `corcept export cloudevents` produces valid CE 1.0 JSONL
- [ ] Hash chain verification documented + hardened or migration path defined
- [ ] `tests/fixtures/` + adversarial scenarios in CI
- [ ] Eval deterministic suite is a merge gate
- [ ] `docs/RELEASE_GATES.md` defines contract-breaking change process
- [ ] `SinkDispatcher` routes ledger (required) + telemetry/debug (best-effort) + CE projection
- [ ] Operator logs under XDG state; project ledger stays in `.corcept/`
- [ ] `corcept audit verify --signed` optional (ST-048)

---

## References

| Source | Path |
| --- | --- |
| Engineering doctrine — event contracts | `~/prj/engineering-doctrine/doctrine/principles/event-contracts.md` |
| Engineering doctrine — state machines | `~/prj/engineering-doctrine/doctrine/principles/state-machines-and-workflows.md` |
| Engineering doctrine — testing | `~/prj/engineering-doctrine/doctrine/principles/testing-strategy.md` |
| Engineering doctrine — CloudEvents tooling | `~/prj/engineering-doctrine/doctrine/tooling/cloudevents.md` |
| Cortex event wire types | `~/prj/cortex/crates/cortex-core/src/event.rs` |
| Algol lifecycle FSM | `~/prj/algol/docs/adr/0002-local-lifecycle-state-machine.md` |
| Algol CE boundary | `~/prj/algol/docs/adr/0010-audit-events-and-cloudevents-boundary.md` |
| taudit contracts | `~/prj/taudit/contracts/` |
| CORCEPT current schemas | `schemas/`, `docs/adr/0006`, `docs/adr/0012` |
