# ADR-0027: BeforeRun primer-injection hook (Channel 1)

- **Status:** Accepted (scaffold; substrate-wiring deferred per ADR-0005)
- **Date:** 2026-05-20
- **Tags:** hooks, primer, run-contract, anti-confabulation, defense-in-depth
- **Related:**
  - engineering-doctrine `claude/anti-confab-priming-pattern-2026-05-19`
    branch (canonical priming block + ADR-0009 v3 model-compat semantics)
  - engineering-doctrine `claude/run-contracts-verifier-packs-v1-2026-05-19`
    branch (run-contract v1 schema with `primer` field)
  - corcept ADR-0005 (triggers substrate, in flight)
  - corcept ADR-0006 (13 canonical hook names, in flight)
  - corcept ADR-0019 (hook lifecycle state machine)

## Context

Stage 2 of the v2 cross-product test (`value-sheet/18-cross-product-test/v2`)
found that unprimed Sonnet 4.6 cells over-claim by ~12 canonical points on
build-class tasks, with the worst failure being a CLI that printed
`Evidence written to: <path>` and exited 0 without writing the file.
Injecting the canonical 1444-byte anti-confabulation primer at the top of
the cell's system prompt closes the delta from +11 to -1: a 12-point lift
on apples-to-apples comparison, holding model and backbone fixed.

The engineering-doctrine `anti-confab-priming-pattern` branch defines three
distribution channels for primer enforcement:

- **Channel 1 (stack-enforced):** the host runtime guarantees the primer is
  prepended to the system prompt at cell start. Structural — there is no
  way for the cell to start without the primer if its run contract declares
  one.
- **Channel 2 (validator-enforced):** the run-contract validator auto-bundles
  the primer when the contract's `context.skills` array includes a
  build-class skill. Catches contract-author omissions at instantiation.
- **Channel 3 (verifier-enforced):** the `priming_active` verifier kind in
  the sibling pack asserts that the rendered prompt contained the
  hash-matched block. Catches runtime drift.

This ADR records Channel 1's implementation. Channels 2 and 3 are in
flight in `engineering-doctrine`.

## Decision

corcept-runtime ships a `BeforeRun` hook handler that:

1. Reads `ctx.run_contract.primer` (a typed `PrimerRef`).
2. Resolves the primer body via a precedence-ordered loader:
   live engineering-doctrine -> `CORCEPT_ENGINEERING_DOCTRINE_PATH` env
   override -> vendored fallback (`include_bytes!`-embedded).
3. Verifies the model-compatibility table:
   - `confirmed_uplift` / `neutral` -> inject;
   - `inverted_avoid` -> refuse via `HookOutcome::AbortStart` with a typed
     reason.
4. SHA-256 the loaded body and compare to the contract's `expected_sha256`.
   Mismatch -> typed `HookError::PrimerIntegrity`.
5. Prepend the body to `ctx.cell.system_prompt`.
6. Emit a `before_run_primer_injection` audit event the
   `priming_active` verifier can read.

The handler lives at
`crates/corcept-runtime/src/hooks/before_run/primer_injection.rs` and the
loader at `crates/corcept-runtime/src/hooks/before_run/primer_loader.rs`.

## Why refusal is at the hook plane (not router-only)

corcept is a load-bearing run-binder for every contract the host orchestrates.
A v3-ADR-0009-style router enforces model allow/deny lists, but the router
is one of three places refusal can happen:

- **router:** allow/deny by model id;
- **hook (this ADR):** allow/deny by primer-model compatibility verdict;
- **validator:** allow/deny by contract schema constraints.

The hook plane is the only plane that has the actual loaded primer in hand
and can verify the compatibility verdict against the body that is about to
be injected. A router permissive enough to admit `haiku-4-5` for some
contracts is still enforceable per-contract here. Defense in depth is
explicit: a contract that slipped past the router (e.g. via a wildcard
allow_list) is caught by the hook before the cell starts.

The Stage 2 empirical anchor is that the unprimed Tools-Haiku cell scored
31 with SKILLS access — a 65-point over-claim. There is no measurement of
primed Tools-Haiku because the priming-block design space for Haiku has
not been explored. Until that gap is closed, the model-compatibility
table marks Haiku `inverted_avoid` and the hook refuses to start.

## Empirical anchor

The 78 -> 85 Sonnet lift cited in the brief refers to the Stage 2
apples-to-apples scoring at
`engineering-doctrine/value-sheet/18-cross-product-test/v2/results/test-1-backbone/canonical-scoring-sonnet-primed.md:238-251`:

- Unprimed canonical: 78
- Primed canonical: 85
- 12-point self-vs-hostile delta tightening

The hook is the only enforcement plane that gives this lift structurally.
Validator-enforcement is paper-only until the cell actually instantiates;
verifier-enforcement runs after-the-fact. Channel 1 is the moat.

## Audit-event compatibility

The `before_run_primer_injection` event is shaped to satisfy the
`priming_active` verifier kind defined in
`engineering-doctrine/contracts/verifier-pack.v1.schema.json` (`$defs.verifier_kind`
enum row 11). The verifier asserts:

- `kind == "before_run_primer_injection"`,
- `decision == "injected"`,
- `primer_sha256 == <contract's expected_sha256>`,
- `source_kind in {engineering_doctrine_live, vendored_fallback}`.

The verifier mark_untrusts the run when `decision == "no_primer"` on a
contract that declared a primer (the validator should have caught this,
but defense-in-depth) or when `decision == "refused_model_compatibility"`
unless the contract explicitly opts into the refusal path.

## TODO(ADR-0005): triggers-substrate wiring

The handler currently consumes a hand-built `BeforeRunContext` because the
canonical triggers substrate (ADR-0005) and 13-hook surface (ADR-0006)
are still in flight. When those land:

1. The wire-level `BeforeRunInput` in `hooks_v2.rs` should gain a `cell`
   block (`{ model: string, system_prompt: string }`).
2. The `try_dispatch_v2("before-run", ...)` path constructs a
   `BeforeRunContext` and invokes
   `PrimerInjectionHook::run` from this ADR.
3. The cached `last_event` on the hook becomes a `SinkDispatcher::emit_all`
   call, so the event lands in the canonical corcept ledger rather than
   only the in-process cell.

The `BeforeRunContext` shape is stable; the substrate wiring is the only
delta. No test rewrites are anticipated at integration time.

## Alternatives considered

- **Validator-only enforcement** (Channel 2): paper-only; the cell can
  still be instantiated by a host that ignores the validator's auto-bundle.
  Rejected as primary defence.
- **Verifier-only enforcement** (Channel 3): catches drift after the fact;
  the bad cell still emitted its (potentially confabulated) output. Rejected
  as primary defence.
- **Hard-coded primer text in corcept source**: removes the canonical
  anchor; any update to the primer requires a corcept release. Rejected;
  loader uses `include_bytes!` so the bytes are git-locked but the
  authority remains the canonical engineering-doctrine skill file.
- **Feature flag to bypass model-compatibility refusal**: defeats the
  defense-in-depth purpose. Rejected outright — the brief explicitly
  forbids this.

## Consequences

- New runtime dependencies: `sha2`, `hex`, `thiserror` (already in the
  workspace).
- One new vendored binary file (`anti-confab-primer.v1.0.0.txt`, 1444
  bytes), marked `binary` in `.gitattributes` so no EOL translation.
- The hook is uncalled until ADR-0005 lands; new tests verify its
  behaviour in-process via `PrimerInjectionHook::run` directly.
- No existing corcept tests break (verified post-commit).
