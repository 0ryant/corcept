---
title: Parity backlog
description: Active backlog for doctrine-aligned contracts, state machines, sinks, and CI parity.
status: complete
---

# Backlog — doctrine parity → code complete

Master plan: [`PARITY-TASKS.md`](PARITY-TASKS.md)

**Code-complete definition:** every item in [Done when](#done-when-code-complete) passes; all ST-027–ST-051 subtasks `complete`; ADRs 0018–0026 `accepted`.

---

## Active subtasks (ST-027 → ST-051)

| ID | Title | Lane | ADR | Status |
| --- | --- | --- | --- | --- |
| [ST-027](subtasks/st-027-vendored-minimum-viable-doctrine.md) | Vendored minimum viable doctrine | P0 | — | complete |
| [ST-028](subtasks/st-028-root-ci-quality-workflow.md) | Root CI quality workflow | P0 | [0012](adr/0012-testing-strategy.md) | complete |
| [ST-029](subtasks/st-029-governance-supply-chain-workflow.md) | Governance / supply-chain workflow | P0 | — | complete |
| [ST-030](subtasks/st-030-contracts--tree-and-examples.md) | `contracts/` tree and examples | P1 | [0018](adr/0018-versioned-ledger-event-types.md) | complete |
| [ST-031](subtasks/st-031-runtime-schema-validation-crate.md) | Runtime schema validation | P1 | [0018](adr/0018-versioned-ledger-event-types.md) | complete |
| [ST-032](subtasks/st-032-versioned-event-type-registry.md) | Versioned event type registry | P1 | [0018](adr/0018-versioned-ledger-event-types.md) | complete |
| [ST-033](subtasks/st-033-hook-lifecycle-state-machine-adr.md) | Hook lifecycle FSM | P2 | [0019](adr/0019-hook-lifecycle-state-machine.md) | complete |
| [ST-034](subtasks/st-034-policy-composition-lattice.md) | Policy composition lattice | P2 | [0020](adr/0020-guard-stop-gate-composition.md) | complete |
| [ST-035](subtasks/st-035-wait-states-and-timeouts.md) | Wait states and timeouts | P2 | [0019](adr/0019-hook-lifecycle-state-machine.md) | complete |
| [ST-036](subtasks/st-036-canonical-hash-hardening.md) | Canonical hash hardening | P3 | [0021](adr/0021-canonical-ledger-hashing.md) | complete |
| [ST-037](subtasks/st-037-ledger-contract-test-suite.md) | Ledger contract test suite | P3 | [0021](adr/0021-canonical-ledger-hashing.md) | complete |
| [ST-038](subtasks/st-038-audit-operation-registry.md) | Audit operation registry | P3 | [0018](adr/0018-versioned-ledger-event-types.md) | complete |
| [ST-039](subtasks/st-039-cloudevents-boundary-adr.md) | CloudEvents boundary ADR | P4 | [0022](adr/0022-cloudevents-audit-boundary.md) | complete |
| [ST-040](subtasks/st-040-cloudevents-schema-and-sink-crate.md) | CloudEvents sink crate | P4 | [0022](adr/0022-cloudevents-audit-boundary.md) | complete |
| [ST-041](subtasks/st-041-cross-surface-contract-parity-test.md) | Cross-surface contract tests | P4 | [0022](adr/0022-cloudevents-audit-boundary.md) | complete |
| [ST-042](subtasks/st-042-testing-adr-enforceable-matrix.md) | Testing ADR matrix | P5 | [0012](adr/0012-testing-strategy.md) | complete |
| [ST-043](subtasks/st-043-adversarial-abuse-case-corpus.md) | Adversarial corpus | P5 | [0020](adr/0020-guard-stop-gate-composition.md) | complete |
| [ST-044](subtasks/st-044-eval-harness-contract-gate.md) | Eval harness CI gate | P5 | [0014](adr/0014-evaluation-stack.md) | complete |
| [ST-045](subtasks/st-045-property-based-tests.md) | Property-based tests | P5 | [0019](adr/0019-hook-lifecycle-state-machine.md) | complete |
| [ST-046](subtasks/st-046-cortex-boundary-stubs.md) | Cortex boundary stubs | P6 | [0023](adr/0023-cortex-boundary.md) | complete |
| [ST-047](subtasks/st-047-xdg-path-layout.md) | XDG path layout | P7 | [0024](adr/0024-storage-layout-xdg-paths.md) | complete |
| [ST-048](subtasks/st-048-ed25519-signed-ledger-rows.md) | Ed25519 signed ledger rows | P7 | [0025](adr/0025-signed-ledger-rows.md) | complete |
| [ST-049](subtasks/st-049-runtime-logging-vs-audit-ledger.md) | Runtime logging vs ledger | P7 | [0026](adr/0026-log-sink-architecture.md) | complete |
| [ST-050](subtasks/st-050-release-artifact-signing.md) | Release artifact signing | P7 | — | complete |
| [ST-051](subtasks/st-051-log-sink-architecture.md) | Log sink architecture | P7 | [0026](adr/0026-log-sink-architecture.md) | complete |

### Proposed ADRs (accept on implementation)

| ADR | Title | Subtask |
| --- | --- | --- |
| [0018](adr/0018-versioned-ledger-event-types.md) | Versioned ledger event types | ST-032 |
| [0019](adr/0019-hook-lifecycle-state-machine.md) | Hook lifecycle state machine | ST-033 |
| [0020](adr/0020-guard-stop-gate-composition.md) | Guard and stop-gate composition | ST-034 |
| [0021](adr/0021-canonical-ledger-hashing.md) | Canonical ledger hashing | ST-036 |
| [0022](adr/0022-cloudevents-audit-boundary.md) | CloudEvents audit boundary | ST-039–041 |
| [0023](adr/0023-cortex-boundary.md) | Cortex boundary | ST-046 |
| [0024](adr/0024-storage-layout-xdg-paths.md) | Storage layout and XDG | ST-047 |
| [0025](adr/0025-signed-ledger-rows.md) | Signed ledger rows | ST-048 |
| [0026](adr/0026-log-sink-architecture.md) | Log sink architecture | ST-049, ST-051 |

---

## Path to code complete

Execute sprints in order. Each sprint ends with `make check` green + sprint acceptance gates.

```text
NOW (v0.4 fullship)
  │
  ▼
S1 — Spine + contracts tree          ST-027, ST-028, ST-030, ST-042
  │   Exit: .doctrine/, quality.yml, contracts/examples validate
  ▼
S2 — Versioned ledger + FSM            ST-031, ST-032, ST-033, ST-037
  │   Exit: ADR-0018/0019 accepted; wire snapshots; hook fixtures
  ▼
S3 — Policy + hash + adversarial       ST-034, ST-036, ST-038, ST-043
  │   Exit: ADR-0020/0021 accepted; operations.yaml CI; 10+ abuse scenarios
  ▼
S4 — CloudEvents + eval gate           ST-039, ST-040, ST-041, ST-044
  │   Exit: corcept export cloudevents; eval-regression.yml on deterministic suite
  ▼
S5 — Governance + boundaries           ST-029, ST-035, ST-045, ST-046
  │   Exit: governance.yml; proptest; boundary schemas (optional integration)
  ▼
S6 — XDG + log sinks                   ST-047, ST-049, ST-051
  │   Exit: ADR-0024/0026 accepted; SinkDispatcher; telemetry skip in CI
  ▼
S7 — Signing                           ST-048, ST-050
  │   Exit: ADR-0025 accepted; verify --signed; release-trust doc
  ▼
CODE COMPLETE (v0.5 parity)
```

### Sprint exit gates (minimum)

| Sprint | Must pass before next |
| --- | --- |
| **S1** | `.github/workflows/quality.yml` green; `contracts/examples/*` jsonschema in CI |
| **S2** | `LedgerEventType` wire snapshot tests; `tests/fixtures/hooks/` ≥6 cases |
| **S3** | `corcept audit verify` on hardened hash; pretool-live + stop-gate 100% corcept |
| **S4** | CE export validates schema; paired eval `--skip-agent` in CI |
| **S5** | gitleaks/taudit in governance.yml; proptest in CI |
| **S6** | Hook default ledger-only; XDG paths tested on macOS + ubuntu |
| **S7** | Signed row round-trip; release workflow documents signed/unsigned artifacts |

---

## Done when (code complete)

- [x] All ST-027–ST-051 → `complete` in [`TASKS.md`](../TASKS.md)
- [x] ADRs 0018–0026 → `accepted`
- [x] `.doctrine/corcept.md` + `docs/doctrine-adoption-map.md`
- [x] `.github/workflows/quality.yml` + `governance.yml` green on `main`
- [x] `contracts/schemas/*` + examples validated in CI
- [x] `corcept.event.*.v1` on all ledger lines + snapshot tests
- [x] Hook FSM ADR implemented in runtime transition IDs
- [x] `SinkDispatcher` + Ledger/Telemetry/Debug/CE/Receipt sinks
- [x] XDG operator paths; project ledger stays `.corcept/`
- [x] `corcept export cloudevents` + cross-surface contract tests
- [x] Adversarial corpus in CI; eval deterministic gate
- [x] `corcept audit verify --signed` (optional mode) + hash hardening
- [x] `docs/RELEASE_GATES.md` + release signing documented

---

## Quick commands (when implemented)

```bash
make check                    # local parity with quality.yml
make paired-receipts          # full benchmark + receipts (agent, slow)

# Target state
corcept doctor --strict
corcept audit verify
corcept audit verify --signed
corcept export cloudevents --ledger .corcept/ledger/events.jsonl --out /tmp/ce.jsonl
```
