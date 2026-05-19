# Doctrine adoption map

| Principle | ADR | Crate / path | CI gate |
| --- | --- | --- | --- |
| Event contracts | 0018, 0022 | `corcept-types`, `contracts/` | `validate-contracts.sh`, `corcept-contract` tests |
| State machines | 0019 | `corcept-runtime` | hook fixture tests |
| Audit logging | 0006, 0025, 0026 | `corcept-ledger`, `corcept-sink` | `corcept audit verify` |
| Testing strategy | 0012 | all crates + `tests/` | `quality.yml`, `proptest` |
| Governance | — | `scripts/supply-chain-gate.sh` | `governance.yml` |
| Boundary admission | 0023 | `contracts/schemas/corcept-boundary-*` | `corcept-contract` |
| XDG layout | 0024 | `corcept-types/paths.rs` | path unit tests |
| Log sinks | 0026 | `corcept-sink` | sink dispatcher tests |
| CloudEvents projection | 0022 | `corcept-sink-cloudevents`, `corcept export cloudevents` | `corcept-contract` cross-surface tests |
| Eval receipts | 0014 | `evals/corcept-eval-suite-v2/fixtures/` | `eval-regression.yml`, `quality.yml` |

See `.doctrine/corcept.md` and `docs/BACKLOG.md`.
