# Test portfolio

CORCEPT testing follows a three-layer pyramid (ADR-0012).

## Layers

| Layer | ~share | Modules | CI job |
| --- | ---: | --- | --- |
| **Fast (unit)** | 70% | `corcept-types`, `corcept-guards`, `corcept-ledger`, `corcept-sink` | `quality.yml` → `cargo test` |
| **Contract / integration** | 25% | `corcept-contract`, `corcept-runtime` fixtures, `corcept-sink-cloudevents` cross-sink, `tests/adversarial/` | `validate-contracts.sh`, `cargo test` |
| **E2E / regression** | 5% | `evals/corcept-eval-suite-v2` deterministic paired run | `quality.yml`, `eval-regression.yml` |

## Adding fixtures

1. Hook inputs → `tests/fixtures/hooks/` (use `__CWD__` placeholder).
2. Adversarial scenarios → `tests/adversarial/scenarios/*.yaml`.
3. Wire examples → `contracts/examples/` + schema in `contracts/schemas/`.

Changing **authority** surfaces (ledger line shape, hook I/O) requires an ADR and schema bump.
Changing **projections** (CloudEvents, eval receipts) requires fixture + schema updates only.

## Property tests

`proptest` modules (bounded cases in CI via `PROPTEST_CASES`):

- `corcept-types` — policy lattice, event wire roundtrip
- `corcept-ledger` — hash chain append/verify

Run locally: `PROPTEST_CASES=256 cargo test proptest`
