# Release gates

## P0 blockers (public contract surfaces)

- All `contracts/schemas/*` examples validate in CI
- `cargo test --workspace` green on ubuntu + macos
- Deterministic eval suite (`run-paired-all --skip-agent`) green
- No gitleaks findings on `main`

## Governance (ST-029)

- `governance.yml` — gitleaks, cargo-audit, trivy fs, actionlint, zizmor
- Local: `make governance` (advisory mode skips hard fail on missing tools)

## Contract-breaking changes

Require ADR update + schema version bump (`v2` or new `$id`).

## Audit ledger signing (ST-048)

- Optional Ed25519 per-row signatures (ADR-0025)
- `corcept key generate` → `$CORCEPT_DATA_HOME/keys/active.ed25519` (0600)
- `corcept audit verify` — hash chain (default)
- `corcept audit verify --signed` — require valid signature on every row
- Opt-in append: `CORCEPT_TRUSTED_HISTORY=1` or `CORCEPT_SIGN_LEDGER=1`

## Release artifact signing (ST-050)

See [`release-trust.md`](release-trust.md).

| Condition | Published artifacts |
| --- | --- |
| Release secrets available | Tarballs + `SHA256SUMS` + minisign `.minisig` |
| No secrets (fork/PR) | Tarballs + `SHA256SUMS` only (document unsigned) |
| Container releases (future) | cosign when OCI publish is added |

Do **not** conflate release minisign/cosign with ledger row Ed25519 — separate trust domains.
