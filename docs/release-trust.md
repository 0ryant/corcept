# Release artifact trust (ST-050)

Release signing is **distinct** from audit ledger row signing (ADR-0025 / ST-048).

## Goals

- Operators can verify release tarballs/binaries came from the project maintainers.
- CI publishes checksums always; signatures when secrets are available.

## Artifact tiers

| Tier | Artifact | Trust mechanism |
| --- | --- | --- |
| **Required** | SHA-256 checksums (`SHA256SUMS` or GitHub `checksums.txt`) | Compare after download |
| **Recommended** | minisign `.minisig` sidecars | Verify with published public key |
| **Optional** | cosign signatures for container/OCI artifacts | `cosign verify` against keyless or keyed policy |

## CI behavior

When release secrets are **present** (e.g. `MINISIGN_SECRET_KEY` in GitHub Actions):

1. Build release artifacts for `linux-x86_64`, `linux-aarch64`, `macos-universal` (or matrix equivalent).
2. Emit `SHA256SUMS`.
3. Sign each artifact with minisign; attach `.minisig` files to the GitHub Release.

When secrets are **absent** (fork PRs, local dry-run):

1. Publish unsigned artifacts + checksums only.
2. Release notes state **unsigned build** — verify checksum, not signature.

## Operator verification

```bash
# Checksum only
shasum -a 256 -c SHA256SUMS

# minisign (when .minisig present)
minisign -Vm corcept-v0.5.0-x86_64-unknown-linux-gnu.tar.gz -P <PUBLISHED_PUBKEY>

# Ledger audit (separate concern)
corcept audit verify --signed
```

## Public key distribution

- minisign public key committed at `docs/release/minisign.pub` (placeholder until first signed release).
- Release notes link to the key fingerprint used for that tag.

## References

- `docs/RELEASE_GATES.md`
- ADR-0025 (ledger row signing — not release signing)
- taudit `docs/release-trust.md` pattern
