# Release signing keys

## minisign public key

When release signing is enabled in CI (`MINISIGN_SECRET_KEY` GitHub secret), artifact `.minisig` sidecars are published alongside tarballs/zip files.

Commit the matching public key here as `minisign.pub` after generating a release keypair locally:

```bash
minisign -G -p docs/release/minisign.pub -s ~/.minisign/corcept-release.key
# Store the secret key in GitHub Actions as MINISIGN_SECRET_KEY (encrypted secret)
```

Verify a signed artifact:

```bash
minisign -Vm corcept-v0.5.0-x86_64-unknown-linux-gnu.tar.gz -P "$(cat docs/release/minisign.pub)"
```

Until the first signed release, artifacts ship with **SHA256SUMS only** (documented in `docs/release-trust.md`).
