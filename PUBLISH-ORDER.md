# corcept publish order

Operator-facing sequence for publishing or privately packaging the corcept
workspace.

The current workspace is version `0.6.0-pre` under BUSL-1.1. Internal path
dependencies in publishable members carry matching `version = "0.6.0-pre"`.
Crates.io publication still requires the operator to decide whether the BUSL
line should be privately distributed, relicensed, or published to a registry
that accepts the gated-tier license.

## Topological order (leaves first)

1. `corcept-types` — no path deps. Safe leaf.
2. `corcept-doctrine` — no path deps (uses anyhow + walkdir only). Independent of 1.
3. `corcept-ledger` — depends on `corcept-types`.
4. `corcept-memory` — depends on `corcept-types`.
5. `corcept-guards` — depends on `corcept-types`, `corcept-ledger`.
6. `corcept-runtime` — depends on `corcept-types`, `corcept-ledger`,
   `corcept-guards`, `corcept-doctrine`, `corcept-memory`. **BLOCKED** — also
   depends on `corcept-sink` and `corcept-contract`, both `publish = false`.
   See "Residual blockers" below.
7. `corcept-cli` — depends on `corcept-runtime`, `corcept-memory`,
   `corcept-doctrine`, `corcept-ledger`. **BLOCKED** — also depends on
   `corcept-sink-cloudevents` (`publish = false`).
8. `create-corcept` — depends on `corcept-runtime`. Eligible once 6 ships.
9. `corcept-mcp` — depends on `mcpact-*` crates from a sibling workspace.
   Source builds use sibling-relative path dependencies with
   `version = "0.2.0-pre.1"`. Registry publication remains **BLOCKED** until
   those `mcpact-*` crates are available from the target registry.

## Per-crate dry-run command

If publishing to a registry, wait for each crate to appear on the index
(usually seconds, sometimes minutes), then dry-run the next one:

```
cargo publish --dry-run -p corcept-types
cargo publish --dry-run -p corcept-doctrine
cargo publish --dry-run -p corcept-ledger
cargo publish --dry-run -p corcept-memory
cargo publish --dry-run -p corcept-guards
# corcept-runtime blocked — see below
# corcept-cli blocked — see below
# create-corcept depends on corcept-runtime — blocked
# corcept-mcp depends on cross-workspace mcpact — blocked
```

## Residual blockers (operator must address)

These cannot be fixed by metadata edits alone — they require a workspace
design decision the publish-readiness agent will not unilaterally make.

### 1. Publishable crate depends on `publish = false` crate

`corcept-runtime` declares `corcept-sink` and `corcept-contract` as
dependencies. Both have `publish = false` in their own `Cargo.toml`. Cargo
will reject `corcept-runtime`'s publish step because its declared deps must
all resolve from a registry source (crates.io), not from a path-only sibling.

`corcept-cli` has the same problem with `corcept-sink-cloudevents`.

**Operator choices:**
- (a) Remove `publish = false` from those three crates and let them publish
  to the target registry as `0.6.0-pre`. Cleanest; assumes they were marked
  private only as a precaution.
- (b) Inline the sink/contract code into `corcept-runtime` / `corcept-cli`
  to drop the dependency. Heavier refactor; preserves the "internal only"
  posture for sinks.
- (c) Split sinks behind a Cargo feature gate so the publishable build
  doesn't pull them in. Most flexible; non-trivial to implement.

### 2. `corcept-mcp` cross-workspace path deps

`crates/corcept-mcp/Cargo.toml` references `mcpact-core`, `mcpact-runtime`,
`mcpact-audit`, `mcpact-policy`, `mcpact-mcp`, `mcpact-manifest` via
sibling-relative path dependencies. That keeps local source builds portable
across machines, but `corcept-mcp` cannot publish until:
- (i) The `mcpact-*` crates land on crates.io (see the mcpact
  publish-readiness PR `claude/publish-readiness-mcpact-2026-05-20`).
- (ii) `corcept-mcp/Cargo.toml` switches its `mcpact-*` entries to plain
  `version = "0.2.0-pre.1"` (no `path`) for registry publication.

## Notes

- LICENSE audit: workspace `license = "BUSL-1.1"` matches the current gated
  tier; pre-v0.6.0 license text is preserved as `LICENSE.old`.
- Cargo.lock changes in this branch reflect the sibling `mcpact-*`
  `0.2.0-pre.1` resolution.
- No new dependencies were added.
