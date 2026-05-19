# Storage layout (ADR-0024)

Two-tier storage: **project authority** in-repo, **operator scope** via XDG.

## Project scope (in-repo)

| Artifact | Default path | Override |
| --- | --- | --- |
| Ledger (authority) | `.corcept/ledger/events.jsonl` | `$CORCEPT_LEDGER` |
| Config | `.corcept/config.yaml` | — |
| Memory | `.corcept/memory/` | — |
| Doctrine | `.doctrine/` | — |

Ledger directory is created with mode **0700** on Unix (`corcept init`, `ensure_ledger`).

## Operator scope (XDG)

Resolution order mirrors taudit/cortex:

| Tier | Env override | XDG fallback | HOME fallback |
| --- | --- | --- | --- |
| Data | `$CORCEPT_DATA_HOME` | `$XDG_DATA_HOME/corcept` | `$HOME/.local/share/corcept` |
| State | `$CORCEPT_STATE_HOME` | `$XDG_STATE_HOME/corcept` | `$HOME/.local/state/corcept` |
| Config | `$CORCEPT_CONFIG_HOME` | `$XDG_CONFIG_HOME/corcept` | `$HOME/.config/corcept` |

Per-artifact overrides:

| Artifact | Path | Skip when |
| --- | --- | --- |
| Telemetry | `$CORCEPT_TELEMETRY_DIR` or `{state}/telemetry/events.jsonl` | No HOME and no override |
| Debug log | `$CORCEPT_LOG_DIR` or `{state}/logs/corcept.log` | No HOME and no override |
| Receipts | `$CORCEPT_RECEIPTS_DIR` or `{data}/receipts/dispatch.jsonl` | No HOME and no override |
| Keys (ST-048) | `{data}/keys/` | — |

## CI / headless

When `HOME` and `CORCEPT_*_HOME` are unset, secondary sinks **silently skip** — hooks must not fail.

## Verification

```bash
corcept doctor --validate-perms    # 0700 on .corcept/ledger and operator data
corcept doctor --strict            # schema + hash chain; status fail on any check
```

Implementation: `crates/corcept-types/src/paths.rs`.
