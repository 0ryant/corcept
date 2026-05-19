# CORCEPT — Minimum Viable Doctrine

**One page.** Read before opening a parity or contract PR.

## Context

- **Program:** CORCEPT — governed Claude Code runtime (hooks, ledger, guards, doctrine, memory).
- **Primary pain:** Agent loops lack durable, inspectable evidence and hard policy boundaries.
- **Non-goals (v0.5):** Hosted multi-tenant, Cortex integration runtime, full SIEM mesh.

## Principles → enforcement

| # | Principle | Binds to | Lane / crate |
| --- | --- | --- | --- |
| 1 | [Event contracts](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/event-contracts.md) | ADR-0018, ADR-0022, `contracts/` | `corcept-types`, `corcept-sink-cloudevents` |
| 2 | [State machines](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/state-machines-and-workflows.md) | ADR-0019 hook FSM | `corcept-runtime` |
| 3 | [Audit logging](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/audit-logging.md) | ADR-0006, ADR-0025, ADR-0026 | `corcept-ledger`, `corcept-sink` |
| 4 | [Testing strategy](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/testing-strategy.md) | ADR-0012, contract tests | `corcept-contract`, CI |
| 5 | [Errors / failure modes](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/errors-and-failure-modes.md) | Guards fail closed | `corcept-guards` |
| 6 | [Single source of truth](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/single-source-of-truth.md) | Ledger = authority; CE = projection | ADR-0022 |
| 7 | [Configuration & secrets](https://github.com/0ryant/engineering-doctrine/blob/main/doctrine/principles/configuration-and-secrets.md) | No secrets in ledger/logs | `corcept-runtime` sanitize |

## Storage split

| Scope | Path | Authority |
| --- | --- | --- |
| Project | `.corcept/` | Ledger, doctrine, memory (gitops) |
| Operator | XDG data/state/config | Telemetry, debug logs, keys |

See ADR-0024.
