# corcept — Claude Code Hook Governance (hook-governance demo)

A complete, reproducible evidence pack for a governed Claude Code session. It
shows the loop corcept runs on every tool call an agent attempts:

> **attempted tool call → guard decision (allow / ask / deny) → append-only ledger entry → independently verifiable, tamper-evident evidence**

Everything under [`decisions/`](decisions) and [`ledger/`](ledger) was produced
by `corcept 0.6.0-pre` from the synthetic hook events in [`events/`](events) —
re-run [`reproduce.ps1`](reproduce.ps1) to regenerate it. No outputs are
hand-edited.

**Everything here is synthetic and nothing is executed.** The events are
`PreToolUse` payloads in the Claude Code hook format; corcept *evaluates* them
and returns a permission decision — the dangerous commands (`rm -rf /`,
`curl | bash`, …) are never run. No real session, repo, or credential is
referenced.

Two complementary scenarios:

- **Scenario A — hook governance** ([`events/`](events) → [`decisions/`](decisions)):
  dangerous tool calls denied, sensitive ones escalated for approval, ordinary
  ones allowed. Best seen in [`decisions/summary.md`](decisions/summary.md).
- **Scenario B — tamper-evident ledger** ([`ledger/`](ledger)): every decision
  is hash-chained into an append-only audit log; `corcept audit verify` proves
  integrity and detects any silent edit.

---

## TL;DR

| | value |
|---|---|
| Hook events governed | **10** |
| Decisions | **5 deny / 2 ask / 3 allow** |
| Ledger rows (hash-chained) | **11** |
| `audit verify` on intact ledger | **pass** (hash_chain_valid: true) |
| `audit verify` after a 1-row edit | **fail** (hash_mismatch, line pinpointed) |

corcept turns "the agent could run anything" into a governed, recorded,
verifiable stream: dangerous calls are blocked at the `PreToolUse` boundary, and
the record of what was decided cannot be silently rewritten after the fact.

---

# Scenario A — hook governance (allow / ask / deny)

## 1. What happened

A Claude Code agent attempts a series of tool calls. Wired through corcept (see
[`settings.json`](settings.json)), each `PreToolUse` event is routed to
`corcept hook pretool-guard` *before* the tool runs. corcept returns the Claude
Code permission protocol (`permissionDecision`: `allow` / `ask` / `deny`).

## 2. What corcept decided — *hidden risk made into a governed decision*

`corcept hook pretool-guard` over the 10 events
([`decisions/summary.md`](decisions/summary.md), raw per-event output in
[`decisions/`](decisions)):

| Event | Tool | Input | Decision | Reason |
|---|---|---|:---:|---|
| `danger-rm-rf` | Bash | `rm -rf /` | **deny** | recursive force deletion of dangerous target `/` |
| `danger-curl-pipe-bash` | Bash | `curl … \| bash` | **deny** | remote fetch piped directly to an interpreter |
| `danger-chmod-777` | Bash | `chmod -R 777 /` | **deny** | chmod mode that makes files world-writable |
| `danger-read-shadow` | Read | `/etc/shadow` | **deny** | secret-like / protected file read |
| `danger-ssh-authkeys` | Bash | `… >> ~/.ssh/authorized_keys` | **deny** | references protected path |
| `ask-git-force-push` | Bash | `git push --force origin main` | **ask** | force-push requires explicit L4 approval |
| `ask-sudo-rm` | Bash | `sudo rm -rf /var/log` | **ask** | recursive force deletion requires approval |
| `ok-cargo-test` | Bash | `cargo test --workspace` | **allow** | passed CORCEPT guard |
| `ok-git-status` | Bash | `git status` | **allow** | passed CORCEPT guard |
| `ok-edit-src` | Edit | `src/main.rs` | **allow** | passed CORCEPT filesystem guard |

Three tiers, not a binary: **deny** stops it, **ask** escalates to a human
(L4 approval), **allow** lets routine work through. Each decision is specific —
it names *why*.

## 3. What remains — *honest residual*

The guard matches a curated set of high-signal patterns, not "all bad commands".
For example, a raw `dd if=/dev/zero of=/dev/sda` passed the guard in testing —
device-level destruction isn't in the current pattern set. corcept reduces the
blast radius of the common, high-frequency footguns and routes the ambiguous
ones to a human; it is **defence in depth, not a complete sandbox**. (For actual
process/network isolation, that is `cellos`'s job, not corcept's.)

---

# Scenario B — tamper-evident ledger

Every decision in Scenario A is appended to a hash-chained, append-only audit
ledger ([`ledger/events.jsonl`](ledger/events.jsonl)). Each row carries the
SHA-256 `hash` of its content plus the `prev_hash` of the row before it, so the
whole log is a chain — and each row records the `authority_level` (`L0_observe`
… `L3_execute_local`), the decision, and the reason.

**Intact** — `corcept audit verify`
([`ledger/verify-intact.json`](ledger/verify-intact.json)):

```json
{ "status": "pass", "hash_chain_valid": true, "rows_scanned": 11, "failures": [] }
```

**Tampered** — an attacker edits one committed row, flipping the `rm -rf /`
decision from `deny` to `allow` without recomputing the chain. `corcept audit
verify` ([`ledger/verify-tampered.json`](ledger/verify-tampered.json)):

```json
{
  "status": "fail",
  "hash_chain_valid": false,
  "rows_scanned": 11,
  "failures": [ { "line": 6, "event_id": "evt_…", "reason": "hash_mismatch" } ]
}
```

The edit is caught and the exact altered row is named. You cannot rewrite what
the agent was allowed to do after the fact — that is the property an auditor
needs. (Details in [`ledger/tamper.txt`](ledger/tamper.txt). The ledger can also
be Ed25519-signed per row: `corcept audit verify --signed`.)

---

## 4. Reusable evidence — *what's in this pack*

```
corcept-hook-governance/
├── README.md                     ← this walkthrough
├── reproduce.ps1                 ← regenerates decisions/ + ledger/
├── settings.json                 ← Claude Code wiring (pretool-guard / posttool-audit)
├── events/                       ← 10 synthetic PreToolUse hook events
│   ├── danger-*.json (5)         ← rm -rf, curl|bash, chmod 777, read shadow, ssh authkeys
│   ├── ask-*.json (2)            ← git force-push, sudo rm
│   └── ok-*.json (3)             ← cargo test, git status, edit src
├── decisions/
│   ├── <event>.decision.json     ← raw corcept hook output per event (Claude Code protocol)
│   └── summary.md                ← decision table (5 deny / 2 ask / 3 allow)
└── ledger/
    ├── events.jsonl              ← the hash-chained append-only audit ledger (11 rows)
    ├── verify-intact.json        ← audit verify → pass
    ├── verify-tampered.json      ← audit verify after a 1-row edit → fail (hash_mismatch)
    └── tamper.txt                ← what the tamper test changes
```

## 5. Reproduce it

Requires the `corcept` binary (`cargo build -p corcept-cli --release` →
`target/release/corcept.exe`). From anywhere:

```powershell
pwsh docs/demo/corcept-hook-governance/reproduce.ps1
```

The script inits a throwaway governed workspace, runs every event through the
PreToolUse guard, audits one completed call, then verifies the ledger intact and
again after tampering a copy.

---

*Generated with `corcept 0.6.0-pre`. All hook events are synthetic; no command is executed.*
