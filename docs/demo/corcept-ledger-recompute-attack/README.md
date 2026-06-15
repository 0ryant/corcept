# corcept — ledger recompute-attack: signing is what makes it tamper-evident

A reproducible evidence pack that answers one sharp question an auditor will ask:

> *"Your ledger is hash-chained. But the hashing code is open source — what stops
> an attacker who can read it from rewriting a row and recomputing the chain?"*

The honest answer: **the keyless hash chain alone does not stop that. Ed25519
signing does.** This pack proves it by construction, and corrects an earlier
overclaim that the hash chain was protected by a *"private prefix."*

Everything under [`cells/`](cells) is produced by
[`reproduce.ps1`](reproduce.ps1) from synthetic decision rows. No outputs are
hand-edited; nothing dangerous is executed.

---

## The overclaim we corrected

The tool description and docs used to say the chain was *"domain-separated under
a **private** prefix, so a hand-rolled hash will not match."* That was wrong in a
load-bearing way. The prefix is:

```rust
// crates/corcept-ledger/src/canonical.rs
pub const HASH_DOMAIN: &str = "corcept:ledger:v1:";   // PUBLIC, in source
```

It is a **public** domain-separation constant. A hand-rolled `sha256(row_bytes)`
disagrees with the committed digest because it omits *canonicalization* and the
*public* prefix — **not** because the prefix is secret. Crucially, an adversary
who can read this repo can reproduce the digest exactly, so they can rewrite a
row **and recompute the entire chain**. We rewrote that wording everywhere
(`corcept_audit_verify.rs`, `signed_row.rs`, `lib.rs`, `SKILLS.md`).

## The threat model

A **source-reading adversary** with write access to `events.jsonl`. They are not
guessing a secret; they know the algorithm. The only thing they do **not** have
is the operator's Ed25519 **private signing key**.

## What the pack shows

| Cell | Command | Verdict | Meaning |
|---|---|:---:|---|
| `01-clean-keyless.json` | `audit verify` | **pass** | clean ledger, keyless |
| `02-clean-signed.json` | `audit verify --signed` | **pass** | clean ledger, signed (control — rules out "signed always fails") |
| `03-attacked-keyless-FALSE-PASS.json` | `audit verify` | **pass** ⚠️ | the recompute attack **FALSE-PASSES** the keyless chain |
| `04-attacked-signed-CATCHES.json` | `audit verify --signed` | **fail** ✓ | signing **CATCHES** it and names the row (`bad_signature`), exits non-zero |

The attack ([`cells/events-recomputed.jsonl`](cells/events-recomputed.jsonl)):
flip the `rm -rf /` row from `deny` to `allow`, then recompute every
`prev_hash`/`hash` over the public prefix. Signatures are left stale — the
attacker cannot forge a new one.

```jsonc
// 03 — keyless verify, attacked ledger: a clean bill of health it should NOT give
{ "status": "pass", "hash_chain_valid": true, "tamper_detected": false }

// 04 — signed verify, attacked ledger: caught, row named, fail-closed
{ "status": "fail", "tamper_detected": true, "tampered_lines": [2, 3],
  "failures": [ { "line": 2, "reason": "bad_signature" }, … ] }
```

(Line 3 also fails: recomputing row 2's hash changes row 3's `prev_hash`, hence
its signing preimage — the chain linkage propagates the break. Line 2 is the
actually-edited row.)

## Why this is honest

- **Deterministic, not a model-lift claim.** It asserts a property of the
  verifier — *signed catches what keyless cannot* — proven by construction and
  pinned by [`crates/corcept-ledger/tests/recompute_attack.rs`](../../../crates/corcept-ledger/tests/recompute_attack.rs)
  (CI-enforced). The clean-signed control rules out a vacuous "signed always
  fails" result.
- **No default flip.** The default mode is unchanged. Enforcement stays exactly
  where it already was: append signed rows with `CORCEPT_SIGN_LEDGER=1` (or
  `CORCEPT_TRUSTED_HISTORY=1`), and gate with `corcept doctor --strict`
  (fail-closed, non-zero exit). The keyless mode is now *honestly labelled* as
  tamper-detection, not tamper-evidence.

## Honest ceiling

Signing proves a row was produced by a holder of the operator key. It does **not**
prove a decision's *content* was correct, and it does not help if the signing key
itself leaks. Cross-machine non-repudiation (binding to an external trust root)
is the `tsign` / cex-spine path, deferred.

## Reproduce it

Requires the `corcept` binary (`cargo build -p corcept-cli --release`). From
anywhere:

```powershell
pwsh docs/demo/corcept-ledger-recompute-attack/reproduce.ps1
```

The script builds a self-contained signed workspace (its key lives under a
throwaway `CORCEPT_DATA_HOME`, never your real key), appends synthetic rows, runs
the recompute attack via
`cargo run -p corcept-ledger --example recompute_attack`, verifies both modes,
and **asserts** the proof (it throws if keyless ever catches the attack or signed
ever misses it).

---

*All ledger rows are synthetic; no command is executed. See
`docs/adr/0025-signed-ledger-rows.md` and `docs/adr/0021-canonical-ledger-hashing.md`.*
