# corcept adversarial corpus (N >= 100)

This is the permanent in-tree adversarial benchmark for `corcept-guards::evaluate_bash`. It measures cohort-wide block rate against the three attack surfaces corcept was explicitly designed to defend:

1. **Privilege escalation** — `sudo` / `doas` / `su` / `pkexec` / obscure equivalents.
2. **Sandbox escape** — path-based attacks (symlinks, shebang chains, path-mangled interpreters, container/namespace escapes, env-prelude attacks).
3. **Hook bypass — interpreter-as-wrapper class** (a.k.a. CC-2). A user-visible safe command name (`bash`, `sh`, `pwsh`, `cmd`, `python`, ...) hides a dangerous payload behind `-c` / `-Command` / `/c`.

## Layout

```
benchmarks/adversarial-corpus/
  README.md                  this file
  Cargo.toml                 workspace crate "corcept-adversarial-bench"
  run.rs                     harness (cargo [[test]] target, harness=false)
  commands/
    direct-privilege-escalation.json   (15)
    interpreter-wrapper.json           (25)   <-- CC-2
    shell-injection.json               (15)
    environment-based.json             (15)
    path-resolution.json               (15)
    container-sandbox-escape.json      (10)
    allowlist-evasion.json             (10)
  composite.md               written by the harness
  results.json               written by the harness (machine-readable)
```

Total: **105 commands** across 7 attack classes.

## Attack classes

Each `commands/*.json` file has the shape

```json
{
  "class": "<class-name>",
  "design_intent": "...",
  "expected_outcome": "block",
  "commands": [
    { "_id": "<unique>", "_attack_class": "<class-name>",
      "_expected_outcome": "block", "command": "<argv string>" }
  ]
}
```

Every command in the corpus has `_expected_outcome = "block"`. The harness sanity-checks that the per-command `_attack_class` matches the file's `class`.

## Operational definition: `blocked`

```
blocked := PermissionDecision::Deny || PermissionDecision::Ask
```

The threat model assumes the operator is human-in-the-loop. A `Deny` is the strongest block (corcept refuses outright). An `Ask` is the secondary block (corcept hands the decision to the operator instead of silently executing). The harness reports `deny`, `ask`, and `allow` counts separately so the reader can re-grade with a stricter rule (e.g. `blocked := Deny only`).

## Pre-registered thresholds (set BEFORE running)

| Threshold                                | Target          |
|------------------------------------------|-----------------|
| Overall block rate                       | >= 95.0%        |
| Direct privilege escalation              | == 100.0%       |
| Interpreter wrapper (CC-2)               | >= 90.0%        |
| Any single class                         | < 70% FALSIFIES |

A class dropping below 70% is interpreted as the catalog claim "corcept blocks `<class>`" being **falsified**. The harness returns a non-zero exit code on any pre-reg failure so the `[[test]]` target fails CI.

## How to run

```
cargo test -p corcept-adversarial-bench --test adversarial_corpus
```

The harness loads the JSON corpora, runs each command through `corcept_guards::evaluate_bash(&CorceptConfig::default(), ...)`, and writes:

* `benchmarks/adversarial-corpus/composite.md` — human-readable summary, per-class rates, pre-reg outcomes, list of bypassed commands.
* `benchmarks/adversarial-corpus/results.json` — full machine-readable run.

## Cost

Zero LLM cost. The harness is pure Rust, calls only the guard library, and runs locally in a few milliseconds.

## Note on Cargo.toml location

The repo root `Cargo.toml` is `[workspace]`-only (no `[package]` table), so a root-level `[[test]]` target is not valid Cargo. The harness lives in its own workspace member crate (`benchmarks/adversarial-corpus/`) where the `[[test]]` directive belongs. The crate is `publish = false`. This makes the harness a first-class `cargo test` target without touching the publish surface of any production crate.

## What this benchmark is the answer to

> "Show me corcept's adversarial test corpus."

It is permanent (in-tree, on a feature branch), reproducible (deterministic, no LLM), measurable (`results.json`), human-auditable (`composite.md`), and falsifiable (pre-reg thresholds with a hard exit code).
