# Delegated authority lanes

Started: 2026-09-28. Initial git state: clean main at 43da6f4; one worktree.

- LANE[1]: owner=root | scope=design, integration, verification | isolation=main
  | writes=AXIOM.md, docs/LANES.md, crates/corcept-runtime/**,
    crates/corcept-cli/src/main.rs, crates/corcept-ledger/src/lib.rs,
    crates/corcept-sink/src/lib.rs, plugins/corcept/hooks/hooks.json, Cargo.lock
  | reads=workspace | depends_on=none | clobber_risk=low
  | contract=reviewable implementation and observed checks | gate=join verification
- LANE[2]: owner=authority_review | scope=issue #13 threat and acceptance review
  | isolation=read-only | writes=none | reads=types, guards, runtime, ledger, schemas
  | depends_on=none | clobber_risk=low | contract=bounded design findings and tests
  | gate=root review against observed source

NEXT[1]: lanes=LANE[1],LANE[2] | reason=independent source/design discovery
| join=interface and implementation lane allocation

- LANE[3]: owner=delegation_guard | scope=typed authority snapshot and pure evaluator
  | isolation=worktree ../corcept-delegation-guard
  | writes=crates/corcept-types/src/delegation.rs, crates/corcept-types/src/lib.rs,
    crates/corcept-guards/src/delegation.rs, crates/corcept-guards/src/lib.rs,
    crates/corcept-guards/Cargo.toml, crates/corcept-guards/tests/delegation.rs,
    tests/fixtures/delegation/**
  | reads=workspace | depends_on=none | clobber_risk=low
  | contract=typed signed policy loader, evaluator, adverse fixtures; actual paths
  | gate=root diff review and joined integration tests
- LANE[4]: owner=delegation_docs | scope=contracts and operator guidance
  | isolation=worktree ../corcept-delegation-docs
  | writes=docs/DELEGATED_AUTHORITY.md, docs/adr/0028-delegated-authority.md,
    README.md, contracts/README.md, contracts/schemas/corcept-delegation-v1.schema.json,
    contracts/schemas/corcept-hook-input-v1.schema.json, schemas/hook-input.schema.json,
    contracts/examples/delegation-allow.json, crates/corcept-contract/src/lib.rs
  | reads=workspace | depends_on=LANE[3] interface | clobber_risk=low
  | contract=honest host/source boundaries and schema/example validation
  | gate=root contract review and tests

NEXT[2]: lanes=LANE[1],LANE[3] | reason=runtime and evaluator use disjoint paths
| join=final evaluator interface; then LANE[4] contracts

Join: core ecb0f45 + a1a265d and contracts 9026489 integrated after actual path
inspection. Root additionally owns formatting-only changes in ledger canonical.rs,
trail.rs, tests/signed_append.rs, runtime tests/doctor_signed.rs, and
sink-cloudevents/src/lib.rs because the required Rust 1.88 workspace format gate
failed on pre-existing drift. No worker writes these paths.

Managed worktree discovery created an unused source checkout under .codex/worktrees;
it was immediately queued for archival. Implementation uses source sibling paths;
no AXIOM runtime deployment or bootstrap content is changed.

All lanes joined. Observed root verification: Rust 1.88 workspace tests (185),
Clippy with warnings denied, formatting, contract tests (12), and whitespace
checks passed. Review findings on Ask handoff, integer hashing, identity privacy,
archive publication, lifecycle signing and policy identification were corrected
and covered by fixtures/integration tests. Worktree commits remain recoverable.

Merge follow-up (operator: "Merge if happy"): implementation lanes above are
complete. The current candidate is a390b55 and the working checkout is clean.

- LANE[5]: owner=root | scope=merge gates and final integration | isolation=main
  | writes=AXIOM.md, docs/LANES.md | reads=workspace, GitHub PR/workflows/runs
  | depends_on=none | clobber_risk=low | contract=observed merge decision and refs
  | gate=source checks, independent review, expected-head merge
- LANE[6]: owner=merge_review | scope=final admission and audit boundary review
  | isolation=read-only | writes=none | reads=guards, runtime, ledger, sink, tests,
    docs and diff | depends_on=none | clobber_risk=low
  | contract=blocking findings with source evidence or bounded no-blocker result
  | gate=root validates findings before merge
NEXT[3]: lanes=LANE[5],LANE[6] | reason=GitHub gates and code review are independent
| join=final merge decision; fixes require a new explicit write scope

Merge review joined: the worker found no feature boundary blocker; root inspected
the admission and signed ledger/sink changes against those findings. The worker
recommended holding for failing inherited supply-chain checks. Root's bounded
source-integration decision and that disagreement are recorded in AXIOM.md DEC[10].
No dependency, license policy, CI setting, or runtime deployment change is made.
