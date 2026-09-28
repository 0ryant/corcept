# Delegated authority at the tool boundary

STATE: CONTROLLED
PHASE: CHECK
Started: 2026-09-28

## Problem and goal

Implement GitHub issue #13: admit each delegated tool action against independent
authority sources and record the decision before execution.

## Constraints

- Preserve existing hook compatibility explicitly; caller strings are assertions.
- No writes to AXIOM runtime roots, bootstrap files, or USER/MEMORY imports.
- McPact #45 owns the upstream contract; inspect its current implementation before
  claiming interoperability. Cortex search returned unrelated candidate context,
  which supplies no implementation or execution authority.

## Criteria and test strategy

- CHK[1]: Latest open issues and upstream contract state are observed through GitHub.
- CHK[2]: Required delegation claims, exact invocation bindings, and scope ceilings
  are evaluated before hook admission. Probe: fixture-driven guard tests.
- CHK[3]: Missing/expired grants, identity/resource mismatch, service/organisation
  denial, and unknown required authority cannot allow. Probe: adverse fixtures.
- CHK[4]: Approval is action-bound, cannot override denial, and cannot replay.
  Probe: approval mutation/replay and runtime integration tests.
- CHK[5]: Ledger evidence reconstructs policy/grant versions and the evaluated
  invocation without credentials. Probe: signed-ledger integration and tampering.
- CHK[6]: Changed contracts, documentation, formatting, lint, and relevant tests
  pass; limitations and preserved state are recorded. Probe: integration checks.

ANTI[1]: No caller-supplied verification marker becomes independent authority.
ANTI[2]: No existing guard denial is weakened by a delegation allow or approval.
ANTI[3]: No unscoped repository or runtime edits; no false verification claims.

## Lanes

See docs/LANES.md. Read-only discovery runs independently from source inspection.
Write lanes will receive disjoint paths and a fixed interface before dispatch.

## Initial evidence

- observed: CMD(git status --short, exit=0): clean at 43da6f4 on main.
- observed: CMD(git worktree list, exit=0): one checkout.
- observed: CMD(git fetch origin, exit=0), HEAD...origin/main: 0/0.
- observed: TOOL(github_search_issues): only open issue is #13.
- observed: TOOL(github_fetch_issue): McPact #45 is open with no comments.
- observed: FILE(canonical AXIOM algorithm and CONTEXT_ROUTING.md): loaded from
  ~/.Codex/pai-axiom; compatibility files have no authority here.

## Decisions

- DEC[1]: GitHub tree inspection found no delegation schema on McPact main;
  implement a provisional Corcept v1 consumer and document the migration boundary.
- DEC[2]: Authority anchors come from operator environment, never hook cwd or
  caller metadata. Signed snapshots bind identity, grant, policy, exact arguments,
  session and invocation; unknown links deny. All tool matchers must be covered.
- DEC[3]: Approval consumption is atomic in protected operator state, independent
  from project ledger rewrites. Archive signed snapshots for offline reconstruction.
- DEC[4]: Active delegation requires signed decision evidence before allow;
  hook failures must return explicit deny JSON. Existing guard denial still wins.
- DEC[5]: Use source sibling worktrees. A tool-created unused managed source
  checkout under .codex/worktrees was queued for archive; deployment roots and
  bootstrap content receive no edits.
- DEC[6]: Native Ask can execute after a UI click without a second hook call.
  Required delegation approvals therefore deny until signed. A valid exact signed
  approval may resolve a base Ask after the authority chain passes; base Deny is
  never overridden. Consume invocation and approval before signed admission.
- DEC[7]: Review found concurrent archive publication and raw derived-sink
  correlation risks. Publish complete snapshots atomically, sync supported
  directory entries, and hash unverified caller references across all sinks.
- DEC[8]: Config schema version is not a policy revision. Record the JCS digest
  of evaluated authority/guards and retain matching config separately; signed
  authority snapshots reconstruct the delegation chain.
- DEC[9]: Rust 1.88 formatting check exposed pre-existing whitespace drift in
  signed_append.rs, doctor_signed.rs, sink-cloudevents/lib.rs and ledger submodules.
  Normalize those formatting-only diffs to pass the required workspace gate.

## CHECK.VERIFY

- CHK[1]: PASS — observed TOOL(github_search_issues, github_fetch_issue),
  CMD(gh issue list/view, exit=0), upstream main tree has no delegation schema.
- CHK[2]: PASS — observed TEST(delegation guard matrix, pass): 23 tests including
  27 fixture mutations bind subjects, cwd, tool, arguments, scope and ceilings.
- CHK[3]: PASS — observed TEST(delegation guard matrix, pass): missing/expired
  grants, identity/resource changes, unknown claims and policy denial reject.
- CHK[4]: PASS — observed TEST(delegation_boundary, pass): 11 integration tests
  include native Ask handling, one-use/reissued approval, simultaneous calls,
  exact invocation, configured ceiling and external user-approval requirements.
- CHK[5]: PASS — observed TEST(delegation_boundary, pass): signed row and immutable
  archive reconstruction, tampering, unsigned history, sidecar mismatch, signer
  failure, broken archive/audit and no plaintext leakage across derived sinks.
- CHK[6]: PASS — observed CMD(Rust 1.88 cargo test --workspace --all-targets
  --locked, exit=0): 185 tests pass with PROPTEST_CASES=32; CMD(Rust 1.88 cargo
  clippy --workspace --all-targets --locked -- -D warnings, exit=0);
  CMD(Rust 1.88 cargo fmt --all -- --check, exit=0), CMD(git diff --check, exit=0).
  Contract tests: 12 pass. Local path guard checked again after staging records.

Commands used explicit cargo/rustc/rustdoc paths from `rustup which --toolchain
1.88.0` and a project-local `target-delegation-1.88`. An initial shared-target
run failed with E0514 due to mixed compiler artifacts; no cache was deleted.

ANTI[1]: PASS — observed DIFF(guards/delegation.rs) and tests: only an externally
pinned signed attestation establishes authority; request assertions are hashed.
ANTI[2]: PASS — observed TEST(delegation_boundary, pass): a signed exact approval
can satisfy Ask; service/organisation/base Deny remains final.
ANTI[3]: PASS — observed initial/final git probes and joined path manifest;
no production deployment, bootstrap edits or USER/MEMORY imports issued.

Capabilities: GitHub API/CLI, source reads, worktrees, independent review,
fixture tests, contracts, lint and format were invoked. Cortex returned unrelated
candidate memories and supplied no execution or completion evidence.

Preserved state: initially clean repository; all final source edits belong to this
issue or recorded formatting repairs. Source sibling worktree commits preserved.
The unused tool-created managed checkout was archived (observed list_artifacts);
its source/attachment metadata is the only managed-root change. AXIOM deployment
content, bootstrap paths, and USER/MEMORY imports were not edited.

## CHECK.RESULT

Completed: native opt-in admission, signed authority consumer, one-use approval,
signed audited decisions, privacy minimization, schema contracts and operator guide.
Compatibility: unconfigured hooks retain guard behavior with explicit
`not_configured` evidence; unconfigured delegation payloads deny.
Residual risk: trusted attestor accuracy, protected operator environment/state,
Windows ACL and power-loss durability, and actual deployed host deny handling
remain deployment assumptions. McPact #45 is a proposal; no upstream schema
interoperability is claimed. Base guard reconstruction needs matching retained
operator config identified by its recorded digest. Live runtime deployment is
outside this source change.

Delivery: observed CMD(git push, exit=0) and CMD(gh pr view, exit=0):
[draft PR #14](https://github.com/0ryant/corcept/pull/14) is open from
feat/delegated-authority to main and attached to this task. No merge or issue
closure was performed. GitHub reported no CI results at the delivery probe;
local checks above are the verification evidence.
