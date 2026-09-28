# ADR-0028: Delegated authority at the PreToolUse boundary

- Status: accepted for implementation
- Date: 2026-09-28
- Issue: [corcept #13](https://github.com/0ryant/corcept/issues/13)
- Tags: authority, hooks, identity, policy, audit

## Context

The existing guard classifies a requested tool operation, but that alone cannot
establish which user granted an agent authority or whether an organisation or
target service permits it. Claude's hook fields and caller-provided strings
cannot authenticate those facts. An approval without an exact operation and
policy version can also be replayed or reused after authority changes.

[McPact #45](https://github.com/0ryant/McPact/issues/45) proposes upstream
delegation policy. Corcept needs a bounded consumer now; it does not claim an
accepted upstream schema or interoperability with that proposal.

## Decision

Introduce provisional `corcept.delegation.v1` hook metadata and an opt-in native
PreToolUse admission gate. The host provides an operator-pinned Ed25519-signed
`corcept.authority-snapshot.v1` snapshot through an absolute
`CORCEPT_DELEGATION_POLICY` path and `CORCEPT_DELEGATION_PUBKEY`. Require an
absolute, pre-existing, protected `CORCEPT_DELEGATION_STATE_DIR` outside the
project for replay consumption and snapshot archival.

Any one authority variable activates the configuration requirement. Partial or
invalid configuration denies. Presented delegation without a configured gate
denies. With neither configured authority nor delegation, record
`not_configured` explicitly and retain existing guard behavior.

The gate verifies the snapshot signature, current validity, strict record
shapes, references and versions. It requires verified attestor claims for the
subject-bound invocation, user grant, capability, service policy, organisation
policy, and any required approval. Signed provenance identifies issuer,
evidence and version. `verified` establishes what the pinned attestor signed;
it does not assert that Corcept queried external identity or policy sources.
`asserted`, `unavailable`, unknown policy and absent evidence deny.

Bind actual `session_id`, `tool_use_id`, `tool_name`, JCS/BLAKE3 digest of the
absolute native `cwd`, tool name and actual tool arguments, and the complete
parsed envelope to a signed invocation. Require canonical `cwd` to equal the
runtime's selected project root, and reject integers outside JCS's safe range.
Require exact scope equality and explicit grant/policy/capability versions.
Reject caller verification flags and malformed references. Authority records
must carry bounded opaque references and keep credentials and raw identifying
resources out.

Compute admission as the intersection of the verified user grant, capability,
service allow, organisation allow, valid exact approval when required, and all
authority ceilings including project `default_max_level`, with conservative
tool floors: observation for native reads, local modification for edits,
execution for Bash, and external side effects for web/MCP tools. Unknown tool
names deny. No grant or approval overrides service or organisation denial or
an existing guard's `Deny`.

At this admission boundary, refine ADR-0020's `Ask` handling: a verified
approval bound to the exact signed invocation can resolve the base guard's
approval requirement. Without one, a base `Ask` becomes `Deny` pending trusted
approval and re-evaluation. Missing required delegation approval also denies.
Returning native `Ask` would let the host execute after a UI response without
protected consumption and mandatory signed admission evidence, so it is not
an authorized delegated-admission path.

Approvals bind invocation ID, grant ID, snapshot ID/version and actual input
digest. The snapshot pins the checked policy and grant versions. Atomically
consume invocation and every valid presented approval ID in protected operator
state before a mandatory signed decision append and before returning allow. Failed or crashed
admissions burn reservations; fresh IDs are required. Archive exact signed
snapshot bytes by BLAKE3 digest and record the digest, archive path, resolved
evidence, independently pinned authority-key digest, final decision and
enforcement status in ledger metadata.

Use `*` for the native PreToolUse matcher, including MCP tool events delivered
by Claude. The generated `corcept_hook_pretool_guard` MCP wrapper does not
inherit the operator environment and remains unsupported for delegated
admission until explicitly integrated.

## Consequences and limits

- The native CLI/plugin path can reject authority before reporting an allow.
  JSON deny output is required for active configuration, verification,
  persistence or signing errors; audit failures may prevent a corresponding
  row from being written.
- Offline reconstruction uses the signed decision row plus its archived
  snapshot, preserving explicit grant, policy and approval versions.
- Host/issuer integration remains responsible for authenticated subjects,
  reliable policy sources and fresh snapshots. Schema validation, self-declared
  identities, and a signed `verified` marker alone do not establish those facts.
- A standalone guard decision does not prove host execution was blocked.
  Deployment verification must cover actual hook invocation and deny handling.
  Native host events also omit `EndConversation` and prompt `@` file reads; see
  the [Claude hook reference](https://code.claude.com/docs/en/hooks).
- Protected state requires operator filesystem controls and a trusted clock.
  A privileged environment/key/state replacement or rollback of consumed state
  can defeat the deployment boundary. Never treat replay-state cleanup as
  routine maintenance.
- No global runtime deployment is part of this source change. Existing
  unconfigured projects retain their established guards with an explicit
  delegation non-enforcement audit status.

## Alternatives considered

Trusting caller identity/status strings cannot authenticate subjects. A user
grant overriding target-service or organisation denial would expand authority
past those owners. Storing replay state solely in the project would let a
project writer erase consumption history. Returning allow before durable signed
audit would make failed evidence persistence invisible. These alternatives are
rejected.

## Verification

The committed schemas and `corcept-contract` tests cover envelope examples,
missing fields, unknown versions/fields, malformed references, malformed hook
delegation and required invocation inputs. Guard/runtime tests cover signature,
binding, expiry, policy intersection, approval reuse, persistence and signed
audit failures. Source-local evidence establishes checkout behavior; live host
enforcement and external source accuracy require deployment evidence.

See [the operator guide](../DELEGATED_AUTHORITY.md) and
[the wire contract](../../contracts/schemas/corcept-delegation-v1.schema.json).
