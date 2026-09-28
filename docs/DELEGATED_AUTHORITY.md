# Delegated authority

Corcept can require a signed authority snapshot before a tool invocation reaches
an allow decision. The gate checks the authenticated attestor's invocation
binding, user grant, capability, organisation policy, target-service policy,
and any required approval, then combines its decision with existing guards.
An existing `Deny` remains final. An existing `Ask` requires an exact signed
approval before delegated admission.

This is an opt-in native `corcept hook pretool-guard`/Claude Code plugin path.
It implements Corcept's provisional `corcept.delegation.v1` consumer envelope
for [issue #13](https://github.com/0ryant/corcept/issues/13).
[McPact #45](https://github.com/0ryant/McPact/issues/45) is the related upstream
proposal. This format makes no upstream interoperability or schema-compliance
claim. See [ADR-0028](adr/0028-delegated-authority.md).

## What supplies authority

The host must obtain identity, grant, capability, organisation and target-service
policy facts from trusted sources and produce an Ed25519-signed snapshot.
Corcept verifies that snapshot against a public key pinned by the operator.
A native Claude hook does not itself authenticate a human, an agent or an
organisation, and it does not query a target service's permissions. A caller's
strings, a tool-name prefix, and `verified: true` cannot supply those facts.

The signed claim states are `verified`, `asserted` and `unavailable`. Only
`verified` claims admit authority. Every claim includes provenance
`issuer_id`, `evidence_id` and a positive version. Here `verified` means the
pinned attestor signed a claim with that state; Corcept has not independently
performed an online identity or policy lookup. Operator trust in the attestor,
its source evidence and snapshot freshness remains required. Plain caller
identity fields are claimed references until they match the signed invocation.

Use opaque principal, organisation, service and resource references. Envelope
references contain 1 to 128 ASCII characters from `[A-Za-z0-9_.:-]`. Do not put
credentials, email addresses, URLs, or raw resource paths in authority records.
Do not encode a secret into an apparently valid opaque reference.

## Operator setup

Supply these variables through the trusted host environment that launches the
native hook:

| Variable | Required value |
| --- | --- |
| `CORCEPT_DELEGATION_POLICY` | Absolute path to the signed snapshot JSON, controlled by the operator |
| `CORCEPT_DELEGATION_PUBKEY` | Pinned Ed25519 public key: 32 bytes encoded as 64 hex characters |
| `CORCEPT_DELEGATION_STATE_DIR` | Pre-existing absolute directory outside the project, protected from agent writes; stores consumed IDs and archived snapshots |

All three are required once any one is present. Empty, partial, unreadable or
invalid configuration denies. A supplied delegation payload without a
configured gate also denies. Without configuration and without a delegation
payload, the audit explicitly records `not_configured` and existing guard
behavior continues. That status provides no delegated-authority assurance.

Provision the existing operator ledger-signing key with `corcept key generate`
before enabling the gate. The gate requires a signed admission row using that
key even if `CORCEPT_TRUSTED_HISTORY` is unset. Set `CORCEPT_TRUSTED_HISTORY=1`
for the rest of the hook lifecycle and use the existing operator data/key paths
when configuring the host. The snapshot-attestor key and ledger-signing key
serve different purposes; pin the intended attestor's public key.

For example, after the operator has provisioned the files and directory:

```bash
export CORCEPT_DELEGATION_POLICY=/var/lib/corcept-authority/snapshot.json
export CORCEPT_DELEGATION_PUBKEY='<replace with the attestor public key: 64 hex characters>'
export CORCEPT_DELEGATION_STATE_DIR=/var/lib/corcept-authority/state
export CORCEPT_TRUSTED_HISTORY=1
```

Use owner-only permissions on Unix or equivalent protected ACLs on Windows.
Protect the snapshot, public-key configuration, state directory, signing keys,
host launcher and hook configuration from agent modification. This guide does
not install a host integration or change global runtime settings.

The plugin's `PreToolUse` matcher is `*`, covering every tool event the host
delivers, including MCP tools. An older installed plugin or generated hook
configuration with a fixed tool list must be updated before claiming that
coverage. Native Claude Code has its own coverage limits: `EndConversation`
skips these events, and prompt `@` file references do not invoke a tool hook.
These are documented in the
[Claude Code hook reference](https://code.claude.com/docs/en/hooks).

The generated MCP `corcept_hook_pretool_guard` wrapper sets
`plan.env.inherit = false`. It does not currently forward this authority
configuration and is unsupported for delegated admission until explicitly
wired to the trusted operator environment. Invoking that wrapper as a candidate
decision tool does not establish enforcement of a later tool execution.

## Envelope and actual invocation

Add `delegation` to the host's `PreToolUse` hook JSON. The envelope contains:

| Field | Meaning |
| --- | --- |
| `schema` | Exactly `corcept.delegation.v1` |
| `correlation_id` | Opaque audit join reference |
| `caller_id`, `agent_id`, `user_id`, `organisation_id` | Claimed subject references to match to the signed binding and grant |
| `target_service`, `capability`, `action`, `resource` | Exact requested scope; no wildcard expansion |
| `grant_id` | Grant reference resolved in the signed snapshot |
| `approval_id` | Optional exact invocation approval reference; omission or null means absent |

The envelope rejects unknown fields and caller-supplied verification markers.
A present null, scalar, array, incomplete, or malformed `delegation` is invalid.
The surrounding hook allows extra native host fields for compatibility.

The delegated hook requires `hook_event_name: "PreToolUse"`, absolute native
`cwd`, `session_id`, `tool_use_id`, `tool_name`, and an object `tool_input`. The
three invocation references have the same ASCII bound as the envelope. If the host includes
`agent_id`, it must equal `delegation.agent_id`.

The guard matches a signed invocation's session, tool-use ID, exact tool name,
and complete parsed delegation envelope. The runtime requires the canonical
`cwd` to equal its selected project root. It computes `input_digest` as
`blake3:<64 lowercase hex characters>` over JCS canonical JSON:

```json
{"cwd":"/tmp/project","tool_name":"mcp__records__get_record","tool_input":{"record_ref":"record:42"}}
```

The digest binds the raw UTF-8 `cwd` string as well as the operation. The gate
rejects integers outside JCS's exact safe range in argument JSON. No
cross-platform native-path interoperability is claimed.

Changing the actual working directory, tool or arguments without a matching
new signed binding denies, even if the caller keeps the same capability/action strings.
[The contract example](../contracts/examples/delegation-allow.json) shows an
MCP read scenario. It is a syntax fixture, contains no signed authority, and
cannot by itself produce an allow decision.

## Signed snapshot and approval lifecycle

The wire object is `{ "snapshot": AuthoritySnapshot, "signature": "..." }`.
The signature is 64 Ed25519 bytes encoded as 128 hex characters. The signing
preimage is the UTF-8 domain `corcept:authority-snapshot:v1:` followed by JCS
canonical JSON of `snapshot`. The public key comes from the operator pin,
never from an untrusted key embedded in the snapshot.

The strict snapshot has schema `corcept.authority-snapshot.v1`, `id`,
`version`, `valid_from`, `expires_at`, and required arrays `invocations`,
`grants`, `capabilities`, `service_policies`, `organisation_policies` and
`approvals`. The first five arrays must be nonempty; `approvals` can be empty.
Objects reject unknown fields. Versions are positive JCS-safe integers;
timestamps are nonnegative Unix seconds. The snapshot validity interval must
contain the grant and approval intervals, and the current time must be inside
each relevant interval. IDs are globally distinct. An invocation's
`(session_id, tool_use_id)` and an approval's invocation reference cannot repeat.
The gate limits snapshot JSON and canonical invocation JSON to 1 MiB, and each
snapshot array to 1,024 records. The approval interval must also be contained
within its grant's interval.

| Record | Binding checked by the gate |
| --- | --- |
| Invocation | `id`, session, tool-use ID, tool name, actual cwd/input digest, complete delegation envelope, required authority and verified claim |
| Grant | `id`, explicit `version`, all subject IDs, exact scope, capability/service/organisation policy IDs and versions, validity, maximum authority, approval requirement and verified claim |
| Capability | ID and version, exact scope, maximum authority and verified claim |
| Service / organisation policy | ID and version, owning service/organisation, exact scope, explicit `allow` decision and verified claim |
| Approval | ID, invocation ID, grant ID, snapshot ID and version, actual input digest, validity and verified claim |

The snapshot version pins the approval to the grant and policy versions carried
by that snapshot. Replacing a grant, policy, invocation or snapshot requires
fresh matching attestations; an old approval cannot be reused for the new
snapshot version. Policy `deny`, `unknown`, missing scope or unverified claims
deny. User grants and approvals never override service or organisation denial.

Required authority must stay within the grant, capability, and configured
`authority.default_max_level` ceilings. The default project ceiling is
`L3_execute_local`; an `L4_external_side_effect` invocation requires the
operator to configure that higher ceiling as well as matching signed authority.

The signed required authority must also meet Corcept's conservative tool floor:

| Tool | Minimum authority |
| --- | --- |
| `Read`, `Glob`, `Grep` | `L0_observe` |
| `Edit`, `Write`, `MultiEdit`, `NotebookEdit` | `L2_modify_local` |
| `Bash` | `L3_execute_local` |
| `WebFetch`, `WebSearch`, any `mcp__` tool | `L4_external_side_effect` |
| Other tool names | Denied while delegated authority is configured |

This conservatively assigns MCP calls the external-side-effect floor, even for
a tool described as a read. A caller's action label cannot lower that floor.
A valid presented approval is checked and consumed even when the grant does not
require approval. Missing required signed approval denies. If an existing base
guard returns `Ask`, only a verified approval bound to this exact invocation
may resolve it. Without that approval, delegated admission denies pending a
fresh trusted approval and re-evaluation. No native UI `Ask` is left to execute
past the consumption/audit gate. An independent base guard's `Deny` stays final.

Corcept is a verifier and consumer here. A trusted host/issuer integration must
create and refresh snapshots from its identity and policy sources; the schema
example is not an issuer or a credential flow.

## Replay state, audit and reconstruction

Before returning an allowed invocation, the gate atomically reserves the signed
invocation ID and any valid approval ID presented under
`CORCEPT_DELEGATION_STATE_DIR`. It then appends a mandatory signed decision row.
A crash or signing/audit
failure after reservation burns those IDs and denies. Reissue new invocation
and approval IDs through the trusted issuer rather than retrying the old ones.

The gate stores the exact signed snapshot bytes under
`snapshots/<blake3-of-signed-JSON-bytes>.json`. This archive digest differs from
the invocation input digest. The ledger's `metadata.delegation` records
evaluator evidence, the snapshot digest and relative archive path, the final
decision, and the enforcement status. Audit consumers can join that row to its
archived snapshot to reconstruct the grant, policy and approval versions that
were checked. Keep the archive, signed ledger and trusted public-key history
together when retaining evidence. `authority_key_digest` identifies the pin by
BLAKE3 of its lowercase public-key hex. The verifier must select its trusted
public key independently; a key digest in a row cannot establish its own trust.
A corrupt or missing archive weakens later reconstruction even if a historical
row still verifies.

Run `corcept audit verify --signed` to verify ledger signatures and the hash
chain. Independently verify the archived snapshot against the pin used at
admission and compare the row's recorded digest and resolved references.
The project ledger remains project-local; the protected consumption/archive
directory is deliberately outside it. Configuration, verification, archive,
consumption and signing errors produce explicit JSON deny output. When the
audit sink itself fails, a deny response does not imply an audit row exists.

Do not clean, reset or roll back live consumption state casually. Restoring an
older copy can make a consumed approval appear unused. Privileged attackers
who can replace the operator environment, public-key pin, hook, signing key,
or protected state can undermine admission. Filesystem protection and a trusted
host clock are deployment requirements, not properties proved by a signature.

## Evidence ceiling

Contract tests prove accepted/rejected JSON shapes. Guard and CLI tests prove
the checkout's decisions, binding checks, replay behavior and signed-audit
failure handling. A standalone `PreToolUse` evaluator returns a decision; it
does not prove the real host actually prevented execution. Verify that the
deployed host invokes the protected native hook for the intended tools and
honours its deny output before making a live enforcement claim.
