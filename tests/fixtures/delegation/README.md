These are synthetic local authority fixtures, not upstream McPact records.
`input.json` has no cwd; the runner supplies its own absolute checkout path.
`authority.json` has a placeholder input digest; the runner binds it to that
exact cwd and input, signs it with a deterministic test-only Ed25519 seed, then
verifies it through the production pinned-key loader. `scenarios.json` applies
one bounded mutation per fixture. No fixture grants runtime authority.

Approval mutation, signature/key tampering, duplicate IDs/references, unsafe
JCS integers, tool authority floors, and evidence redaction are additional
cases in `crates/corcept-guards/tests/delegation.rs`.
