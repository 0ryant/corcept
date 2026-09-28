//! Signed delegated authority regressions. Keys/identities are synthetic.

use corcept_guards::delegation::AUTHORITY_SIGNATURE_DOMAIN;
use corcept_guards::{
    authority_signing_bytes, evaluate_delegation, invocation_digest, load_authority,
    parse_authority,
};
use corcept_types::{
    AuthorityLevel, AuthoritySnapshot, ClaimState, DelegationApproval, HookEnvelope,
    PermissionDecision, SignedAuthoritySnapshot,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

const NOW: i64 = 1000;

fn fixture() -> (HookEnvelope, AuthoritySnapshot) {
    let mut input: HookEnvelope = serde_json::from_str(include_str!(
        "../../../tests/fixtures/delegation/input.json"
    ))
    .unwrap();
    input.cwd = Some(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap(),
    );
    let mut snapshot: AuthoritySnapshot = serde_json::from_str(include_str!(
        "../../../tests/fixtures/delegation/authority.json"
    ))
    .unwrap();
    snapshot.invocations[0].input_digest = invocation_digest(&input).unwrap();
    (input, snapshot)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn pinned_key() -> String {
    hex::encode(signing_key().verifying_key().as_bytes())
}

fn signed(snapshot: &AuthoritySnapshot) -> String {
    let signature = signing_key().sign(&authority_signing_bytes(snapshot).unwrap());
    serde_json::to_string(&SignedAuthoritySnapshot {
        snapshot: snapshot.clone(),
        signature: hex::encode(signature.to_bytes()),
    })
    .unwrap()
}

// Signing malformed but JSON/JCS-safe structures is deliberately possible in
// these negative tests, independent of the guarded production signing helper.
fn signed_unchecked(snapshot: Value) -> String {
    axiom_canonical::assert_jcs_safe(&snapshot).unwrap();
    let mut material = AUTHORITY_SIGNATURE_DOMAIN.as_bytes().to_vec();
    material.extend(axiom_canonical::to_jcs_bytes(&snapshot).unwrap());
    let signature = signing_key().sign(&material);
    serde_json::to_string(&json!({
        "snapshot": snapshot,
        "signature": hex::encode(signature.to_bytes()),
    }))
    .unwrap()
}

fn verified(snapshot: &AuthoritySnapshot) -> AuthoritySnapshot {
    parse_authority(&signed(snapshot), &pinned_key()).unwrap()
}

fn with_approval(
    mut input: HookEnvelope,
    mut snapshot: AuthoritySnapshot,
    required: bool,
) -> (HookEnvelope, AuthoritySnapshot) {
    let id = "approval:fixture-1";
    input.extra.get_mut("delegation").unwrap()["approval_id"] = json!(id);
    snapshot.invocations[0].delegation.approval_id = Some(id.to_string());
    snapshot.grants[0].approval_required = required;
    snapshot.approvals.push(DelegationApproval {
        id: id.to_string(),
        invocation_id: snapshot.invocations[0].id.clone(),
        grant_id: snapshot.grants[0].id.clone(),
        snapshot_id: snapshot.id.clone(),
        snapshot_version: snapshot.version,
        input_digest: snapshot.invocations[0].input_digest.clone(),
        valid_from: 900,
        expires_at: 1500,
        claim: snapshot.invocations[0].claim.clone(),
    });
    snapshot.approvals[0].claim.provenance.evidence_id = "evidence:approval-1".to_string();
    (input, snapshot)
}

#[derive(Deserialize)]
struct Scenario {
    id: String,
    expected: PermissionDecision,
    reason_code: String,
    #[serde(default)]
    input_set: BTreeMap<String, Value>,
    #[serde(default)]
    input_remove: Vec<String>,
    #[serde(default)]
    snapshot_set: BTreeMap<String, Value>,
}

#[test]
fn signed_fixture_matrix_covers_subject_scope_policy_and_authority_failures() {
    let scenarios: Vec<Scenario> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/delegation/scenarios.json"
    ))
    .unwrap();
    assert_eq!(scenarios.len(), 27);
    for scenario in scenarios {
        let (input, snapshot) = fixture();
        let mut input = serde_json::to_value(input).unwrap();
        let mut snapshot = serde_json::to_value(snapshot).unwrap();
        for (pointer, value) in scenario.input_set {
            *input.pointer_mut(&pointer).expect("existing input field") = value;
        }
        for pointer in scenario.input_remove {
            let (parent, field) = pointer.rsplit_once('/').unwrap();
            input
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        for (pointer, value) in scenario.snapshot_set {
            *snapshot
                .pointer_mut(&pointer)
                .expect("existing snapshot field") = value;
        }
        let input: HookEnvelope = serde_json::from_value(input).unwrap();
        let snapshot: AuthoritySnapshot = serde_json::from_value(snapshot).unwrap();
        let result = evaluate_delegation(&input, &verified(&snapshot), NOW);
        assert_eq!(result.guard.decision, scenario.expected, "{}", scenario.id);
        assert_eq!(
            result.evidence["reason_code"], scenario.reason_code,
            "{}",
            scenario.id
        );
        assert_eq!(result.evidence["evaluated_at"], NOW);
        assert_eq!(result.approval_id, None);
        assert!(!serde_json::to_string(&result.evidence)
            .unwrap()
            .contains("delegation-argument-sentinel"));
    }
}

#[test]
fn pinned_loader_accepts_only_exact_domain_signed_snapshot() {
    let (_, snapshot) = fixture();
    let raw = signed(&snapshot);
    assert_eq!(parse_authority(&raw, &pinned_key()).unwrap(), snapshot);
    let other_key = SigningKey::from_bytes(&[24; 32]);
    assert!(parse_authority(&raw, &hex::encode(other_key.verifying_key().as_bytes())).is_err());
    let wrong_domain = signing_key().sign(&axiom_canonical::to_jcs_bytes(&snapshot).unwrap());
    let wrong_domain = serde_json::to_string(&SignedAuthoritySnapshot {
        snapshot,
        signature: hex::encode(wrong_domain.to_bytes()),
    })
    .unwrap();
    assert_eq!(
        parse_authority(&wrong_domain, &pinned_key()).unwrap_err(),
        "authority_signature_mismatch"
    );
}

#[test]
fn load_reads_signed_file_and_fails_closed_for_bad_inputs() {
    let (_, snapshot) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.json");
    std::fs::write(&path, signed(&snapshot)).unwrap();
    assert_eq!(load_authority(&path, &pinned_key()).unwrap(), snapshot);
    assert!(load_authority(&dir.path().join("absent.json"), &pinned_key()).is_err());
    for key in ["", "abcd", &"z".repeat(64)] {
        assert!(load_authority(&path, key).is_err());
    }
    std::fs::write(&path, "credential-sentinel: malformed json").unwrap();
    let error = load_authority(&path, &pinned_key()).unwrap_err();
    assert_eq!(error, "authority_invalid_json");
    assert!(!error.contains("credential-sentinel"));
    assert!(parse_authority(&" ".repeat(1_048_577), &pinned_key()).is_err());
}

#[test]
fn signature_and_signed_body_tampering_fail() {
    let (_, snapshot) = fixture();
    let mut raw: Value = serde_json::from_str(&signed(&snapshot)).unwrap();
    raw["snapshot"]["grants"][0]["version"] = json!(4);
    assert_eq!(
        parse_authority(&serde_json::to_string(&raw).unwrap(), &pinned_key()).unwrap_err(),
        "authority_signature_mismatch"
    );
    let mut raw: Value = serde_json::from_str(&signed(&snapshot)).unwrap();
    raw["signature"] = json!("00".repeat(64));
    assert!(parse_authority(&serde_json::to_string(&raw).unwrap(), &pinned_key()).is_err());
}

#[test]
fn unknown_fields_and_duplicate_json_fields_are_rejected() {
    let (_, snapshot) = fixture();
    let original = serde_json::to_value(snapshot).unwrap();
    for parent in [
        "",
        "/invocations/0",
        "/invocations/0/delegation",
        "/invocations/0/claim",
        "/invocations/0/claim/provenance",
        "/grants/0",
        "/grants/0/scope",
        "/grants/0/capability_ref",
        "/capabilities/0",
        "/service_policies/0",
        "/organisation_policies/0",
    ] {
        let mut value = original.clone();
        value.pointer_mut(parent).unwrap()["untrusted_status"] = json!("verified");
        assert_eq!(
            parse_authority(&signed_unchecked(value), &pinned_key()).unwrap_err(),
            "authority_invalid_json",
            "unknown field in {parent}"
        );
    }
    let raw = signed_unchecked(original);
    let duplicated = raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert_ne!(raw, duplicated);
    assert_eq!(
        parse_authority(&duplicated, &pinned_key()).unwrap_err(),
        "authority_invalid_json"
    );
    let mut wrapper: Value = serde_json::from_str(&raw).unwrap();
    wrapper["pubkey"] = json!(pinned_key());
    assert!(parse_authority(&serde_json::to_string(&wrapper).unwrap(), &pinned_key()).is_err());
}

#[test]
fn missing_fields_do_not_default_to_authority() {
    let (_, snapshot) = fixture();
    let original = serde_json::to_value(snapshot).unwrap();
    for field in [
        "schema",
        "id",
        "version",
        "valid_from",
        "expires_at",
        "invocations",
        "grants",
        "capabilities",
        "service_policies",
        "organisation_policies",
        "approvals",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            parse_authority(&signed_unchecked(value), &pinned_key()).is_err(),
            "{field}"
        );
    }
    let mut value = original;
    value["invocations"][0]
        .as_object_mut()
        .unwrap()
        .remove("required_authority");
    assert!(parse_authority(&signed_unchecked(value), &pinned_key()).is_err());
}

#[test]
fn duplicate_ids_host_bindings_and_version_references_are_rejected() {
    let (_, snapshot) = fixture();
    let original = serde_json::to_value(snapshot).unwrap();
    let mut duplicate_id = original.clone();
    duplicate_id["capabilities"][0]["id"] = json!("grant:fixture-1");
    assert_eq!(
        parse_authority(&signed_unchecked(duplicate_id), &pinned_key()).unwrap_err(),
        "identifier_duplicated"
    );
    let mut duplicate_binding = original.clone();
    let mut second = duplicate_binding["invocations"][0].clone();
    second["id"] = json!("invocation:distinct-id");
    duplicate_binding["invocations"]
        .as_array_mut()
        .unwrap()
        .push(second);
    assert_eq!(
        parse_authority(&signed_unchecked(duplicate_binding), &pinned_key()).unwrap_err(),
        "invocation_duplicated"
    );
    for pointer in [
        "/grants/0/capability_ref/version",
        "/grants/0/service_policy_ref/version",
        "/grants/0/organisation_policy_ref/version",
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = json!(99);
        assert_eq!(
            parse_authority(&signed_unchecked(value), &pinned_key()).unwrap_err(),
            "reference_unresolved"
        );
    }
    let mut value = original;
    value["invocations"][0]["delegation"]["grant_id"] = json!("grant:unknown");
    assert_eq!(
        parse_authority(&signed_unchecked(value), &pinned_key()).unwrap_err(),
        "grant_reference_unresolved"
    );
}

#[test]
fn snapshot_schema_identifier_version_and_interval_validation_is_strict() {
    let (_, snapshot) = fixture();
    let original = serde_json::to_value(snapshot).unwrap();
    for (pointer, replacement) in [
        ("/schema", json!("corcept.authority-snapshot.v2")),
        ("/id", json!("")),
        ("/id", json!("contains whitespace")),
        ("/id", json!("user@example.test")),
        ("/id", json!("x".repeat(129))),
        ("/version", json!(0)),
        ("/valid_from", json!(-1)),
        ("/expires_at", json!(900)),
        ("/grants/0/valid_from", json!(899)),
        ("/grants/0/expires_at", json!(1901)),
        ("/grants/0/version", json!(0)),
        ("/service_policies/0/version", json!(0)),
        ("/invocations/0/claim/provenance/version", json!(0)),
        ("/capabilities", json!([])),
        ("/organisation_policies", json!([])),
    ] {
        let mut snapshot = original.clone();
        *snapshot.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            parse_authority(&signed_unchecked(snapshot), &pinned_key()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn invocation_digest_is_jcs_order_independent_and_binds_cwd_tool_and_args() {
    let (input, snapshot) = fixture();
    let digest = invocation_digest(&input).unwrap();
    let mut reordered = input.clone();
    reordered.tool_input = Some(
        serde_json::from_str(
            r#"{"content":"delegation-argument-sentinel","file_path":"document.txt"}"#,
        )
        .unwrap(),
    );
    assert_eq!(invocation_digest(&reordered).unwrap(), digest);
    for mutate in 0..3 {
        let mut changed = input.clone();
        match mutate {
            0 => changed.cwd = Some(input.cwd.as_ref().unwrap().join("other-root")),
            1 => changed.tool_name = Some("Edit".to_string()),
            _ => changed.tool_input.as_mut().unwrap()["content"] = json!("mutated"),
        }
        assert_ne!(invocation_digest(&changed).unwrap(), digest);
        assert_eq!(
            evaluate_delegation(&changed, &verified(&snapshot), NOW)
                .guard
                .decision,
            PermissionDecision::Deny
        );
    }
}

#[test]
fn unsafe_jcs_integer_argument_substitution_is_rejected() {
    let (mut input, mut snapshot) = fixture();
    for unsafe_number in [9_007_199_254_740_992_u64, 9_007_199_254_740_993_u64] {
        input.tool_input = Some(json!({ "nested": { "id": unsafe_number } }));
        assert_eq!(
            invocation_digest(&input).unwrap_err(),
            "canonical_json_unsafe"
        );
        assert_eq!(
            evaluate_delegation(&input, &snapshot, NOW).guard.decision,
            PermissionDecision::Deny
        );
    }
    snapshot.version = 9_007_199_254_740_993;
    assert!(authority_signing_bytes(&snapshot).is_err());
    input.tool_input = Some(json!({ "nested": { "id": -9_007_199_254_740_992_i64 } }));
    assert!(invocation_digest(&input).is_err());
    input.tool_input = Some(json!({ "nested": { "id": 9_007_199_254_740_991_u64 } }));
    assert!(invocation_digest(&input).is_ok());
    input.tool_input =
        Some(serde_json::from_str(r#"{"id":200000000000000000000000000000001}"#).unwrap());
    assert!(invocation_digest(&input).is_err());
}

#[test]
fn malformed_and_caller_verified_metadata_never_authorizes_or_leaks() {
    let (input, snapshot) = fixture();
    let snapshot = verified(&snapshot);
    for delegation in [
        Value::Null,
        json!("credential-sentinel"),
        json!([]),
        json!({}),
    ] {
        let mut changed = input.clone();
        changed.extra.insert("delegation".to_string(), delegation);
        let result = evaluate_delegation(&changed, &snapshot, NOW);
        assert_eq!(result.guard.decision, PermissionDecision::Deny);
        assert!(!serde_json::to_string(&result.evidence)
            .unwrap()
            .contains("credential-sentinel"));
    }
    let mut changed = input.clone();
    changed.extra.get_mut("delegation").unwrap()["claim_state"] = json!("verified");
    assert_eq!(
        evaluate_delegation(&changed, &snapshot, NOW).evidence["reason_code"],
        "delegation_invalid"
    );
    for pointer in [
        "caller_id",
        "agent_id",
        "user_id",
        "organisation_id",
        "target_service",
        "capability",
        "action",
        "resource",
        "grant_id",
        "correlation_id",
    ] {
        let mut changed = input.clone();
        changed.extra.get_mut("delegation").unwrap()[pointer] =
            json!("credential-sentinel@example.test");
        let result = evaluate_delegation(&changed, &snapshot, NOW);
        assert_eq!(result.guard.decision, PermissionDecision::Deny);
        assert!(!serde_json::to_string(&result.evidence)
            .unwrap()
            .contains("credential-sentinel"));
    }
}

#[test]
fn syntax_valid_unverified_request_references_are_hashed_in_evidence() {
    let (input, snapshot) = fixture();
    let snapshot = verified(&snapshot);
    for field in [
        "caller_id",
        "agent_id",
        "user_id",
        "organisation_id",
        "target_service",
        "capability",
        "action",
        "resource",
        "grant_id",
        "correlation_id",
        "approval_id",
    ] {
        let mut changed = input.clone();
        changed.extra.get_mut("delegation").unwrap()[field] = json!("credential-sentinel");
        let result = evaluate_delegation(&changed, &snapshot, NOW);
        assert_eq!(result.guard.decision, PermissionDecision::Deny);
        assert!(
            !serde_json::to_string(&result.evidence)
                .unwrap()
                .contains("credential-sentinel"),
            "{field}"
        );
        assert!(!result.guard.reason.contains("credential-sentinel"));
    }
}

#[test]
fn unknown_approval_reference_is_not_ignored_without_approval_requirement() {
    let (mut input, mut snapshot) = fixture();
    input.extra.get_mut("delegation").unwrap()["approval_id"] = json!("approval:unknown");
    assert_eq!(
        evaluate_delegation(&input, &verified(&snapshot), NOW)
            .guard
            .decision,
        PermissionDecision::Deny
    );
    snapshot.invocations[0].delegation.approval_id = Some("approval:unknown".to_string());
    assert_eq!(
        parse_authority(
            &signed_unchecked(serde_json::to_value(snapshot).unwrap()),
            &pinned_key()
        )
        .unwrap_err(),
        "approval_reference_unresolved"
    );
}

#[cfg(unix)]
#[test]
fn invalid_utf8_native_cwd_is_rejected_without_lossy_conversion() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let (mut input, _) = fixture();
    input.cwd = Some(PathBuf::from(OsString::from_vec(vec![b'/', 0xff])));
    assert_eq!(
        invocation_digest(&input).unwrap_err(),
        "invocation_cwd_invalid"
    );
}

#[test]
fn hook_host_fields_and_argument_shape_are_required() {
    let (input, snapshot) = fixture();
    let snapshot = verified(&snapshot);
    for mutation in 0..11 {
        let mut changed = input.clone();
        match mutation {
            0 => changed.hook_event_name = "PostToolUse".to_string(),
            1 => changed.session_id = None,
            2 => changed.tool_use_id = None,
            3 => changed.tool_name = None,
            4 => changed.cwd = None,
            5 => changed.cwd = Some(PathBuf::from("relative-root")),
            6 => changed.tool_input = None,
            7 => changed.tool_input = Some(Value::Null),
            8 => changed.tool_input = Some(json!([])),
            9 => changed.tool_input = Some(json!("raw args")),
            _ => changed.tool_use_id = Some("unknown-tool-use".to_string()),
        }
        assert_eq!(
            evaluate_delegation(&changed, &snapshot, NOW).guard.decision,
            PermissionDecision::Deny,
            "mutation {mutation}"
        );
    }
    let mut no_native_agent = input;
    no_native_agent.agent_id = None;
    assert_eq!(
        evaluate_delegation(&no_native_agent, &snapshot, NOW)
            .guard
            .decision,
        PermissionDecision::Allow
    );
}

#[test]
fn required_authority_uses_conservative_host_floor_not_base_allow_l0() {
    let (input, snapshot) = fixture();
    for (tool, level, accepted) in [
        ("Read", AuthorityLevel::L0Observe, true),
        ("Write", AuthorityLevel::L0Observe, false),
        ("Bash", AuthorityLevel::L2ModifyLocal, false),
        ("Bash", AuthorityLevel::L3ExecuteLocal, true),
        ("mcp__fixture__write", AuthorityLevel::L3ExecuteLocal, false),
        (
            "mcp__fixture__write",
            AuthorityLevel::L4ExternalSideEffect,
            true,
        ),
        ("WebFetch", AuthorityLevel::L3ExecuteLocal, false),
        ("WebFetch", AuthorityLevel::L4ExternalSideEffect, true),
        ("UnknownTool", AuthorityLevel::L4ExternalSideEffect, false),
        ("write", AuthorityLevel::L4ExternalSideEffect, false),
    ] {
        let mut input = input.clone();
        let mut snapshot = snapshot.clone();
        input.tool_name = Some(tool.to_string());
        snapshot.invocations[0].tool_name = tool.to_string();
        snapshot.invocations[0].input_digest = invocation_digest(&input).unwrap();
        snapshot.invocations[0].required_authority = level;
        snapshot.grants[0].max_authority = AuthorityLevel::L4ExternalSideEffect;
        snapshot.capabilities[0].max_authority = AuthorityLevel::L4ExternalSideEffect;
        let result = evaluate_delegation(&input, &verified(&snapshot), NOW);
        assert_eq!(
            result.guard.decision == PermissionDecision::Allow,
            accepted,
            "{tool} {level}"
        );
        assert_eq!(result.guard.authority_level, level);
    }
}

#[test]
fn expiry_intervals_are_start_inclusive_end_exclusive() {
    let (input, snapshot) = fixture();
    let snapshot = verified(&snapshot);
    for (now, code) in [
        (899, "snapshot_not_yet_valid"),
        (900, "authority_verified"),
        (1599, "authority_verified"),
        (1600, "grant_expired"),
        (1900, "snapshot_expired"),
    ] {
        assert_eq!(
            evaluate_delegation(&input, &snapshot, now).evidence["reason_code"],
            code
        );
    }
    let (input, snapshot) = with_approval(input, snapshot, true);
    let snapshot = verified(&snapshot);
    assert_eq!(
        evaluate_delegation(&input, &snapshot, 1499).guard.decision,
        PermissionDecision::Allow
    );
    assert_eq!(
        evaluate_delegation(&input, &snapshot, 1500).evidence["reason_code"],
        "approval_expired"
    );
}

#[test]
fn exact_verified_approval_is_used_and_optional_approval_is_also_reserved() {
    let (input, snapshot) = fixture();
    for required in [false, true] {
        let (input, snapshot) = with_approval(input.clone(), snapshot.clone(), required);
        let result = evaluate_delegation(&input, &verified(&snapshot), NOW);
        assert_eq!(result.guard.decision, PermissionDecision::Allow);
        assert_eq!(
            result.invocation_id.as_deref(),
            Some("invocation:fixture-1")
        );
        assert_eq!(result.approval_id.as_deref(), Some("approval:fixture-1"));
        assert_eq!(result.evidence["approval_used"], true);
        assert_eq!(result.evidence["required_authority"], "L2_modify_local");
    }
}

#[test]
fn approval_cannot_resolve_service_or_organisation_denial() {
    let (input, snapshot) = with_approval(fixture().0, fixture().1, true);
    for organisation in [false, true] {
        let mut snapshot = snapshot.clone();
        let policy = if organisation {
            &mut snapshot.organisation_policies[0]
        } else {
            &mut snapshot.service_policies[0]
        };
        policy.decision = corcept_types::DelegationPolicyDecision::Deny;
        let result = evaluate_delegation(&input, &verified(&snapshot), NOW);
        assert_eq!(result.guard.decision, PermissionDecision::Deny);
        assert_eq!(result.approval_id, None);
        assert_eq!(result.evidence["approval_used"], false);
    }
}

#[test]
fn approval_is_never_used_when_unverified_or_not_yet_valid() {
    let (input, snapshot) = with_approval(fixture().0, fixture().1, true);
    for state in [ClaimState::Asserted, ClaimState::Unavailable] {
        let mut snapshot = snapshot.clone();
        snapshot.approvals[0].claim.state = state;
        let result = evaluate_delegation(&input, &verified(&snapshot), NOW);
        assert_eq!(result.evidence["reason_code"], "approval_unverified");
        assert_eq!(result.approval_id, None);
    }
    let mut snapshot = snapshot;
    snapshot.approvals[0].valid_from = 1001;
    assert_eq!(
        evaluate_delegation(&input, &verified(&snapshot), NOW).evidence["reason_code"],
        "approval_not_yet_valid"
    );
}

#[test]
fn changed_invocation_arguments_envelope_and_approval_reference_are_denied() {
    let (input, snapshot) = with_approval(fixture().0, fixture().1, true);
    let snapshot = verified(&snapshot);
    for mutation in 0..7 {
        let mut input = input.clone();
        match mutation {
            0 => input.tool_input.as_mut().unwrap()["content"] = json!("changed"),
            1 => {
                input.extra.get_mut("delegation").unwrap()["approval_id"] = json!("approval:other")
            }
            2 => {
                input.extra.get_mut("delegation").unwrap()["correlation_id"] =
                    json!("correlation:other")
            }
            3 => input.extra.get_mut("delegation").unwrap()["user_id"] = json!("user:other"),
            4 => input.session_id = Some("session:other".to_string()),
            5 => input.tool_use_id = Some("tool-use:other".to_string()),
            _ => input
                .extra
                .get_mut("delegation")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("approval_id")
                .map(|_| ())
                .unwrap(),
        }
        let result = evaluate_delegation(&input, &snapshot, NOW);
        assert_eq!(result.guard.decision, PermissionDecision::Deny);
        assert_eq!(result.approval_id, None);
    }
}

#[test]
fn approval_mutations_duplicate_references_and_snapshot_version_change_are_denied() {
    let (input, snapshot) = with_approval(fixture().0, fixture().1, true);
    let original = serde_json::to_value(&snapshot).unwrap();
    for (pointer, replacement) in [
        ("/approvals/0/invocation_id", json!("invocation:unknown")),
        ("/approvals/0/grant_id", json!("grant:unknown")),
        ("/approvals/0/snapshot_id", json!("snapshot:other")),
        ("/approvals/0/snapshot_version", json!(2)),
        (
            "/approvals/0/input_digest",
            json!(format!("blake3:{}", "a".repeat(64))),
        ),
        ("/approvals/0/valid_from", json!(899)),
        ("/approvals/0/expires_at", json!(1601)),
        ("/version", json!(2)),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            parse_authority(&signed_unchecked(value), &pinned_key()).is_err(),
            "{pointer}"
        );
    }
    let mut duplicated = snapshot.clone();
    let mut second = duplicated.approvals[0].clone();
    second.id = "approval:distinct-id".to_string();
    duplicated.approvals.push(second);
    assert_eq!(
        parse_authority(
            &signed_unchecked(serde_json::to_value(duplicated).unwrap()),
            &pinned_key()
        )
        .unwrap_err(),
        "approval_reference_duplicated"
    );
    let mut changed = snapshot;
    changed.version += 1;
    assert_eq!(
        evaluate_delegation(&input, &changed, NOW).guard.decision,
        PermissionDecision::Deny
    );
}

#[test]
fn sibling_approval_cannot_be_substituted_even_with_valid_ids() {
    let (input, mut snapshot) = with_approval(fixture().0, fixture().1, true);
    let mut sibling = snapshot.invocations[0].clone();
    sibling.id = "invocation:sibling".to_string();
    sibling.tool_use_id = "tool-use:sibling".to_string();
    sibling.delegation.approval_id = Some("approval:sibling".to_string());
    let mut approval = snapshot.approvals[0].clone();
    approval.id = "approval:sibling".to_string();
    approval.invocation_id = sibling.id.clone();
    snapshot.invocations.push(sibling);
    snapshot.approvals.push(approval);
    let snapshot = verified(&snapshot);
    let mut changed = input;
    changed.extra.get_mut("delegation").unwrap()["approval_id"] = json!("approval:sibling");
    assert_eq!(
        evaluate_delegation(&changed, &snapshot, NOW).evidence["reason_code"],
        "invocation_binding_mismatch"
    );
    let mut inconsistent = snapshot;
    inconsistent.invocations[0].delegation.approval_id = Some("approval:sibling".to_string());
    assert!(authority_signing_bytes(&inconsistent).is_err());
}

#[test]
fn evidence_contains_exact_versions_provenance_time_and_no_raw_arguments() {
    let (input, mut snapshot) = fixture();
    for denied in [false, true] {
        if denied {
            snapshot.organisation_policies[0].decision =
                corcept_types::DelegationPolicyDecision::Deny;
        }
        let result = evaluate_delegation(&input, &verified(&snapshot), NOW);
        assert_eq!(result.evidence["evaluated_at"], NOW);
        assert_eq!(result.evidence["snapshot"]["version"], 1);
        assert_eq!(result.evidence["grant"]["version"], 3);
        assert_eq!(result.evidence["capability"]["version"], 2);
        assert_eq!(result.evidence["service_policy"]["version"], 4);
        assert_eq!(result.evidence["organisation_policy"]["version"], 5);
        assert_eq!(
            result.evidence["grant"]["claim"]["provenance"]["evidence_id"],
            "evidence:grant-1"
        );
        assert!(result.evidence["correlation_id"]
            .as_str()
            .unwrap()
            .starts_with("blake3:"));
        assert_eq!(
            result.evidence["bound_correlation_id"],
            "correlation:fixture-1"
        );
        assert_eq!(result.evidence["bound_tool_name"], "Write");
        assert_eq!(result.evidence["requested_claim_state"], "asserted");
        assert_eq!(
            result.evidence["evaluated_subjects"]["user_id"],
            "user:fixture-1"
        );
        assert_eq!(
            result.evidence["input_digest"],
            invocation_digest(&input).unwrap()
        );
        assert_eq!(result.evidence["required_authority"], "L2_modify_local");
        let evidence = serde_json::to_string(&result.evidence).unwrap();
        assert!(!evidence.contains("delegation-argument-sentinel"));
        assert!(!evidence.contains("document.txt"));
        assert!(!evidence.contains(env!("CARGO_MANIFEST_DIR")));
    }
}
