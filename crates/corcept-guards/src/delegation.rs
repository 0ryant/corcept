//! Fail-closed delegated authority evaluation over an operator-pinned snapshot.
//!
//! Callers must obtain the snapshot with [`parse_authority`] or
//! [`load_authority`]; constructing/deserializing the type is not verification.
//! The signer independently attests subject identity and action/resource
//! semantics for the exact host invocation. This module checks that binding,
//! not the semantic truth of an opaque resource reference.
//!
//! Evaluation alone does not admit a call. The runtime must preserve other
//! guards' Deny/Ask decisions, apply operator authority limits, and atomically
//! reserve every invocation ID and any used approval ID before emitting Allow.

use crate::GuardVerdict;
use corcept_types::{
    AuthorityClaim, AuthorityLevel, AuthoritySnapshot, ClaimState, DelegationEnvelope,
    DelegationPolicyDecision, DelegationScope, HookEnvelope, PermissionDecision, PolicyRule,
    SignedAuthoritySnapshot, VersionedReference, AUTHORITY_SNAPSHOT_SCHEMA,
    DELEGATION_DECISION_SCHEMA, DELEGATION_SCHEMA,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

pub const AUTHORITY_SIGNATURE_DOMAIN: &str = "corcept:authority-snapshot:v1:";
const MAX_JSON_BYTES: usize = 1_048_576;
const MAX_COLLECTION_ITEMS: usize = 1_024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone)]
pub struct DelegationEvaluation {
    pub guard: GuardVerdict,
    pub evidence: Value,
    /// Present only when a verified exact approval was used. Reserve atomically.
    pub approval_id: Option<String>,
    /// Present after the host invocation binding was verified. Reserve on Allow.
    pub invocation_id: Option<String>,
}

impl DelegationEvaluation {
    fn new() -> Self {
        Self {
            guard: GuardVerdict::deny("Delegation denied: unresolved.", AuthorityLevel::L0Observe),
            evidence: json!({
                "schema": DELEGATION_DECISION_SCHEMA,
                "decision": "deny",
                "reason_code": "unresolved",
                "approval_used": false,
            }),
            approval_id: None,
            invocation_id: None,
        }
    }

    fn finish(mut self, decision: PermissionDecision, code: &'static str) -> Self {
        self.guard.decision = decision;
        self.guard.reason = format!("Delegation {decision}: {code}.");
        self.evidence["decision"] = json!(decision);
        self.evidence["reason_code"] = json!(code);
        self
    }

    fn deny(self, code: &'static str) -> Self {
        self.finish(PermissionDecision::Deny, code)
    }
}

/// Read once, bound memory use, and verify exactly the parsed signed snapshot.
/// Runtime callers that archive input should instead read once themselves and
/// use [`parse_authority`] on those same bytes to avoid a second-read race.
pub fn load_authority(path: &Path, pinned_pubkey_hex: &str) -> Result<AuthoritySnapshot, String> {
    let file = std::fs::File::open(path).map_err(|_| "authority_unreadable".to_string())?;
    let mut raw = String::new();
    file.take((MAX_JSON_BYTES + 1) as u64)
        .read_to_string(&mut raw)
        .map_err(|_| "authority_unreadable".to_string())?;
    parse_authority(&raw, pinned_pubkey_hex)
}

/// Verify strict Ed25519 over domain-separated JCS. No embedded key, caller
/// claim status, unknown field, duplicate field, or invalid reference is trusted.
pub fn parse_authority(
    raw_json: &str,
    pinned_pubkey_hex: &str,
) -> Result<AuthoritySnapshot, String> {
    if raw_json.len() > MAX_JSON_BYTES {
        return Err("authority_too_large".to_string());
    }
    let signed: SignedAuthoritySnapshot =
        serde_json::from_str(raw_json).map_err(|_| "authority_invalid_json".to_string())?;
    let material = authority_signing_bytes(&signed.snapshot)?;
    if pinned_pubkey_hex.len() != 64 {
        return Err("authority_invalid_key".to_string());
    }
    let key_bytes: [u8; 32] = hex::decode(pinned_pubkey_hex)
        .map_err(|_| "authority_invalid_key".to_string())?
        .try_into()
        .map_err(|_| "authority_invalid_key".to_string())?;
    let key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| "authority_invalid_key".to_string())?;
    if signed.signature.len() != 128 {
        return Err("authority_invalid_signature".to_string());
    }
    let signature_bytes =
        hex::decode(&signed.signature).map_err(|_| "authority_invalid_signature".to_string())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "authority_invalid_signature".to_string())?;
    key.verify_strict(&material, &signature)
        .map_err(|_| "authority_signature_mismatch".to_string())?;
    Ok(signed.snapshot)
}

/// Interoperable signing material for this provisional schema. JCS integer
/// safety is checked explicitly because the shared canonicalizer is opt-in.
pub fn authority_signing_bytes(snapshot: &AuthoritySnapshot) -> Result<Vec<u8>, String> {
    validate_snapshot(snapshot).map_err(str::to_string)?;
    let canonical = safe_jcs_bytes(snapshot).map_err(str::to_string)?;
    let mut material = AUTHORITY_SIGNATURE_DOMAIN.as_bytes().to_vec();
    material.extend_from_slice(&canonical);
    Ok(material)
}

/// BLAKE3 JCS of the exact native cwd, tool name, and argument object. Session
/// and tool-use IDs are separately bound by the signed invocation record.
pub fn invocation_digest(input: &HookEnvelope) -> Result<String, String> {
    let cwd = input
        .cwd
        .as_deref()
        .filter(|path| path.is_absolute())
        .and_then(Path::to_str)
        .ok_or_else(|| "invocation_cwd_invalid".to_string())?;
    let tool_name = input
        .tool_name
        .as_deref()
        .filter(|name| opaque(name))
        .ok_or_else(|| "invocation_tool_invalid".to_string())?;
    let tool_input = input
        .tool_input
        .as_ref()
        .filter(|args| args.is_object())
        .ok_or_else(|| "invocation_args_invalid".to_string())?;
    let material = safe_jcs_bytes(&json!({
        "cwd": cwd,
        "tool_name": tool_name,
        "tool_input": tool_input,
    }))
    .map_err(str::to_string)?;
    Ok(format!("blake3:{}", blake3::hash(&material).to_hex()))
}

/// All claims must be verified in a snapshot authenticated by the loader.
/// Any unknown or unresolved authority is Deny. Missing required approval is
/// Deny: a native host Ask could admit execution without rechecking signed proof.
#[must_use]
pub fn evaluate_delegation(
    input: &HookEnvelope,
    snapshot: &AuthoritySnapshot,
    now: i64,
) -> DelegationEvaluation {
    let mut result = DelegationEvaluation::new();
    result.evidence["evaluated_at"] = json!(now);
    if let Err(code) = validate_snapshot(snapshot) {
        return result.deny(code);
    }
    result.evidence["snapshot"] = json!({
        "id": snapshot.id,
        "version": snapshot.version,
        "valid_from": snapshot.valid_from,
        "expires_at": snapshot.expires_at,
    });
    if now < snapshot.valid_from {
        return result.deny("snapshot_not_yet_valid");
    }
    if now >= snapshot.expires_at {
        return result.deny("snapshot_expired");
    }
    if input.hook_event_name != "PreToolUse" {
        return result.deny("hook_event_invalid");
    }
    let envelope: DelegationEnvelope = match input.extra.get("delegation") {
        Some(value) => match serde_json::from_value(value.clone()) {
            Ok(envelope) => envelope,
            Err(_) => return result.deny("delegation_invalid"),
        },
        None => return result.deny("delegation_missing"),
    };
    if validate_envelope(&envelope).is_err() {
        return result.deny("delegation_invalid");
    }
    result.evidence["correlation_id"] = json!(reference_digest(&envelope.correlation_id));
    result.evidence["requested_claim_state"] = json!(ClaimState::Asserted);
    result.evidence["requested_subjects"] = json!({
        "caller_id": reference_digest(&envelope.caller_id),
        "agent_id": reference_digest(&envelope.agent_id),
        "user_id": reference_digest(&envelope.user_id),
        "organisation_id": reference_digest(&envelope.organisation_id),
    });
    result.evidence["requested_scope"] = json!({
        "target_service": reference_digest(&envelope.target_service),
        "capability": reference_digest(&envelope.capability),
        "action": reference_digest(&envelope.action),
        "resource": reference_digest(&envelope.resource),
    });
    let Some(session_id) = input.session_id.as_deref().filter(|id| opaque(id)) else {
        return result.deny("session_id_invalid");
    };
    let Some(tool_use_id) = input.tool_use_id.as_deref().filter(|id| opaque(id)) else {
        return result.deny("tool_use_id_invalid");
    };
    if input
        .agent_id
        .as_deref()
        .is_some_and(|id| !opaque(id) || id != envelope.agent_id)
    {
        return result.deny("host_agent_mismatch");
    }
    let digest = match invocation_digest(input) {
        Ok(digest) => digest,
        Err(_) => return result.deny("invocation_input_invalid"),
    };
    result.evidence["input_digest"] = json!(digest);
    let Some(binding) = snapshot
        .invocations
        .iter()
        .find(|binding| binding.session_id == session_id && binding.tool_use_id == tool_use_id)
    else {
        return result.deny("invocation_unknown");
    };
    result.guard.authority_level = binding.required_authority;
    result.evidence["required_authority"] = json!(binding.required_authority);
    result.evidence["invocation"] = json!({ "id": binding.id, "claim": binding.claim });
    if binding.claim.state != ClaimState::Verified {
        return result.deny("invocation_unverified");
    }
    if binding.tool_name != input.tool_name.as_deref().unwrap_or_default()
        || binding.input_digest != digest
        || binding.delegation != envelope
    {
        return result.deny("invocation_binding_mismatch");
    }
    let Some(floor) = tool_authority_floor(&binding.tool_name) else {
        return result.deny("tool_authority_unknown");
    };
    if authority_rank(binding.required_authority) < authority_rank(floor) {
        return result.deny("required_authority_understated");
    }
    result.invocation_id = Some(binding.id.clone());
    result.evidence["bound_correlation_id"] = json!(binding.delegation.correlation_id);
    result.evidence["bound_tool_name"] = json!(binding.tool_name);
    result.evidence["evaluated_subjects"] = json!({
        "caller_id": binding.delegation.caller_id,
        "agent_id": binding.delegation.agent_id,
        "user_id": binding.delegation.user_id,
        "organisation_id": binding.delegation.organisation_id,
    });
    let grant = snapshot
        .grants
        .iter()
        .find(|grant| grant.id == envelope.grant_id)
        .expect("validated invocation grant reference");
    let capability = snapshot
        .capabilities
        .iter()
        .find(|rule| rule.id == grant.capability_ref.id)
        .expect("validated capability reference");
    let service = snapshot
        .service_policies
        .iter()
        .find(|rule| rule.id == grant.service_policy_ref.id)
        .expect("validated service policy reference");
    let organisation = snapshot
        .organisation_policies
        .iter()
        .find(|rule| rule.id == grant.organisation_policy_ref.id)
        .expect("validated organisation policy reference");
    result.evidence["grant"] = json!({
        "id": grant.id,
        "version": grant.version,
        "claim": grant.claim,
        "valid_from": grant.valid_from,
        "expires_at": grant.expires_at,
        "max_authority": grant.max_authority,
        "approval_required": grant.approval_required,
    });
    result.evidence["scope"] = json!(grant.scope);
    result.evidence["capability"] = json!({
        "id": capability.id,
        "version": capability.version,
        "claim": capability.claim,
        "max_authority": capability.max_authority,
    });
    result.evidence["service_policy"] = policy_evidence(service);
    result.evidence["organisation_policy"] = policy_evidence(organisation);
    if grant.claim.state != ClaimState::Verified {
        return result.deny("grant_unverified");
    }
    if now < grant.valid_from {
        return result.deny("grant_not_yet_valid");
    }
    if now >= grant.expires_at {
        return result.deny("grant_expired");
    }
    if grant.caller_id != envelope.caller_id
        || grant.agent_id != envelope.agent_id
        || grant.user_id != envelope.user_id
        || grant.organisation_id != envelope.organisation_id
    {
        return result.deny("grant_subject_mismatch");
    }
    if grant.scope != envelope.scope() {
        return result.deny("grant_scope_mismatch");
    }
    if capability.claim.state != ClaimState::Verified {
        return result.deny("capability_unverified");
    }
    if capability.scope != grant.scope {
        return result.deny("capability_scope_mismatch");
    }
    if authority_rank(binding.required_authority) > authority_rank(grant.max_authority) {
        return result.deny("grant_authority_exceeded");
    }
    if authority_rank(binding.required_authority) > authority_rank(capability.max_authority) {
        return result.deny("capability_authority_exceeded");
    }
    if service.claim.state != ClaimState::Verified {
        return result.deny("service_policy_unverified");
    }
    if service.owner_id != envelope.target_service || service.scope != grant.scope {
        return result.deny("service_policy_scope_mismatch");
    }
    match service.decision {
        DelegationPolicyDecision::Deny => return result.deny("service_policy_denied"),
        DelegationPolicyDecision::Unknown => return result.deny("service_policy_unknown"),
        DelegationPolicyDecision::Allow => {}
    }
    if organisation.claim.state != ClaimState::Verified {
        return result.deny("organisation_policy_unverified");
    }
    if organisation.owner_id != envelope.organisation_id || organisation.scope != grant.scope {
        return result.deny("organisation_policy_scope_mismatch");
    }
    match organisation.decision {
        DelegationPolicyDecision::Deny => return result.deny("organisation_policy_denied"),
        DelegationPolicyDecision::Unknown => return result.deny("organisation_policy_unknown"),
        DelegationPolicyDecision::Allow => {}
    }
    let Some(approval_id) = envelope.approval_id.as_deref() else {
        return if grant.approval_required {
            result.deny("approval_required")
        } else {
            result.finish(PermissionDecision::Allow, "authority_verified")
        };
    };
    let approval = snapshot
        .approvals
        .iter()
        .find(|approval| approval.id == approval_id)
        .expect("validated approval reference");
    result.evidence["approval"] = json!({
        "id": approval.id,
        "snapshot_version": approval.snapshot_version,
        "claim": approval.claim,
        "valid_from": approval.valid_from,
        "expires_at": approval.expires_at,
    });
    if approval.claim.state != ClaimState::Verified {
        return result.deny("approval_unverified");
    }
    if now < approval.valid_from {
        return result.deny("approval_not_yet_valid");
    }
    if now >= approval.expires_at {
        return result.deny("approval_expired");
    }
    // Structural validation checks linkage for every approval, including unused
    // rows. Repeat the exact admission binding here to keep this boundary clear.
    if approval.invocation_id != binding.id
        || approval.grant_id != grant.id
        || approval.snapshot_id != snapshot.id
        || approval.snapshot_version != snapshot.version
        || approval.input_digest != digest
    {
        return result.deny("approval_binding_mismatch");
    }
    result.approval_id = Some(approval.id.clone());
    result.evidence["approval_used"] = json!(true);
    result.finish(PermissionDecision::Allow, "authority_and_approval_verified")
}

fn safe_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, &'static str> {
    let value = serde_json::to_value(value).map_err(|_| "canonical_json_invalid")?;
    if !canonical_numbers_safe(&value) {
        return Err("canonical_json_unsafe");
    }
    axiom_canonical::assert_jcs_safe(&value).map_err(|_| "canonical_json_unsafe")?;
    let bytes = axiom_canonical::to_jcs_bytes(&value).map_err(|_| "canonical_json_invalid")?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err("canonical_json_too_large");
    }
    Ok(bytes)
}

fn canonical_numbers_safe(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_u64() {
                integer <= MAX_SAFE_INTEGER
            } else if let Some(integer) = number.as_i64() {
                integer.unsigned_abs() <= MAX_SAFE_INTEGER
            } else {
                number.as_f64().is_some_and(|number| {
                    number.is_finite() && number.abs() <= MAX_SAFE_INTEGER as f64
                })
            }
        }
        Value::Array(values) => values.iter().all(canonical_numbers_safe),
        Value::Object(values) => values.values().all(canonical_numbers_safe),
        _ => true,
    }
}

fn opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn valid_version(version: u64) -> bool {
    version > 0 && version <= MAX_SAFE_INTEGER
}

fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_interval(valid_from: i64, expires_at: i64) -> bool {
    valid_from >= 0 && expires_at > valid_from && expires_at as u64 <= MAX_SAFE_INTEGER
}

fn validate_claim(claim: &AuthorityClaim) -> Result<(), &'static str> {
    if !opaque(&claim.provenance.issuer_id)
        || !opaque(&claim.provenance.evidence_id)
        || !valid_version(claim.provenance.version)
    {
        return Err("provenance_invalid");
    }
    Ok(())
}

fn validate_scope(scope: &DelegationScope) -> Result<(), &'static str> {
    if ![
        &scope.target_service,
        &scope.capability,
        &scope.action,
        &scope.resource,
    ]
    .into_iter()
    .all(|id| opaque(id))
    {
        return Err("scope_invalid");
    }
    Ok(())
}

fn validate_envelope(envelope: &DelegationEnvelope) -> Result<(), &'static str> {
    if envelope.schema != DELEGATION_SCHEMA
        || ![
            &envelope.caller_id,
            &envelope.agent_id,
            &envelope.user_id,
            &envelope.organisation_id,
            &envelope.grant_id,
            &envelope.correlation_id,
        ]
        .into_iter()
        .all(|id| opaque(id))
        || envelope
            .approval_id
            .as_deref()
            .is_some_and(|id| !opaque(id))
    {
        return Err("delegation_invalid");
    }
    validate_scope(&envelope.scope())
}

fn insert_id<'a>(ids: &mut HashSet<&'a str>, id: &'a str) -> Result<(), &'static str> {
    if !opaque(id) {
        return Err("identifier_invalid");
    }
    if !ids.insert(id) {
        return Err("identifier_duplicated");
    }
    Ok(())
}

fn validate_reference(
    reference: &VersionedReference,
    mut rows: impl Iterator<Item = (String, u64)>,
) -> Result<(), &'static str> {
    if !opaque(&reference.id) || !valid_version(reference.version) {
        return Err("reference_invalid");
    }
    if !rows.any(|(id, version)| id == reference.id && version == reference.version) {
        return Err("reference_unresolved");
    }
    Ok(())
}

fn validate_snapshot(snapshot: &AuthoritySnapshot) -> Result<(), &'static str> {
    if snapshot.schema != AUTHORITY_SNAPSHOT_SCHEMA
        || !valid_version(snapshot.version)
        || !valid_interval(snapshot.valid_from, snapshot.expires_at)
    {
        return Err("snapshot_invalid");
    }
    for length in [
        snapshot.invocations.len(),
        snapshot.grants.len(),
        snapshot.capabilities.len(),
        snapshot.service_policies.len(),
        snapshot.organisation_policies.len(),
    ] {
        if length == 0 || length > MAX_COLLECTION_ITEMS {
            return Err("snapshot_collection_invalid");
        }
    }
    if snapshot.approvals.len() > MAX_COLLECTION_ITEMS {
        return Err("snapshot_collection_invalid");
    }
    let mut ids = HashSet::new();
    insert_id(&mut ids, &snapshot.id)?;
    let mut host_invocations = HashSet::new();
    for binding in &snapshot.invocations {
        insert_id(&mut ids, &binding.id)?;
        if !opaque(&binding.session_id)
            || !opaque(&binding.tool_use_id)
            || !opaque(&binding.tool_name)
            || !valid_digest(&binding.input_digest)
        {
            return Err("invocation_invalid");
        }
        if !host_invocations.insert((&binding.session_id, &binding.tool_use_id)) {
            return Err("invocation_duplicated");
        }
        validate_envelope(&binding.delegation)?;
        validate_claim(&binding.claim)?;
    }
    for grant in &snapshot.grants {
        insert_id(&mut ids, &grant.id)?;
        if !valid_version(grant.version)
            || ![
                &grant.caller_id,
                &grant.agent_id,
                &grant.user_id,
                &grant.organisation_id,
            ]
            .into_iter()
            .all(|id| opaque(id))
            || !valid_interval(grant.valid_from, grant.expires_at)
            || grant.valid_from < snapshot.valid_from
            || grant.expires_at > snapshot.expires_at
        {
            return Err("grant_invalid");
        }
        validate_scope(&grant.scope)?;
        validate_claim(&grant.claim)?;
    }
    for capability in &snapshot.capabilities {
        insert_id(&mut ids, &capability.id)?;
        if !valid_version(capability.version) {
            return Err("capability_invalid");
        }
        validate_scope(&capability.scope)?;
        validate_claim(&capability.claim)?;
    }
    for policy in snapshot
        .service_policies
        .iter()
        .chain(snapshot.organisation_policies.iter())
    {
        insert_id(&mut ids, &policy.id)?;
        if !valid_version(policy.version) || !opaque(&policy.owner_id) {
            return Err("policy_invalid");
        }
        validate_scope(&policy.scope)?;
        validate_claim(&policy.claim)?;
    }
    for grant in &snapshot.grants {
        validate_reference(
            &grant.capability_ref,
            snapshot
                .capabilities
                .iter()
                .map(|row| (row.id.clone(), row.version)),
        )?;
        validate_reference(
            &grant.service_policy_ref,
            snapshot
                .service_policies
                .iter()
                .map(|row| (row.id.clone(), row.version)),
        )?;
        validate_reference(
            &grant.organisation_policy_ref,
            snapshot
                .organisation_policies
                .iter()
                .map(|row| (row.id.clone(), row.version)),
        )?;
    }
    let mut approved_invocations = HashSet::new();
    for approval in &snapshot.approvals {
        insert_id(&mut ids, &approval.id)?;
        if !opaque(&approval.invocation_id)
            || !opaque(&approval.grant_id)
            || approval.snapshot_id != snapshot.id
            || approval.snapshot_version != snapshot.version
            || !valid_digest(&approval.input_digest)
            || !valid_interval(approval.valid_from, approval.expires_at)
            || approval.valid_from < snapshot.valid_from
            || approval.expires_at > snapshot.expires_at
        {
            return Err("approval_invalid");
        }
        if !approved_invocations.insert(&approval.invocation_id) {
            return Err("approval_reference_duplicated");
        }
        validate_claim(&approval.claim)?;
        let binding = snapshot
            .invocations
            .iter()
            .find(|row| row.id == approval.invocation_id)
            .ok_or("approval_reference_unresolved")?;
        let grant = snapshot
            .grants
            .iter()
            .find(|row| row.id == approval.grant_id)
            .ok_or("approval_reference_unresolved")?;
        if binding.delegation.grant_id != grant.id
            || binding.delegation.approval_id.as_deref() != Some(approval.id.as_str())
            || approval.input_digest != binding.input_digest
            || approval.valid_from < grant.valid_from
            || approval.expires_at > grant.expires_at
        {
            return Err("approval_binding_invalid");
        }
    }
    for binding in &snapshot.invocations {
        if !snapshot
            .grants
            .iter()
            .any(|grant| grant.id == binding.delegation.grant_id)
        {
            return Err("grant_reference_unresolved");
        }
        if let Some(id) = binding.delegation.approval_id.as_deref() {
            if !snapshot
                .approvals
                .iter()
                .any(|approval| approval.id == id && approval.invocation_id == binding.id)
            {
                return Err("approval_reference_unresolved");
            }
        }
    }
    Ok(())
}

fn policy_evidence(policy: &PolicyRule) -> Value {
    json!({
        "id": policy.id,
        "version": policy.version,
        "claim": policy.claim,
        "decision": policy.decision,
    })
}

fn reference_digest(reference: &str) -> String {
    let mut material = b"corcept:delegation-request-reference:v1:".to_vec();
    material.extend_from_slice(reference.as_bytes());
    format!("blake3:{}", blake3::hash(&material).to_hex())
}

fn authority_rank(level: AuthorityLevel) -> u8 {
    match level {
        AuthorityLevel::L0Observe => 0,
        AuthorityLevel::L1Propose => 1,
        AuthorityLevel::L2ModifyLocal => 2,
        AuthorityLevel::L3ExecuteLocal => 3,
        AuthorityLevel::L4ExternalSideEffect => 4,
    }
}

fn tool_authority_floor(tool: &str) -> Option<AuthorityLevel> {
    match tool {
        "Read" | "Glob" | "Grep" => Some(AuthorityLevel::L0Observe),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => Some(AuthorityLevel::L2ModifyLocal),
        "Bash" => Some(AuthorityLevel::L3ExecuteLocal),
        "WebFetch" | "WebSearch" => Some(AuthorityLevel::L4ExternalSideEffect),
        tool if tool.starts_with("mcp__") => Some(AuthorityLevel::L4ExternalSideEffect),
        _ => None,
    }
}
