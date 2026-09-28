//! Provisional Corcept delegation contract. These records carry candidate
//! authority until an operator-pinned signature is verified by the guard.
//!
//! Subject, scope, and provenance strings are opaque references, never names,
//! credentials, URLs, paths, or personal data. The guard validates their bounds.

use crate::AuthorityLevel;
use serde::{Deserialize, Serialize};

pub const DELEGATION_SCHEMA: &str = "corcept.delegation.v1";
pub const AUTHORITY_SNAPSHOT_SCHEMA: &str = "corcept.authority-snapshot.v1";
pub const DELEGATION_DECISION_SCHEMA: &str = "corcept.delegation-decision.v1";

/// Caller metadata is a request to exercise authority, never proof of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEnvelope {
    pub schema: String,
    pub caller_id: String,
    pub agent_id: String,
    pub user_id: String,
    pub organisation_id: String,
    pub target_service: String,
    pub capability: String,
    pub action: String,
    pub resource: String,
    pub grant_id: String,
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimState {
    Verified,
    Asserted,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub issuer_id: String,
    pub evidence_id: String,
    pub version: u64,
}

/// Claim state is authoritative only inside a verified signed snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityClaim {
    pub state: ClaimState,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationScope {
    pub target_service: String,
    pub capability: String,
    pub action: String,
    pub resource: String,
}

impl DelegationEnvelope {
    pub fn scope(&self) -> DelegationScope {
        DelegationScope {
            target_service: self.target_service.clone(),
            capability: self.capability.clone(),
            action: self.action.clone(),
            resource: self.resource.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedReference {
    pub id: String,
    pub version: u64,
}

/// The trusted attestor binds identities and opaque scope references to the
/// exact host invocation. It must classify the action/resource semantics and
/// required authority; matching caller strings alone is not an attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBinding {
    pub id: String,
    pub session_id: String,
    pub tool_use_id: String,
    pub tool_name: String,
    pub input_digest: String,
    pub delegation: DelegationEnvelope,
    pub required_authority: AuthorityLevel,
    pub claim: AuthorityClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGrant {
    pub id: String,
    pub version: u64,
    pub caller_id: String,
    pub agent_id: String,
    pub user_id: String,
    pub organisation_id: String,
    pub scope: DelegationScope,
    pub capability_ref: VersionedReference,
    pub service_policy_ref: VersionedReference,
    pub organisation_policy_ref: VersionedReference,
    pub valid_from: i64,
    pub expires_at: i64,
    pub max_authority: AuthorityLevel,
    pub approval_required: bool,
    pub claim: AuthorityClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRule {
    pub id: String,
    pub version: u64,
    pub scope: DelegationScope,
    pub max_authority: AuthorityLevel,
    pub claim: AuthorityClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DelegationPolicyDecision {
    Allow,
    Deny,
    Unknown,
}

/// Service and organisation rules live in distinct snapshot collections. Their
/// owner references must match the service and organisation respectively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub version: u64,
    pub owner_id: String,
    pub scope: DelegationScope,
    pub decision: DelegationPolicyDecision,
    pub claim: AuthorityClaim,
}

/// A single-use approval is pinned to one attested invocation and one snapshot
/// version. The runtime must atomically reserve its ID before returning Allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationApproval {
    pub id: String,
    pub invocation_id: String,
    pub grant_id: String,
    pub snapshot_id: String,
    pub snapshot_version: u64,
    pub input_digest: String,
    pub valid_from: i64,
    pub expires_at: i64,
    pub claim: AuthorityClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    pub schema: String,
    pub id: String,
    pub version: u64,
    pub valid_from: i64,
    pub expires_at: i64,
    pub invocations: Vec<InvocationBinding>,
    pub grants: Vec<DelegationGrant>,
    pub capabilities: Vec<CapabilityRule>,
    pub service_policies: Vec<PolicyRule>,
    pub organisation_policies: Vec<PolicyRule>,
    pub approvals: Vec<DelegationApproval>,
}

/// The key is deliberately external. A key bundled with these records would
/// let an untrusted requester appoint its own authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthoritySnapshot {
    pub snapshot: AuthoritySnapshot,
    pub signature: String,
}
