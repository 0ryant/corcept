use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod event_type;
pub mod hook_fsm;
pub mod paths;
pub mod policy;

pub use event_type::{LedgerEventKind, LEDGER_EVENT_SCHEMA};
pub use hook_fsm::{transition_for, HookState, HookTransition};
pub use paths::{
    active_signing_key_path, debug_log_path, dir_permissions_secure, operator_data_dir,
    operator_keys_dir, operator_paths_available, operator_state_dir, project_corcept_dir,
    project_ledger, project_ledger_dir, receipts_dir, telemetry_path, trust_keys_dir,
};
pub use policy::{compose_pre_tool, compose_stop, StopDecision};

pub const CORCEPT_DIR: &str = ".corcept";
pub const CLAUDE_DIR: &str = ".claude";
pub const CONFIG_FILE: &str = ".corcept/config.yaml";
pub const LEDGER_FILE: &str = ".corcept/ledger/events.jsonl";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityLevel {
    #[serde(rename = "L0_observe")]
    #[default]
    L0Observe,
    #[serde(rename = "L1_propose")]
    L1Propose,
    #[serde(rename = "L2_modify_local")]
    L2ModifyLocal,
    #[serde(rename = "L3_execute_local")]
    L3ExecuteLocal,
    #[serde(rename = "L4_external_side_effect")]
    L4ExternalSideEffect,
}

impl std::fmt::Display for AuthorityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            AuthorityLevel::L0Observe => "L0_observe",
            AuthorityLevel::L1Propose => "L1_propose",
            AuthorityLevel::L2ModifyLocal => "L2_modify_local",
            AuthorityLevel::L3ExecuteLocal => "L3_execute_local",
            AuthorityLevel::L4ExternalSideEffect => "L4_external_side_effect",
        };
        write!(f, "{value}")
    }
}

impl AuthorityLevel {
    /// Map the corcept `AuthorityLevel` ladder onto the cex envelope-v2
    /// `cexauthorityclass` value space {observe|analyze|plan|mutate|destroy|
    /// credential} so aegress corridor-verify can ingest corcept rows.
    ///
    /// SYN-1 cex emission seam (envelope-v2). The mapping is intentionally
    /// lossy: corcept's L1_propose is a *plan* and L2_modify_local is treated
    /// as *analyze* (local-only, reversible inspection-grade change) per the
    /// SYN-1 seam spec; L3/L4 escalate to mutate/destroy.
    pub fn cex_authority_class(self) -> &'static str {
        match self {
            AuthorityLevel::L0Observe => "observe",
            AuthorityLevel::L1Propose => "plan",
            AuthorityLevel::L2ModifyLocal => "analyze",
            AuthorityLevel::L3ExecuteLocal => "mutate",
            AuthorityLevel::L4ExternalSideEffect => "destroy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionDecision {
    Allow,
    Deny,
    Ask,
    Defer,
}

impl std::fmt::Display for PermissionDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            PermissionDecision::Allow => "allow",
            PermissionDecision::Deny => "deny",
            PermissionDecision::Ask => "ask",
            PermissionDecision::Defer => "defer",
        };
        write!(f, "{value}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorceptConfig {
    pub version: u32,
    pub project: ProjectConfig,
    pub authority: AuthorityConfig,
    pub doctrine: DoctrineConfig,
    pub memory: MemoryConfig,
    pub guards: GuardConfig,
    pub testing: TestingConfig,
}

impl Default for CorceptConfig {
    fn default() -> Self {
        let mut commands = BTreeMap::new();
        commands.insert(
            "rust".to_string(),
            vec![
                "cargo test".to_string(),
                "cargo clippy --workspace --all-targets".to_string(),
            ],
        );
        commands.insert(
            "javascript".to_string(),
            vec!["npm test".to_string(), "npm run typecheck".to_string()],
        );
        commands.insert(
            "typescript".to_string(),
            vec!["pnpm test".to_string(), "pnpm typecheck".to_string()],
        );
        commands.insert("python".to_string(), vec!["pytest".to_string()]);

        Self {
            version: 1,
            project: ProjectConfig {
                name: "auto".to_string(),
                repo_root: "auto".to_string(),
                default_branch: "main".to_string(),
            },
            authority: AuthorityConfig {
                default_max_level: AuthorityLevel::L3ExecuteLocal,
                l4_requires_user_invocation: true,
            },
            doctrine: DoctrineConfig {
                path: ".corcept/doctrine".to_string(),
                max_injected_chars: 6000,
                strategy: "relevant_only".to_string(),
            },
            memory: MemoryConfig {
                path: ".corcept/memory".to_string(),
                max_items: 8,
                max_injected_chars: 4000,
                require_user_approval: true,
                require_evidence: true,
            },
            guards: GuardConfig {
                filesystem: FilesystemGuardConfig {
                    deny_outside_repo: true,
                    protect: vec![
                        ".env".to_string(),
                        ".env.*".to_string(),
                        "**/*.env".to_string(),
                        "**/*.pem".to_string(),
                        "**/*.key".to_string(),
                        "**/*.p12".to_string(),
                        "**/*.pfx".to_string(),
                        "**/id_rsa*".to_string(),
                        "**/id_ed25519*".to_string(),
                        "**/.ssh/**".to_string(),
                        ".aws/**".to_string(),
                        ".gcp/**".to_string(),
                        ".azure/**".to_string(),
                        ".git/**".to_string(),
                        ".npmrc".to_string(),
                        ".pypirc".to_string(),
                        ".netrc".to_string(),
                        "**/*secret*.env".to_string(),
                        "**/*secrets*.env".to_string(),
                        "**/*credential*.json".to_string(),
                        "**/*credentials*.json".to_string(),
                        "**/*token*.json".to_string(),
                    ],
                },
                bash: BashGuardConfig {
                    deny: vec![
                        "rm -rf /".to_string(),
                        "sudo rm -rf /".to_string(),
                        "curl *|sh".to_string(),
                        "curl * | sh".to_string(),
                        "wget *|sh".to_string(),
                        "wget * | sh".to_string(),
                        "chmod -R 777 *".to_string(),
                    ],
                    ask: vec![
                        "npm install *".to_string(),
                        "npm i *".to_string(),
                        "bun add *".to_string(),
                        "pnpm i *".to_string(),
                        "pnpm add *".to_string(),
                        "pnpm install *".to_string(),
                        "yarn add *".to_string(),
                        "pip install *".to_string(),
                        "python -m pip install *".to_string(),
                        "cargo install *".to_string(),
                        "cargo add *".to_string(),
                        "go get *".to_string(),
                        "git push *".to_string(),
                        "git clean *".to_string(),
                        "git reset --hard *".to_string(),
                        "docker run *".to_string(),
                        "kubectl *".to_string(),
                        "terraform apply *".to_string(),
                        "az *".to_string(),
                        "gcloud *".to_string(),
                        "aws *".to_string(),
                        "terraform destroy *".to_string(),
                    ],
                },
                network: NetworkGuardConfig {
                    allow_webfetch: true,
                    require_citation_for_external_claims: true,
                },
            },
            testing: TestingConfig {
                stale_after_source_change: true,
                commands,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub repo_root: String,
    pub default_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityConfig {
    pub default_max_level: AuthorityLevel,
    pub l4_requires_user_invocation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctrineConfig {
    pub path: String,
    pub max_injected_chars: usize,
    pub strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub path: String,
    pub max_items: usize,
    pub max_injected_chars: usize,
    pub require_user_approval: bool,
    pub require_evidence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    pub filesystem: FilesystemGuardConfig,
    pub bash: BashGuardConfig,
    pub network: NetworkGuardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemGuardConfig {
    pub deny_outside_repo: bool,
    pub protect: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BashGuardConfig {
    pub deny: Vec<String>,
    pub ask: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGuardConfig {
    pub allow_webfetch: bool,
    pub require_citation_for_external_claims: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestingConfig {
    pub stale_after_source_change: bool,
    pub commands: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookEnvelope {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<PathBuf>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    #[serde(default)]
    pub tool_response: Option<Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub stop_hook_active: Option<bool>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookOutput {
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    pub continue_: Option<bool>,
    #[serde(rename = "suppressOutput", skip_serializing_if = "Option::is_none")]
    pub suppress_output: Option<bool>,
    #[serde(rename = "stopReason", skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

impl HookOutput {
    pub fn pretool(decision: PermissionDecision, reason: impl Into<String>) -> Self {
        Self {
            suppress_output: Some(true),
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some(decision),
                permission_decision_reason: Some(reason.into()),
                additional_context: None,
                updated_input: None,
            }),
            ..Self::default()
        }
    }

    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            decision: Some("block".to_string()),
            reason: Some(reason.into()),
            ..Self::default()
        }
    }

    pub fn context(
        hook_event_name: impl Into<String>,
        additional_context: impl Into<String>,
    ) -> Self {
        Self {
            suppress_output: Some(true),
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: hook_event_name.into(),
                permission_decision: None,
                permission_decision_reason: None,
                additional_context: Some(additional_context.into()),
                updated_input: None,
            }),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision", skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<PermissionDecision>,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<Value>,
}

fn default_ledger_schema() -> String {
    LEDGER_EVENT_SCHEMA.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEvent {
    #[serde(default = "default_ledger_schema")]
    pub schema: String,
    pub id: String,
    pub ts: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub actor: String,
    pub event_type: String,
    pub authority_level: AuthorityLevel,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub decision_reason: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<RowSignature>,
    // --- SYN-1 cex emission seam (envelope-v2) ---------------------------
    // Additive, optional cex* correlation fields. Field names + value spaces
    // match `aegress_core::CexCloudEvent` so aegress corridor-verify can
    // ingest projected corcept rows. Every field is `Option<String>` with
    // `skip_serializing_if = "Option::is_none"`, so stripping the cex* fields
    // leaves a valid CloudEvent / ledger row. These do NOT participate in the
    // existing SHA-256 ledger hash chain semantics beyond being part of the
    // canonical body like any other field; `cexreceipthash`, when present, is
    // BLAKE3 (ADR-0003) of the row canonical body and is computed at the
    // CloudEvents projection over the finalized row — it is NOT the SHA-256
    // ledger `hash`.
    /// cex authority class: observe|analyze|plan|mutate|destroy|credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cexauthorityclass: Option<String>,
    /// cex trust ceiling: inferred|reviewed|signed|verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cextrustceiling: Option<String>,
    /// cex session id (mirrors `session_id`; the natural cex correlation key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cexsessionid: Option<String>,
    /// cex parent-trace id. corcept is the only tool with a natural parent
    /// link: the upstream `tool_use_id` of the Claude tool call being hooked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cexparenttrace: Option<String>,
    /// cex doctrine cite for the emitting seam.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cexdoctrinecite: Option<String>,
    /// cex receipt hash: BLAKE3 (ADR-0003) of the row canonical body when
    /// emitted. Distinct from the SHA-256 ledger `hash` chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cexreceipthash: Option<String>,
    /// cex revocation/identity status of the signing key (envelope-v2 §ADR-0002).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cexrevocation: Option<String>,
}

/// Ed25519 per-row signature (ADR-0025).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RowSignature {
    pub schema_version: u32,
    pub key_id: String,
    pub signed_at: String,
    /// Standard base64-encoded 64-byte Ed25519 signature.
    pub bytes: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryScope {
    #[serde(default)]
    pub repos: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCandidate {
    pub id: String,
    pub title: String,
    pub claim: String,
    pub scope: MemoryScope,
    pub evidence: Vec<String>,
    pub confidence: String,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub risk_if_wrong: Option<String>,
    pub proposed_by: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedMemory {
    pub id: String,
    pub title: String,
    pub claim: String,
    pub authority: String,
    pub scope: MemoryScope,
    pub evidence: Vec<String>,
    pub approved_by: String,
    pub approved_at: String,
    #[serde(default)]
    pub review_after: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctrineScope {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctrineRule {
    pub id: String,
    pub title: String,
    pub authority: String,
    pub scope: DoctrineScope,
    pub status: String,
    pub created_at: String,
    pub created_by: String,
    #[serde(default)]
    pub supersedes: Vec<String>,
    pub rule: String,
    pub rationale: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_protected_files() {
        let config = CorceptConfig::default();
        assert!(config.guards.filesystem.protect.iter().any(|p| p == ".env"));
    }

    #[test]
    fn pretool_output_serializes_permission_decision() {
        let out = HookOutput::pretool(PermissionDecision::Deny, "blocked");
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("deny"));
    }
}
