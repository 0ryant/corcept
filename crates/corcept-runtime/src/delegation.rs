//! Operator-attested delegation at the native command-hook boundary.
//!
//! The host payload is an assertion. Only an externally pinned signed snapshot
//! can bind it to independently attested identities and authority sources.

use crate::append_hook_event_with_metadata;
use anyhow::{Context, Result};
use corcept_guards::delegation::{evaluate_delegation, invocation_digest, parse_authority};
use corcept_guards::{compose_guard_verdicts, evaluate_pre_tool, GuardVerdict};
use corcept_types::{
    dir_permissions_secure, AuthorityLevel, CorceptConfig, HookEnvelope, HookOutput,
    LedgerEventKind, PermissionDecision,
};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static ARCHIVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct AuthoritySource {
    pub policy_file: PathBuf,
    pub pinned_pubkey_hex: String,
    pub state_dir: PathBuf,
}

impl AuthoritySource {
    pub(crate) fn configured() -> bool {
        [
            "CORCEPT_DELEGATION_POLICY",
            "CORCEPT_DELEGATION_PUBKEY",
            "CORCEPT_DELEGATION_STATE_DIR",
        ]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    }
    /// Any configured field activates the gate. Partial configuration fails
    /// closed; neither cwd nor caller JSON can select these authority anchors.
    pub fn from_env() -> Result<Option<Self>> {
        let policy = std::env::var_os("CORCEPT_DELEGATION_POLICY");
        let pubkey = std::env::var_os("CORCEPT_DELEGATION_PUBKEY");
        let state = std::env::var_os("CORCEPT_DELEGATION_STATE_DIR");
        if policy.is_none() && pubkey.is_none() && state.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            policy_file: policy.context("delegation policy required")?.into(),
            pinned_pubkey_hex: pubkey
                .context("delegation public key required")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid delegation public key"))?,
            state_dir: state.context("delegation state directory required")?.into(),
        }))
    }
}

/// Explicit-source entry point for trusted embedders and tests. The native hook
/// calls this with operator environment configuration, never caller metadata.
pub fn handle_pretool(
    root: &Path,
    input: &HookEnvelope,
    config: &CorceptConfig,
    source: Option<&AuthoritySource>,
) -> Result<HookOutput> {
    match handle_pretool_inner(root, input, config, source) {
        Ok(output) => Ok(output),
        Err(_) => record_failure(root, input, source.is_some()),
    }
}

pub(crate) fn record_failure(
    root: &Path,
    input: &HookEnvelope,
    require_signed: bool,
) -> Result<HookOutput> {
    record_decision(
        root,
        input,
        GuardVerdict::deny(
            "CORCEPT admission failed: authority or audit evidence unavailable.",
            AuthorityLevel::L0Observe,
        ),
        json!({
            "schema":"corcept.delegation-decision.v1", "status":"admission_unavailable",
            "identity_verification":"unavailable"
        }),
        require_signed,
    )
}

fn handle_pretool_inner(
    root: &Path,
    input: &HookEnvelope,
    config: &CorceptConfig,
    source: Option<&AuthoritySource>,
) -> Result<HookOutput> {
    let mut base = evaluate_pre_tool(input, config);
    let Some(source) = source else {
        let requested = input.extra.contains_key("delegation");
        let verdict = if requested {
            GuardVerdict::deny(
                "Delegation supplied without a configured authority source.",
                AuthorityLevel::L0Observe,
            )
        } else {
            base
        };
        return record_decision(
            root,
            input,
            verdict,
            json!({
                "schema": "corcept.delegation-decision.v1",
                "status": if requested { "authority_not_configured" } else { "not_configured" },
                "identity_verification": "unavailable"
            }),
            false,
        );
    };

    // Read once: the archived bytes are precisely the authenticated input.
    anyhow::ensure!(
        input
            .cwd
            .as_ref()
            .context("delegated cwd required")?
            .canonicalize()?
            == root.canonicalize()?,
        "delegated cwd differs from the admission root"
    );
    let state = validate_source(root, source)?;
    let mut raw = String::new();
    fs::File::open(&source.policy_file)
        .context("reading authority snapshot")?
        .take(1_048_577)
        .read_to_string(&mut raw)?;
    let snapshot = parse_authority(&raw, &source.pinned_pubkey_hex)
        .map_err(|_| anyhow::anyhow!("authority snapshot verification failed"))?;
    let digest = blake3::hash(raw.as_bytes()).to_hex().to_string();
    let archive = archive_snapshot(&state, &digest, raw.as_bytes())?;
    let mut evaluation = evaluate_delegation(input, &snapshot, chrono::Utc::now().timestamp());
    let base_decision = base.decision;

    if evaluation.guard.decision == PermissionDecision::Allow {
        let binding = snapshot
            .invocations
            .iter()
            .find(|binding| Some(&binding.id) == evaluation.invocation_id.as_ref())
            .context("evaluated invocation missing")?;
        if authority_rank(base.authority_level) > authority_rank(binding.required_authority) {
            evaluation.guard = GuardVerdict::deny(
                "Signed invocation understates the guard's required authority.",
                base.authority_level,
            );
        } else if authority_rank(binding.required_authority)
            > authority_rank(config.authority.default_max_level)
        {
            evaluation.guard = GuardVerdict::deny(
                "Delegation exceeds configured authority ceiling.",
                binding.required_authority,
            );
        } else if binding.required_authority == AuthorityLevel::L4ExternalSideEffect
            && config.authority.l4_requires_user_invocation
            && evaluation.approval_id.is_none()
        {
            evaluation.guard = GuardVerdict::deny(
                "External action requires an action-bound user approval.",
                binding.required_authority,
            );
        }
    }
    // Native Ask can execute after a UI click without calling us again. Only
    // independently attested, exact pending-action approval can resolve it.
    if base.decision == PermissionDecision::Ask
        && evaluation.guard.decision == PermissionDecision::Allow
    {
        base = if evaluation.approval_id.is_some() {
            GuardVerdict {
                decision: PermissionDecision::Allow,
                reason: "Action-bound signed approval satisfied the pending guard request.".into(),
                authority_level: base.authority_level,
            }
        } else {
            GuardVerdict::deny(
                "Pending action requires a signed action-bound approval and reevaluation.",
                base.authority_level,
            )
        };
    }
    let required = evaluation.guard.authority_level;
    let mut verdict = compose_guard_verdicts([base, evaluation.guard]);
    if verdict.decision == PermissionDecision::Ask {
        verdict.decision = PermissionDecision::Deny;
        verdict.reason = "Delegated admission awaits verified action-bound approval.".into();
    }
    if authority_rank(required) > authority_rank(verdict.authority_level) {
        verdict.authority_level = required;
    }
    let evidence = evaluation
        .evidence
        .as_object_mut()
        .context("invalid delegation evidence")?;
    evidence.insert("status".into(), json!("enforced"));
    evidence.insert("snapshot_digest".into(), json!(format!("blake3:{digest}")));
    evidence.insert("snapshot_file".into(), json!(archive));
    evidence.insert(
        "authority_key_digest".into(),
        json!(format!(
            "blake3:{}",
            blake3::hash(source.pinned_pubkey_hex.to_ascii_lowercase().as_bytes()).to_hex()
        )),
    );
    evidence.insert(
        "configured_max_authority".into(),
        json!(config.authority.default_max_level),
    );
    evidence.insert("base_guard_decision".into(), json!(base_decision));
    evidence.insert("guard_config_schema_version".into(), json!(config.version));
    let policy = json!({"authority":config.authority,"guards":config.guards});
    axiom_canonical::assert_jcs_safe(&policy)?;
    let policy_bytes = axiom_canonical::to_jcs_bytes(&policy)?;
    evidence.insert(
        "guard_policy_digest".into(),
        json!(format!("blake3:{}", blake3::hash(&policy_bytes).to_hex())),
    );
    evidence.insert(
        "l4_requires_user_invocation".into(),
        json!(config.authority.l4_requires_user_invocation),
    );

    if verdict.decision == PermissionDecision::Allow {
        // Reservation precedes audit and returned allow. Partial reservations
        // deliberately remain consumed on failure: availability cannot enable
        // approval replay. IDs remain consumed across policy versions.
        let invocation = evaluation
            .invocation_id
            .as_deref()
            .context("invocation id required")?;
        let consumed =
            reserve_once(&state, "invocation", invocation).and_then(|_| {
                match evaluation.approval_id.as_deref() {
                    Some(id) => reserve_once(&state, "approval", id),
                    None => Ok(()),
                }
            });
        if consumed.is_err() {
            verdict = GuardVerdict::deny(
                "Delegated invocation or approval is consumed or unavailable.",
                verdict.authority_level,
            );
            evidence.insert("replay_state".into(), json!("consumed_or_unavailable"));
        } else {
            evidence.insert("replay_state".into(), json!("consumed"));
        }
    }
    record_decision(root, input, verdict, evaluation.evidence, true)
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

fn record_decision(
    root: &Path,
    input: &HookEnvelope,
    verdict: GuardVerdict,
    mut evidence: Value,
    require_signed: bool,
) -> Result<HookOutput> {
    evidence["final_decision"] = json!(verdict.decision);
    // Persist opaque evaluated references and digests only. Raw hook fields and
    // arguments can carry credentials or personal data even on denied calls.
    let audit_input = HookEnvelope {
        session_id: input.session_id.clone(),
        tool_use_id: input.tool_use_id.clone(),
        tool_name: input.tool_name.clone(),
        hook_event_name: "PreToolUse".into(),
        ..HookEnvelope::default()
    };
    let compatibility = evidence.get("status").and_then(Value::as_str) == Some("not_configured");
    let target = if compatibility {
        corcept_guards::extract_path(input.tool_input.as_ref())
            .or_else(|| corcept_guards::extract_command(input.tool_input.as_ref()))
    } else {
        None
    };
    append_hook_event_with_metadata(
        root,
        if compatibility { input } else { &audit_input },
        "pretool-guard",
        LedgerEventKind::ToolRequested,
        verdict.authority_level,
        target,
        Some(&verdict.decision.to_string()),
        Some("Tool-boundary authority decision"),
        Some(evidence),
        require_signed,
    )?;
    Ok(verdict.to_hook_output())
}

pub(crate) fn host_reference_digest(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn validate_source(root: &Path, source: &AuthoritySource) -> Result<PathBuf> {
    anyhow::ensure!(
        source.policy_file.is_absolute() && source.state_dir.is_absolute(),
        "delegation paths must be absolute"
    );
    let project = root.canonicalize().context("resolving project root")?;
    // A missing replay root is a failed deployment, never a fresh grant store.
    let state = source
        .state_dir
        .canonicalize()
        .context("delegation state root must exist")?;
    anyhow::ensure!(
        state.is_dir() && !state.starts_with(&project),
        "delegation state must be outside the project"
    );
    anyhow::ensure!(
        dir_permissions_secure(&state),
        "delegation state permissions insecure"
    );
    let policy = source
        .policy_file
        .canonicalize()
        .context("resolving authority snapshot")?;
    anyhow::ensure!(
        !policy.starts_with(&project),
        "authority snapshot must be outside the project"
    );
    Ok(state)
}

fn state_subdir(state: &Path, name: &str) -> Result<PathBuf> {
    let path = state.join(name);
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(&path) {
        Ok(()) => {
            sync_directory(state)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let resolved = path.canonicalize()?;
    anyhow::ensure!(
        resolved.parent() == Some(state)
            && resolved.is_dir()
            && !fs::symlink_metadata(&path)?.file_type().is_symlink()
            && dir_permissions_secure(&resolved),
        "unsafe delegation state subdirectory"
    );
    Ok(resolved)
}

fn archive_snapshot(state: &Path, digest: &str, bytes: &[u8]) -> Result<String> {
    let directory = state_subdir(state, "snapshots")?;
    let path = directory.join(format!("{digest}.json"));
    // Publish only fully written bytes. Hard-link creation atomically refuses
    // replacement, so two different calls can safely archive the same snapshot.
    let sequence = ARCHIVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(".{digest}.{}.{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let cleanup = ArchiveTemporary(temporary.clone());
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    match fs::hard_link(&temporary, &path) {
        Ok(()) => {
            sync_directory(&directory)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(
                !fs::symlink_metadata(&path)?.file_type().is_symlink() && fs::read(&path)? == bytes,
                "archived snapshot changed"
            );
        }
        Err(error) => return Err(error.into()),
    }
    drop(cleanup);
    Ok(format!("snapshots/{digest}.json"))
}

struct ArchiveTemporary(PathBuf);
impl Drop for ArchiveTemporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn reserve_once(state: &Path, kind: &str, id: &str) -> Result<()> {
    let directory = state_subdir(state, "consumed")?;
    let digest = blake3::hash(format!("corcept:delegation-consumed:v1:{kind}:{id}").as_bytes());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(digest.to_hex().to_string()))?;
    file.write_all(b"consumed\n")?;
    file.sync_all()?;
    sync_directory(&directory)?;
    Ok(())
}

/// Completion is an observation linked to a prior invocation, not a new grant.
pub(crate) fn posttool_evidence(input: &HookEnvelope) -> Result<Value> {
    Ok(json!({
        "schema": "corcept.delegation-decision.v1",
        "status": "completion_observed",
        "invocation_digest": invocation_digest(input).map_err(|_| anyhow::anyhow!("invalid invocation"))?,
        "tool_use_id": input.tool_use_id.as_ref().map(|id| host_reference_digest(id)),
        "identity_verification": "asserted"
    }))
}
