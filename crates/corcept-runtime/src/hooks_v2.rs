//! ADR-0006 13-hook canonical surface (v2).
//!
//! Today corcept maps 5 of the 13 canonical lifecycle hooks (SessionStart,
//! UserPromptSubmit, PreToolUse, PostToolUse, Stop) onto the existing
//! `handle_hook` switch (see `lib.rs::handle_hook`). This module adds the
//! remaining 10 names verbatim per the operator directive in
//! `ecosystem-catalog/adrs/0006-hooks-as-host-side-non-model-controlled.md`:
//!
//! - `BeforeRun`               (`before-run`)
//! - `AfterRun`                (`after-run`)
//! - `BeforeSubprocessSpawn`   (`before-subprocess-spawn`)
//! - `AfterSubprocessExit`     (`after-subprocess-exit`)
//! - `BeforeFileWrite`         (`before-file-write`)
//! - `AfterFileWrite`          (`after-file-write`)
//! - `BeforeNetworkAccess`     (`before-network-access`)
//! - `BeforeFinalAnswer`       (`before-final-answer`)
//! - `OnClaimEmitted`          (`on-claim-emitted`)
//! - `OnError`                 (`on-error`)
//!
//! Each new hook:
//!
//! 1. Defines a typed input struct (`#[serde(deny_unknown_fields)]`).
//! 2. Defines a typed output struct with a `Verdict` enum
//!    (`allow` / `deny` / `inspect` / `error`).
//! 3. Emits an audit event via `append_audit_v2` on the existing
//!    corcept ledger.
//! 4. Returns a default `Allow` verdict (record-only).
//!
//! These are framework scaffolds. Policies (cellos confinement,
//! tapprove claim_audit, tsafe env injection, etc.) layer on top per
//! ADR-0006's "Per-tool implications" table.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use corcept_sink::{build_ledger_event, SinkDispatcher, SinkRecord};
use corcept_types::{AuthorityLevel, HookEnvelope, LedgerEventKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Shared output: Verdict enum + HookOutputV2
// ---------------------------------------------------------------------------

/// The decision a v2 hook returns.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Hook allows the lifecycle position to continue.
    Allow,
    /// Hook blocks the lifecycle position (downstream short-circuit).
    Deny,
    /// Hook is record-only and records its observation without gating.
    Inspect,
    /// Hook itself encountered an internal error.
    Error,
}

/// Common output shape for all v2 hooks. Carries the verdict, an
/// optional human-readable reason, and an optional `additional_context`
/// the host MAY surface to the model (ADR-0006 `mutate` semantic).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookOutputV2 {
    /// The 13-hook canonical name this output is for (e.g. `BeforeRun`).
    pub hook: &'static str,
    /// The verdict — `allow`/`deny`/`inspect`/`error`.
    pub verdict: Verdict,
    /// Optional human-readable reason; populated on `Deny`/`Error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional context the host MAY surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl HookOutputV2 {
    /// Build an `Allow` (record-only) output for the given hook.
    pub fn allow(hook: &'static str) -> Self {
        Self {
            hook,
            verdict: Verdict::Allow,
            reason: None,
            additional_context: None,
        }
    }

    /// Build an `Inspect` output for the given hook.
    pub fn inspect(hook: &'static str, context: impl Into<String>) -> Self {
        Self {
            hook,
            verdict: Verdict::Inspect,
            reason: None,
            additional_context: Some(context.into()),
        }
    }

    /// Build a `Deny` output with reason.
    pub fn deny(hook: &'static str, reason: impl Into<String>) -> Self {
        Self {
            hook,
            verdict: Verdict::Deny,
            reason: Some(reason.into()),
            additional_context: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-hook typed input shapes
// ---------------------------------------------------------------------------

/// `BeforeRun` input. Fires when a run contract activates, before any
/// tool use. Inputs come from the run-contract validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeforeRunInput {
    /// Run contract id.
    pub run_contract: String,
    /// Run contract fingerprint.
    pub run_contract_fingerprint: String,
    /// Trigger that activated the run (one of ADR-0005 variant names).
    pub trigger_type: String,
    /// Trigger payload sha256 (for replay protection in audit).
    pub trigger_payload_sha256: String,
    /// Optional bindings the trigger injected into the run context.
    #[serde(default)]
    pub bindings: BTreeMap<String, Value>,
    /// Optional session id (host-provided).
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `AfterRun` input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfterRunInput {
    /// Run contract id.
    pub run_contract: String,
    /// Run contract fingerprint.
    pub run_contract_fingerprint: String,
    /// `success` / `failed` / `aborted`.
    pub status: String,
    /// Optional summary of emitted artefacts.
    #[serde(default)]
    pub artefacts: Vec<String>,
    /// Optional session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `BeforeSubprocessSpawn` input — fires before the tool implementation
/// invokes `Command::new()` / `execve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeforeSubprocessSpawnInput {
    /// Program path (argv[0]).
    pub program: String,
    /// Arguments (argv[1..]).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Environment variables (key -> value). Should be filtered before reaching here.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Working directory.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `AfterSubprocessExit` input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfterSubprocessExitInput {
    /// Program that ran.
    pub program: String,
    /// Argv as launched.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Exit code (None if signalled).
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Sha256 of stdout (host pre-computes; we never see raw stdout).
    #[serde(default)]
    pub stdout_sha256: Option<String>,
    /// Sha256 of stderr.
    #[serde(default)]
    pub stderr_sha256: Option<String>,
    /// Latency in milliseconds.
    #[serde(default)]
    pub latency_ms: Option<u64>,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `BeforeFileWrite` input — fires before a write touches disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeforeFileWriteInput {
    /// Target path.
    pub path: String,
    /// Peeked content sha256 (host computes; hook does not see content).
    #[serde(default)]
    pub content_sha256: Option<String>,
    /// Byte count.
    #[serde(default)]
    pub byte_count: Option<u64>,
    /// `create` / `overwrite` / `append`.
    pub write_mode: String,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `AfterFileWrite` input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfterFileWriteInput {
    /// Path written.
    pub path: String,
    /// Bytes written.
    pub bytes_written: u64,
    /// Final sha256.
    pub sha256: String,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `BeforeNetworkAccess` input — fires before any outbound socket / HTTP call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeforeNetworkAccessInput {
    /// Destination host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// `tcp` / `udp` / `https` / `http`.
    pub protocol: String,
    /// HTTP method if applicable.
    #[serde(default)]
    pub method: Option<String>,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `BeforeFinalAnswer` input — fires once before the model's terminal
/// response is emitted to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeforeFinalAnswerInput {
    /// Sha256 of the candidate final answer text.
    pub final_answer_sha256: String,
    /// Byte length.
    pub final_answer_bytes: u64,
    /// Run contract id (if the host knows it).
    #[serde(default)]
    pub run_contract: Option<String>,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `OnClaimEmitted` input — fires every time the model emits a typed claim
/// shape (e.g. "I wrote file X" / "test passed" / "evidence emitted").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnClaimEmittedInput {
    /// `wrote_file` / `test_passed` / `evidence_emitted` / `verified` / etc.
    pub claim_shape: String,
    /// Sha256 of the claim text.
    pub claim_sha256: String,
    /// JSON pointer or human-readable target the claim references.
    #[serde(default)]
    pub target: Option<String>,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// `OnError` input — fires on any phase error (validator fail, hook deny,
/// tool error, verifier fail, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnErrorInput {
    /// Lifecycle phase the error occurred in.
    pub phase: String,
    /// Error kind (free-form code; the host categorises).
    pub error_kind: String,
    /// Sha256 of any error text (we don't transport raw text through the hook).
    #[serde(default)]
    pub error_sha256: Option<String>,
    /// Session id.
    #[serde(default)]
    pub session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers — each takes its typed input and emits an audit row.
// ---------------------------------------------------------------------------

/// `BeforeRun` handler.
pub fn handle_before_run(root: &Path, input: BeforeRunInput) -> Result<HookOutputV2> {
    append_audit_v2(
        root,
        "BeforeRun",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.run_contract.clone()),
        Some("allow"),
        Some("BeforeRun fired"),
        run_contract_metadata(
            &input.run_contract,
            &input.run_contract_fingerprint,
            &input.trigger_type,
            &input.trigger_payload_sha256,
        ),
    )?;
    Ok(HookOutputV2::allow("BeforeRun"))
}

/// `AfterRun` handler.
pub fn handle_after_run(root: &Path, input: AfterRunInput) -> Result<HookOutputV2> {
    let mut meta =
        run_contract_metadata(&input.run_contract, &input.run_contract_fingerprint, "", "");
    meta.insert("status".to_string(), Value::String(input.status.clone()));
    if !input.artefacts.is_empty() {
        meta.insert(
            "artefacts".to_string(),
            Value::Array(
                input
                    .artefacts
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }
    append_audit_v2(
        root,
        "AfterRun",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.run_contract.clone()),
        Some("record_only"),
        Some("AfterRun fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("AfterRun"))
}

/// `BeforeSubprocessSpawn` handler.
pub fn handle_before_subprocess_spawn(
    root: &Path,
    input: BeforeSubprocessSpawnInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert("program".to_string(), Value::String(input.program.clone()));
    if !input.argv.is_empty() {
        meta.insert(
            "argv".to_string(),
            Value::Array(
                input
                    .argv
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }
    meta.insert(
        "env_keys".to_string(),
        Value::Array(
            input
                .env
                .keys()
                .map(|k| Value::String(k.clone()))
                .collect(),
        ),
    );
    if let Some(cwd) = &input.cwd {
        meta.insert("cwd".to_string(), Value::String(cwd.clone()));
    }
    append_audit_v2(
        root,
        "BeforeSubprocessSpawn",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.program.clone()),
        Some("allow"),
        Some("BeforeSubprocessSpawn fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("BeforeSubprocessSpawn"))
}

/// `AfterSubprocessExit` handler.
pub fn handle_after_subprocess_exit(
    root: &Path,
    input: AfterSubprocessExitInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert("program".to_string(), Value::String(input.program.clone()));
    if let Some(exit_code) = input.exit_code {
        meta.insert(
            "exit_code".to_string(),
            Value::Number(serde_json::Number::from(exit_code as i64)),
        );
    }
    if let Some(s) = &input.stdout_sha256 {
        meta.insert("stdout_sha256".to_string(), Value::String(s.clone()));
    }
    if let Some(s) = &input.stderr_sha256 {
        meta.insert("stderr_sha256".to_string(), Value::String(s.clone()));
    }
    if let Some(lat) = input.latency_ms {
        meta.insert(
            "latency_ms".to_string(),
            Value::Number(serde_json::Number::from(lat)),
        );
    }
    let decision = match input.exit_code {
        Some(0) => "pass",
        Some(_) => "fail",
        None => "recorded",
    };
    append_audit_v2(
        root,
        "AfterSubprocessExit",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.program.clone()),
        Some(decision),
        Some("AfterSubprocessExit fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("AfterSubprocessExit"))
}

/// `BeforeFileWrite` handler.
pub fn handle_before_file_write(
    root: &Path,
    input: BeforeFileWriteInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert("path".to_string(), Value::String(input.path.clone()));
    meta.insert(
        "write_mode".to_string(),
        Value::String(input.write_mode.clone()),
    );
    if let Some(s) = &input.content_sha256 {
        meta.insert("content_sha256".to_string(), Value::String(s.clone()));
    }
    if let Some(b) = input.byte_count {
        meta.insert(
            "byte_count".to_string(),
            Value::Number(serde_json::Number::from(b)),
        );
    }
    append_audit_v2(
        root,
        "BeforeFileWrite",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.path.clone()),
        Some("allow"),
        Some("BeforeFileWrite fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("BeforeFileWrite"))
}

/// `AfterFileWrite` handler.
pub fn handle_after_file_write(
    root: &Path,
    input: AfterFileWriteInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert("path".to_string(), Value::String(input.path.clone()));
    meta.insert(
        "bytes_written".to_string(),
        Value::Number(serde_json::Number::from(input.bytes_written)),
    );
    meta.insert("sha256".to_string(), Value::String(input.sha256.clone()));
    append_audit_v2(
        root,
        "AfterFileWrite",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.path.clone()),
        Some("record_only"),
        Some("AfterFileWrite fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("AfterFileWrite"))
}

/// `BeforeNetworkAccess` handler.
pub fn handle_before_network_access(
    root: &Path,
    input: BeforeNetworkAccessInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert("host".to_string(), Value::String(input.host.clone()));
    meta.insert(
        "port".to_string(),
        Value::Number(serde_json::Number::from(input.port)),
    );
    meta.insert(
        "protocol".to_string(),
        Value::String(input.protocol.clone()),
    );
    if let Some(m) = &input.method {
        meta.insert("method".to_string(), Value::String(m.clone()));
    }
    append_audit_v2(
        root,
        "BeforeNetworkAccess",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(format!("{}:{}", input.host, input.port)),
        Some("allow"),
        Some("BeforeNetworkAccess fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("BeforeNetworkAccess"))
}

/// `BeforeFinalAnswer` handler.
pub fn handle_before_final_answer(
    root: &Path,
    input: BeforeFinalAnswerInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert(
        "final_answer_sha256".to_string(),
        Value::String(input.final_answer_sha256.clone()),
    );
    meta.insert(
        "final_answer_bytes".to_string(),
        Value::Number(serde_json::Number::from(input.final_answer_bytes)),
    );
    if let Some(rc) = &input.run_contract {
        meta.insert("run_contract".to_string(), Value::String(rc.clone()));
    }
    append_audit_v2(
        root,
        "BeforeFinalAnswer",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        input.run_contract.clone(),
        Some("allow"),
        Some("BeforeFinalAnswer fired"),
        meta,
    )?;
    Ok(HookOutputV2::allow("BeforeFinalAnswer"))
}

/// `OnClaimEmitted` handler.
pub fn handle_on_claim_emitted(
    root: &Path,
    input: OnClaimEmittedInput,
) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert(
        "claim_shape".to_string(),
        Value::String(input.claim_shape.clone()),
    );
    meta.insert(
        "claim_sha256".to_string(),
        Value::String(input.claim_sha256.clone()),
    );
    if let Some(t) = &input.target {
        meta.insert("target".to_string(), Value::String(t.clone()));
    }
    append_audit_v2(
        root,
        "OnClaimEmitted",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        input.target.clone(),
        Some("record_only"),
        Some(&format!("OnClaimEmitted: {}", input.claim_shape)),
        meta,
    )?;
    Ok(HookOutputV2::allow("OnClaimEmitted"))
}

/// `OnError` handler.
pub fn handle_on_error(root: &Path, input: OnErrorInput) -> Result<HookOutputV2> {
    let mut meta = BTreeMap::new();
    meta.insert("phase".to_string(), Value::String(input.phase.clone()));
    meta.insert(
        "error_kind".to_string(),
        Value::String(input.error_kind.clone()),
    );
    if let Some(sha) = &input.error_sha256 {
        meta.insert("error_sha256".to_string(), Value::String(sha.clone()));
    }
    append_audit_v2(
        root,
        "OnError",
        AuthorityLevel::L0Observe,
        input.session_id.clone(),
        Some(input.error_kind.clone()),
        Some("record_only"),
        Some(&format!("OnError in phase {}", input.phase)),
        meta,
    )?;
    Ok(HookOutputV2::allow("OnError"))
}

// ---------------------------------------------------------------------------
// Dispatcher — single entry point used by `handle_hook` in `lib.rs`.
// ---------------------------------------------------------------------------

/// Dispatch raw JSON to the right v2 handler by command name.
/// Returns `Ok(None)` if the command is not one of the 10 v2 commands —
/// the caller should fall through to the legacy 5-hook switch.
pub fn try_dispatch_v2(
    raw_json: &str,
    command: &str,
    root: &Path,
) -> Result<Option<HookOutputV2>> {
    let out = match command {
        "before-run" => {
            let input: BeforeRunInput =
                serde_json::from_str(raw_json).context("parsing BeforeRun hook input")?;
            handle_before_run(root, input)?
        }
        "after-run" => {
            let input: AfterRunInput =
                serde_json::from_str(raw_json).context("parsing AfterRun hook input")?;
            handle_after_run(root, input)?
        }
        "before-subprocess-spawn" => {
            let input: BeforeSubprocessSpawnInput = serde_json::from_str(raw_json)
                .context("parsing BeforeSubprocessSpawn hook input")?;
            handle_before_subprocess_spawn(root, input)?
        }
        "after-subprocess-exit" => {
            let input: AfterSubprocessExitInput = serde_json::from_str(raw_json)
                .context("parsing AfterSubprocessExit hook input")?;
            handle_after_subprocess_exit(root, input)?
        }
        "before-file-write" => {
            let input: BeforeFileWriteInput = serde_json::from_str(raw_json)
                .context("parsing BeforeFileWrite hook input")?;
            handle_before_file_write(root, input)?
        }
        "after-file-write" => {
            let input: AfterFileWriteInput = serde_json::from_str(raw_json)
                .context("parsing AfterFileWrite hook input")?;
            handle_after_file_write(root, input)?
        }
        "before-network-access" => {
            let input: BeforeNetworkAccessInput = serde_json::from_str(raw_json)
                .context("parsing BeforeNetworkAccess hook input")?;
            handle_before_network_access(root, input)?
        }
        "before-final-answer" => {
            let input: BeforeFinalAnswerInput = serde_json::from_str(raw_json)
                .context("parsing BeforeFinalAnswer hook input")?;
            handle_before_final_answer(root, input)?
        }
        "on-claim-emitted" => {
            let input: OnClaimEmittedInput =
                serde_json::from_str(raw_json).context("parsing OnClaimEmitted hook input")?;
            handle_on_claim_emitted(root, input)?
        }
        "on-error" => {
            let input: OnErrorInput =
                serde_json::from_str(raw_json).context("parsing OnError hook input")?;
            handle_on_error(root, input)?
        }
        _ => return Ok(None),
    };
    Ok(Some(out))
}

/// The 10 v2 hook command names (for CLI help / validation).
pub const V2_COMMANDS: &[&str] = &[
    "before-run",
    "after-run",
    "before-subprocess-spawn",
    "after-subprocess-exit",
    "before-file-write",
    "after-file-write",
    "before-network-access",
    "before-final-answer",
    "on-claim-emitted",
    "on-error",
];

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

fn run_contract_metadata(
    contract: &str,
    fingerprint: &str,
    trigger_type: &str,
    trigger_payload_sha256: &str,
) -> BTreeMap<String, Value> {
    let mut meta = BTreeMap::new();
    if !contract.is_empty() {
        meta.insert(
            "run_contract".to_string(),
            Value::String(contract.to_string()),
        );
    }
    if !fingerprint.is_empty() {
        meta.insert(
            "run_contract_fingerprint".to_string(),
            Value::String(fingerprint.to_string()),
        );
    }
    if !trigger_type.is_empty() {
        meta.insert(
            "trigger_type".to_string(),
            Value::String(trigger_type.to_string()),
        );
    }
    if !trigger_payload_sha256.is_empty() {
        meta.insert(
            "trigger_payload_sha256".to_string(),
            Value::String(trigger_payload_sha256.to_string()),
        );
    }
    meta
}

#[allow(clippy::too_many_arguments)]
fn append_audit_v2(
    root: &Path,
    hook_name: &str,
    authority_level: AuthorityLevel,
    session_id: Option<String>,
    target: Option<String>,
    decision: Option<&str>,
    reason: Option<&str>,
    extra: BTreeMap<String, Value>,
) -> Result<()> {
    // Reuse the existing ledger event kind. ADR-0006 hooks are
    // record-only at the MVP layer; specific policies that layer on top
    // can emit narrower event kinds. The `hook` metadata field is the
    // canonical hook name, kept stable across v2 events.
    let kind = LedgerEventKind::ToolCompleted;

    let mut metadata = extra;
    metadata.insert(
        "hook".to_string(),
        Value::String(hook_name.to_string()),
    );
    metadata.insert(
        "hook_surface".to_string(),
        Value::String("v2".to_string()),
    );

    // Build a HookEnvelope-shaped record for the existing emitter.
    let envelope = HookEnvelope {
        session_id: session_id.clone(),
        ..Default::default()
    };
    let event = build_ledger_event(
        envelope.session_id.clone(),
        envelope
            .agent_type
            .clone()
            .unwrap_or_else(|| "corcept-runtime".to_string()),
        kind,
        authority_level,
        Some(hook_name.to_string()),
        target,
        decision.map(ToOwned::to_owned),
        reason.map(ToOwned::to_owned),
        metadata,
    );
    let correlation = session_id.unwrap_or_else(|| "unknown".to_string());
    let outcome = decision.unwrap_or("recorded");
    let record = SinkRecord::new(correlation, kind, outcome);
    let dispatcher = SinkDispatcher::hook_default(root);
    dispatcher.emit_all(&record, Some(&event))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{init_project, InitOptions};
    use corcept_ledger::read_events;

    fn init_temp() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        init_project(InitOptions {
            path: dir.path().to_path_buf(),
            dry_run: false,
            force: false,
        })
        .unwrap();
        dir
    }

    #[test]
    fn v2_commands_list_is_ten() {
        assert_eq!(
            V2_COMMANDS.len(),
            10,
            "ADR-0006: 10 new canonical hook names"
        );
    }

    #[test]
    fn deny_unknown_fields_on_before_run() {
        let raw = r#"{"run_contract":"c","run_contract_fingerprint":"sha256:0","trigger_type":"manual","trigger_payload_sha256":"sha256:0","unknown":true}"#;
        let err = serde_json::from_str::<BeforeRunInput>(raw);
        assert!(err.is_err(), "deny_unknown_fields should reject");
    }

    #[test]
    fn deny_unknown_fields_on_each_v2_input() {
        let cases: &[(&str, &str)] = &[
            ("AfterRunInput", r#"{"run_contract":"c","run_contract_fingerprint":"f","status":"success","unknown":true}"#),
            ("BeforeSubprocessSpawnInput", r#"{"program":"p","unknown":true}"#),
            ("AfterSubprocessExitInput", r#"{"program":"p","unknown":true}"#),
            ("BeforeFileWriteInput", r#"{"path":"/x","write_mode":"create","unknown":true}"#),
            ("AfterFileWriteInput", r#"{"path":"/x","bytes_written":0,"sha256":"sha256:0","unknown":true}"#),
            ("BeforeNetworkAccessInput", r#"{"host":"h","port":80,"protocol":"https","unknown":true}"#),
            ("BeforeFinalAnswerInput", r#"{"final_answer_sha256":"sha256:0","final_answer_bytes":0,"unknown":true}"#),
            ("OnClaimEmittedInput", r#"{"claim_shape":"wrote_file","claim_sha256":"sha256:0","unknown":true}"#),
            ("OnErrorInput", r#"{"phase":"validate","error_kind":"E_X","unknown":true}"#),
        ];
        for (name, raw) in cases {
            let err = match *name {
                "AfterRunInput" => serde_json::from_str::<AfterRunInput>(raw).err(),
                "BeforeSubprocessSpawnInput" => serde_json::from_str::<BeforeSubprocessSpawnInput>(raw).err(),
                "AfterSubprocessExitInput" => serde_json::from_str::<AfterSubprocessExitInput>(raw).err(),
                "BeforeFileWriteInput" => serde_json::from_str::<BeforeFileWriteInput>(raw).err(),
                "AfterFileWriteInput" => serde_json::from_str::<AfterFileWriteInput>(raw).err(),
                "BeforeNetworkAccessInput" => serde_json::from_str::<BeforeNetworkAccessInput>(raw).err(),
                "BeforeFinalAnswerInput" => serde_json::from_str::<BeforeFinalAnswerInput>(raw).err(),
                "OnClaimEmittedInput" => serde_json::from_str::<OnClaimEmittedInput>(raw).err(),
                "OnErrorInput" => serde_json::from_str::<OnErrorInput>(raw).err(),
                _ => unreachable!(),
            };
            assert!(err.is_some(), "{name} should reject unknown fields");
        }
    }

    #[test]
    fn before_run_writes_audit_event() {
        let dir = init_temp();
        let raw = serde_json::json!({
            "run_contract": "pr-evidence-build",
            "run_contract_fingerprint": "sha256:abc",
            "trigger_type": "manual",
            "trigger_payload_sha256": "sha256:def",
            "bindings": {"pr_url": "https://github.com/o/r/pull/1"},
            "session_id": "s1"
        })
        .to_string();
        let out = try_dispatch_v2(&raw, "before-run", dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.hook, "BeforeRun");
        let events = read_events(dir.path()).unwrap();
        assert!(events.iter().any(|e| e.tool.as_deref() == Some("BeforeRun")));
    }

    #[test]
    fn all_ten_v2_handlers_can_be_invoked() {
        let dir = init_temp();
        let cases: &[(&str, serde_json::Value)] = &[
            (
                "before-run",
                serde_json::json!({"run_contract":"c","run_contract_fingerprint":"sha256:0","trigger_type":"manual","trigger_payload_sha256":"sha256:0"}),
            ),
            (
                "after-run",
                serde_json::json!({"run_contract":"c","run_contract_fingerprint":"sha256:0","status":"success"}),
            ),
            (
                "before-subprocess-spawn",
                serde_json::json!({"program":"echo","argv":["hi"]}),
            ),
            (
                "after-subprocess-exit",
                serde_json::json!({"program":"echo","argv":["hi"],"exit_code":0}),
            ),
            (
                "before-file-write",
                serde_json::json!({"path":"/tmp/x","write_mode":"create","byte_count":4}),
            ),
            (
                "after-file-write",
                serde_json::json!({"path":"/tmp/x","bytes_written":4,"sha256":"sha256:abc"}),
            ),
            (
                "before-network-access",
                serde_json::json!({"host":"api.example.com","port":443,"protocol":"https","method":"GET"}),
            ),
            (
                "before-final-answer",
                serde_json::json!({"final_answer_sha256":"sha256:f","final_answer_bytes":100}),
            ),
            (
                "on-claim-emitted",
                serde_json::json!({"claim_shape":"wrote_file","claim_sha256":"sha256:c","target":"/tmp/x"}),
            ),
            (
                "on-error",
                serde_json::json!({"phase":"validate","error_kind":"E_PARSE","error_sha256":"sha256:e"}),
            ),
        ];
        for (command, payload) in cases {
            let out = try_dispatch_v2(&payload.to_string(), command, dir.path())
                .unwrap_or_else(|e| panic!("dispatch {command}: {e}"))
                .unwrap_or_else(|| panic!("dispatch {command} returned None"));
            assert_eq!(out.verdict, Verdict::Allow, "{command} verdict");
        }
        let events = read_events(dir.path()).unwrap();
        let v2_events: Vec<_> = events
            .iter()
            .filter(|e| {
                e.metadata
                    .get("hook_surface")
                    .and_then(|v| v.as_str())
                    == Some("v2")
            })
            .collect();
        assert_eq!(v2_events.len(), 10, "10 v2 audit rows expected");
    }

    #[test]
    fn try_dispatch_v2_returns_none_for_legacy() {
        let dir = init_temp();
        let raw = r#"{}"#;
        let out = try_dispatch_v2(raw, "pretool-guard", dir.path()).unwrap();
        assert!(out.is_none(), "legacy commands fall through");
    }
}
