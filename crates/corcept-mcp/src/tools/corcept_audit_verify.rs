//! Generated tool `corcept_audit_verify`.

use crate::server_config;
use async_trait::async_trait;
use mcpact_audit::AuditSink;
use mcpact_mcp::{McpTool, ToolCallResult, ToolDefinition};
use mcpact_runtime::{ExecutionPlan, Executor};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CorceptAuditVerifyArgs {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub signed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Tool;

impl Tool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl McpTool for Tool {
    fn definition(&self) -> ToolDefinition {
        let schema = schemars::schema_for!(CorceptAuditVerifyArgs);
        ToolDefinition {
            name: "corcept_audit_verify".into(),
            title: Some("Corcept Audit Verify".into()),
            description: "Verify the integrity of the append-only ledger hash chain. This is the ONLY supported way to determine ledger integrity. Do NOT compute SHA-256 yourself: the chain is canonicalized and domain-separated under a PUBLIC, source-visible prefix (`HASH_DOMAIN` = \"corcept:ledger:v1:\"), so a naive hash over the raw row bytes will not match and will false-flag a clean ledger. Report this tool's verdict VERBATIM. Read the structured result: top-level `tamper_detected: bool` is the verdict and `tampered_lines: [..]` lists the failing 1-based rows; the process also exits non-zero when tampering is detected (fail-closed). The keyless hash chain (signed=false) is a tamper-DETECTION checksum: it catches accidental corruption and a NAIVE editor who does not recompute the chain, but because the prefix is public an adversary who can read this source can rewrite a row AND recompute the whole chain, which signed=false will FALSE-PASS. Use signed=true for tamper-EVIDENCE against such an adversary: it requires a valid Ed25519 signature (from a key the adversary does not hold) on every row (Trust ceiling: Verified). Without signed, hash-chain integrity only (Trust ceiling: Signed). Authority: Observe.".into(),
            input_schema: serde_json::to_value(&schema).unwrap_or_else(|_| json!({"type":"object"})),
            output_schema: None,
            annotations: Some(mcpact_mcp::ToolDefinition::mcpact_annotations(mcpact_core::AuthorityClass::Observe, server_config::TRUST)),
        }
    }

    async fn call(&self, arguments: serde_json::Value) -> ToolCallResult {
        let args: CorceptAuditVerifyArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(err) => return ToolCallResult::error(format!("invalid arguments: {err}")),
        };

        let tool_spec: mcpact_manifest::ToolSpec = match serde_json::from_str(include_str!(
            concat!("../../.mcpact/tools/corcept_audit_verify.json")
        )) {
            Ok(spec) => spec,
            Err(err) => return ToolCallResult::error(format!("tool spec load failed: {err}")),
        };
        let args_json = match serde_json::to_value(&args) {
            Ok(value) => value,
            Err(err) => {
                return ToolCallResult::error(format!("argument serialization failed: {err}"))
            }
        };
        let workspace = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let ctx = mcpact_policy::PolicyContext {
            workspace_root: workspace,
            trust_ceiling: server_config::TRUST,
            approved: std::env::var("MCPACT_APPROVED").is_ok_and(|value| value == "1"),
            allow_network: tool_spec.policy.network,
            allowed_secrets: BTreeSet::new(),
        };
        match mcpact_policy::evaluate_invocation(&ctx, &tool_spec, &args_json) {
            Ok(decision) if decision.allowed => {}
            Ok(decision) => {
                let reason = decision.reason.clone();
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "corcept_audit_verify",
                    mcpact_core::AuthorityClass::Observe,
                    &reason,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(reason);
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "corcept_audit_verify",
                    mcpact_core::AuthorityClass::Observe,
                    err.to_string(),
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(err.to_string());
            }
        }

        let mut plan =
            ExecutionPlan::new(server_config::binary_path().to_string_lossy().to_string());
        plan.argv = Vec::new();
        // `--path` is a flag on the `audit` PARENT, not on the `verify`
        // subcommand (see corcept-cli clap definition). It MUST be pushed
        // before `verify`, otherwise clap rejects it ("unexpected argument
        // --path") and the tool errors on any non-default workspace, which is
        // what forced weak callers into hand-rolled hashing. Correct shape:
        //   audit --path <X> verify [--signed]
        plan.argv.push("audit".into());
        if let Some(path) = args.path {
            plan.argv.push("--path".into());
            plan.argv.push(path);
        }
        plan.argv.push("verify".into());
        if args.signed {
            plan.argv.push("--signed".into());
        }
        let redacted = Vec::new();
        plan.redacted_arg_indexes = redacted;
        plan.env.inherit = false;

        plan.timeout = std::time::Duration::from_secs(60);
        plan.max_output_bytes = 1048576;
        plan.output_mode = mcpact_runtime::OutputMode::Json;
        plan.authority = mcpact_core::AuthorityClass::Observe;

        let plan_for_audit = plan.clone();
        match Executor.execute(plan).await {
            Ok(result) => {
                let event = mcpact_audit::EvidenceEvent::tool_executed(
                    "corcept_audit_verify",
                    &plan_for_audit,
                    &result,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                if let Some(value) = result.structured {
                    ToolCallResult::structured(value)
                } else if result.stderr.is_empty() {
                    ToolCallResult::text(result.stdout)
                } else {
                    ToolCallResult::text(format!("{}\n{}", result.stdout, result.stderr))
                }
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_failed(
                    "corcept_audit_verify",
                    &plan_for_audit,
                    err.to_string(),
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                ToolCallResult::error(format!("execution failed: {err}"))
            }
        }
    }
}
