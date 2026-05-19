//! Generated tool `corcept_memory_promote`.

use crate::server_config;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use mcpact_mcp::{McpTool, ToolCallResult, ToolDefinition};
use mcpact_runtime::{ExecutionPlan, Executor};
use mcpact_audit::AuditSink;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorceptMemoryPromoteArgs {
    pub candidate_id: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Tool;

impl Tool {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl McpTool for Tool {
    fn definition(&self) -> ToolDefinition {
        let schema = schemars::schema_for!(CorceptMemoryPromoteArgs);
        ToolDefinition {
            name: "corcept_memory_promote".into(),
            title: Some("Corcept Memory Promote".into()),
            description: "Promote a candidate memory from the corcept session ledger to the cortex memory store. Authority: Plan (dry-run evaluation) escalating to Mutate on actual promotion. Trust ceiling: Reviewed. Approval-gated on mutation (approval = on-mutation). Confined to .corcept/ ledger paths.".into(),
            input_schema: serde_json::to_value(&schema).unwrap_or_else(|_| json!({"type":"object"})),
            output_schema: None,
            annotations: Some(mcpact_mcp::ToolDefinition::mcpact_annotations(mcpact_core::AuthorityClass::Plan, server_config::TRUST)),
        }
    }

    async fn call(&self, arguments: serde_json::Value) -> ToolCallResult {
        let args: CorceptMemoryPromoteArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(err) => return ToolCallResult::error(format!("invalid arguments: {err}")),
        };

        let tool_spec: mcpact_manifest::ToolSpec = match serde_json::from_str(include_str!(concat!("../../.mcpact/tools/corcept_memory_promote.json"))) {
            Ok(spec) => spec,
            Err(err) => return ToolCallResult::error(format!("tool spec load failed: {err}")),
        };
        let args_json = match serde_json::to_value(&args) {
            Ok(value) => value,
            Err(err) => return ToolCallResult::error(format!("argument serialization failed: {err}")),
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
                    "corcept_memory_promote",
                    mcpact_core::AuthorityClass::Plan,
                    &reason,
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(reason);
            }
            Err(err) => {
                let event = mcpact_audit::EvidenceEvent::tool_denied(
                    "corcept_memory_promote",
                    mcpact_core::AuthorityClass::Plan,
                    err.to_string(),
                );
                let sink = server_config::audit_sink();
                let _ = sink.emit(&event).await;
                return ToolCallResult::error(err.to_string());
            }
        }

        let mut plan = ExecutionPlan::new(server_config::binary_path().to_string_lossy().to_string());
        plan.argv = Vec::new();
        plan.argv.push("memory".into());
        plan.argv.push("promote".into());
        plan.argv.push("--candidate-id".into());
        plan.argv.push(args.candidate_id.to_string());
        if args.dry_run { plan.argv.push("--dry-run".into()); }
        if args.path.is_some() {
        plan.argv.push("--path".into());
        plan.argv.push(match args.path { Some(v) => v, None => String::new() });
        }
        let redacted = Vec::new();
        plan.redacted_arg_indexes = redacted;
        plan.env.inherit = false;
        plan.env.allow = vec!["CORTEX_URL".into(), "CORCEPT_LEDGER_PATH".into()];

        plan.timeout = std::time::Duration::from_secs(60);
        plan.max_output_bytes = 524288;
        plan.output_mode = mcpact_runtime::OutputMode::Json;
        plan.authority = mcpact_core::AuthorityClass::Plan;

        let plan_for_audit = plan.clone();
        match Executor::default().execute(plan).await {
            Ok(result) => {
                let event = mcpact_audit::EvidenceEvent::tool_executed("corcept_memory_promote", &plan_for_audit, &result);
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
                    "corcept_memory_promote",
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
