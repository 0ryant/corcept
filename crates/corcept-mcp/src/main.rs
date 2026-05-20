//! Generated McPact MCP server crate. Do not edit generated code directly.
//!
//! Direct process::Command invocations in mcpact-generated tool dispatch
//! are a lint violation (see security_grep invariant). Version probing at
//! startup uses `mcpact_runtime::SafeCommand` instead.

mod server_config;
mod tools;
#[cfg(test)]
mod tests;

use mcpact_mcp::ToolRegistry;
use mcpact_runtime::SafeCommand;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    server_config::init("corcept")?;
    // Startup binary probe via SafeCommand (argv-only, env-cleared, timeout-bounded).
    let _ = SafeCommand::new(&server_config::binary_path().to_string_lossy())
        .args(&["--version"])
        .timeout(Duration::from_secs(5))
        .run_raw()
        .await;

    let mut registry = ToolRegistry::new();
    // v1 tools (10).
    registry.register(tools::corcept_audit_verify::Tool::new());
    registry.register(tools::corcept_doctor::Tool::new());
    registry.register(tools::corcept_export_cloudevents::Tool::new());
    registry.register(tools::corcept_hook_posttool_audit::Tool::new());
    registry.register(tools::corcept_hook_pretool_guard::Tool::new());
    registry.register(tools::corcept_hook_session_start::Tool::new());
    registry.register(tools::corcept_hook_stop_check::Tool::new());
    registry.register(tools::corcept_hook_user_prompt_submit::Tool::new());
    registry.register(tools::corcept_key_generate::Tool::new());
    registry.register(tools::corcept_memory_promote::Tool::new());
    // ADR-0006 13-hook canonical surface (v2) — 10 new tools.
    registry.register(tools::corcept_hook_before_run::Tool::new());
    registry.register(tools::corcept_hook_after_run::Tool::new());
    registry.register(tools::corcept_hook_before_subprocess_spawn::Tool::new());
    registry.register(tools::corcept_hook_after_subprocess_exit::Tool::new());
    registry.register(tools::corcept_hook_before_file_write::Tool::new());
    registry.register(tools::corcept_hook_after_file_write::Tool::new());
    registry.register(tools::corcept_hook_before_network_access::Tool::new());
    registry.register(tools::corcept_hook_before_final_answer::Tool::new());
    registry.register(tools::corcept_hook_on_claim_emitted::Tool::new());
    registry.register(tools::corcept_hook_on_error::Tool::new());
    mcpact_mcp::serve_stdio(registry).await?;
    Ok(())
}
