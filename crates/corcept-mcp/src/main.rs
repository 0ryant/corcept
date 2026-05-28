//! Generated McPact MCP server crate. Do not edit generated code directly.

mod server_config;
mod tools;

use mcpact_mcp::ToolRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    server_config::init("corcept")?;
    let _ = std::process::Command::new(server_config::binary_path())
        .args(["--version".to_string()])
        .status();

    let mut registry = ToolRegistry::new();
    registry.register(tools::corcept_audit_verify::Tool::new());
    registry.register(tools::corcept_doctor::Tool::new());
    registry.register(tools::corcept_export_cloudevents::Tool::new());
    registry.register(tools::corcept_hook_posttool_audit::Tool::new());
    registry.register(tools::corcept_hook_pretool_guard::Tool::new());
    registry.register(tools::corcept_hook_session_start::Tool::new());
    registry.register(tools::corcept_hook_stop_check::Tool::new());
    registry.register(tools::corcept_hook_user_prompt_submit::Tool::new());
    registry.register(tools::corcept_key_generate::Tool::new());
    mcpact_mcp::serve_stdio(registry).await?;
    Ok(())
}
