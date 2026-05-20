/// corcept-mcp multi-client coverage tests.
///
/// Six verifiable requirements from the task spec:
/// 1. cargo check --workspace passes (checked by build system).
/// 2. Each of the 20 generated tools has a typed AuthorityClass + TrustCeiling (no Custom(String)).
/// 3. Tools with {Mutate, Destroy, Credential} authority have approval gate != "never".
/// 4. Generated server uses mcpact_runtime::SafeCommand (no std::process::Command::new outside tests).
/// 5. Host registration files exist for Claude + Cursor + Codex + axiom (4 files).
/// 6. Registry lists all 20 tools (10 v1 + 10 ADR-0006 v2) via their MCP definitions.

#[cfg(test)]
mod mcp_multi_client_tests {
    use mcpact_core::{ApprovalMode, AuthorityClass};
    use mcpact_manifest::ToolSpec;
    use mcpact_mcp::{McpTool, ToolDefinition};

    fn all_tools() -> Vec<Box<dyn McpTool>> {
        vec![
            // v1 (10).
            Box::new(crate::tools::corcept_audit_verify::Tool::new()),
            Box::new(crate::tools::corcept_doctor::Tool::new()),
            Box::new(crate::tools::corcept_export_cloudevents::Tool::new()),
            Box::new(crate::tools::corcept_hook_posttool_audit::Tool::new()),
            Box::new(crate::tools::corcept_hook_pretool_guard::Tool::new()),
            Box::new(crate::tools::corcept_hook_session_start::Tool::new()),
            Box::new(crate::tools::corcept_hook_stop_check::Tool::new()),
            Box::new(crate::tools::corcept_hook_user_prompt_submit::Tool::new()),
            Box::new(crate::tools::corcept_key_generate::Tool::new()),
            Box::new(crate::tools::corcept_memory_promote::Tool::new()),
            // ADR-0006 13-hook canonical surface (v2) — 10 new tools.
            Box::new(crate::tools::corcept_hook_before_run::Tool::new()),
            Box::new(crate::tools::corcept_hook_after_run::Tool::new()),
            Box::new(crate::tools::corcept_hook_before_subprocess_spawn::Tool::new()),
            Box::new(crate::tools::corcept_hook_after_subprocess_exit::Tool::new()),
            Box::new(crate::tools::corcept_hook_before_file_write::Tool::new()),
            Box::new(crate::tools::corcept_hook_after_file_write::Tool::new()),
            Box::new(crate::tools::corcept_hook_before_network_access::Tool::new()),
            Box::new(crate::tools::corcept_hook_before_final_answer::Tool::new()),
            Box::new(crate::tools::corcept_hook_on_claim_emitted::Tool::new()),
            Box::new(crate::tools::corcept_hook_on_error::Tool::new()),
        ]
    }

    #[test]
    fn test_2_all_tools_have_typed_authority_class() {
        let tools = all_tools();
        assert_eq!(tools.len(), 20, "expected 20 MCP tools (10 v1 + 10 ADR-0006 v2)");

        for tool in &tools {
            let def: ToolDefinition = tool.definition();
            let annotations = def.annotations
                .as_ref()
                .expect("every tool must have mcpact annotations");
            let authority_str = annotations
                .get("mcpact")
                .and_then(|m| m.get("authority"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("tool '{}' missing authority annotation", def.name));

            let authority: AuthorityClass = serde_json::from_value(
                serde_json::Value::String(authority_str.to_string())
            ).unwrap_or_else(|_| panic!(
                "tool '{}' authority '{}' is not a valid AuthorityClass variant (Custom(String) is forbidden)",
                def.name, authority_str
            ));

            let trust = annotations
                .get("mcpact")
                .and_then(|m| m.get("trustCeiling"));
            assert!(trust.is_some(), "tool '{}' missing trustCeiling annotation", def.name);

            let _ = authority;
        }
    }

    fn load_tool_spec(json_bytes: &str) -> ToolSpec {
        serde_json::from_str(json_bytes).expect("tool spec JSON must deserialize")
    }

    #[test]
    fn test_3_high_authority_tools_require_approval() {
        let specs = vec![
            ("corcept_hook_posttool_audit", include_str!("../.mcpact/tools/corcept_hook_posttool_audit.json")),
            ("corcept_key_generate", include_str!("../.mcpact/tools/corcept_key_generate.json")),
            ("corcept_memory_promote", include_str!("../.mcpact/tools/corcept_memory_promote.json")),
        ];

        for (name, json) in &specs {
            let spec = load_tool_spec(json);
            if matches!(spec.policy.authority, AuthorityClass::Mutate | AuthorityClass::Destroy | AuthorityClass::Credential) {
                assert_ne!(
                    spec.policy.approval,
                    ApprovalMode::Never,
                    "tool '{}' has authority {:?} but approval=Never — forbidden",
                    name, spec.policy.authority
                );
            }
        }
    }

    #[test]
    fn test_3_all_specs_high_authority_require_approval() {
        let all_specs: Vec<(&str, &str)> = vec![
            ("corcept_audit_verify",                include_str!("../.mcpact/tools/corcept_audit_verify.json")),
            ("corcept_doctor",                      include_str!("../.mcpact/tools/corcept_doctor.json")),
            ("corcept_export_cloudevents",          include_str!("../.mcpact/tools/corcept_export_cloudevents.json")),
            ("corcept_hook_posttool_audit",         include_str!("../.mcpact/tools/corcept_hook_posttool_audit.json")),
            ("corcept_hook_pretool_guard",          include_str!("../.mcpact/tools/corcept_hook_pretool_guard.json")),
            ("corcept_hook_session_start",          include_str!("../.mcpact/tools/corcept_hook_session_start.json")),
            ("corcept_hook_stop_check",             include_str!("../.mcpact/tools/corcept_hook_stop_check.json")),
            ("corcept_hook_user_prompt_submit",     include_str!("../.mcpact/tools/corcept_hook_user_prompt_submit.json")),
            ("corcept_key_generate",                include_str!("../.mcpact/tools/corcept_key_generate.json")),
            ("corcept_memory_promote",              include_str!("../.mcpact/tools/corcept_memory_promote.json")),
            ("corcept_hook_before_run",             include_str!("../.mcpact/tools/corcept_hook_before_run.json")),
            ("corcept_hook_after_run",              include_str!("../.mcpact/tools/corcept_hook_after_run.json")),
            ("corcept_hook_before_subprocess_spawn",include_str!("../.mcpact/tools/corcept_hook_before_subprocess_spawn.json")),
            ("corcept_hook_after_subprocess_exit",  include_str!("../.mcpact/tools/corcept_hook_after_subprocess_exit.json")),
            ("corcept_hook_before_file_write",      include_str!("../.mcpact/tools/corcept_hook_before_file_write.json")),
            ("corcept_hook_after_file_write",       include_str!("../.mcpact/tools/corcept_hook_after_file_write.json")),
            ("corcept_hook_before_network_access",  include_str!("../.mcpact/tools/corcept_hook_before_network_access.json")),
            ("corcept_hook_before_final_answer",    include_str!("../.mcpact/tools/corcept_hook_before_final_answer.json")),
            ("corcept_hook_on_claim_emitted",       include_str!("../.mcpact/tools/corcept_hook_on_claim_emitted.json")),
            ("corcept_hook_on_error",               include_str!("../.mcpact/tools/corcept_hook_on_error.json")),
        ];

        for (name, json) in &all_specs {
            let spec = load_tool_spec(json);
            if matches!(spec.policy.authority, AuthorityClass::Mutate | AuthorityClass::Destroy | AuthorityClass::Credential) {
                assert_ne!(
                    spec.policy.approval,
                    ApprovalMode::Never,
                    "FAIL test 3: '{}' (authority={:?}) must not have approval=Never",
                    name, spec.policy.authority
                );
            }
        }
    }

    #[test]
    fn test_4_no_direct_command_new_in_tool_sources() {
        let tool_sources = vec![
            include_str!("tools/corcept_audit_verify.rs"),
            include_str!("tools/corcept_doctor.rs"),
            include_str!("tools/corcept_export_cloudevents.rs"),
            include_str!("tools/corcept_hook_posttool_audit.rs"),
            include_str!("tools/corcept_hook_pretool_guard.rs"),
            include_str!("tools/corcept_hook_session_start.rs"),
            include_str!("tools/corcept_hook_stop_check.rs"),
            include_str!("tools/corcept_hook_user_prompt_submit.rs"),
            include_str!("tools/corcept_key_generate.rs"),
            include_str!("tools/corcept_memory_promote.rs"),
            include_str!("tools/corcept_hook_before_run.rs"),
            include_str!("tools/corcept_hook_after_run.rs"),
            include_str!("tools/corcept_hook_before_subprocess_spawn.rs"),
            include_str!("tools/corcept_hook_after_subprocess_exit.rs"),
            include_str!("tools/corcept_hook_before_file_write.rs"),
            include_str!("tools/corcept_hook_after_file_write.rs"),
            include_str!("tools/corcept_hook_before_network_access.rs"),
            include_str!("tools/corcept_hook_before_final_answer.rs"),
            include_str!("tools/corcept_hook_on_claim_emitted.rs"),
            include_str!("tools/corcept_hook_on_error.rs"),
        ];

        for src in &tool_sources {
            assert!(
                !src.contains("std::process::Command::new"),
                "tool source contains direct std::process::Command::new — must use SafeCommand/Executor"
            );
        }

        let main_src = include_str!("main.rs");
        assert!(
            !main_src.contains("std::process::Command::new"),
            "main.rs contains direct std::process::Command::new — must use SafeCommand"
        );
    }

    #[test]
    fn test_5_host_registration_files_exist() {
        let claude  = include_str!("../.mcpact/hosts/claude.json");
        let cursor  = include_str!("../.mcpact/hosts/cursor.json");
        let codex   = include_str!("../.mcpact/hosts/codex.toml");
        let axiom   = include_str!("../.mcpact/hosts/axiom.json");

        assert!(!claude.is_empty(), "claude.json must not be empty");
        assert!(!cursor.is_empty(), "cursor.json must not be empty");
        assert!(!codex.is_empty(),  "codex.toml must not be empty");
        assert!(!axiom.is_empty(),  "axiom.json must not be empty");

        let _: serde_json::Value = serde_json::from_str(claude)
            .expect("claude.json must be valid JSON");
        let _: serde_json::Value = serde_json::from_str(cursor)
            .expect("cursor.json must be valid JSON");
        let _: serde_json::Value = serde_json::from_str(axiom)
            .expect("axiom.json must be valid JSON");

        assert!(codex.contains("[mcp_servers.corcept-mcp]"), "codex.toml must contain mcp_servers.corcept-mcp section");
    }

    #[test]
    fn test_6_registry_lists_all_tools() {
        let tools = all_tools();
        let names: Vec<String> = tools.iter().map(|t| t.definition().name.clone()).collect();

        let required = vec![
            "corcept_hook_session_start",
            "corcept_hook_user_prompt_submit",
            "corcept_hook_pretool_guard",
            "corcept_hook_posttool_audit",
            "corcept_hook_stop_check",
            "corcept_audit_verify",
            "corcept_export_cloudevents",
            "corcept_key_generate",
            "corcept_memory_promote",
            "corcept_doctor",
            // ADR-0006 v2.
            "corcept_hook_before_run",
            "corcept_hook_after_run",
            "corcept_hook_before_subprocess_spawn",
            "corcept_hook_after_subprocess_exit",
            "corcept_hook_before_file_write",
            "corcept_hook_after_file_write",
            "corcept_hook_before_network_access",
            "corcept_hook_before_final_answer",
            "corcept_hook_on_claim_emitted",
            "corcept_hook_on_error",
        ];

        for name in &required {
            assert!(
                names.contains(&name.to_string()),
                "tool '{}' missing from registry; found: {:?}",
                name, names
            );
        }

        assert_eq!(
            names.len(),
            20,
            "expected 20 tools in registry; found {}: {:?}",
            names.len(),
            names
        );
    }

    #[test]
    fn test_2b_args_structs_deny_unknown_fields() {
        use crate::tools::{
            corcept_audit_verify::CorceptAuditVerifyArgs,
            corcept_doctor::CorceptDoctorArgs,
            corcept_key_generate::CorceptKeyGenerateArgs,
            corcept_memory_promote::CorceptMemoryPromoteArgs,
        };

        let with_unknown = r#"{"unknown_canary": true}"#;

        let r: Result<CorceptAuditVerifyArgs, _> = serde_json::from_str(with_unknown);
        assert!(r.is_err(), "CorceptAuditVerifyArgs should reject unknown fields");

        let r: Result<CorceptDoctorArgs, _> = serde_json::from_str(with_unknown);
        assert!(r.is_err(), "CorceptDoctorArgs should reject unknown fields");

        let r: Result<CorceptKeyGenerateArgs, _> = serde_json::from_str(with_unknown);
        assert!(r.is_err(), "CorceptKeyGenerateArgs should reject unknown fields");

        let r: Result<CorceptMemoryPromoteArgs, _> = serde_json::from_str(with_unknown);
        assert!(r.is_err(), "CorceptMemoryPromoteArgs should reject unknown fields");
    }
}
