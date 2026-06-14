use anyhow::{Context, Result};
use corcept_contract::validate_value;
use corcept_doctrine::{default_documents, validate as validate_doctrine};
use corcept_guards::{
    evaluate_pre_tool, evaluate_stop, extract_command, extract_path, StopVerdict,
};
use corcept_ledger::{
    ensure_ledger, read_events, verify_hash_chain_readonly, verify_ledger, VerifyFailureReason,
};
use corcept_memory::ensure_dirs as ensure_memory_dirs;
use corcept_sink::{build_ledger_event, SinkDispatcher, SinkRecord};
use corcept_types::{
    dir_permissions_secure, operator_data_dir, project_ledger_dir, transition_for, AuthorityLevel,
    CorceptConfig, HookEnvelope, HookOutput, LedgerEventKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitOptions {
    pub path: PathBuf,
    pub dry_run: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitReport {
    pub path: PathBuf,
    pub dry_run: bool,
    pub created: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub skipped: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorOptions {
    #[serde(default)]
    pub validate_perms: bool,
    #[serde(default)]
    pub strict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub status: String,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub status: String,
    pub event_count: usize,
    pub hash_chain_valid: bool,
    pub last_event: Option<String>,
    pub warnings: Vec<String>,
}

pub fn init_project(options: InitOptions) -> Result<InitReport> {
    let root = options.path;
    let mut report = InitReport {
        path: root.clone(),
        dry_run: options.dry_run,
        created: vec![],
        modified: vec![],
        skipped: vec![],
        warnings: vec![],
    };

    plan_dir(&root.join(".claude"), &mut report, options.dry_run)?;
    plan_dir(
        &root.join(".corcept").join("doctrine"),
        &mut report,
        options.dry_run,
    )?;
    plan_dir(
        &root.join(".corcept").join("memory").join("accepted"),
        &mut report,
        options.dry_run,
    )?;
    plan_dir(
        &root.join(".corcept").join("memory").join("candidates"),
        &mut report,
        options.dry_run,
    )?;
    plan_dir(
        &root.join(".corcept").join("memory").join("rejected"),
        &mut report,
        options.dry_run,
    )?;
    plan_dir(
        &root.join(".corcept").join("ledger"),
        &mut report,
        options.dry_run,
    )?;
    plan_dir(
        &root.join(".corcept").join("reports"),
        &mut report,
        options.dry_run,
    )?;

    write_file(
        &root.join(".corcept").join("config.yaml"),
        &serde_yaml::to_string(&CorceptConfig::default())?,
        options.force,
        options.dry_run,
        &mut report,
    )?;
    write_file(
        &root.join(".claude").join("CLAUDE.md"),
        render_claude_md(),
        options.force,
        options.dry_run,
        &mut report,
    )?;
    write_file(
        &root.join(".claude").join("settings.json"),
        &render_project_settings()?,
        options.force,
        options.dry_run,
        &mut report,
    )?;

    for (name, content) in default_documents() {
        write_file(
            &root.join(".corcept").join("doctrine").join(name),
            content,
            options.force,
            options.dry_run,
            &mut report,
        )?;
    }

    write_file(
        &root
            .join(".corcept")
            .join("memory")
            .join("accepted")
            .join("README.md"),
        "# Accepted Memory\n\nApproved project memory lives here.\n",
        options.force,
        options.dry_run,
        &mut report,
    )?;
    write_file(
        &root
            .join(".corcept")
            .join("memory")
            .join("candidates")
            .join("README.md"),
        "# Candidate Memory\n\nEvidence-backed proposed memories live here until promoted.\n",
        options.force,
        options.dry_run,
        &mut report,
    )?;
    write_file(
        &root
            .join(".corcept")
            .join("memory")
            .join("rejected")
            .join("README.md"),
        "# Rejected Memory\n\nRejected or superseded memory candidates live here.\n",
        options.force,
        options.dry_run,
        &mut report,
    )?;

    if !options.dry_run {
        ensure_ledger(&root)?;
        ensure_memory_dirs(&root)?;
    } else {
        report
            .created
            .push(root.join(".corcept").join("ledger").join("events.jsonl"));
    }

    Ok(report)
}

fn plan_dir(path: &Path, report: &mut InitReport, dry_run: bool) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    report.created.push(path.to_path_buf());
    if !dry_run {
        fs::create_dir_all(path)
            .with_context(|| format!("creating directory {}", path.display()))?;
    }
    Ok(())
}

fn write_file(
    path: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
    report: &mut InitReport,
) -> Result<()> {
    if path.exists() && !force {
        report.skipped.push(path.to_path_buf());
        return Ok(());
    }
    if path.exists() {
        report.modified.push(path.to_path_buf());
    } else {
        report.created.push(path.to_path_buf());
    }
    if !dry_run {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

pub fn load_config(root: impl AsRef<Path>) -> Result<CorceptConfig> {
    let path = root.as_ref().join(".corcept").join("config.yaml");
    if !path.exists() {
        return Ok(CorceptConfig::default());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("reading config {}", path.display()))?;
    Ok(serde_yaml::from_str(&raw)?)
}

pub fn doctor(path: impl AsRef<Path>) -> Result<DoctorReport> {
    doctor_with_options(path, DoctorOptions::default())
}

pub fn doctor_with_options(path: impl AsRef<Path>, options: DoctorOptions) -> Result<DoctorReport> {
    let root = path.as_ref();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "config",
        root.join(".corcept/config.yaml").exists(),
        "Project config exists",
    );
    push_check(
        &mut checks,
        "claude_md",
        root.join(".claude/CLAUDE.md").exists(),
        "Claude project instructions exist",
    );
    push_check(
        &mut checks,
        "ledger",
        root.join(".corcept/ledger/events.jsonl").exists(),
        "Ledger exists",
    );
    push_check(
        &mut checks,
        "memory",
        root.join(".corcept/memory").exists(),
        "Memory directory exists",
    );

    let doctrine_warnings = validate_doctrine(root)
        .unwrap_or_else(|err| vec![format!("Doctrine validation failed: {err}")]);
    push_check(
        &mut checks,
        "doctrine",
        doctrine_warnings.is_empty(),
        if doctrine_warnings.is_empty() {
            "Doctrine validates"
        } else {
            "Doctrine warnings present"
        },
    );

    let hash_valid = verify_hash_chain_readonly(root).unwrap_or(false);
    push_check(
        &mut checks,
        "ledger_hash_chain",
        hash_valid,
        "Ledger hash chain verifies",
    );

    if options.strict {
        let schema_ok = validate_ledger_schema(root);
        push_check(
            &mut checks,
            "ledger_schema",
            schema_ok,
            "Ledger events validate against corcept.ledger_event.v1 schema",
        );

        let (signed_ok, signed_detail) = ledger_signing_check(root);
        push_check(&mut checks, "ledger_signed", signed_ok, &signed_detail);
    }

    if options.validate_perms {
        let ledger_dir = project_ledger_dir(root);
        let ledger_perms = dir_permissions_secure(&ledger_dir);
        push_check(
            &mut checks,
            "ledger_dir_perms",
            ledger_perms,
            "Project ledger directory is owner-only (0700) or absent",
        );
        if let Some(op_data) = operator_data_dir() {
            if op_data.exists() {
                let op_perms = dir_permissions_secure(&op_data);
                push_check(
                    &mut checks,
                    "operator_data_dir_perms",
                    op_perms,
                    "Operator data directory is owner-only (0700)",
                );
            }
        }
    }

    let all_pass = checks.iter().all(|check| check.status == "pass");
    let status = if all_pass {
        "pass"
    } else if options.strict {
        "fail"
    } else {
        "warn"
    }
    .to_string();
    Ok(DoctorReport { status, checks })
}

fn validate_ledger_schema(root: &Path) -> bool {
    let Ok(events) = read_events(root) else {
        return false;
    };
    for event in events {
        let Ok(value) = serde_json::to_value(&event) else {
            return false;
        };
        if validate_value("corcept-ledger-event-v1.schema.json", &value).is_err() {
            return false;
        }
    }
    true
}

/// Strict-mode tamper-evidence check: every audit-bearing ledger row must carry
/// a valid Ed25519 signature that verifies against the operator trust store.
///
/// An unsigned hash-chain alone is NOT tamper-evident against an adversary who can
/// rewrite `events.jsonl` and recompute the chain (the hash chain links rows to each
/// other, but nothing binds them to a key the attacker does not hold). `corcept doctor
/// --strict` therefore HARD-FAILS on an unsigned audit-bearing ledger rather than
/// silently passing. An empty ledger (nothing to protect yet) passes.
///
/// Returns `(passed, human-readable detail)`.
fn ledger_signing_check(root: &Path) -> (bool, String) {
    let report = match verify_ledger(root, true) {
        Ok(report) => report,
        Err(err) => {
            return (
                false,
                format!("Ledger signature verification could not run: {err}"),
            );
        }
    };

    if report.rows_scanned == 0 {
        return (
            true,
            "Ledger is empty; no audit rows require signatures".to_string(),
        );
    }

    if report.is_pass() {
        return (
            true,
            format!(
                "All {} audit rows carry a valid Ed25519 signature (tamper-evident)",
                report.rows_scanned
            ),
        );
    }

    // Surface the dominant failure class so the operator knows whether the ledger is
    // unsigned (the default-posture gap) or signed-but-broken (key/tamper problem).
    let unsigned_rows = report
        .failures
        .iter()
        .filter(|f| matches!(f.reason, VerifyFailureReason::MissingSignature))
        .count();
    let detail = if unsigned_rows > 0 {
        format!(
            "{unsigned_rows} of {} audit rows are UNSIGNED — an unsigned hash chain is not \
             tamper-evident; generate a key (`corcept key generate`) and enable signed history \
             (CORCEPT_TRUSTED_HISTORY=1)",
            report.rows_scanned
        )
    } else {
        format!(
            "{} of {} audit rows failed signature verification (key/tamper)",
            report.failures.len(),
            report.rows_scanned
        )
    };
    (false, detail)
}

fn push_check(checks: &mut Vec<CheckResult>, name: &str, pass: bool, detail: &str) {
    checks.push(CheckResult {
        name: name.to_string(),
        status: if pass { "pass" } else { "warn" }.to_string(),
        detail: detail.to_string(),
    });
}

pub fn audit(path: impl AsRef<Path>) -> Result<AuditReport> {
    let events = read_events(&path).unwrap_or_default();
    let hash_chain_valid = verify_hash_chain_readonly(&path).unwrap_or(false);
    let mut warnings = Vec::new();
    if !hash_chain_valid {
        warnings.push("Ledger hash chain is invalid or ledger is missing.".to_string());
    }
    let last_event = events.last().map(|event| event.event_type.clone());
    Ok(AuditReport {
        status: if warnings.is_empty() { "pass" } else { "warn" }.to_string(),
        event_count: events.len(),
        hash_chain_valid,
        last_event,
        warnings,
    })
}

pub fn handle_hook(raw_json: &str, command: &str) -> Result<HookOutput> {
    let input: HookEnvelope = serde_json::from_str(raw_json).context("parsing hook input JSON")?;
    let cwd = input.cwd.clone().unwrap_or(std::env::current_dir()?);
    let config = load_config(&cwd).unwrap_or_default();

    match command {
        "session-start" => {
            append_hook_event(
                &cwd,
                &input,
                "session-start",
                LedgerEventKind::SessionStarted,
                AuthorityLevel::L0Observe,
                None,
                Some("allow"),
                Some("Session started"),
            )?;
            Ok(HookOutput::context("SessionStart", "CORCEPT active: doctrine, memory, guard, and audit policy loaded. Use CORCEPT skills for structured workflows."))
        }
        "user-prompt-submit" => {
            let prompt = input.prompt.clone().unwrap_or_default();
            append_hook_event(
                &cwd,
                &input,
                "user-prompt-submit",
                LedgerEventKind::PromptSubmitted,
                AuthorityLevel::L0Observe,
                None,
                Some("allow"),
                Some("Prompt received"),
            )?;
            let context = classify_prompt_context(&prompt);
            Ok(HookOutput::context("UserPromptSubmit", context))
        }
        "pretool-guard" => {
            let verdict = evaluate_pre_tool(&input, &config);
            let target = extract_path(input.tool_input.as_ref())
                .or_else(|| extract_command(input.tool_input.as_ref()));
            append_hook_event(
                &cwd,
                &input,
                "pretool-guard",
                LedgerEventKind::ToolRequested,
                verdict.authority_level,
                target,
                Some(&verdict.decision.to_string()),
                Some(&verdict.reason),
            )?;
            Ok(verdict.to_hook_output())
        }
        "posttool-audit" => {
            let event_kind = classify_posttool_event(&input);
            let decision = classify_posttool_decision(&input);
            let target = extract_path(input.tool_input.as_ref())
                .or_else(|| extract_command(input.tool_input.as_ref()));
            append_hook_event(
                &cwd,
                &input,
                "posttool-audit",
                event_kind,
                AuthorityLevel::L3ExecuteLocal,
                target,
                Some(&decision),
                Some("PostToolUse audited"),
            )?;
            Ok(HookOutput::context(
                "PostToolUse",
                "CORCEPT audited the completed tool call.",
            ))
        }
        "stop-check" => match evaluate_stop(&cwd, input.stop_hook_active.unwrap_or(false)) {
            StopVerdict::Allow(reason) => {
                append_hook_event(
                    &cwd,
                    &input,
                    "stop-check",
                    LedgerEventKind::StopAllowed,
                    AuthorityLevel::L0Observe,
                    None,
                    Some("allow"),
                    Some(&reason),
                )?;
                Ok(HookOutput::default())
            }
            StopVerdict::Block(reason) => {
                append_hook_event(
                    &cwd,
                    &input,
                    "stop-check",
                    LedgerEventKind::StopBlocked,
                    AuthorityLevel::L0Observe,
                    None,
                    Some("block"),
                    Some(&reason),
                )?;
                Ok(HookOutput::block(reason))
            }
        },
        other => Ok(HookOutput::block(format!(
            "Unknown CORCEPT hook command: {other}"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_hook_event(
    root: &Path,
    input: &HookEnvelope,
    command: &str,
    kind: LedgerEventKind,
    authority_level: AuthorityLevel,
    target: Option<String>,
    decision: Option<&str>,
    reason: Option<&str>,
) -> Result<()> {
    let transition = transition_for(command, kind, decision);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "transition_id".to_string(),
        serde_json::Value::String(transition.id().to_string()),
    );
    if let Some(tool_input) = &input.tool_input {
        metadata.insert("tool_input".to_string(), sanitize_value(tool_input));
    }
    let event = build_ledger_event(
        input.session_id.clone(),
        input
            .agent_type
            .clone()
            .unwrap_or_else(|| "corcept-runtime".to_string()),
        kind,
        authority_level,
        input.tool_name.clone(),
        target,
        decision.map(ToOwned::to_owned),
        reason.map(ToOwned::to_owned),
        metadata,
    );
    let correlation = input
        .session_id
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let outcome = decision.unwrap_or("recorded");
    let record = SinkRecord::new(correlation, kind, outcome);
    let dispatcher = SinkDispatcher::hook_default(root);
    dispatcher.emit_all(&record, Some(&event))?;
    Ok(())
}

fn sanitize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sanitized = map
                .iter()
                .map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("token")
                        || lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("key")
                    {
                        (key.clone(), Value::String("[REDACTED]".to_string()))
                    } else {
                        (key.clone(), sanitize_value(value))
                    }
                })
                .collect();
            Value::Object(sanitized)
        }
        Value::Array(values) => Value::Array(values.iter().map(sanitize_value).collect()),
        other => other.clone(),
    }
}

fn classify_prompt_context(prompt: &str) -> String {
    let lower = prompt.to_ascii_lowercase();
    if [
        "deploy",
        "prod",
        "production",
        "secret",
        "token",
        "auth",
        "billing",
        "migration",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        "CORCEPT: This prompt appears security- or side-effect-sensitive. Apply doctrine, require concrete evidence, and treat production/external actions as L4.".to_string()
    } else {
        "CORCEPT: Use bounded diffs, explicit assumptions, and evidence-backed completion."
            .to_string()
    }
}

fn classify_posttool_event(input: &HookEnvelope) -> LedgerEventKind {
    match input.tool_name.as_deref().unwrap_or_default() {
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => LedgerEventKind::FileModified,
        "Bash" => {
            let command = extract_command(input.tool_input.as_ref()).unwrap_or_default();
            if is_test_command(&command) {
                LedgerEventKind::TestRun
            } else {
                LedgerEventKind::CommandExecuted
            }
        }
        _ => LedgerEventKind::ToolCompleted,
    }
}

fn is_test_command(command: &str) -> bool {
    let normalized = command
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let test_prefixes = [
        "cargo test",
        "cargo nextest",
        "npm test",
        "npm run test",
        "pnpm test",
        "pnpm run test",
        "yarn test",
        "bun test",
        "pytest",
        "python -m pytest",
        "python3 -m pytest",
        "go test",
        "mvn test",
        "gradle test",
        "./gradlew test",
    ];
    test_prefixes
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix} ")))
}

fn classify_posttool_decision(input: &HookEnvelope) -> String {
    let exit_code = input
        .tool_response
        .as_ref()
        .and_then(|value| value.get("exit_code"))
        .and_then(|value| value.as_i64());
    match exit_code {
        Some(0) => "pass".to_string(),
        Some(_) => "fail".to_string(),
        None => "recorded".to_string(),
    }
}

fn render_project_settings() -> Result<String> {
    let value = json!({
        "hooks": {
            "SessionStart": [{ "matcher": "", "hooks": [{ "type": "command", "command": "corcept hook session-start" }] }],
            "UserPromptSubmit": [{ "matcher": "", "hooks": [{ "type": "command", "command": "corcept hook user-prompt-submit" }] }],
            "PreToolUse": [{ "matcher": "Bash|Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch", "hooks": [{ "type": "command", "command": "corcept hook pretool-guard" }] }],
            "PostToolUse": [{ "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit", "hooks": [{ "type": "command", "command": "corcept hook posttool-audit" }] }],
            "Stop": [{ "matcher": "", "hooks": [{ "type": "command", "command": "corcept hook stop-check" }] }]
        }
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

fn render_claude_md() -> &'static str {
    r#"# CORCEPT Project Instructions

You are operating inside an CORCEPT-governed project.

## Authority

Follow this precedence:

1. Direct user instruction for the current task.
2. Active CORCEPT doctrine.
3. Accepted CORCEPT memory.
4. This file.
5. Skill or agent-local instructions.

Do not promote memory or doctrine without explicit approval.

## Operating rules

- State assumptions before acting when scope is unclear.
- Prefer bounded diffs.
- Do not edit files outside approved task scope.
- Do not claim tests passed unless you ran them or the user provided evidence.
- Treat secrets as unreadable; identify their presence only.
- Use CORCEPT skills for structured workflows.

## Required evidence

For completed coding work, report files changed, tests run, test result, known untested risks, and unresolved issues.
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::LedgerEventKind;
    use serde_json::{json, Value};
    use std::fs;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    fn load_fixture(name: &str, cwd: &Path) -> String {
        let raw = fs::read_to_string(repo_root().join("tests/fixtures/hooks").join(name))
            .unwrap_or_else(|_| panic!("fixture {name}"));
        let mut value: Value = serde_json::from_str(&raw).expect("fixture json");
        value["cwd"] = Value::String(cwd.to_string_lossy().into_owned());
        serde_json::to_string(&value).expect("fixture json string")
    }

    fn init_temp_project() -> tempfile::TempDir {
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
    fn dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("project");
        let report = init_project(InitOptions {
            path: target.clone(),
            dry_run: true,
            force: false,
        })
        .unwrap();
        assert!(report.created.iter().any(|p| p.ends_with("config.yaml")));
        assert!(!target.exists());
    }

    #[test]
    fn hook_denies_dangerous_command() {
        let dir = tempfile::tempdir().unwrap();
        init_project(InitOptions {
            path: dir.path().to_path_buf(),
            dry_run: false,
            force: false,
        })
        .unwrap();
        let input = json!({
            "session_id":"s",
            "transcript_path":"/tmp/t.jsonl",
            "cwd": dir.path(),
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"rm -rf /"},
            "tool_use_id":"t"
        });
        let out = handle_hook(&input.to_string(), "pretool-guard").unwrap();
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("deny"));
    }

    #[test]
    fn hook_fixture_pretool_denies_rm_rf() {
        run_hook_fixture("pretool-bash-rm-rf.json", "pretool-guard", |out| {
            assert!(out.contains("deny"));
        });
    }

    #[test]
    fn hook_fixture_pretool_denies_env_read() {
        run_hook_fixture("pretool-read-env.json", "pretool-guard", |out| {
            assert!(out.contains("deny"));
        });
    }

    #[test]
    fn hook_fixture_pretool_asks_npm_install() {
        run_hook_fixture("pretool-bash-npm-install.json", "pretool-guard", |out| {
            assert!(out.contains("ask"));
        });
    }

    #[test]
    fn hook_fixture_pretool_allows_safe_echo() {
        run_hook_fixture("pretool-bash-safe.json", "pretool-guard", |out| {
            assert!(!out.contains("deny") && !out.contains("ask"));
        });
    }

    #[test]
    fn hook_fixture_posttool_records_event() {
        run_hook_fixture("posttool-npm-test.json", "posttool-audit", |_| {});
    }

    #[test]
    fn hook_fixture_session_start_writes_versioned_event() {
        let dir = init_temp_project();
        let raw = load_fixture("session-start.json", dir.path());
        handle_hook(&raw, "session-start").unwrap();
        let events = read_events(dir.path()).unwrap();
        assert!(events.iter().any(|e| {
            LedgerEventKind::SessionStarted.matches_str(&e.event_type)
                && e.metadata.get("transition_id").and_then(|v| v.as_str())
                    == Some("T010_session_start")
        }));
    }

    #[test]
    fn hook_fixture_stop_check_allows_clean_project() {
        run_hook_fixture("stop-check.json", "stop-check", |out| {
            assert!(!out.contains("block"));
        });
    }

    fn run_hook_fixture(name: &str, command: &str, assert_out: impl FnOnce(&str)) {
        let dir = init_temp_project();
        let raw = load_fixture(name, dir.path());
        let out = handle_hook(&raw, command).unwrap();
        let json = serde_json::to_string(&out).unwrap();
        assert_out(&json);
        assert!(!read_events(dir.path()).unwrap().is_empty());
    }
}
