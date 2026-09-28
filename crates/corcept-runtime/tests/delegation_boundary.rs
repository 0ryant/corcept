use corcept_guards::delegation::{authority_signing_bytes, invocation_digest};
use corcept_ledger::{generate_operator_key, read_events, verify_ledger};
use corcept_runtime::delegation::{handle_pretool, AuthoritySource};
use corcept_runtime::{handle_hook, init_project, InitOptions};
use corcept_types::delegation::AuthoritySnapshot;
use corcept_types::{CorceptConfig, HookEnvelope, HookOutput, PermissionDecision};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Environment(Vec<(&'static str, Option<OsString>)>);
impl Environment {
    fn set(name: &'static str, value: &Path) -> Self {
        let old = std::env::var_os(name);
        std::env::set_var(name, value);
        Self(vec![(name, old)])
    }
    fn clear(name: &'static str) -> Self {
        let old = std::env::var_os(name);
        std::env::remove_var(name);
        Self(vec![(name, old)])
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        for (name, old) in &self.0 {
            match old {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

struct Case {
    _directory: tempfile::TempDir,
    project: PathBuf,
    source: AuthoritySource,
    input: HookEnvelope,
    snapshot: Value,
    key: SigningKey,
}

impl Case {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let state = directory.path().join("operator-state");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&state).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let input: HookEnvelope = serde_json::from_value(json!({
            "cwd": project, "session_id":"session-1", "tool_use_id":"tool-use-1",
            "hook_event_name":"PreToolUse", "tool_name":"Read", "agent_id":"agent-1",
            "tool_input":{"file_path":"document.txt","credentials":"private-credential-value"},
            "delegation": {
                "schema":"corcept.delegation.v1", "correlation_id":"correlation-1",
                "caller_id":"caller-1", "agent_id":"agent-1", "user_id":"user-1",
                "organisation_id":"org-1", "target_service":"service-1",
                "capability":"document-read", "action":"read", "resource":"document-42",
                "grant_id":"grant-1", "approval_id":"approval-1"
            }
        }))
        .unwrap();
        let claim = json!({"state":"verified","provenance":{
            "issuer_id":"resolver-1","evidence_id":"evidence-1","version":1
        }});
        let scope = json!({"target_service":"service-1","capability":"document-read",
            "action":"read","resource":"document-42"});
        let digest = invocation_digest(&input).unwrap();
        let snapshot = json!({
            "schema":"corcept.authority-snapshot.v1", "id":"snapshot-1", "version":1,
            "valid_from":1700000000, "expires_at":4102444800_i64,
            "invocations":[{"id":"invocation-1","session_id":"session-1",
                "tool_use_id":"tool-use-1","tool_name":"Read","input_digest":digest,
                "delegation":input.extra["delegation"],"required_authority":"L0_observe","claim":claim}],
            "grants":[{"id":"grant-1","version":1,"caller_id":"caller-1","agent_id":"agent-1",
                "user_id":"user-1","organisation_id":"org-1","scope":scope,
                "capability_ref":{"id":"capability-rule-1","version":1},
                "service_policy_ref":{"id":"service-policy-1","version":1},
                "organisation_policy_ref":{"id":"org-policy-1","version":1},
                "valid_from":1700000000,"expires_at":4102444800_i64,
                "max_authority":"L3_execute_local","approval_required":true,"claim":claim}],
            "capabilities":[{"id":"capability-rule-1","version":1,"scope":scope,
                "max_authority":"L3_execute_local","claim":claim}],
            "service_policies":[{"id":"service-policy-1","version":1,"owner_id":"service-1",
                "scope":scope,"decision":"allow","claim":claim}],
            "organisation_policies":[{"id":"org-policy-1","version":1,"owner_id":"org-1",
                "scope":scope,"decision":"allow","claim":claim}],
            "approvals":[{"id":"approval-1","invocation_id":"invocation-1","grant_id":"grant-1",
                "snapshot_id":"snapshot-1","snapshot_version":1,"input_digest":digest,
                "valid_from":1700000000,"expires_at":4102444800_i64,"claim":claim}]
        });
        let key = SigningKey::from_bytes(&[42; 32]);
        let source = AuthoritySource {
            policy_file: directory.path().join("authority.json"),
            pinned_pubkey_hex: hex::encode(key.verifying_key().as_bytes()),
            state_dir: state,
        };
        let case = Self {
            _directory: directory,
            project,
            source,
            input,
            snapshot,
            key,
        };
        case.write_snapshot();
        case
    }

    fn write_snapshot(&self) {
        let typed: AuthoritySnapshot = serde_json::from_value(self.snapshot.clone()).unwrap();
        let signature = self.key.sign(&authority_signing_bytes(&typed).unwrap());
        fs::write(
            &self.source.policy_file,
            serde_json::to_vec(&json!({
                "snapshot":typed,"signature":hex::encode(signature.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn run(&self) -> anyhow::Result<HookOutput> {
        handle_pretool(
            &self.project,
            &self.input,
            &CorceptConfig::default(),
            Some(&self.source),
        )
    }

    fn retarget(&mut self, tool: &str, args: Value, authority: corcept_types::AuthorityLevel) {
        self.input.tool_name = Some(tool.into());
        self.input.tool_input = Some(args);
        let digest = invocation_digest(&self.input).unwrap();
        self.snapshot["invocations"][0]["tool_name"] = json!(tool);
        self.snapshot["invocations"][0]["input_digest"] = json!(digest);
        self.snapshot["invocations"][0]["required_authority"] = json!(authority);
        self.snapshot["grants"][0]["max_authority"] = json!("L4_external_side_effect");
        self.snapshot["capabilities"][0]["max_authority"] = json!("L4_external_side_effect");
        self.snapshot["approvals"][0]["input_digest"] = json!(digest);
        self.write_snapshot();
    }

    fn omit_approval(&mut self) {
        self.input
            .extra
            .get_mut("delegation")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("approval_id");
        self.snapshot["invocations"][0]["delegation"]
            .as_object_mut()
            .unwrap()
            .remove("approval_id");
        self.snapshot["grants"][0]["approval_required"] = json!(false);
        self.snapshot["approvals"] = json!([]);
        self.write_snapshot();
    }
}

fn decision(output: &HookOutput) -> PermissionDecision {
    output
        .hook_specific_output
        .as_ref()
        .unwrap()
        .permission_decision
        .unwrap()
}

#[test]
fn signed_decisions_are_bound_reconstructable_and_one_use() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let case = Case::new();
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Allow);
    let events = read_events(&case.project).unwrap();
    assert_eq!(
        events.len(),
        1,
        "the decision must exist before returned allow"
    );
    assert!(events[0].signature.is_some());
    let basis = &events[0].metadata["delegation"];
    assert_eq!(basis["final_decision"], "allow");
    assert_eq!(basis["replay_state"], "consumed");
    let archive = case
        .source
        .state_dir
        .join(basis["snapshot_file"].as_str().unwrap());
    assert_eq!(
        fs::read(archive).unwrap(),
        fs::read(&case.source.policy_file).unwrap()
    );
    assert!(verify_ledger(&case.project, true).unwrap().is_pass());
    let ledger = corcept_ledger::ledger_path(&case.project);
    assert!(!fs::read_to_string(&ledger)
        .unwrap()
        .contains("private-credential-value"));
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Deny);
    assert_eq!(read_events(&case.project).unwrap().len(), 2);

    // Reissuing the snapshot/version and invocation cannot resurrect approval.
    let mut updated = case.snapshot.clone();
    updated["version"] = json!(2);
    updated["invocations"][0]["id"] = json!("invocation-2");
    updated["invocations"][0]["tool_use_id"] = json!("tool-use-2");
    updated["approvals"][0]["snapshot_version"] = json!(2);
    updated["approvals"][0]["invocation_id"] = json!("invocation-2");
    let mut case = case;
    case.input.tool_use_id = Some("tool-use-2".into());
    case.snapshot = updated;
    case.write_snapshot();
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Deny);

    let mut rows: Vec<Value> = fs::read_to_string(&ledger)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    rows[0]["metadata"]["delegation"]["final_decision"] = json!("deny");
    fs::write(
        &ledger,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    assert!(!verify_ledger(&case.project, true).unwrap().is_pass());
    assert!(
        case.run().is_err(),
        "corrupt signed history cannot admit or manufacture a valid decision row"
    );
}

#[test]
fn pending_guard_approval_and_runtime_authority_limits_are_enforced() {
    use corcept_types::AuthorityLevel;
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let mut case = Case::new();
    case.retarget(
        "WebFetch",
        json!({"url":"https://example.test/document"}),
        AuthorityLevel::L4ExternalSideEffect,
    );
    assert_eq!(
        decision(&case.run().unwrap()),
        PermissionDecision::Deny,
        "default L3 ceiling is hard"
    );
    let mut config = CorceptConfig::default();
    config.authority.default_max_level = AuthorityLevel::L4ExternalSideEffect;
    config.guards.network.allow_webfetch = false;
    assert_eq!(
        decision(&handle_pretool(&case.project, &case.input, &config, Some(&case.source)).unwrap()),
        PermissionDecision::Allow,
        "verified exact approval may satisfy a pending guard request"
    );
    let events = read_events(&case.project).unwrap();
    assert_eq!(
        events[1].authority_level,
        AuthorityLevel::L4ExternalSideEffect
    );
    assert_eq!(
        events[1].metadata["delegation"]["base_guard_decision"],
        "ask"
    );

    let mut case = Case::new();
    case.retarget(
        "WebFetch",
        json!({"url":"https://example.test/document"}),
        AuthorityLevel::L4ExternalSideEffect,
    );
    case.omit_approval();
    config.guards.network.allow_webfetch = true;
    assert_eq!(
        decision(&handle_pretool(&case.project, &case.input, &config, Some(&case.source)).unwrap()),
        PermissionDecision::Deny,
        "L4 user-invocation policy requires signed approval"
    );
    config.authority.l4_requires_user_invocation = false;
    config.guards.network.allow_webfetch = false;
    assert_eq!(
        decision(&handle_pretool(&case.project, &case.input, &config, Some(&case.source)).unwrap()),
        PermissionDecision::Deny,
        "base Ask cannot hand off execution to a native UI click"
    );
    assert!(!case.source.state_dir.join("consumed").exists());
    let events = read_events(&case.project).unwrap();
    assert_ne!(
        events[0].metadata["delegation"]["guard_policy_digest"],
        events[1].metadata["delegation"]["guard_policy_digest"],
        "schema version alone is not policy identity"
    );

    let mut case = Case::new();
    case.retarget(
        "Bash",
        json!({"command":"git push origin main"}),
        AuthorityLevel::L3ExecuteLocal,
    );
    assert_eq!(
        decision(&handle_pretool(&case.project, &case.input, &config, Some(&case.source)).unwrap()),
        PermissionDecision::Deny,
        "base L4 requirement cannot be understated as signed L3"
    );
}

#[test]
fn configured_hook_lifecycle_is_signed_without_ambient_sign_flag() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    let _sign = Environment::clear("CORCEPT_SIGN_LEDGER");
    let _trusted = Environment::clear("CORCEPT_TRUSTED_HISTORY");
    generate_operator_key(false).unwrap();
    let case = Case::new();
    let _policy = Environment::set("CORCEPT_DELEGATION_POLICY", &case.source.policy_file);
    let _pin = Environment::set(
        "CORCEPT_DELEGATION_PUBKEY",
        Path::new(&case.source.pinned_pubkey_hex),
    );
    let _state = Environment::set("CORCEPT_DELEGATION_STATE_DIR", &case.source.state_dir);
    handle_hook(
        &json!({"cwd":case.project,"session_id":"session-1","hook_event_name":"SessionStart"})
            .to_string(),
        "session-start",
    )
    .unwrap();
    handle_hook(&json!({"cwd":case.project,"session_id":"session-1","hook_event_name":"UserPromptSubmit","prompt":"Read document."}).to_string(),"user-prompt-submit").unwrap();
    assert_eq!(
        decision(
            &handle_hook(
                &serde_json::to_string(&case.input).unwrap(),
                "pretool-guard"
            )
            .unwrap()
        ),
        PermissionDecision::Allow
    );
    let events = read_events(&case.project).unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|row| row.signature.is_some()));
    assert!(verify_ledger(&case.project, true).unwrap().is_pass());
}

#[test]
fn partial_operator_configuration_is_an_explicit_signed_denial() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let case = Case::new();
    let _policy = Environment::set("CORCEPT_DELEGATION_POLICY", &case.source.policy_file);
    let _pin = Environment::clear("CORCEPT_DELEGATION_PUBKEY");
    let _state = Environment::clear("CORCEPT_DELEGATION_STATE_DIR");
    let output = handle_hook(
        &serde_json::to_string(&case.input).unwrap(),
        "pretool-guard",
    )
    .unwrap();
    assert_eq!(decision(&output), PermissionDecision::Deny);
    let events = read_events(&case.project).unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].signature.is_some());
    assert_eq!(
        events[0].metadata["delegation"]["status"],
        "admission_unavailable"
    );
}

#[test]
fn independent_concurrent_calls_publish_a_fresh_snapshot_atomically() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let mut case = Case::new();
    let mut binding = case.snapshot["invocations"][0].clone();
    binding["id"] = json!("invocation-2");
    binding["tool_use_id"] = json!("tool-use-2");
    binding["delegation"]["approval_id"] = json!("approval-2");
    let mut approval = case.snapshot["approvals"][0].clone();
    approval["id"] = json!("approval-2");
    approval["invocation_id"] = json!("invocation-2");
    case.snapshot["invocations"]
        .as_array_mut()
        .unwrap()
        .push(binding);
    case.snapshot["approvals"]
        .as_array_mut()
        .unwrap()
        .push(approval);
    case.write_snapshot();
    let mut second = case.input.clone();
    second.tool_use_id = Some("tool-use-2".into());
    second.extra.get_mut("delegation").unwrap()["approval_id"] = json!("approval-2");
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            decision(&case.run().unwrap())
        });
        let second = scope.spawn(|| {
            barrier.wait();
            decision(
                &handle_pretool(
                    &case.project,
                    &second,
                    &CorceptConfig::default(),
                    Some(&case.source),
                )
                .unwrap(),
            )
        });
        assert_eq!(first.join().unwrap(), PermissionDecision::Allow);
        assert_eq!(second.join().unwrap(), PermissionDecision::Allow);
    });
    assert!(verify_ledger(&case.project, true).unwrap().is_pass());
}

#[test]
fn unsigned_history_and_modified_sidecar_cannot_admit() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    let _sign = Environment::clear("CORCEPT_SIGN_LEDGER");
    let _trusted = Environment::clear("CORCEPT_TRUSTED_HISTORY");
    generate_operator_key(false).unwrap();
    let case = Case::new();
    handle_hook(
        &json!({"cwd":case.project,"hook_event_name":"SessionStart"}).to_string(),
        "session-start",
    )
    .unwrap();
    assert!(
        case.run().is_err(),
        "an unsigned prior row must not be laundered into signed history"
    );
    let case = Case::new();
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Allow);
    fs::write(
        corcept_ledger::last_hash_path(&case.project),
        "blake3:incorrect-tip",
    )
    .unwrap();
    assert!(
        case.run().is_err(),
        "signed history and append tip must agree"
    );
}

#[test]
fn unmatched_identifiers_and_completion_arguments_do_not_leak_to_sinks() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let mut case = Case::new();
    let _policy = Environment::set("CORCEPT_DELEGATION_POLICY", &case.source.policy_file);
    let _pin = Environment::set(
        "CORCEPT_DELEGATION_PUBKEY",
        Path::new(&case.source.pinned_pubkey_hex),
    );
    let _state = Environment::set("CORCEPT_DELEGATION_STATE_DIR", &case.source.state_dir);
    let output = operator.path().join("derived");
    let _telemetry = Environment::set("CORCEPT_TELEMETRY", Path::new("1"));
    let _telemetry_dir = Environment::set("CORCEPT_TELEMETRY_DIR", &output);
    let _log = Environment::set("CORCEPT_LOG_DIR", &operator.path().join("debug.log"));
    let _receipts = Environment::set("CORCEPT_RECEIPTS", Path::new("1"));
    let _receipt_dir = Environment::set("CORCEPT_RECEIPTS_DIR", &operator.path().join("receipts"));
    case.input.session_id = Some("private-session-value".into());
    case.input.tool_use_id = Some("private-tool-use-value".into());
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Deny);
    case.input.hook_event_name = "PostToolUse".into();
    handle_hook(
        &serde_json::to_string(&case.input).unwrap(),
        "posttool-audit",
    )
    .unwrap();
    for path in [
        corcept_ledger::ledger_path(&case.project),
        output.join("events.jsonl"),
        operator.path().join("debug.log"),
        operator.path().join("receipts/dispatch.jsonl"),
    ] {
        let raw = fs::read_to_string(path).unwrap();
        for secret in [
            "private-session-value",
            "private-tool-use-value",
            "private-credential-value",
        ] {
            assert!(
                !raw.contains(secret),
                "secret appeared in persistent evidence"
            );
        }
    }
}

#[test]
fn simultaneous_approval_admissions_allow_exactly_once() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let case = Case::new();
    // Pre-create archive so the test targets the atomic consumption join.
    let raw = fs::read(&case.source.policy_file).unwrap();
    let snapshots = case.source.state_dir.join("snapshots");
    fs::create_dir(&snapshots).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&snapshots, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        snapshots.join(format!("{}.json", blake3::hash(&raw).to_hex())),
        raw,
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let case = &case;
                scope.spawn(move || {
                    barrier.wait();
                    decision(&case.run().unwrap())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|&&value| value == PermissionDecision::Allow)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|&&value| value == PermissionDecision::Deny)
            .count(),
        1
    );
    assert_eq!(read_events(&case.project).unwrap().len(), 2);
    assert!(verify_ledger(&case.project, true).unwrap().is_pass());
}

#[test]
fn denied_service_and_existing_guards_cannot_be_overridden() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    generate_operator_key(false).unwrap();
    let mut case = Case::new();
    case.snapshot["service_policies"][0]["decision"] = json!("deny");
    case.write_snapshot();
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Deny);
    assert!(!case.source.state_dir.join("consumed").exists());

    let mut case = Case::new();
    case.input.tool_input.as_mut().unwrap()["file_path"] = json!(".env");
    let digest = invocation_digest(&case.input).unwrap();
    case.snapshot["invocations"][0]["input_digest"] = json!(digest);
    case.snapshot["approvals"][0]["input_digest"] = json!(digest);
    case.write_snapshot();
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Deny);
    assert!(!case.source.state_dir.join("consumed").exists());
}

#[test]
fn unavailable_authority_signer_archive_and_audit_never_allow() {
    let _lock = ENV_LOCK.lock().unwrap();
    let operator = tempfile::tempdir().unwrap();
    let _env = Environment::set("CORCEPT_DATA_HOME", operator.path());
    let case = Case::new();
    assert!(
        case.run().is_err(),
        "missing signer cannot fall back to unsigned"
    );
    generate_operator_key(false).unwrap();
    assert_eq!(
        decision(&case.run().unwrap()),
        PermissionDecision::Deny,
        "failure after reservation consumes the action"
    );
    let case = Case::new();
    fs::remove_dir(&case.source.state_dir).unwrap();
    assert_eq!(
        decision(&case.run().unwrap()),
        PermissionDecision::Deny,
        "missing replay root must not reset authority"
    );
    let case = Case::new();
    fs::create_dir(case.project.join(".corcept")).unwrap();
    fs::write(case.project.join(".corcept/ledger"), "blocked").unwrap();
    assert!(case.run().is_err(), "failed audit cannot emit allow");
    let case = Case::new();
    fs::write(case.source.state_dir.join("snapshots"), "blocked").unwrap();
    assert_eq!(
        decision(&case.run().unwrap()),
        PermissionDecision::Deny,
        "failed archive cannot emit allow"
    );
    let mut case = Case::new();
    case.input.extra.remove("delegation");
    assert_eq!(decision(&case.run().unwrap()), PermissionDecision::Deny);
}

#[test]
fn native_errors_deny_and_installed_matchers_cover_mcp() {
    let _lock = ENV_LOCK.lock().unwrap();
    assert_eq!(
        decision(&handle_hook("invalid-json", "pretool-guard").unwrap()),
        PermissionDecision::Deny
    );
    let directory = tempfile::tempdir().unwrap();
    init_project(InitOptions {
        path: directory.path().to_path_buf(),
        dry_run: false,
        force: false,
    })
    .unwrap();
    let settings: Value = serde_json::from_str(
        &fs::read_to_string(directory.path().join(".claude/settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(settings["hooks"]["PreToolUse"][0]["matcher"], "*");
    let hooks: Value =
        serde_json::from_str(include_str!("../../../plugins/corcept/hooks/hooks.json")).unwrap();
    assert_eq!(hooks["hooks"]["PreToolUse"][0]["matcher"], "*");
    fs::write(
        directory.path().join(".corcept/config.yaml"),
        "not: valid: yaml",
    )
    .unwrap();
    let raw = json!({"cwd":directory.path(),"hook_event_name":"PreToolUse",
        "tool_name":"mcp__target__read","tool_input":{}})
    .to_string();
    assert_eq!(
        decision(&handle_hook(&raw, "pretool-guard").unwrap()),
        PermissionDecision::Deny
    );
}
