use corcept_memory::{new_candidate, write_candidate};
use corcept_runtime::{handle_hook, init_project, InitOptions};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct TempProject {
    dir: tempfile::TempDir,
}

impl TempProject {
    fn new() -> Self {
        Self::with_init(true)
    }

    fn with_init(init: bool) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("corcept-mcp-test-")
            .tempdir()
            .unwrap();
        let path = dir.path().to_path_buf();
        if init {
            init_project(InitOptions {
                path: path.clone(),
                dry_run: false,
                force: false,
            })
            .unwrap();
        }
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

struct McpHarness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpHarness {
    fn start(root: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_corcept"))
            .args(["serve", "--path", &root.to_string_lossy()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());

        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{}", serde_json::to_string(&message).unwrap()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).unwrap();
        assert!(read > 0, "expected MCP response line");
        serde_json::from_str(line.trim_end()).unwrap()
    }

    fn initialize(&mut self) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "corcept-cli-test",
                    "version": "0.1.0"
                }
            }
        }));
        let response = self.recv();
        self.send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
        response
    }

    fn shutdown(mut self) {
        drop(self.stdin);
        let status = self.child.wait().unwrap();
        assert!(status.success(), "corcept serve exited with {status}");
    }
}

fn seed_candidate(root: &Path) {
    let candidate = new_candidate(
        "Convention",
        "Use explicit errors",
        vec!["src/lib.rs:10".to_string()],
        "mcp-test",
    );
    write_candidate(root, &candidate).unwrap();
}

fn seed_ledger(root: &Path) {
    handle_hook(
        &json!({
            "session_id": "sess-1",
            "cwd": root,
            "hook_event_name": "SessionStart"
        })
        .to_string(),
        "session-start",
    )
    .unwrap();
}

fn last_hash_path(root: &Path) -> PathBuf {
    root.join(".corcept").join("ledger").join("last_hash")
}

#[test]
fn serve_initializes_lists_tools_and_handles_bounded_calls() {
    let project = TempProject::new();
    seed_candidate(project.path());
    seed_ledger(project.path());
    let sidecar = last_hash_path(project.path());
    if sidecar.exists() {
        fs::remove_file(&sidecar).unwrap();
    }

    let mut harness = McpHarness::start(project.path());

    let initialize = harness.initialize();
    assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(initialize["result"]["serverInfo"]["name"], "corcept");
    assert!(initialize["result"]["capabilities"]["tools"].is_object());

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }));
    let listed = harness.recv();
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: BTreeSet<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "audit_report".to_string(),
            "candidate_memory_list".to_string(),
            "cloudevents_preview".to_string(),
            "doctor_report".to_string(),
            "doctrine_validate".to_string(),
        ])
    );
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["openWorldHint"], false);
    }

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "doctor_report",
            "arguments": {
                "strict": true
            }
        }
    }));
    let doctor = harness.recv();
    assert_eq!(doctor["result"]["structuredContent"]["status"], "pass");
    assert!(
        !sidecar.exists(),
        "doctor_report must not recreate last_hash"
    );

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "audit_report"
        }
    }));
    let audit = harness.recv();
    assert_eq!(audit["result"]["structuredContent"]["status"], "pass");
    assert!(
        audit["result"]["structuredContent"]["event_count"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(
        !sidecar.exists(),
        "audit_report must not recreate last_hash"
    );

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "doctrine_validate"
        }
    }));
    let doctrine = harness.recv();
    assert_eq!(doctrine["result"]["structuredContent"]["status"], "pass");

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "candidate_memory_list",
            "arguments": {
                "limit": 5
            }
        }
    }));
    let candidates = harness.recv();
    assert_eq!(candidates["result"]["structuredContent"]["count"], 1);
    assert_eq!(
        candidates["result"]["structuredContent"]["candidates"][0]["title"],
        "Convention"
    );

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "cloudevents_preview",
            "arguments": {
                "limit": 2
            }
        }
    }));
    let preview = harness.recv();
    assert_eq!(preview["result"]["structuredContent"]["preview_count"], 1);
    assert_eq!(
        preview["result"]["structuredContent"]["events"][0]["source"],
        "io.corcept/ledger"
    );

    harness.shutdown();
}

#[test]
fn serve_candidate_memory_list_does_not_create_memory_dirs() {
    let project = TempProject::with_init(false);
    let memory_root = project.path().join(".corcept").join("memory");
    let mut harness = McpHarness::start(project.path());

    let _ = harness.initialize();

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "candidate_memory_list",
            "arguments": {
                "limit": 5
            }
        }
    }));
    let response = harness.recv();
    assert_eq!(response["result"]["structuredContent"]["count"], 0);
    assert!(
        !memory_root.exists(),
        "candidate_memory_list must not create .corcept/memory"
    );

    harness.shutdown();
}

#[test]
fn serve_returns_typed_invalid_argument_error() {
    let project = TempProject::new();
    let mut harness = McpHarness::start(project.path());

    let _ = harness.initialize();

    harness.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "candidate_memory_list",
            "arguments": {
                "limit": 0
            }
        }
    }));
    let response = harness.recv();
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["structuredContent"]["error"]["code"],
        "invalid_arguments"
    );
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("limit must be >= 1"));

    harness.shutdown();
}
