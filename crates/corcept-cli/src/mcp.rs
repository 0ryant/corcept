use anyhow::{anyhow, Result};
use corcept_ledger::{read_events, verify_ledger};
use corcept_memory::list_candidates;
use corcept_runtime::{audit, doctor_with_options, DoctorOptions};
use corcept_sink_cloudevents::project_event;
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

const PROTOCOL_VERSION: &str = "2025-06-18";

pub fn serve(path: PathBuf) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut server = McpServer::new(path);

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        if let Some(response) = server.handle_line(&line) {
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
        }
    }

    Ok(())
}

struct McpServer {
    root: PathBuf,
    initialized: bool,
}

enum ToolCallOutcome {
    Success(Value),
    InvalidArguments(String),
}

impl McpServer {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            initialized: false,
        }
    }

    fn handle_line(&mut self, line: &str) -> Option<Value> {
        let parsed: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                return Some(json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {err}")
                    }
                }));
            }
        };

        let id = parsed.get("id").cloned();
        let method = match parsed.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => {
                return Some(json!({
                    "jsonrpc": "2.0",
                    "id": id.unwrap_or(Value::Null),
                    "error": {
                        "code": -32600,
                        "message": "Invalid request: missing method"
                    }
                }));
            }
        };

        match self.handle_request(method, parsed.get("params"), id.clone()) {
            Ok(Some(response)) => Some(response),
            Ok(None) => None,
            Err(err) => Some(json!({
                "jsonrpc": "2.0",
                "id": id.unwrap_or(Value::Null),
                "error": {
                    "code": -32603,
                    "message": format!("Internal error: {err}")
                }
            })),
        }
    }

    fn handle_request(
        &mut self,
        method: &str,
        params: Option<&Value>,
        id: Option<Value>,
    ) -> Result<Option<Value>> {
        match method {
            "initialize" => {
                self.initialized = true;
                Ok(Some(json!({
                    "jsonrpc": "2.0",
                    "id": id.unwrap_or(Value::Null),
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {
                                "listChanged": false
                            }
                        },
                        "serverInfo": {
                            "name": "corcept",
                            "version": env!("CARGO_PKG_VERSION")
                        },
                        "instructions": "Opt-in bounded MCP server exposing read-mostly Corcept reports and previews."
                    }
                })))
            }
            "notifications/initialized" => Ok(None),
            "tools/list" => {
                self.require_initialized()?;
                Ok(Some(json!({
                    "jsonrpc": "2.0",
                    "id": id.unwrap_or(Value::Null),
                    "result": {
                        "tools": tool_definitions()
                    }
                })))
            }
            "tools/call" => {
                self.require_initialized()?;
                let request = params
                    .and_then(Value::as_object)
                    .ok_or_else(|| anyhow!("tools/call params must be an object"))?;
                let name = request
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("tools/call requires a string name"))?;
                let arguments = match request.get("arguments") {
                    Some(Value::Object(map)) => Some(map),
                    Some(_) => {
                        return Ok(Some(json!({
                            "jsonrpc": "2.0",
                            "id": id.unwrap_or(Value::Null),
                            "result": tool_error("invalid_arguments", "arguments must be an object")
                        })));
                    }
                    None => None,
                };

                match self.call_tool(name, arguments)? {
                    ToolCallOutcome::Success(result) => Ok(Some(json!({
                        "jsonrpc": "2.0",
                        "id": id.unwrap_or(Value::Null),
                        "result": tool_success(result)
                    }))),
                    ToolCallOutcome::InvalidArguments(message) => Ok(Some(json!({
                        "jsonrpc": "2.0",
                        "id": id.unwrap_or(Value::Null),
                        "result": tool_error("invalid_arguments", &message)
                    }))),
                }
            }
            _ => Ok(Some(json!({
                "jsonrpc": "2.0",
                "id": id.unwrap_or(Value::Null),
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {method}")
                }
            }))),
        }
    }

    fn require_initialized(&self) -> Result<()> {
        if self.initialized {
            Ok(())
        } else {
            Err(anyhow!("Server not initialized"))
        }
    }

    fn call_tool(
        &self,
        name: &str,
        arguments: Option<&Map<String, Value>>,
    ) -> Result<ToolCallOutcome> {
        match name {
            "doctor_report" => {
                let strict = match parse_bool(arguments, "strict") {
                    Ok(value) => value,
                    Err(message) => return Ok(ToolCallOutcome::InvalidArguments(message)),
                };
                let validate_perms = match parse_bool(arguments, "validate_perms") {
                    Ok(value) => value,
                    Err(message) => return Ok(ToolCallOutcome::InvalidArguments(message)),
                };
                let report = doctor_with_options(
                    &self.root,
                    DoctorOptions {
                        validate_perms,
                        strict,
                    },
                )?;
                Ok(ToolCallOutcome::Success(serde_json::to_value(report)?))
            }
            "audit_report" => {
                let signed = match parse_bool(arguments, "signed") {
                    Ok(value) => value,
                    Err(message) => return Ok(ToolCallOutcome::InvalidArguments(message)),
                };
                let report = audit(&self.root)?;
                let verification = verify_ledger(&self.root, signed)?;
                Ok(ToolCallOutcome::Success(json!({
                    "status": report.status,
                    "event_count": report.event_count,
                    "hash_chain_valid": report.hash_chain_valid,
                    "last_event": report.last_event,
                    "warnings": report.warnings,
                    "verification": verification,
                })))
            }
            "doctrine_validate" => {
                let warnings = corcept_doctrine::validate(&self.root)?;
                Ok(ToolCallOutcome::Success(json!({
                    "status": if warnings.is_empty() { "pass" } else { "warn" },
                    "warnings": warnings,
                })))
            }
            "candidate_memory_list" => {
                let limit = match parse_limit(arguments, "limit", 20) {
                    Ok(value) => value,
                    Err(message) => return Ok(ToolCallOutcome::InvalidArguments(message)),
                };
                let candidates = list_candidates(&self.root, limit)?;
                Ok(ToolCallOutcome::Success(json!({
                    "count": candidates.len(),
                    "candidates": candidates,
                })))
            }
            "cloudevents_preview" => {
                let limit = match parse_limit(arguments, "limit", 10) {
                    Ok(value) => value,
                    Err(message) => return Ok(ToolCallOutcome::InvalidArguments(message)),
                };
                let events = read_events(&self.root)?
                    .into_iter()
                    .take(limit)
                    .map(|event| project_event(&event))
                    .collect::<Vec<_>>();
                Ok(ToolCallOutcome::Success(json!({
                    "preview_count": events.len(),
                    "events": events,
                    "projection": "derived_cloudevents",
                    "authority": project_ledger_path(&self.root),
                })))
            }
            _ => Err(anyhow!("Unknown tool: {name}")),
        }
    }
}

fn parse_bool(arguments: Option<&Map<String, Value>>, key: &str) -> std::result::Result<bool, String> {
    match arguments.and_then(|args| args.get(key)) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

fn parse_limit(
    arguments: Option<&Map<String, Value>>,
    key: &str,
    default: usize,
) -> std::result::Result<usize, String> {
    match arguments.and_then(|args| args.get(key)) {
        None => Ok(default),
        Some(Value::Number(number)) => {
            let Some(value) = number.as_u64() else {
                return Err(format!("{key} must be a positive integer"));
            };
            if value == 0 {
                return Err(format!("{key} must be >= 1"));
            }
            if value > 100 {
                return Err(format!("{key} must be <= 100"));
            }
            Ok(value as usize)
        }
        Some(_) => Err(format!("{key} must be a positive integer")),
    }
}

fn tool_success(structured_content: Value) -> Value {
    let text = serde_json::to_string_pretty(&structured_content)
        .unwrap_or_else(|_| structured_content.to_string());
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": structured_content
    })
}

fn tool_error(code: &str, message: &str) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "structuredContent": {
            "error": {
                "code": code,
                "message": message
            }
        },
        "isError": true
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "doctor_report",
            "title": "Doctor Report",
            "description": "Return the Corcept doctor report for the bound project root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "strict": { "type": "boolean" },
                    "validate_perms": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        }),
        json!({
            "name": "audit_report",
            "title": "Audit Report",
            "description": "Return ledger audit status and verification details for the bound project root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "signed": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        }),
        json!({
            "name": "doctrine_validate",
            "title": "Doctrine Validate",
            "description": "Validate project doctrine files without mutating project state.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        }),
        json!({
            "name": "candidate_memory_list",
            "title": "Candidate Memory List",
            "description": "List candidate memory files from the bound project root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100
                    }
                },
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        }),
        json!({
            "name": "cloudevents_preview",
            "title": "CloudEvents Preview",
            "description": "Preview derived CloudEvents documents from the authority ledger without writing exports.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100
                    }
                },
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        }),
    ]
}

fn read_only_annotations() -> Value {
    json!({
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": false
    })
}

fn project_ledger_path(root: &Path) -> String {
    root.join(".corcept")
        .join("ledger")
        .join("events.jsonl")
        .display()
        .to_string()
}
