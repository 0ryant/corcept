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
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();
    let mut server = McpServer::new(path);

    while let Some((message, mode)) = read_transport_message(&mut stdin)? {
        if let Some(response) = server.handle_message(&message) {
            write_transport_message(&mut stdout, mode, &response)?;
            stdout.flush()?;
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum TransportMode {
    LineDelimited,
    Framed,
}

fn read_transport_message(
    reader: &mut impl BufRead,
) -> io::Result<Option<(String, TransportMode)>> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(None);
        }

        if buffer.starts_with(b"Content-Length:") {
            return read_framed_message(reader)
                .map(|message| message.map(|message| (message, TransportMode::Framed)));
        }

        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(None);
        }

        if line.trim().is_empty() {
            continue;
        }

        let message = line.trim_end_matches(['\r', '\n']).to_owned();
        return Ok(Some((message, TransportMode::LineDelimited)));
    }
}

fn read_framed_message(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut content_length = None;

    loop {
        let mut header_line = String::new();
        let bytes_read = reader.read_line(&mut header_line)?;
        if bytes_read == 0 {
            if content_length.is_none() {
                return Ok(None);
            }

            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated MCP frame headers",
            ));
        }

        if header_line == "\r\n" || header_line == "\n" {
            break;
        }

        let header_line = header_line.trim_end_matches(['\r', '\n']);
        if let Some(value) = header_line.strip_prefix("Content-Length:") {
            let parsed = value.trim().parse::<usize>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Content-Length header: {error}"),
                )
            })?;
            content_length = Some(parsed);
        }
    }

    let content_length = content_length.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Content-Length header in MCP frame",
        )
    })?;
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    String::from_utf8(body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_transport_message(
    writer: &mut impl Write,
    mode: TransportMode,
    response: &Value,
) -> io::Result<()> {
    let response = serde_json::to_string(response)?;
    match mode {
        TransportMode::LineDelimited => writeln!(writer, "{response}")?,
        TransportMode::Framed => {
            write!(writer, "Content-Length: {}\r\n\r\n", response.len())?;
            writer.write_all(response.as_bytes())?;
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

    fn handle_message(&mut self, line: &str) -> Option<Value> {
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
                            "result": tool_error(
                                "invalid_arguments",
                                "arguments must be an object",
                                Some(&self.root),
                            )
                        })));
                    }
                    None => None,
                };

                match self.call_tool(name, arguments)? {
                    ToolCallOutcome::Success(result) => Ok(Some(json!({
                        "jsonrpc": "2.0",
                        "id": id.unwrap_or(Value::Null),
                        "result": tool_success(self.with_served_root(result))
                    }))),
                    ToolCallOutcome::InvalidArguments(message) => Ok(Some(json!({
                        "jsonrpc": "2.0",
                        "id": id.unwrap_or(Value::Null),
                        "result": tool_error("invalid_arguments", &message, Some(&self.root))
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

    fn with_served_root(&self, structured_content: Value) -> Value {
        add_served_root(structured_content, &self.root)
    }
}

fn parse_bool(
    arguments: Option<&Map<String, Value>>,
    key: &str,
) -> std::result::Result<bool, String> {
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

fn tool_error(code: &str, message: &str, served_root: Option<&Path>) -> Value {
    let mut structured_content = json!({
        "error": {
            "code": code,
            "message": message
        }
    });
    if let Some(served_root) = served_root {
        structured_content = add_served_root(structured_content, served_root);
    }
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "structuredContent": structured_content,
        "isError": true
    })
}

fn add_served_root(structured_content: Value, root: &Path) -> Value {
    match structured_content {
        Value::Object(mut object) => {
            object.insert(
                "served_root".to_string(),
                Value::String(root.display().to_string()),
            );
            Value::Object(object)
        }
        value => json!({
            "served_root": root.display().to_string(),
            "result": value,
        }),
    }
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
