//! CloudEvents 1.0 projection for CORCEPT ledger lines (ADR-0022).

use anyhow::{Context, Result};
use corcept_ledger::read_events_file;
use corcept_types::{LedgerEvent, LedgerEventKind};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const EVENT_SOURCE: &str = "io.corcept/ledger";
pub const PROVENANCE_REPO: &str = "corcept";
pub const PROVENANCE_PRODUCER: &str = "corcept-sink-cloudevents";
pub const PROVENANCE_KIND: &str = "audit";
pub const PROVENANCE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimal CloudEvents 1.0 JSON envelope (hand-rolled, no cloudevents-sdk).
#[derive(Debug, Clone, Serialize)]
pub struct CloudEventV1 {
    pub specversion: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacontenttype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    pub correlationid: String,
    pub provenancerepo: String,
    pub provenanceproducer: String,
    pub provenanceversion: String,
    pub provenancekind: String,
    pub corcepteventfingerprint: String,
}

pub fn ce_type_for(kind: LedgerEventKind) -> &'static str {
    match kind {
        LedgerEventKind::SessionStarted => "io.corcept.hook.session_started.v1",
        LedgerEventKind::PromptSubmitted => "io.corcept.hook.prompt_submitted.v1",
        LedgerEventKind::ToolRequested => "io.corcept.hook.tool_requested.v1",
        LedgerEventKind::ToolDecided => "io.corcept.hook.tool_decided.v1",
        LedgerEventKind::FileModified => "io.corcept.hook.file_modified.v1",
        LedgerEventKind::CommandExecuted => "io.corcept.hook.command_executed.v1",
        LedgerEventKind::TestRun => "io.corcept.hook.test_run.v1",
        LedgerEventKind::ToolCompleted => "io.corcept.hook.tool_completed.v1",
        LedgerEventKind::StopAllowed => "io.corcept.hook.stop_allowed.v1",
        LedgerEventKind::StopBlocked => "io.corcept.hook.stop_blocked.v1",
    }
}

/// Stable 32-hex fingerprint shared across ledger projection surfaces.
pub fn event_fingerprint(event: &LedgerEvent) -> String {
    let material = format!(
        "{}|{}|{}|{}",
        event.id,
        event.event_type,
        event.decision.as_deref().unwrap_or(""),
        event.session_id.as_deref().unwrap_or("")
    );
    let digest = Sha256::digest(material.as_bytes());
    hex::encode(digest)[..32].to_string()
}

fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, val) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("password")
                    || lower.contains("api_key")
                {
                    out.insert(key.clone(), json!("[REDACTED]"));
                } else {
                    out.insert(key.clone(), redact_value(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        other => other.clone(),
    }
}

fn redact_metadata(metadata: &std::collections::BTreeMap<String, Value>) -> Value {
    redact_value(&serde_json::to_value(metadata).unwrap_or(json!({})))
}

pub fn project_event(event: &LedgerEvent) -> CloudEventV1 {
    let kind = LedgerEventKind::parse(&event.event_type);
    let fingerprint = event_fingerprint(event);
    let correlation = event.session_id.clone().unwrap_or_else(|| event.id.clone());

    let mut data = json!({
        "ledger_event_id": event.id,
        "schema": event.schema,
        "event_type": event.event_type,
        "authority_level": event.authority_level.to_string(),
        "decision": event.decision,
        "decision_reason": event.decision_reason,
        "tool": event.tool,
        "target": event.target,
        "fingerprint": fingerprint,
    });
    if let Some(obj) = data.as_object_mut() {
        if !event.metadata.is_empty() {
            obj.insert("metadata".to_string(), redact_metadata(&event.metadata));
        }
        obj.insert(
            "transition_id".to_string(),
            event
                .metadata
                .get("transition_id")
                .cloned()
                .unwrap_or(Value::Null),
        );
    }

    CloudEventV1 {
        specversion: "1.0".to_string(),
        id: event.id.clone(),
        source: EVENT_SOURCE.to_string(),
        ty: ce_type_for(kind).to_string(),
        subject: event.session_id.clone(),
        datacontenttype: Some("application/json".to_string()),
        time: Some(event.ts.clone()),
        data: Some(data),
        correlationid: correlation,
        provenancerepo: PROVENANCE_REPO.to_string(),
        provenanceproducer: PROVENANCE_PRODUCER.to_string(),
        provenanceversion: PROVENANCE_VERSION.to_string(),
        provenancekind: PROVENANCE_KIND.to_string(),
        corcepteventfingerprint: fingerprint,
    }
}

pub fn export_cloudevents(ledger: &Path, out: &Path) -> Result<usize> {
    let events = read_events_file(ledger)?;
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out)
        .with_context(|| format!("open {}", out.display()))?;
    for event in &events {
        let ce = project_event(event);
        writeln!(file, "{}", serde_json::to_string(&ce)?)?;
    }
    Ok(events.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::{AuthorityLevel, LEDGER_EVENT_SCHEMA};
    use std::collections::BTreeMap;

    fn sample_event() -> LedgerEvent {
        LedgerEvent {
            schema: LEDGER_EVENT_SCHEMA.to_string(),
            id: "evt_ce_test".to_string(),
            ts: "2026-05-18T12:00:00.000Z".to_string(),
            session_id: Some("sess-1".to_string()),
            actor: "corcept-runtime".to_string(),
            event_type: LedgerEventKind::ToolRequested.wire_str().to_string(),
            authority_level: AuthorityLevel::L3ExecuteLocal,
            tool: Some("Bash".to_string()),
            target: Some("rm -rf /".to_string()),
            decision: Some("deny".to_string()),
            decision_reason: Some("blocked".to_string()),
            evidence_refs: vec![],
            prev_hash: None,
            hash: None,
            metadata: BTreeMap::from([(
                "tool_input".to_string(),
                json!({"command": "rm -rf /", "api_key": "sk-secret"}),
            )]),
            signature: None,
        }
    }

    #[test]
    fn projects_all_required_ce_fields() {
        let ce = project_event(&sample_event());
        assert_eq!(ce.specversion, "1.0");
        assert_eq!(ce.id, "evt_ce_test");
        assert_eq!(ce.ty, "io.corcept.hook.tool_requested.v1");
        assert_eq!(ce.correlationid, "sess-1");
        assert_eq!(ce.corcepteventfingerprint.len(), 32);
    }

    #[test]
    fn redacts_secret_like_metadata() {
        let ce = project_event(&sample_event());
        let data = ce.data.expect("data");
        let metadata = data.get("metadata").expect("metadata");
        assert!(metadata.to_string().contains("[REDACTED]"));
        assert!(!metadata.to_string().contains("sk-secret"));
    }

    #[test]
    fn fingerprint_is_stable() {
        let event = sample_event();
        assert_eq!(event_fingerprint(&event), event_fingerprint(&event));
    }
}
