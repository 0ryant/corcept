//! Log sink architecture (ADR-0026).

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use corcept_ledger::append_event;
use corcept_sink_cloudevents::project_event;
use corcept_types::{
    debug_log_path, receipts_dir, telemetry_path, AuthorityLevel, LedgerEvent, LedgerEventKind,
    LEDGER_EVENT_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Internal sink-dispatch DIAGNOSTIC schema. This is NOT the doctrine receipt.
///
/// The load-bearing `axiom.receipt.v1` receipt (pattern 07) is emitted by the
/// CLI verbs via `corcept_ledger::Receipt` — tool / operation / outcome /
/// inputs+outputs (BLAKE3) / audit_chain linkage, signed Ed25519. `SinkRecord`
/// remains a lightweight per-emit dispatch breadcrumb for the telemetry / debug
/// / receipt-dispatch sinks and is intentionally kept separate.
pub const SINK_RECORD_SCHEMA: &str = "corcept.sink_record.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkRecord {
    pub schema: String,
    pub correlation_id: String,
    pub event_type: String,
    pub ts: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl SinkRecord {
    pub fn new(
        correlation_id: impl Into<String>,
        kind: LedgerEventKind,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            schema: SINK_RECORD_SCHEMA.to_string(),
            correlation_id: correlation_id.into(),
            event_type: kind.wire_str().to_string(),
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            outcome: outcome.into(),
            hook_event: None,
            duration_ms: None,
            metadata: BTreeMap::new(),
        }
    }
}

pub trait LogSink: Send + Sync {
    fn id(&self) -> &'static str;
    fn is_authority(&self) -> bool;
    fn emit(&self, record: &SinkRecord, ledger: Option<&LedgerEvent>) -> Result<()>;
}

pub struct LedgerSink {
    root: PathBuf,
}

impl LedgerSink {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }
}

impl LogSink for LedgerSink {
    fn id(&self) -> &'static str {
        "ledger"
    }

    fn is_authority(&self) -> bool {
        true
    }

    fn emit(&self, _record: &SinkRecord, ledger: Option<&LedgerEvent>) -> Result<()> {
        let event = ledger.context("ledger sink requires LedgerEvent")?;
        append_event(&self.root, event.clone()).context("append ledger event")?;
        Ok(())
    }
}

pub struct TelemetrySink;

impl LogSink for TelemetrySink {
    fn id(&self) -> &'static str {
        "telemetry"
    }

    fn is_authority(&self) -> bool {
        false
    }

    fn emit(&self, record: &SinkRecord, _ledger: Option<&LedgerEvent>) -> Result<()> {
        let Some(base) = telemetry_path() else {
            return Ok(());
        };
        fs::create_dir_all(&base).ok();
        let path = base.join("events.jsonl");
        append_jsonl(&path, record)
    }
}

pub struct DebugLogSink;

impl LogSink for DebugLogSink {
    fn id(&self) -> &'static str {
        "debug"
    }

    fn is_authority(&self) -> bool {
        false
    }

    fn emit(&self, record: &SinkRecord, _ledger: Option<&LedgerEvent>) -> Result<()> {
        let Some(path) = debug_log_path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let line = format!(
            "ts={} correlation_id={} event_type={} outcome={}",
            record.ts, record.correlation_id, record.event_type, record.outcome
        );
        append_line(&path, &line)
    }
}

/// Best-effort CloudEvents projection sink (derived from ledger event).
pub struct CloudEventsSink {
    out: PathBuf,
}

impl CloudEventsSink {
    pub fn new(out: impl AsRef<Path>) -> Self {
        Self {
            out: out.as_ref().to_path_buf(),
        }
    }

    pub fn from_env_or_skip() -> Option<Self> {
        let path = std::env::var("CORCEPT_CE_OUT").ok().map(PathBuf::from)?;
        Some(Self::new(path))
    }
}

impl LogSink for CloudEventsSink {
    fn id(&self) -> &'static str {
        "cloudevents"
    }

    fn is_authority(&self) -> bool {
        false
    }

    fn emit(&self, _record: &SinkRecord, ledger: Option<&LedgerEvent>) -> Result<()> {
        let event = ledger.context("cloudevents sink requires LedgerEvent")?;
        if let Some(parent) = self.out.parent() {
            fs::create_dir_all(parent).ok();
        }
        let ce = project_event(event);
        append_jsonl(&self.out, &ce)
    }
}

/// Best-effort eval/operator receipt dispatch log (not authority).
pub struct ReceiptSink;

impl LogSink for ReceiptSink {
    fn id(&self) -> &'static str {
        "receipt"
    }

    fn is_authority(&self) -> bool {
        false
    }

    fn emit(&self, record: &SinkRecord, _ledger: Option<&LedgerEvent>) -> Result<()> {
        let Some(base) = receipts_dir() else {
            return Ok(());
        };
        fs::create_dir_all(&base).ok();
        append_jsonl(&base.join("dispatch.jsonl"), record)
    }
}

pub struct SinkDispatcher {
    sinks: Vec<Box<dyn LogSink>>,
}

impl SinkDispatcher {
    /// Hook hot path: ledger only unless operator sinks explicitly enabled.
    pub fn hook_default(root: impl AsRef<Path>) -> Self {
        let mut d = Self { sinks: Vec::new() };
        d.add(LedgerSink::new(root));
        if std::env::var("CORCEPT_TELEMETRY").ok().as_deref() == Some("1") {
            d.add(TelemetrySink);
            d.add(DebugLogSink);
        }
        if std::env::var("CORCEPT_LOG").ok().as_deref() == Some("debug") && !d.has_sink("debug") {
            d.add(DebugLogSink);
        }
        if let Some(ce) = CloudEventsSink::from_env_or_skip() {
            d.add(ce);
        }
        if std::env::var("CORCEPT_RECEIPTS").ok().as_deref() == Some("1") {
            d.add(ReceiptSink);
        }
        d
    }

    fn has_sink(&self, id: &str) -> bool {
        self.sinks.iter().any(|s| s.id() == id)
    }

    pub fn add(&mut self, sink: impl LogSink + 'static) {
        self.sinks.push(Box::new(sink));
    }

    pub fn sink_ids(&self) -> Vec<&'static str> {
        self.sinks.iter().map(|s| s.id()).collect()
    }

    pub fn emit_all(&self, record: &SinkRecord, ledger: Option<&LedgerEvent>) -> Result<()> {
        for sink in &self.sinks {
            if let Err(err) = sink.emit(record, ledger) {
                if sink.is_authority() {
                    return Err(err);
                }
                eprintln!("corcept sink {} best-effort failure: {err}", sink.id());
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_ledger_event(
    session_id: Option<String>,
    actor: impl Into<String>,
    kind: LedgerEventKind,
    authority_level: AuthorityLevel,
    tool: Option<String>,
    target: Option<String>,
    decision: Option<String>,
    decision_reason: Option<String>,
    metadata: BTreeMap<String, serde_json::Value>,
) -> LedgerEvent {
    LedgerEvent {
        schema: LEDGER_EVENT_SCHEMA.to_string(),
        id: String::new(),
        ts: String::new(),
        session_id,
        actor: actor.into(),
        event_type: kind.wire_str().to_string(),
        authority_level,
        tool,
        target,
        decision,
        decision_reason,
        evidence_refs: vec![],
        prev_hash: None,
        hash: None,
        metadata,
        signature: None,
        // cex* correlation fields are stamped at the runtime emission seam
        // (append_hook_event); build_ledger_event leaves them None so the
        // ledger row stays additive when no cex context is supplied.
        cexauthorityclass: None,
        cextrustceiling: None,
        cexsessionid: None,
        cexparenttrace: None,
        cexdoctrinecite: None,
        cexreceipthash: None,
        cexrevocation: None,
    }
}

fn append_jsonl(path: &Path, value: &impl Serialize) -> Result<()> {
    let line = serde_json::to_string(value)?;
    append_line(path, &line)
}

fn append_line(path: &Path, line: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{line}").with_context(|| format!("append {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::AuthorityLevel;
    use tempfile::tempdir;

    #[test]
    fn ledger_sink_required() {
        let dir = tempdir().unwrap();
        let dispatcher = SinkDispatcher::hook_default(dir.path());
        let record = SinkRecord::new("s1", LedgerEventKind::ToolRequested, "deny");
        let err = dispatcher.emit_all(&record, None).unwrap_err();
        assert!(err.to_string().contains("LedgerEvent"));
    }

    #[test]
    fn ledger_sink_appends() {
        let dir = tempdir().unwrap();
        let dispatcher = SinkDispatcher::hook_default(dir.path());
        let record = SinkRecord::new("s1", LedgerEventKind::ToolRequested, "deny");
        let event = build_ledger_event(
            Some("s1".into()),
            "corcept-runtime",
            LedgerEventKind::ToolRequested,
            AuthorityLevel::L3ExecuteLocal,
            Some("Bash".into()),
            Some("rm -rf /".into()),
            Some("deny".into()),
            Some("blocked".into()),
            BTreeMap::new(),
        );
        dispatcher.emit_all(&record, Some(&event)).unwrap();
        let events = corcept_ledger::read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "corcept.event.tool_requested.v1");
    }

    #[test]
    fn hook_default_is_ledger_only_without_env() {
        std::env::remove_var("CORCEPT_TELEMETRY");
        std::env::remove_var("CORCEPT_CE_OUT");
        std::env::remove_var("CORCEPT_RECEIPTS");
        std::env::remove_var("CORCEPT_LOG");
        let dir = tempdir().unwrap();
        let dispatcher = SinkDispatcher::hook_default(dir.path());
        assert_eq!(dispatcher.sink_ids(), vec!["ledger"]);
    }

    #[test]
    fn secondary_sink_failure_does_not_block_ledger() {
        std::env::remove_var("CORCEPT_TELEMETRY");
        std::env::remove_var("CORCEPT_CE_OUT");
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("block");
        fs::write(&blocker, b"x").unwrap();
        let bad_ce = blocker.join("ce.jsonl");
        let mut dispatcher = SinkDispatcher::hook_default(dir.path());
        dispatcher.add(CloudEventsSink::new(&bad_ce));
        let record = SinkRecord::new("s1", LedgerEventKind::SessionStarted, "allow");
        let event = build_ledger_event(
            Some("s1".into()),
            "test",
            LedgerEventKind::SessionStarted,
            AuthorityLevel::L0Observe,
            None,
            None,
            Some("allow".into()),
            None,
            BTreeMap::new(),
        );
        dispatcher.emit_all(&record, Some(&event)).unwrap();
        assert_eq!(corcept_ledger::read_events(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn cloudevents_sink_appends_projection() {
        let dir = tempdir().unwrap();
        let ce_path = dir.path().join("ce.jsonl");
        let mut dispatcher = SinkDispatcher::hook_default(dir.path());
        dispatcher.add(CloudEventsSink::new(&ce_path));
        let record = SinkRecord::new("s1", LedgerEventKind::ToolRequested, "deny");
        let event = build_ledger_event(
            Some("s1".into()),
            "test",
            LedgerEventKind::ToolRequested,
            AuthorityLevel::L3ExecuteLocal,
            None,
            None,
            Some("deny".into()),
            None,
            BTreeMap::new(),
        );
        dispatcher.emit_all(&record, Some(&event)).unwrap();
        let raw = fs::read_to_string(&ce_path).unwrap();
        assert!(raw.contains("io.corcept.hook.tool_requested.v1"));
    }
}
