//! CloudEvents 1.0 projection for CORCEPT ledger lines (ADR-0022).

use anyhow::{Context, Result};
use corcept_ledger::read_events_file;
use corcept_types::{LedgerEvent, LedgerEventKind};
use serde::Serialize;
use serde_json::{json, Value};
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
    // --- SYN-1 cex emission extension attributes (envelope-v2) -----------
    // Copied from the ledger row's cex* fields. All optional + skipped when
    // None, so stripping the cex* extension attrs leaves a valid CloudEvent.
    // Names + value spaces match aegress_core::CexCloudEvent so aegress
    // corridor-verify can ingest these rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cexauthorityclass: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cextrustceiling: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cexsessionid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cexparenttrace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cexdoctrinecite: Option<String>,
    /// BLAKE3 (ADR-0003) of the finalized row canonical body. NOT the SHA-256
    /// ledger hash chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cexreceipthash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cexrevocation: Option<String>,
}

/// cex content addressing is BLAKE3 (ADR-0003; SHA-256-as-content-address is
/// FORBIDDEN). `cexreceipthash` is BLAKE3 of the row canonical body per
/// envelope-v2 — distinct from corcept's ledger hash chain.
///
/// # AXIOM conformance (Phase-3 reconcile)
///
/// The canonical form is now the shared **RFC-8785 (JCS)** canonicalizer
/// ([`axiom_canonical::to_jcs_bytes`]) and the digest is the shared
/// [`axiom_hash::blake3_hex`] — the SAME path aegress's corridor oracle
/// (`aegress_core::blake3_jcs_value`) uses. corcept stamps `cextrustceiling =
/// "reviewed"`, so its rows are not subject to aegress's `signed`/`verified`
/// receipt-hash recompute; this hash is self-consistent within corcept and
/// carries the `blake3:` prefix corcept's own surfaces expect. The volatile
/// `cexreceipthash` field is excluded from the body so the hash cannot cover
/// itself.
pub fn cex_receipt_hash(event: &LedgerEvent) -> Option<String> {
    let mut value = serde_json::to_value(event).ok()?;
    if let Value::Object(map) = &mut value {
        map.remove("cexreceipthash");
    }
    let bytes = axiom_canonical::to_jcs_bytes(&value).ok()?;
    Some(format!("blake3:{}", axiom_hash::blake3_hex(&bytes)))
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
///
/// BLAKE3 per ADR-0003 (a content address of the row identity tuple, not a MAC).
/// The 32-hex truncation preserves the field width; only the hash function
/// changes. This `corcepteventfingerprint` is corcept-internal to the CloudEvents
/// projection — it is not part of the aegress cex corridor recompute (which keys
/// on the `cex*` extension attrs), so the migration does not regress the corridor.
pub fn event_fingerprint(event: &LedgerEvent) -> String {
    let material = format!(
        "{}|{}|{}|{}",
        event.id,
        event.event_type,
        event.decision.as_deref().unwrap_or(""),
        event.session_id.as_deref().unwrap_or("")
    );
    axiom_hash::blake3_hex(material.as_bytes())[..32].to_string()
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
        // SYN-1 cex emission: copy the row's cex* fields onto extension attrs.
        // cexreceipthash is recomputed here as BLAKE3 of the finalized row
        // canonical body (the seam leaves it None because id/ts/hash are not
        // assigned until append_event). If the row carried a precomputed
        // cexreceipthash it is preserved; otherwise we compute one.
        cexauthorityclass: event.cexauthorityclass.clone(),
        cextrustceiling: event.cextrustceiling.clone(),
        cexsessionid: event
            .cexsessionid
            .clone()
            .or_else(|| event.session_id.clone()),
        cexparenttrace: event.cexparenttrace.clone(),
        cexdoctrinecite: event.cexdoctrinecite.clone(),
        cexreceipthash: event.cexreceipthash.clone().or_else(|| cex_receipt_hash(event)),
        cexrevocation: event.cexrevocation.clone(),
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
            cexauthorityclass: None,
            cextrustceiling: None,
            cexsessionid: None,
            cexparenttrace: None,
            cexdoctrinecite: None,
            cexreceipthash: None,
            cexrevocation: None,
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

    /// A row as stamped by the SYN-1 runtime emission seam (append_hook_event):
    /// cexsessionid/cexparenttrace/cextrustceiling/cexauthorityclass populated,
    /// cexreceipthash left None (computed at projection over the finalized row).
    fn cex_stamped_event() -> LedgerEvent {
        let mut event = sample_event();
        event.cexsessionid = Some("sess-1".to_string());
        event.cexparenttrace = Some("toolu_parent_123".to_string());
        event.cextrustceiling = Some("reviewed".to_string());
        // L3ExecuteLocal -> mutate per the SYN-1 ladder mapping.
        event.cexauthorityclass = Some(AuthorityLevel::L3ExecuteLocal.cex_authority_class().to_string());
        event.cexdoctrinecite = Some("corcept:syn-1:cex-spine".to_string());
        event
    }

    #[test]
    fn cex_authority_ladder_maps_to_envelope_v2_space() {
        assert_eq!(AuthorityLevel::L0Observe.cex_authority_class(), "observe");
        assert_eq!(AuthorityLevel::L1Propose.cex_authority_class(), "plan");
        assert_eq!(AuthorityLevel::L2ModifyLocal.cex_authority_class(), "analyze");
        assert_eq!(AuthorityLevel::L3ExecuteLocal.cex_authority_class(), "mutate");
        assert_eq!(
            AuthorityLevel::L4ExternalSideEffect.cex_authority_class(),
            "destroy"
        );
    }

    #[test]
    fn projection_populates_cex_fields() {
        let ce = project_event(&cex_stamped_event());
        // Stamped-at-seam fields flow through to extension attrs.
        assert_eq!(ce.cexauthorityclass.as_deref(), Some("mutate"));
        assert_eq!(ce.cextrustceiling.as_deref(), Some("reviewed"));
        assert_eq!(ce.cexsessionid.as_deref(), Some("sess-1"));
        assert_eq!(ce.cexparenttrace.as_deref(), Some("toolu_parent_123"));
        assert_eq!(ce.cexdoctrinecite.as_deref(), Some("corcept:syn-1:cex-spine"));
        // cexreceipthash is computed at projection: BLAKE3 (ADR-0003), NOT SHA-256.
        let hash = ce.cexreceipthash.expect("cexreceipthash present");
        assert!(hash.starts_with("blake3:"), "cex content addressing must be BLAKE3, got {hash}");
        assert!(!hash.starts_with("sha256:"), "SHA-256-as-content-address is FORBIDDEN");

        // Value spaces match aegress envelope-v2 so corridor-verify can ingest.
        const AUTHORITY_SPACE: &[&str] =
            &["observe", "analyze", "plan", "mutate", "destroy", "credential"];
        const TRUST_SPACE: &[&str] = &["inferred", "reviewed", "signed", "verified"];
        assert!(AUTHORITY_SPACE.contains(&ce.cexauthorityclass.as_deref().unwrap()));
        assert!(TRUST_SPACE.contains(&ce.cextrustceiling.as_deref().unwrap()));
    }

    #[test]
    fn cex_fields_are_additive_stripping_leaves_valid_cloudevent() {
        let ce = project_event(&cex_stamped_event());
        let mut value = serde_json::to_value(&ce).expect("serialize CE");
        let obj = value.as_object_mut().expect("CE is a JSON object");

        // The serialized CE carries the cex* extension attrs.
        for k in [
            "cexauthorityclass",
            "cextrustceiling",
            "cexsessionid",
            "cexparenttrace",
            "cexdoctrinecite",
            "cexreceipthash",
        ] {
            assert!(obj.contains_key(k), "expected cex attr {k} in projection");
        }

        // Strip every cex* extension attr. What remains must still be a valid
        // CloudEvent 1.0 envelope: required core attrs present + no cex* leakage.
        let cex_keys: Vec<String> = obj
            .keys()
            .filter(|k| k.starts_with("cex"))
            .cloned()
            .collect();
        for k in &cex_keys {
            obj.remove(k);
        }
        for required in ["specversion", "id", "source", "type"] {
            assert!(
                obj.contains_key(required),
                "stripped CE missing required CloudEvents attr {required}"
            );
        }
        assert_eq!(obj.get("specversion").and_then(Value::as_str), Some("1.0"));
        assert!(
            !obj.keys().any(|k| k.starts_with("cex")),
            "no cex* attrs should remain after stripping"
        );
    }

    #[test]
    fn cex_receipt_hash_is_stable_and_self_consistent() {
        let event = cex_stamped_event();
        let h1 = cex_receipt_hash(&event).expect("hash");
        // Recomputing yields the same hash (canonical body is deterministic).
        assert_eq!(h1, cex_receipt_hash(&event).expect("hash"));
        // Setting the row's own cexreceipthash to the computed value must NOT
        // change the recomputed hash (the field is excluded from the body).
        let mut with_hash = event;
        with_hash.cexreceipthash = Some(h1.clone());
        assert_eq!(cex_receipt_hash(&with_hash).expect("hash"), h1);
    }
}
