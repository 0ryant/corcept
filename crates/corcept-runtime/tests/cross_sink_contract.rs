//! Cross-surface contract parity: ledger authority vs CloudEvents projection.

use corcept_ledger::{append_event, ensure_ledger};
use corcept_runtime::{handle_hook, init_project, InitOptions};
use corcept_sink_cloudevents::{event_fingerprint, export_cloudevents, project_event};
use corcept_types::{AuthorityLevel, LedgerEventKind, LEDGER_EVENT_SCHEMA};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

#[test]
fn hook_ledger_and_cloudevents_share_ids_and_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    init_project(InitOptions {
        path: dir.path().to_path_buf(),
        dry_run: false,
        force: false,
    })
    .unwrap();

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hooks/pretool-bash-rm-rf.json");
    let raw = fs::read_to_string(&root).unwrap();
    let mut input: Value = serde_json::from_str(&raw).unwrap();
    input["cwd"] = Value::String(dir.path().to_string_lossy().into_owned());
    let input = serde_json::to_string(&input).unwrap();
    handle_hook(&input, "pretool-guard").unwrap();

    let ledger_path = dir.path().join(".corcept/ledger/events.jsonl");
    let out = dir.path().join("audit-ce.jsonl");
    let count = export_cloudevents(&ledger_path, &out).unwrap();
    assert_eq!(count, 1);

    let ledger_line = fs::read_to_string(&ledger_path).unwrap();
    let event: corcept_types::LedgerEvent = serde_json::from_str(ledger_line.trim()).unwrap();
    let ce_line = fs::read_to_string(&out).unwrap();
    let ce: serde_json::Value = serde_json::from_str(ce_line.trim()).unwrap();

    assert_eq!(
        ce.get("id").and_then(|v| v.as_str()),
        Some(event.id.as_str())
    );
    assert_eq!(
        ce.get("corcepteventfingerprint").and_then(|v| v.as_str()),
        Some(event_fingerprint(&event).as_str())
    );
    assert_eq!(
        ce.get("type").and_then(|v| v.as_str()),
        Some(project_event(&event).ty.as_str())
    );
}

#[test]
fn export_does_not_mutate_ledger() {
    let dir = tempfile::tempdir().unwrap();
    ensure_ledger(dir.path()).unwrap();
    append_event(
        dir.path(),
        corcept_types::LedgerEvent {
            schema: LEDGER_EVENT_SCHEMA.to_string(),
            id: "evt_export".to_string(),
            ts: "2026-05-18T12:00:00.000Z".to_string(),
            session_id: Some("s".to_string()),
            actor: "test".to_string(),
            event_type: LedgerEventKind::SessionStarted.wire_str().to_string(),
            authority_level: AuthorityLevel::L0Observe,
            tool: None,
            target: None,
            decision: Some("allow".to_string()),
            decision_reason: None,
            evidence_refs: vec![],
            prev_hash: None,
            hash: None,
            metadata: BTreeMap::new(),
            signature: None,
        },
    )
    .unwrap();

    let ledger_path = dir.path().join(".corcept/ledger/events.jsonl");
    let before = fs::read_to_string(&ledger_path).unwrap();
    export_cloudevents(&ledger_path, &dir.path().join("ce.jsonl")).unwrap();
    let after = fs::read_to_string(&ledger_path).unwrap();
    assert_eq!(before, after);
}
