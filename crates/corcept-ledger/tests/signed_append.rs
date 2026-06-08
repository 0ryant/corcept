//! Integration tests for signed ledger append and verify.

use corcept_ledger::{
    append_event, generate_operator_key, hash_event_legacy, ledger_path, verify_hash_chain,
    verify_ledger, VerifyFailureReason,
};
use corcept_types::{AuthorityLevel, LedgerEventKind, LEDGER_EVENT_SCHEMA};
use std::collections::BTreeMap;

fn sample_event(kind: LedgerEventKind) -> corcept_types::LedgerEvent {
    corcept_types::LedgerEvent {
        schema: LEDGER_EVENT_SCHEMA.to_string(),
        id: String::new(),
        ts: String::new(),
        session_id: Some("sess-sign".to_string()),
        actor: "test".to_string(),
        event_type: kind.wire_str().to_string(),
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
    }
}

fn clear_signing_env() {
    std::env::remove_var("CORCEPT_DATA_HOME");
    std::env::remove_var("CORCEPT_TRUSTED_HISTORY");
    std::env::remove_var("CORCEPT_SIGN_LEDGER");
}

#[test]
fn signed_and_unsigned_verify_modes() {
    clear_signing_env();

    let unsigned_dir = tempfile::tempdir().unwrap();
    let appended = append_event(
        unsigned_dir.path(),
        sample_event(LedgerEventKind::SessionStarted),
    )
    .unwrap();
    assert!(appended.signature.is_none());
    let unsigned_report = verify_ledger(unsigned_dir.path(), true).unwrap();
    assert!(!unsigned_report.is_pass(), "{unsigned_report:?}");
    assert_eq!(
        unsigned_report.failures[0].reason,
        VerifyFailureReason::MissingSignature
    );

    let signed_dir = tempfile::tempdir().unwrap();
    std::env::set_var("CORCEPT_DATA_HOME", signed_dir.path());
    std::env::set_var("CORCEPT_TRUSTED_HISTORY", "1");
    generate_operator_key(false).unwrap();
    let signed = append_event(
        signed_dir.path(),
        sample_event(LedgerEventKind::SessionStarted),
    )
    .unwrap();
    assert!(signed.signature.is_some());
    let signed_report = verify_ledger(signed_dir.path(), true).unwrap();
    assert!(signed_report.is_pass(), "{signed_report:?}");
    assert!(verify_hash_chain(signed_dir.path()).unwrap());

    clear_signing_env();
}

#[test]
fn legacy_only_row_fails_by_default_but_warns_when_opted_in() {
    clear_signing_env();
    std::env::remove_var("CORCEPT_ALLOW_LEGACY_HASH");

    let dir = tempfile::tempdir().unwrap();
    let mut event = sample_event(LedgerEventKind::SessionStarted);
    event.id = "evt_legacy".to_string();
    event.ts = "2026-05-18T00:00:00.000Z".to_string();
    // Stamp a LEGACY (un-domain-separated) hash, bypassing append_event's
    // hardened hashing, to simulate an attacker-rewritten / pre-ADR-0021 row.
    event.hash = Some(hash_event_legacy(&event).unwrap());
    let line = serde_json::to_string(&event).unwrap();
    corcept_ledger::ensure_ledger(dir.path()).unwrap();
    std::fs::write(ledger_path(dir.path()), format!("{line}\n")).unwrap();

    // Default policy: legacy is rejected as a hard hash failure.
    let report = verify_ledger(dir.path(), false).unwrap();
    assert!(!report.is_pass(), "{report:?}");
    assert!(report
        .failures
        .iter()
        .any(|f| f.reason == VerifyFailureReason::LegacyHashFormat));
    assert!(!verify_hash_chain(dir.path()).unwrap());

    // Opt-in: legacy is accepted but surfaced as a non-fatal warning.
    std::env::set_var("CORCEPT_ALLOW_LEGACY_HASH", "1");
    let report = verify_ledger(dir.path(), false).unwrap();
    assert!(report.is_pass(), "{report:?}");
    assert!(report
        .warnings
        .iter()
        .any(|w| w.reason == VerifyFailureReason::LegacyHashFormat));
    assert!(verify_hash_chain(dir.path()).unwrap());

    std::env::remove_var("CORCEPT_ALLOW_LEGACY_HASH");
}
