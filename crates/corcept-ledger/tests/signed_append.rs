//! Integration tests for signed ledger append and verify.

use corcept_ledger::{
    append_event, generate_operator_key, verify_hash_chain, verify_ledger, VerifyFailureReason,
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
