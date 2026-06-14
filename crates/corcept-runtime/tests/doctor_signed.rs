//! `corcept doctor --strict` must fail closed on an unsigned audit-bearing ledger.
//!
//! An unsigned hash chain alone is not tamper-evident: an adversary who can rewrite
//! `events.jsonl` can recompute the chain. Strict doctor therefore HARD-FAILS unless
//! every audit row carries a valid Ed25519 signature verifiable against the operator
//! trust store. This test exercises the three load-bearing paths in one serial test
//! because the signing posture is selected by process-global env vars.

use corcept_ledger::{append_event, generate_operator_key};
use corcept_runtime::{doctor_with_options, init_project, DoctorOptions, InitOptions};
use corcept_types::{AuthorityLevel, LedgerEvent, LedgerEventKind, LEDGER_EVENT_SCHEMA};
use std::collections::BTreeMap;
use std::path::Path;

fn sample_event() -> LedgerEvent {
    LedgerEvent {
        schema: LEDGER_EVENT_SCHEMA.to_string(),
        id: String::new(),
        ts: String::new(),
        session_id: Some("sess-doctor".to_string()),
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
    }
}

fn clear_signing_env() {
    std::env::remove_var("CORCEPT_DATA_HOME");
    std::env::remove_var("CORCEPT_TRUSTED_HISTORY");
    std::env::remove_var("CORCEPT_SIGN_LEDGER");
}

fn init_project_at(root: &Path) {
    init_project(InitOptions {
        path: root.to_path_buf(),
        dry_run: false,
        force: false,
    })
    .unwrap();
}

fn strict() -> DoctorOptions {
    DoctorOptions {
        validate_perms: false,
        strict: true,
    }
}

fn ledger_signed_check(report: &corcept_runtime::DoctorReport) -> &corcept_runtime::CheckResult {
    report
        .checks
        .iter()
        .find(|c| c.name == "ledger_signed")
        .expect("strict doctor must emit a ledger_signed check")
}

#[test]
fn strict_doctor_fails_closed_on_unsigned_and_passes_when_signed() {
    clear_signing_env();

    // --- (1) empty ledger: nothing to protect yet -> ledger_signed passes.
    let empty_dir = tempfile::tempdir().unwrap();
    init_project_at(empty_dir.path());
    let empty_report = doctor_with_options(empty_dir.path(), strict()).unwrap();
    assert_eq!(
        ledger_signed_check(&empty_report).status,
        "pass",
        "empty ledger has no audit rows to sign: {empty_report:?}"
    );

    // --- (2) unsigned audit-bearing ledger: strict doctor HARD-FAILS.
    let unsigned_dir = tempfile::tempdir().unwrap();
    init_project_at(unsigned_dir.path());
    let appended = append_event(unsigned_dir.path(), sample_event()).unwrap();
    assert!(
        appended.signature.is_none(),
        "no trusted-history env set, so the row must be unsigned"
    );
    let unsigned_report = doctor_with_options(unsigned_dir.path(), strict()).unwrap();
    let check = ledger_signed_check(&unsigned_report);
    assert_eq!(
        check.status, "warn",
        "an unsigned audit row must fail the ledger_signed check: {unsigned_report:?}"
    );
    assert!(
        check.detail.contains("UNSIGNED"),
        "detail must name the unsigned-row gap, got: {}",
        check.detail
    );
    assert_eq!(
        unsigned_report.status, "fail",
        "strict doctor must report overall fail when the ledger is unsigned: {unsigned_report:?}"
    );

    // Without --strict the same ledger must NOT add the check and must not fail
    // (preserves existing non-strict behaviour for ordinary local use).
    let lenient_report = doctor_with_options(unsigned_dir.path(), DoctorOptions::default()).unwrap();
    assert!(
        lenient_report
            .checks
            .iter()
            .all(|c| c.name != "ledger_signed"),
        "ledger_signed is a strict-only check: {lenient_report:?}"
    );
    assert_ne!(
        lenient_report.status, "fail",
        "non-strict doctor never hard-fails on unsigned ledgers: {lenient_report:?}"
    );

    // --- (3) signed audit-bearing ledger: strict doctor passes the check.
    let signed_dir = tempfile::tempdir().unwrap();
    let data_home = tempfile::tempdir().unwrap();
    std::env::set_var("CORCEPT_DATA_HOME", data_home.path());
    std::env::set_var("CORCEPT_TRUSTED_HISTORY", "1");
    generate_operator_key(false).unwrap();
    init_project_at(signed_dir.path());
    let signed = append_event(signed_dir.path(), sample_event()).unwrap();
    assert!(
        signed.signature.is_some(),
        "CORCEPT_TRUSTED_HISTORY=1 must sign appended rows"
    );
    let signed_report = doctor_with_options(signed_dir.path(), strict()).unwrap();
    assert_eq!(
        ledger_signed_check(&signed_report).status,
        "pass",
        "a fully-signed ledger must pass ledger_signed: {signed_report:?}"
    );

    clear_signing_env();
}
