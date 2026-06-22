//! Integration tests for signed ledger append and verify.

use corcept_ledger::{
    append_event, generate_operator_key, hash_event_legacy, ledger_path, verify_hash_chain,
    verify_ledger, VerifyFailureReason,
};
use corcept_types::{AuthorityLevel, LedgerEventKind, LEDGER_EVENT_SCHEMA};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

/// Serializes the tests that mutate process-global signing env vars
/// (`CORCEPT_DATA_HOME`, `CORCEPT_TRUSTED_HISTORY`, `CORCEPT_SIGN_LEDGER`,
/// `CORCEPT_ALLOW_LEGACY_HASH`). `cargo test` runs the tests in this binary on
/// parallel threads, and `std::env::set_var`/`remove_var` are process-wide, so
/// without this lock one signing test can clobber another's env mid-run — a
/// 1-in-5 flake under `cargo test --workspace`. Holding the guard for the whole
/// test body guarantees at most one env-mutating test touches these vars at a
/// time. The hash-chain tamper test deliberately takes no lock (see its note).
static SIGNING_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the signing-env lock, recovering from poisoning so that one panicking
/// (failed-assertion) test does not turn every serialized sibling into a
/// confusing `PoisonError` instead of its real verdict.
fn lock_signing_env() -> MutexGuard<'static, ()> {
    SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
        cexauthorityclass: None,
        cextrustceiling: None,
        cexsessionid: None,
        cexparenttrace: None,
        cexdoctrinecite: None,
        cexreceipthash: None,
        cexrevocation: None,
    }
}

fn clear_signing_env() {
    std::env::remove_var("CORCEPT_DATA_HOME");
    std::env::remove_var("CORCEPT_TRUSTED_HISTORY");
    std::env::remove_var("CORCEPT_SIGN_LEDGER");
}

#[test]
fn signed_and_unsigned_verify_modes() {
    let _env_guard = lock_signing_env();
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
    let _env_guard = lock_signing_env();
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

#[test]
fn tampered_row_sets_typed_top_level_verdict() {
    // Intentionally does NOT mutate process-global signing env vars: the
    // hash-chain tamper verdict is independent of signing mode (verified with
    // require_signed=false), so this test stays isolation-safe even when run in
    // parallel with the env-mutating signing tests in this file. The tamper is
    // a hard HashMismatch (kept-old-hash), which is rejected regardless of the
    // legacy-hash opt-in, so this test reads no signing/legacy env vars either.
    let dir = tempfile::tempdir().unwrap();
    // Two clean, hardened rows from append_event.
    append_event(dir.path(), sample_event(LedgerEventKind::SessionStarted)).unwrap();
    let second = append_event(dir.path(), sample_event(LedgerEventKind::SessionStarted)).unwrap();

    // Sanity: clean ledger -> no tamper, empty tampered_lines.
    let clean = verify_ledger(dir.path(), false).unwrap();
    assert!(clean.is_pass(), "{clean:?}");
    assert!(!clean.tamper_detected, "{clean:?}");
    assert!(clean.tampered_lines.is_empty(), "{clean:?}");

    // Tamper: rewrite the second row's payload but keep its committed hash, so a
    // naive hand-rolled SHA-256 would never reproduce the (domain-separated)
    // digest. Only the canonical verifier owns this verdict.
    let raw = std::fs::read_to_string(ledger_path(dir.path())).unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    let mut tampered: corcept_types::LedgerEvent =
        serde_json::from_str(&lines[1]).unwrap();
    tampered.decision = Some("deny".to_string());
    tampered.hash = second.hash.clone(); // keep the OLD hash -> mismatch
    lines[1] = serde_json::to_string(&tampered).unwrap();
    std::fs::write(ledger_path(dir.path()), format!("{}\n", lines.join("\n"))).unwrap();

    let report = verify_ledger(dir.path(), false).unwrap();
    assert!(!report.is_pass(), "{report:?}");
    assert!(report.tamper_detected, "{report:?}");
    assert_eq!(report.status, "fail");
    assert_eq!(report.tampered_lines, vec![2], "{report:?}");
    assert!(report
        .failures
        .iter()
        .any(|f| f.reason == VerifyFailureReason::HashMismatch));
}
