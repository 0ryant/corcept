//! Adversarial-recompute attack fixture (corcept level-up 2026-06-15).
//!
//! Proves the honest ceiling of the keyless hash chain and corrects the former
//! "PRIVATE prefix" overclaim: the domain-separation prefix
//! (`HASH_DOMAIN = "corcept:ledger:v1:"`) is PUBLIC and visible in source, so a
//! source-reading adversary can rewrite a committed row AND recompute the entire
//! hash chain over it. The keyless verify (`verify_ledger(.., false)`) therefore
//! FALSE-PASSES such an attack — it is a tamper-DETECTION checksum against
//! accidental corruption and naive edits, NOT tamper-EVIDENCE against an
//! adversary.
//!
//! Ed25519 signing (`verify_ledger(.., true)`) is what makes the ledger
//! tamper-evident in that threat model: the adversary cannot forge a signature
//! without the operator's private key, so the signed verifier CATCHES the
//! recompute attack and NAMES the failing row.
//!
//! This is a DETERMINISTIC integrity proof, not a model-lift claim: it asserts a
//! property of the verifier (signed catches what keyless cannot), proven by
//! construction. The control arm (clean signed ledger passes both modes) rules
//! out a vacuous "signed always fails" result.
//!
//! Doctrine: ADR-0006 (event-ledger-hash-chain), ADR-0021 (canonical hashing),
//! ADR-0025 (signed ledger rows — "hash chain detects tamper but does not
//! provide non-repudiation"). No ADR is violated; this only documents and tests
//! the boundary those ADRs already draw.

use corcept_ledger::{
    append_event, generate_operator_key, hash_event_hardened, ledger_path, verify_ledger,
    VerifyFailureReason, HASH_DOMAIN,
};
use corcept_types::{AuthorityLevel, LedgerEvent, LedgerEventKind, LEDGER_EVENT_SCHEMA};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Serializes the env-sensitive scenarios in THIS test binary. `append_event`
/// signing and `--signed` trust-dir resolution both read process-global env
/// (`CORCEPT_DATA_HOME` / `CORCEPT_TRUSTED_HISTORY`); without a lock the
/// multi-threaded test runner races them.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn sample_event(kind: LedgerEventKind, decision: &str) -> LedgerEvent {
    LedgerEvent {
        schema: LEDGER_EVENT_SCHEMA.to_string(),
        id: String::new(),
        ts: String::new(),
        session_id: Some("sess-recompute".to_string()),
        actor: "agent".to_string(),
        event_type: kind.wire_str().to_string(),
        authority_level: AuthorityLevel::L3ExecuteLocal,
        tool: Some("Bash".to_string()),
        target: Some("rm -rf /".to_string()),
        decision: Some(decision.to_string()),
        decision_reason: Some("policy".to_string()),
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
    std::env::remove_var("CORCEPT_ALLOW_LEGACY_HASH");
}

/// The adversary model: a source-reading attacker who edits a committed row and
/// then recomputes the WHOLE chain over the PUBLIC domain prefix. This rebuilds
/// every `hash`/`prev_hash` so the chain is internally consistent again, exactly
/// as `append_event` would have produced it. Signatures (if present) are left
/// untouched — the attacker cannot re-sign without the operator's private key.
fn adversary_recompute_chain(events: &mut [LedgerEvent]) {
    let mut previous: Option<String> = None;
    for event in events.iter_mut() {
        event.prev_hash = previous.clone();
        // Recompute the committed hash exactly as the ledger does, using the
        // PUBLIC HASH_DOMAIN prefix the attacker can read from source. The hash
        // covers neither `hash` nor `signature` (see canonical.rs), so the stale
        // signature does not perturb the recomputed digest.
        event.hash = Some(hash_event_hardened(event).unwrap());
        previous = event.hash.clone();
    }
}

/// Helper: write a slice of events back to the ledger file as JSONL.
fn write_ledger(dir: &std::path::Path, events: &[LedgerEvent]) {
    let body = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(ledger_path(dir), format!("{body}\n")).unwrap();
}

/// Read the ledger file back into events.
fn read_ledger(dir: &std::path::Path) -> Vec<LedgerEvent> {
    std::fs::read_to_string(ledger_path(dir))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// CORE PROOF. A signed ledger is rewritten by a source-reading adversary who
/// recomputes the entire public-prefix hash chain. The keyless verify
/// FALSE-PASSES; the signed verify CATCHES it and names the row.
#[test]
fn recompute_attack_false_passes_keyless_but_signed_catches_it() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_signing_env();

    // Build a SIGNED ledger (operator key present, trusted-history append on).
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("CORCEPT_DATA_HOME", dir.path());
    std::env::set_var("CORCEPT_TRUSTED_HISTORY", "1");
    generate_operator_key(false).unwrap();

    append_event(
        dir.path(),
        sample_event(LedgerEventKind::SessionStarted, "allow"),
    )
    .unwrap();
    // The row the auditor cares about: a denied dangerous command.
    let denied = append_event(
        dir.path(),
        sample_event(LedgerEventKind::ToolDecided, "deny"),
    )
    .unwrap();
    append_event(
        dir.path(),
        sample_event(LedgerEventKind::ToolDecided, "allow"),
    )
    .unwrap();
    assert!(
        denied.signature.is_some(),
        "rows must be signed: {denied:?}"
    );

    // Control sanity: the clean signed ledger passes BOTH modes.
    assert!(
        verify_ledger(dir.path(), false).unwrap().is_pass(),
        "clean keyless verify must pass"
    );
    assert!(
        verify_ledger(dir.path(), true).unwrap().is_pass(),
        "clean signed verify must pass"
    );

    // ADVERSARY: read the ledger, flip the denied row to "allow", and recompute
    // the ENTIRE chain over the public prefix. Signatures are left stale.
    let mut events = read_ledger(dir.path());
    assert_eq!(events[1].decision.as_deref(), Some("deny"));
    events[1].decision = Some("allow".to_string());
    adversary_recompute_chain(&mut events);
    write_ledger(dir.path(), &events);

    // (1) KEYLESS verify FALSE-PASSES: the recomputed chain is internally
    // consistent under the public prefix, so the keyless checksum is satisfied.
    // This is the honest ceiling — keyless = detection, not evidence.
    let keyless = verify_ledger(dir.path(), false).unwrap();
    assert!(
        keyless.is_pass(),
        "keyless verify FALSE-PASSES the recompute attack by construction (public prefix); \
         got {keyless:?}"
    );
    assert!(!keyless.tamper_detected, "{keyless:?}");

    // (2) SIGNED verify CATCHES it: the stale signature no longer matches the
    // rewritten preimage, and the attacker cannot forge a new one without the
    // operator's private key. The exact altered row is named.
    let signed = verify_ledger(dir.path(), true).unwrap();
    assert!(
        !signed.is_pass(),
        "signed verify must catch the recompute attack: {signed:?}"
    );
    assert!(signed.tamper_detected, "{signed:?}");
    assert!(
        signed.tampered_lines.contains(&2),
        "signed verify must name the tampered row (line 2): {signed:?}"
    );
    assert!(
        signed
            .failures
            .iter()
            .any(|f| f.line == 2 && f.reason == VerifyFailureReason::BadSignature),
        "the tampered row must fail with BadSignature: {signed:?}"
    );

    clear_signing_env();
}

/// The whole proof hinges on the prefix being PUBLIC. Pin that fact so a future
/// change that (mistakenly) treats the prefix as a secret breaks this test and
/// the documentation claim together.
#[test]
fn hash_domain_prefix_is_public_and_source_visible() {
    // A literal, in-source constant — the adversary reads exactly this.
    assert_eq!(HASH_DOMAIN, "corcept:ledger:v1:");
}

/// Negative control: an UNSIGNED ledger subjected to the same recompute attack
/// also false-passes the keyless verify (same ceiling) AND cannot be rescued by
/// `--signed`, because there is no signature to anchor trust. This distinguishes
/// "signing is the load-bearing element" from "any --signed run happens to
/// fail": an unsigned ledger fails `--signed` with MissingSignature (a
/// fail-closed verdict), i.e. the keyless chain alone is never tamper-evident.
#[test]
fn unsigned_recompute_attack_is_undetectable_even_with_signed_flag() {
    // Build the unsigned ledger directly (no `append_event`, so no dependence on
    // process-global signing env). Still take the lock because `--signed`
    // resolves the trust dir from env.
    let _guard = ENV_LOCK.lock().unwrap();
    clear_signing_env();

    let dir = tempfile::tempdir().unwrap();
    corcept_ledger::ensure_ledger(dir.path()).unwrap();

    let mut events = vec![
        sample_event(LedgerEventKind::SessionStarted, "allow"),
        sample_event(LedgerEventKind::ToolDecided, "deny"),
    ];
    for (i, e) in events.iter_mut().enumerate() {
        e.id = format!("evt_unsigned_{i}");
        e.ts = "2026-06-15T00:00:00.000Z".to_string();
    }
    // Build a clean, hardened, UNSIGNED hash chain.
    adversary_recompute_chain(&mut events);
    write_ledger(dir.path(), &events);
    assert!(
        events.iter().all(|e| e.signature.is_none()),
        "unsigned ledger has no signatures"
    );

    // Adversary flips the decision and recomputes the chain.
    events[1].decision = Some("allow".to_string());
    adversary_recompute_chain(&mut events);
    write_ledger(dir.path(), &events);

    // Keyless: false-pass (recomputed, internally consistent).
    assert!(
        verify_ledger(dir.path(), false).unwrap().is_pass(),
        "keyless verify false-passes the unsigned recompute attack"
    );

    // Signed flag on an unsigned ledger: fails CLOSED with MissingSignature on
    // every row — it never confers tamper-evidence retroactively. The fix is to
    // sign at append (CORCEPT_SIGN_LEDGER=1) and enforce at doctor --strict.
    let signed = verify_ledger(dir.path(), true).unwrap();
    assert!(!signed.is_pass(), "{signed:?}");
    assert!(
        signed
            .failures
            .iter()
            .any(|f| f.reason == VerifyFailureReason::MissingSignature),
        "unsigned rows must fail --signed with MissingSignature: {signed:?}"
    );

    clear_signing_env();
}
