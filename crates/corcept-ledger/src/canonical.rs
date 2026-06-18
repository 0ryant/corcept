//! Domain-separated canonical JSON for ledger hashing (ADR-0021).
//!
//! # AXIOM conformance (ADR-0003 / pattern 03)
//!
//! Content addressing is **BLAKE3** via [`axiom_hash::blake3_hex`], and the
//! canonical byte form is **RFC-8785 (JCS)** via [`axiom_canonical::to_jcs_bytes`].
//! This replaces the previous SHA-256 + hand-rolled key-sort. The stored hash
//! therefore carries the `blake3:` prefix. This is a BREAKING re-key of the
//! ledger hash chain: rows hashed under the old SHA-256 scheme will not verify
//! unless the operator opts into the legacy scheme (`CORCEPT_ALLOW_LEGACY_HASH`),
//! which exists only as a downgrade-with-warning bridge.
//!
//! The domain-separation prefix ([`HASH_DOMAIN`]) is retained: it binds a digest
//! to "this is a corcept ledger row" so a bare BLAKE3 of the same bytes cannot be
//! replayed into the chain. It is distinct from the cex corridor's
//! `cexreceipthash` (also BLAKE3, computed over a different body), which is left
//! untouched.

use anyhow::Result;
use corcept_types::LedgerEvent;
use serde_json::Value;

/// Domain prefix bound into the hashed bytes (ADR-0021). Binds a digest to the
/// corcept ledger so a bare content hash cannot be replayed into the chain.
pub const HASH_DOMAIN: &str = "corcept:ledger:v1:";

/// BLAKE3 content-address prefix for hardened ledger hashes (ADR-0003).
pub const HASH_PREFIX: &str = "blake3:";

/// Legacy SHA-256 prefix, retained only so [`classify_event_hash`] can detect a
/// downgrade and surface it. No new hashes are written with this prefix.
const LEGACY_PREFIX: &str = "sha256:";

/// Compute the hardened content address of an event: `blake3:<hex>` over
/// `HASH_DOMAIN || JCS(event sans hash/signature)`.
///
/// JCS (RFC-8785) sorts object keys recursively, so the digest is independent of
/// serialization order. `hash` and `signature` are excluded so the digest is
/// self-consistent (it cannot cover itself).
pub fn hash_event_hardened(event: &LedgerEvent) -> Result<String> {
    let mut clone = event.clone();
    clone.hash = None;
    clone.signature = None;
    let canonical = axiom_canonical::to_jcs_bytes(&clone)?;
    let mut material = HASH_DOMAIN.as_bytes().to_vec();
    material.extend_from_slice(&canonical);
    Ok(format!("{HASH_PREFIX}{}", axiom_hash::blake3_hex(&material)))
}

/// Legacy un-domain-separated SHA-256 hash kept ONLY for downgrade detection.
///
/// This reproduces the pre-ADR-0003 (and pre-ADR-0021) scheme so
/// [`classify_event_hash`] can recognise an old row and report the downgrade.
/// It is never written for new rows.
pub fn hash_event_legacy(event: &LedgerEvent) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut clone = event.clone();
    clone.hash = None;
    clone.signature = None;
    let canonical = serde_json::to_string(&clone)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(format!("{LEGACY_PREFIX}{}", hex::encode(hasher.finalize())))
}

/// True when the operator has explicitly opted into accepting the legacy
/// SHA-256, un-domain-separated hash format (`CORCEPT_ALLOW_LEGACY_HASH=1|true`).
///
/// The legacy format predates ADR-0003/ADR-0021 and is neither BLAKE3,
/// domain-separated, nor JCS-canonicalized. Accepting it silently defeats the
/// hardening, so it must be opt-in and off by default.
pub fn allow_legacy_hash() -> bool {
    std::env::var("CORCEPT_ALLOW_LEGACY_HASH")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Result of matching a stored hash against the known schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashMatch {
    /// Matches the ADR-0003 hardened (BLAKE3, domain-separated, JCS) scheme.
    Hardened,
    /// Matches only the legacy SHA-256 scheme (downgrade — surfaces a warning).
    Legacy,
    /// Matches neither scheme (tampered or missing).
    None,
}

/// Classify how the stored hash matches, independent of whether the legacy
/// scheme is accepted. Callers decide whether `Legacy` counts as valid.
pub fn classify_event_hash(event: &LedgerEvent) -> Result<HashMatch> {
    let Some(stored) = event.hash.as_deref() else {
        return Ok(HashMatch::None);
    };
    if stored == hash_event_hardened(event)? {
        return Ok(HashMatch::Hardened);
    }
    if stored == hash_event_legacy(event)? {
        return Ok(HashMatch::Legacy);
    }
    Ok(HashMatch::None)
}

/// Verify a row's stored hash. The legacy SHA-256 format is only accepted when
/// the operator opts in via `CORCEPT_ALLOW_LEGACY_HASH`; by default only the
/// ADR-0003 hardened BLAKE3 scheme is accepted so that the hardening is enforced
/// rather than advisory.
pub fn verify_event_hash(event: &LedgerEvent) -> Result<bool> {
    Ok(match classify_event_hash(event)? {
        HashMatch::Hardened => true,
        HashMatch::Legacy => allow_legacy_hash(),
        HashMatch::None => false,
    })
}

/// Recursively sort object keys. Retained for callers that need a stable
/// `serde_json::Value` ordering for display; the *hash* path uses JCS directly.
#[must_use]
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::{AuthorityLevel, LEDGER_EVENT_SCHEMA};
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn sample_event() -> LedgerEvent {
        LedgerEvent {
            schema: LEDGER_EVENT_SCHEMA.to_string(),
            id: "evt_test".to_string(),
            ts: "2026-05-18T00:00:00.000Z".to_string(),
            session_id: Some("s".to_string()),
            actor: "test".to_string(),
            event_type: "corcept.event.tool_requested.v1".to_string(),
            authority_level: AuthorityLevel::L3ExecuteLocal,
            tool: Some("Bash".to_string()),
            target: Some("rm -rf /".to_string()),
            decision: Some("deny".to_string()),
            decision_reason: Some("blocked".to_string()),
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

    #[test]
    fn hardened_hash_is_blake3_prefixed() {
        let event = sample_event();
        let h = hash_event_hardened(&event).unwrap();
        assert!(h.starts_with("blake3:"), "expected blake3 prefix, got {h}");
        assert!(!h.starts_with("sha256:"));
        // blake3: + 64 lowercase hex chars.
        assert_eq!(h.len(), "blake3:".len() + 64);
    }

    #[test]
    fn key_reorder_does_not_change_hardened_hash() {
        let event = sample_event();
        let h1 = hash_event_hardened(&event).unwrap();
        let mut value = serde_json::to_value(&event).unwrap();
        if let Value::Object(map) = &mut value {
            let decision = map.remove("decision").unwrap();
            map.insert("decision".to_string(), decision);
        }
        let mut reordered: LedgerEvent = serde_json::from_value(value).unwrap();
        reordered.hash = None;
        let h2 = hash_event_hardened(&reordered).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn tampered_decision_fails_verify() {
        let event = sample_event();
        let hash = hash_event_hardened(&event).unwrap();
        let mut tampered = event.clone();
        tampered.decision = Some("allow".to_string());
        tampered.hash = Some(hash);
        assert!(!verify_event_hash(&tampered).unwrap());
    }

    #[test]
    fn legacy_hash_rejected_by_default() {
        // Legacy (SHA-256, un-domain-separated) rows must NOT verify unless the
        // operator explicitly opts in. classify_event_hash still reports the
        // downgrade so operators can be warned.
        let event = sample_event();
        let hash = hash_event_legacy(&event).unwrap();
        let mut stored = event.clone();
        stored.hash = Some(hash);
        assert_eq!(classify_event_hash(&stored).unwrap(), HashMatch::Legacy);
        // Without the opt-in env var, the default policy rejects legacy.
        assert!(!allow_legacy_hash());
        assert!(!verify_event_hash(&stored).unwrap());
    }

    #[test]
    fn hardened_hash_classifies_as_hardened() {
        let event = sample_event();
        let hash = hash_event_hardened(&event).unwrap();
        let mut stored = event.clone();
        stored.hash = Some(hash);
        assert_eq!(classify_event_hash(&stored).unwrap(), HashMatch::Hardened);
        assert!(verify_event_hash(&stored).unwrap());
    }
}
