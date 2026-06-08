//! Domain-separated canonical JSON for ledger hashing (ADR-0021).

use anyhow::Result;
use corcept_types::LedgerEvent;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const HASH_DOMAIN: &str = "corcept:ledger:v1:";

pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            Value::Object(sorted.into_iter().collect::<Map<_, _>>())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

pub fn hash_event_hardened(event: &LedgerEvent) -> Result<String> {
    let mut clone = event.clone();
    clone.hash = None;
    clone.signature = None;
    let value = serde_json::to_value(&clone)?;
    let canonical = serde_json::to_string(&canonicalize(&value))?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn hash_event_legacy(event: &LedgerEvent) -> Result<String> {
    let mut clone = event.clone();
    clone.hash = None;
    clone.signature = None;
    let canonical = serde_json::to_string(&clone)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// True when the operator has explicitly opted into accepting the legacy,
/// un-domain-separated hash format (`CORCEPT_ALLOW_LEGACY_HASH=1|true`).
///
/// The legacy format predates ADR-0021 and is NOT domain-separated or
/// canonicalized. Accepting it silently defeats the ADR-0021 hardening, so it
/// must be opt-in and off by default.
pub fn allow_legacy_hash() -> bool {
    std::env::var("CORCEPT_ALLOW_LEGACY_HASH")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Result of matching a stored hash against the known schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashMatch {
    /// Matches the ADR-0021 hardened (domain-separated, canonicalized) scheme.
    Hardened,
    /// Matches only the legacy un-hardened scheme (downgrade — surfaces a warning).
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

/// Verify a row's stored hash. The legacy un-domain-separated format is only
/// accepted when the operator opts in via `CORCEPT_ALLOW_LEGACY_HASH`; by
/// default only the ADR-0021 hardened scheme is accepted so that the
/// hardening is enforced rather than advisory.
pub fn verify_event_hash(event: &LedgerEvent) -> Result<bool> {
    Ok(match classify_event_hash(event)? {
        HashMatch::Hardened => true,
        HashMatch::Legacy => allow_legacy_hash(),
        HashMatch::None => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::{AuthorityLevel, LEDGER_EVENT_SCHEMA};
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
        }
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
        // Legacy (un-domain-separated) rows must NOT verify unless the
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
