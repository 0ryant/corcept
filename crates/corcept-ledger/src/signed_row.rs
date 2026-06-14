//! Ed25519 signed ledger rows (ADR-0025).

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, Utc};
use corcept_types::{LedgerEvent, RowSignature};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::canonical::hash_event_hardened;

pub const SIGN_DOMAIN: &str = "corcept:ledger:sign:v1:";
pub const ATTESTATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyFailureReason {
    MissingSignature,
    BadSignature,
    UnknownKeyId,
    UnknownAttestationSchemaVersion,
    HashMismatch,
    HashChainBreak,
    /// Row verifies only under the legacy un-domain-separated hash scheme.
    /// The ADR-0021 hardening is not in effect for this row (downgrade).
    LegacyHashFormat,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyFailure {
    pub line: usize,
    pub event_id: Option<String>,
    pub reason: VerifyFailureReason,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyReport {
    pub status: String,
    pub hash_chain_valid: bool,
    pub signed_mode: bool,
    pub rows_scanned: usize,
    /// Explicit, top-level tamper verdict. `true` iff the chain failed
    /// integrity (status == "fail"). A consumer must never re-derive this by
    /// hand-hashing rows: the chain is domain-separated under a private prefix
    /// (see `HASH_DOMAIN` / `SIGN_DOMAIN`), so a naive SHA-256 over the row
    /// bytes will not reproduce the committed digest and will false-flag a
    /// clean ledger. Read this field verbatim.
    #[serde(default)]
    pub tamper_detected: bool,
    /// 1-based line numbers (matching `failures[].line`) of every row that
    /// failed integrity. Empty on a clean ledger.
    #[serde(default)]
    pub tampered_lines: Vec<usize>,
    pub failures: Vec<VerifyFailure>,
    /// Non-fatal downgrade notices (e.g. a row that only matches the legacy
    /// un-domain-separated hash scheme while the operator has opted into
    /// accepting legacy hashes). Surfaced so the downgrade is never silent.
    #[serde(default)]
    pub warnings: Vec<VerifyFailure>,
}

impl VerifyReport {
    pub fn is_pass(&self) -> bool {
        self.status == "pass"
    }
}

pub fn key_fingerprint(pubkey: &VerifyingKey) -> String {
    let digest = Sha256::digest(pubkey.as_bytes());
    format!("fp:{}", hex::encode(&digest[..16]))
}

pub fn signing_preimage(event: &LedgerEvent) -> Result<Vec<u8>> {
    let hash = hash_event_hardened(event)?;
    Ok(format!("{SIGN_DOMAIN}{hash}").into_bytes())
}

pub fn sign_event(event: &LedgerEvent, signing_key: &SigningKey) -> Result<RowSignature> {
    let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let verifying_key = signing_key.verifying_key();
    let key_id = key_fingerprint(&verifying_key);
    let sig = signing_key.sign(&signing_preimage(event)?);
    Ok(RowSignature {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        key_id,
        signed_at,
        bytes: STANDARD.encode(sig.to_bytes()),
    })
}

pub fn verify_row_signature(
    event: &LedgerEvent,
    trust_dir: impl AsRef<Path>,
) -> Result<Result<(), VerifyFailureReason>> {
    let Some(sig) = event.signature.as_ref() else {
        return Ok(Err(VerifyFailureReason::MissingSignature));
    };
    if sig.schema_version != ATTESTATION_SCHEMA_VERSION {
        return Ok(Err(VerifyFailureReason::UnknownAttestationSchemaVersion));
    }
    let pubkey = load_trust_pubkey(trust_dir.as_ref(), &sig.key_id)?;
    let Some(pubkey) = pubkey else {
        return Ok(Err(VerifyFailureReason::UnknownKeyId));
    };
    let Ok(bytes) = STANDARD.decode(&sig.bytes) else {
        return Ok(Err(VerifyFailureReason::BadSignature));
    };
    if bytes.len() != 64 {
        return Ok(Err(VerifyFailureReason::BadSignature));
    }
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
        return Ok(Err(VerifyFailureReason::BadSignature));
    };
    if pubkey
        .verify(&signing_preimage(event)?, &signature)
        .is_err()
    {
        return Ok(Err(VerifyFailureReason::BadSignature));
    }
    Ok(Ok(()))
}

pub fn load_trust_pubkey(trust_dir: &Path, key_id: &str) -> Result<Option<VerifyingKey>> {
    let path = trust_dir.join(format!("{key_id}.pub"));
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read(&path).with_context(|| format!("reading trust key {}", path.display()))?;
    if raw.len() != 32 {
        anyhow::bail!("trust pubkey {} must be 32 bytes", path.display());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(Some(VerifyingKey::from_bytes(&arr)?))
}

pub fn trusted_history_enabled() -> bool {
    std::env::var("CORCEPT_TRUSTED_HISTORY")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::{AuthorityLevel, LEDGER_EVENT_SCHEMA};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn sample_event() -> LedgerEvent {
        LedgerEvent {
            schema: LEDGER_EVENT_SCHEMA.to_string(),
            id: "evt_sign".to_string(),
            ts: "2026-05-18T12:00:00.000Z".to_string(),
            session_id: Some("s1".to_string()),
            actor: "test".to_string(),
            event_type: "corcept.event.tool_decided.v1".to_string(),
            authority_level: AuthorityLevel::L3ExecuteLocal,
            tool: Some("Bash".to_string()),
            target: Some("rm -rf /".to_string()),
            decision: Some("deny".to_string()),
            decision_reason: Some("blocked".to_string()),
            evidence_refs: vec![],
            prev_hash: None,
            hash: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
            metadata: BTreeMap::new(),
            signature: None,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let dir = tempfile::tempdir().unwrap();
        let trust = dir.path().join("trust");
        std::fs::create_dir_all(&trust).unwrap();
        let fp = key_fingerprint(&verifying_key);
        std::fs::write(trust.join(format!("{fp}.pub")), verifying_key.as_bytes()).unwrap();

        let mut event = sample_event();
        event.signature = Some(sign_event(&event, &signing_key).unwrap());
        assert!(verify_row_signature(&event, &trust).unwrap().is_ok());
    }

    #[test]
    fn tampered_hash_fails_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let dir = tempfile::tempdir().unwrap();
        let trust = dir.path().join("trust");
        std::fs::create_dir_all(&trust).unwrap();
        let fp = key_fingerprint(&verifying_key);
        std::fs::write(trust.join(format!("{fp}.pub")), verifying_key.as_bytes()).unwrap();

        let mut event = sample_event();
        event.signature = Some(sign_event(&event, &signing_key).unwrap());
        event.decision = Some("allow".to_string());
        assert_eq!(
            verify_row_signature(&event, &trust).unwrap(),
            Err(VerifyFailureReason::BadSignature)
        );
    }

    #[test]
    fn missing_signature_is_typed() {
        let dir = tempfile::tempdir().unwrap();
        let event = sample_event();
        assert_eq!(
            verify_row_signature(&event, dir.path()).unwrap(),
            Err(VerifyFailureReason::MissingSignature)
        );
    }
}
