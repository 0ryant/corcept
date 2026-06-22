//! `axiom.audit.v1` BLAKE3-chained audit trail and `axiom.receipt.v1` receipt
//! emission for corcept (pattern 07 + pattern 09).
//!
//! corcept's authority ledger ([`crate::append_event`], `.corcept/ledger/events.jsonl`)
//! is a domain-separated, optionally Ed25519-signed hash chain (ADR-0021/0025).
//! It is the per-session governance record. This module adds the *doctrine*
//! substrate **alongside** it — without re-keying or re-genesis-ing the
//! authority ledger:
//!
//! * an append-only, hash-chained `audit-trail.jsonl` at the repo root
//!   (`seq` / `prev_hash` / `row_hash = BLAKE3(JCS(row))` / genesis), via the
//!   shared [`axiom_audit`] crate; it records each CLI verb invocation; and
//! * a signed `axiom.receipt.v1` receipt carrying BLAKE3 digests of the artifacts
//!   an operation touched plus an `audit_chain` linkage back to the trail tip,
//!   via the shared [`axiom_receipt`] mechanism. This is the real receipt that
//!   replaces the thin `corcept.sink_record.v1` diagnostic.
//!
//! The receipt is signed in-process with a **pinned dev Ed25519 seed** (the same
//! RFC-8032 test-vector seed the reference tools use). It is not a secret: a
//! verifier checks the signature against the pinned public key. corcept does not
//! hold a production key here, so a verifier treats the signature as proof the
//! receipt was produced by a corcept build, not as an organizational attestation.
//! (Operator-key Ed25519 attestation of authority rows stays in
//! [`crate::signed_row`].)

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use axiom_audit::{AuditEntry, ReceiptLink};
use axiom_receipt::{Ed25519Signer, Jcs, KeyClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::key;

pub use axiom_audit::{ChainVerdict, AUDIT_SCHEMA, GENESIS_HASH, TRAIL_FILENAME};

/// Receipt schema tag. Verifiers reject anything else.
pub const RECEIPT_SCHEMA: &str = "axiom.receipt.v1";

/// Canonical tool name embedded in every audit row and receipt.
pub const TOOL_NAME: &str = "corcept";

/// corcept version stamped into rows/receipts.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Identifier of the pinned in-process receipt-signing key. Re-exported from
/// [`crate::key`], the single source of truth for the receipt signer.
pub const PINNED_KEY_ID: &str = key::PINNED_KEY_ID;

/// Errors from the audit-trail / receipt path.
#[derive(Debug, Error)]
pub enum TrailError {
    /// Underlying audit-chain error (IO, parse, canonicalization).
    #[error("audit-trail error: {0}")]
    Audit(#[from] axiom_audit::AuditError),

    /// Receipt signing / canonicalization error.
    #[error("receipt error: {0}")]
    Receipt(#[from] axiom_receipt::ReceiptError),

    /// Content hashing of an input/output artifact failed.
    #[error("hash error: {0}")]
    Hash(#[from] axiom_hash::HashError),

    /// Receipt JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, TrailError>;

/// The pinned in-process receipt signer (the verification anchor; the *active*
/// signer used to produce receipts may be a deployment key, see [`key`]).
#[must_use]
fn signer() -> Ed25519Signer {
    key::pinned_signer()
}

/// A cross-process advisory lock guarding read-then-append on a single
/// `audit-trail.jsonl`.
///
/// [`axiom_audit::append`] reads the tip then appends and is **not** atomic
/// across processes: two corcept CLI invocations targeting the same repo root
/// can each read the same tip and interleave their writes, concatenating two
/// rows onto one physical line — a malformed-JSONL corruption no later read can
/// parse. Serializing the whole tip-read → receipt-write → row-append critical
/// section behind this lock makes concurrent emission safe with no new dep.
///
/// The lock is a sibling `audit-trail.jsonl.lock` file created with `create_new`
/// (the portable atomic test-and-set on Windows and Unix). The guard removes it
/// on drop. A bounded spin-retry tolerates a crashed holder by breaking a stale
/// lock.
#[derive(Debug)]
pub struct TrailLock {
    path: PathBuf,
}

impl TrailLock {
    /// Acquire the lock guarding `<repo>/audit-trail.jsonl`. Blocks (bounded
    /// spin) until the lock is free or a stale lock is reclaimed.
    ///
    /// # Errors
    /// [`TrailError::Audit`] wrapping an IO error if the lock directory cannot be
    /// created or the lock cannot be taken within the deadline.
    pub fn acquire(repo: &Path) -> Result<Self> {
        if let Err(e) = std::fs::create_dir_all(repo) {
            return Err(audit_io(e));
        }
        let path = repo.join(format!("{TRAIL_FILENAME}.lock"));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Self::reclaim_if_stale(&path);
                    if Instant::now() >= deadline {
                        return Err(audit_io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("audit-trail lock {} held too long", path.display()),
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(audit_io(e)),
            }
        }
    }

    /// Reclaim a lock whose holder appears to have crashed (file older than the
    /// max critical-section budget). Best-effort: a benign race where another
    /// process removes it first is ignored.
    fn reclaim_if_stale(path: &Path) {
        const STALE_AFTER: Duration = Duration::from_secs(30);
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().map(|d| d > STALE_AFTER).unwrap_or(false) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

impl Drop for TrailLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Wrap a `std::io::Error` as an [`axiom_audit::AuditError`] so lock failures
/// surface through the same [`TrailError::Audit`] channel as append failures.
fn audit_io(e: std::io::Error) -> TrailError {
    TrailError::Audit(axiom_audit::AuditError::Io(e))
}

/// The pinned public key (lowercase hex) a verifier checks receipt signatures
/// against.
#[must_use]
pub fn pinned_public_key_hex() -> String {
    hex_encode(&signer().verifying_key_bytes())
}

/// Append one `axiom.audit.v1` row to `<repo>/audit-trail.jsonl`, computing
/// `seq` / `prev_hash` / `row_hash` from the trail tip. Returns the appended row.
///
/// `outcome` is the pattern-07/09 vocabulary (`"ok" | "failed" | "degraded"`);
/// `exit_code` is the pattern-11 process code for the operation. When a receipt
/// was written, pass its repo-relative path and BLAKE3 so the row links it.
///
/// # Errors
/// [`TrailError::Audit`] on a read/write/canonicalization failure.
pub fn append_audit(
    repo: &Path,
    operation: &str,
    outcome: &str,
    exit_code: i32,
    timestamp: &str,
    receipt: ReceiptLink,
) -> Result<axiom_audit::AuditRow> {
    let trail = repo.join(TRAIL_FILENAME);
    let row = axiom_audit::append(
        &trail,
        &AuditEntry {
            tool: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            operation: operation.to_string(),
            timestamp: timestamp.to_string(),
            outcome: outcome.to_string(),
            exit_code,
            receipt,
        },
    )?;
    Ok(row)
}

/// Verify the `<repo>/audit-trail.jsonl` chain end to end (pattern 09): schema,
/// monotonic `seq`, genesis-anchored links, and that every `row_hash`
/// recomputes. Fail-closed: returns a typed [`ChainVerdict`], never panics.
///
/// # Errors
/// [`TrailError::Audit`] if the trail cannot be read or a row cannot be re-hashed.
pub fn verify_trail(repo: &Path) -> Result<ChainVerdict> {
    Ok(axiom_audit::verify_chain(&repo.join(TRAIL_FILENAME))?)
}

/// A content-addressed artifact: a kind, a path, and its BLAKE3 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// `"file" | "dir" | "ledger" | "candidate" | ...`.
    pub kind: String,
    /// Path (repo-relative where applicable).
    pub path: String,
    /// Lowercase-hex BLAKE3 of the artifact's content.
    pub blake3: String,
}

impl Artifact {
    /// Content-address a file on disk (BLAKE3).
    ///
    /// # Errors
    /// [`TrailError::Hash`] if the file cannot be read.
    pub fn of_file(kind: &str, path: &str, on_disk: &Path) -> Result<Self> {
        Ok(Self {
            kind: kind.to_string(),
            path: path.to_string(),
            blake3: axiom_hash::blake3_file(on_disk)?,
        })
    }

    /// Content-address in-memory bytes (BLAKE3).
    #[must_use]
    pub fn of_bytes(kind: &str, path: &str, bytes: &[u8]) -> Self {
        Self {
            kind: kind.to_string(),
            path: path.to_string(),
            blake3: axiom_hash::blake3_hex(bytes),
        }
    }
}

/// `audit_chain` linkage embedded in a receipt (pattern 07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLink {
    /// Repo-relative path to the trail file (`audit-trail.jsonl`).
    pub trail_path: String,
    /// `seq` of the row this operation appended.
    pub seq: u64,
    /// `row_hash` of that row (the trail tip after this operation).
    pub row_hash: String,
}

/// The canonical, signed body of an `axiom.receipt.v1` receipt for corcept.
///
/// The signature is computed over the RFC-8785 (JCS) canonical bytes of exactly
/// this struct, so any verifier recomputes identical bytes. This replaces the
/// thin [`crate::SinkRecord`]-shaped `corcept.sink_record.v1` with a real
/// receipt: tool / operation / outcome / inputs+outputs (BLAKE3) / audit_chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Schema tag, always [`RECEIPT_SCHEMA`].
    pub schema: String,
    /// Canonical tool name, always [`TOOL_NAME`].
    pub tool: String,
    /// Tool semver.
    pub tool_version: String,
    /// Operation that produced the receipt (e.g. `"audit verify"`, `"export"`).
    pub operation: String,
    /// Pattern-07 outcome vocabulary: `"ok" | "failed" | "degraded"`.
    pub outcome: String,
    /// Inputs operated on, each content-addressed with BLAKE3.
    pub inputs: Vec<Artifact>,
    /// Outputs produced, each content-addressed with BLAKE3.
    pub outputs: Vec<Artifact>,
    /// Audit-chain linkage to the appended trail row.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub audit_chain: Option<AuditLink>,
    /// Doctrine citations grounding corcept's claims (free-form anchors).
    pub doctrine_citations: Vec<String>,
    /// RFC-3339 creation timestamp.
    pub created_at: String,
    /// Identifier of the key the signature is under.
    pub key_id: String,
    /// Signing-key tier: `dev` (the pinned demo key — mechanism, not origin) or
    /// `deployment` (a configured `CORCEPT_SIGNING_SEED_HEX` deployment key —
    /// origin-grade once its trust root is published). Stamped inside the signed
    /// body so it cannot be relabelled after signing.
    pub key_class: KeyClass,
}

impl ReceiptBody {
    /// Build a body with the fixed identity fields filled in.
    #[must_use]
    pub fn new(operation: &str, outcome: &str, created_at: &str) -> Self {
        Self {
            schema: RECEIPT_SCHEMA.to_string(),
            tool: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            operation: operation.to_string(),
            outcome: outcome.to_string(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            audit_chain: None,
            doctrine_citations: default_citations(),
            created_at: created_at.to_string(),
            key_id: key::active_key_id(),
            key_class: key::active_key_class(),
        }
    }
}

/// Default doctrine citations for a corcept receipt.
#[must_use]
fn default_citations() -> Vec<String> {
    vec![
        "ecosystem-catalog/standardisation/CONFORMANCE.md#corcept".to_string(),
        "ecosystem-catalog pattern-07 (receipt-emission)".to_string(),
        "ecosystem-catalog pattern-09 (audit-chain)".to_string(),
        "ecosystem-catalog ADR-0003 / engineering-doctrine ADR-0022 (BLAKE3)".to_string(),
    ]
}

/// A complete, signed receipt: the canonical body plus its detached hex
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The signed body.
    pub body: ReceiptBody,
    /// Lowercase-hex Ed25519 signature over `JCS(body)`.
    pub signature: String,
}

impl Receipt {
    /// Sign `body` under the **active** receipt key (a deployment key from
    /// `CORCEPT_SIGNING_SEED_HEX` if configured, else the pinned dev key),
    /// producing a complete receipt. The `key_id` / `key_class` already stamped
    /// into the body by [`ReceiptBody::new`] describe that same active key.
    ///
    /// # Errors
    /// [`TrailError::Receipt`] if the body cannot be canonicalized/signed.
    pub fn sign(body: ReceiptBody) -> Result<Self> {
        let (sig, _key_id) = axiom_receipt::sign_bytes(&Jcs(&body), &key::active_signer())?;
        Ok(Self {
            body,
            signature: hex_encode(&sig),
        })
    }

    /// Serialise to pretty JSON suitable for writing to disk.
    ///
    /// # Errors
    /// [`TrailError::Json`] on a serialization failure.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a receipt from JSON.
    ///
    /// # Errors
    /// [`TrailError::Json`] on a parse failure.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Typed verdict from [`verify_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerdict {
    /// Schema, key_id, and Ed25519 signature all hold.
    Valid,
    /// Verification failed; the string explains why.
    Invalid(String),
}

/// Offline-verify a receipt against the **pinned dev** public key:
/// 1. schema must be `axiom.receipt.v1`;
/// 2. `key_class` must be `dev` and `key_id` must match the pinned key;
/// 3. the Ed25519 signature must verify over the JCS canonical body.
///
/// This is the in-tree verifier and it is anchored on the pinned dev key by
/// design (mechanism, not origin). A `deployment`-class receipt
/// (`CORCEPT_SIGNING_SEED_HEX` was set at sign time) is **out of scope** here:
/// its authenticity is rooted in the deployment's own published
/// [`axiom_receipt::TrustRoot`], not in this pinned anchor. Such a receipt is
/// returned as [`ReceiptVerdict::Invalid`] with an explicit
/// deployment-trust-root message rather than silently treated as a forgery, so
/// the boundary is never confused with tamper.
///
/// Returns a typed [`ReceiptVerdict`]; never panics.
///
/// # Errors
/// [`TrailError::Receipt`] only if the verifier key material is malformed (it is
/// pinned, so this should not occur); verification failures are returned as
/// [`ReceiptVerdict::Invalid`], not errors.
pub fn verify_receipt(receipt: &Receipt) -> Result<ReceiptVerdict> {
    if receipt.body.schema != RECEIPT_SCHEMA {
        return Ok(ReceiptVerdict::Invalid(format!(
            "unsupported schema: {}",
            receipt.body.schema
        )));
    }
    if receipt.body.key_class.is_deployment() {
        return Ok(ReceiptVerdict::Invalid(format!(
            "deployment-class receipt (key_id {}): verify against the deployment's \
             published trust root, not the pinned dev anchor",
            receipt.body.key_id
        )));
    }
    if receipt.body.key_id != PINNED_KEY_ID {
        return Ok(ReceiptVerdict::Invalid(format!(
            "unknown key_id: {}",
            receipt.body.key_id
        )));
    }
    let sig = match hex_decode_64(&receipt.signature) {
        Ok(sig) => sig,
        Err(why) => return Ok(ReceiptVerdict::Invalid(why)),
    };
    let verifier = axiom_receipt::Ed25519Verifier::from_pubkey(signer().verifying_key_bytes())?;
    match axiom_receipt::verify_bytes(&Jcs(&receipt.body), &sig, &verifier) {
        Ok(()) => Ok(ReceiptVerdict::Valid),
        Err(e) => Ok(ReceiptVerdict::Invalid(e.to_string())),
    }
}

/// Lowercase-hex encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode a 128-char lowercase-hex string into a 64-byte signature.
fn hex_decode_64(s: &str) -> std::result::Result<[u8; 64], String> {
    if s.len() != 128 {
        return Err(format!("signature must be 128 hex chars, got {}", s.len()));
    }
    let raw = hex::decode(s).map_err(|e| format!("signature not lowercase hex: {e}"))?;
    raw.try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_chains_and_verifies() {
        let dir = tempdir().unwrap();
        let r0 = append_audit(
            dir.path(),
            "audit verify",
            "ok",
            0,
            "2026-06-16T00:00:00Z",
            ReceiptLink::None,
        )
        .unwrap();
        let r1 = append_audit(
            dir.path(),
            "export",
            "ok",
            0,
            "2026-06-16T00:00:01Z",
            ReceiptLink::Present {
                path: "receipts/v.json".to_string(),
                blake3: axiom_hash::blake3_hex(b"v"),
            },
        )
        .unwrap();
        assert_eq!(r0.seq, 0);
        assert_eq!(r0.prev_hash, GENESIS_HASH);
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_hash, r0.row_hash);

        match verify_trail(dir.path()).unwrap() {
            ChainVerdict::Valid { rows, head_hash } => {
                assert_eq!(rows, 2);
                assert_eq!(head_hash, r1.row_hash);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn empty_trail_is_valid() {
        let dir = tempdir().unwrap();
        assert_eq!(
            verify_trail(dir.path()).unwrap(),
            ChainVerdict::Valid {
                rows: 0,
                head_hash: String::new()
            }
        );
    }

    #[test]
    fn tampered_row_breaks_chain() {
        let dir = tempdir().unwrap();
        append_audit(
            dir.path(),
            "audit verify",
            "ok",
            0,
            "2026-06-16T00:00:00Z",
            ReceiptLink::None,
        )
        .unwrap();
        let trail = dir.path().join(TRAIL_FILENAME);
        let mut rows = axiom_audit::read_rows(&trail).unwrap();
        rows[0].exit_code = 99; // body changes but row_hash is now stale.
        let line = serde_json::to_string(&rows[0]).unwrap();
        std::fs::write(&trail, format!("{line}\n")).unwrap();
        assert!(matches!(
            verify_trail(dir.path()).unwrap(),
            ChainVerdict::Broken(_)
        ));
    }

    #[test]
    fn receipt_signs_and_verifies() {
        let mut body = ReceiptBody::new("audit verify", "ok", "2026-06-16T00:00:00Z");
        body.inputs
            .push(Artifact::of_bytes("ledger", ".corcept/ledger/events.jsonl", b"{}"));
        body.audit_chain = Some(AuditLink {
            trail_path: TRAIL_FILENAME.to_string(),
            seq: 0,
            row_hash: axiom_hash::blake3_hex(b"row"),
        });
        let receipt = Receipt::sign(body.clone()).unwrap();
        assert_eq!(receipt.signature.len(), 128);
        assert_eq!(verify_receipt(&receipt).unwrap(), ReceiptVerdict::Valid);

        // A round-trip through JSON still verifies.
        let json = receipt.to_json().unwrap();
        let parsed = Receipt::from_json(&json).unwrap();
        assert_eq!(verify_receipt(&parsed).unwrap(), ReceiptVerdict::Valid);
    }

    #[test]
    fn tampered_receipt_body_fails() {
        let body = ReceiptBody::new("audit verify", "ok", "2026-06-16T00:00:00Z");
        let mut receipt = Receipt::sign(body).unwrap();
        receipt.body.outcome = "failed".to_string(); // mutate after signing
        assert!(matches!(
            verify_receipt(&receipt).unwrap(),
            ReceiptVerdict::Invalid(_)
        ));
    }

    #[test]
    fn wrong_schema_is_rejected() {
        let mut body = ReceiptBody::new("audit verify", "ok", "2026-06-16T00:00:00Z");
        body.schema = "axiom.receipt.v0".to_string();
        let receipt = Receipt::sign(body).unwrap();
        assert!(matches!(
            verify_receipt(&receipt).unwrap(),
            ReceiptVerdict::Invalid(_)
        ));
    }

    #[test]
    fn concurrent_locked_appends_never_corrupt_the_trail() {
        let dir = tempdir().unwrap();
        let repo = dir.path().to_path_buf();
        const THREADS: usize = 8;
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let repo = repo.clone();
            handles.push(std::thread::spawn(move || {
                let _lock = TrailLock::acquire(&repo).unwrap();
                append_audit(
                    &repo,
                    "audit verify",
                    "ok",
                    0,
                    "2026-06-16T00:00:00Z",
                    ReceiptLink::Present {
                        path: format!("receipts/{t}.json"),
                        blake3: axiom_hash::blake3_hex(format!("row-{t}").as_bytes()),
                    },
                )
                .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let trail = repo.join(TRAIL_FILENAME);
        let rows = axiom_audit::read_rows(&trail).unwrap();
        assert_eq!(rows.len(), THREADS, "every locked append must be its own row");
        match verify_trail(&repo).unwrap() {
            ChainVerdict::Valid { rows: n, .. } => assert_eq!(n, THREADS),
            other => panic!("expected Valid chain, got {other:?}"),
        }
        let text = std::fs::read_to_string(&trail).unwrap();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            assert_eq!(
                line.matches("\"schema\"").count(),
                1,
                "a line concatenated two rows: {line}"
            );
        }
    }

    #[test]
    fn receipt_key_class_defaults_dev_and_is_tamper_proof() {
        // With no CORCEPT_SIGNING_SEED_HEX in this process, the active receipt
        // signer is the pinned dev key, so a fresh receipt self-labels `dev`
        // (mechanism, not origin) and verifies against the pinned anchor.
        let body = ReceiptBody::new("audit verify", "ok", "2026-06-16T00:00:00Z");
        assert_eq!(body.key_class, KeyClass::Dev);
        assert_eq!(body.key_id, PINNED_KEY_ID);
        let receipt = Receipt::sign(body).unwrap();
        assert_eq!(verify_receipt(&receipt).unwrap(), ReceiptVerdict::Valid);

        // key_class lives INSIDE the signed body: relabelling a dev receipt as
        // `deployment` after signing breaks the signature (fail-closed). The
        // deployment-class short-circuit reports out-of-scope, never Valid.
        let mut forged = receipt.clone();
        forged.body.key_class = KeyClass::Deployment;
        assert!(matches!(
            verify_receipt(&forged).unwrap(),
            ReceiptVerdict::Invalid(_)
        ));
    }

    #[test]
    fn pinned_public_key_is_rfc8032_vector() {
        assert_eq!(
            pinned_public_key_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }
}
