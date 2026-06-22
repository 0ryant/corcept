//! Receipt-signing key resolution for corcept's `axiom.receipt.v1` receipts
//! (the doctrine substrate in [`crate::trail`]).
//!
//! corcept emits two independent classes of signed artifact:
//!
//! * **Authority ledger rows** ([`crate::signed_row`]) are signed by an
//!   *operator-generated* Ed25519 key (`corcept key generate`, OsRng, on disk),
//!   verified against a published `<key_id>.pub` trust file. That path is
//!   genuinely operator-key driven and is **not** touched here: its key class is
//!   a property of the on-disk key the operator minted, never an env override.
//! * **`axiom.receipt.v1` receipts** ([`crate::trail`]) are signed in-process by
//!   a **pinned dev Ed25519 seed** (the RFC-8032 test vector) so any verifier can
//!   reconstruct the public key offline. That is "mechanism, not origin": it
//!   proves a receipt was produced by a corcept build, not by a held secret.
//!
//! This module adds the deployment-key *fallback* to the receipt path only: when
//! `CORCEPT_SIGNING_SEED_HEX` is set to a valid 32-byte seed, receipts sign under
//! that deployment key instead of the pinned dev key, and stamp
//! [`KeyClass::Deployment`] inside the signed body. Resolution lives once in
//! [`axiom_receipt::Keyring`]; this just constructs corcept's keyring and surfaces
//! the active signer / id / class. Verification of deployment receipts is the
//! deployment's responsibility via its published trust root (see
//! [`axiom_receipt::TrustRoot`]); the in-tree [`crate::trail::verify_receipt`]
//! path stays anchored on the pinned dev key.

use axiom_receipt::{DeploymentKeyEnv, Ed25519Signer, KeyClass, Keyring};

/// The pinned in-process receipt-signing seed: the RFC-8032 ed25519 test vector.
/// NOT a secret — pinned and public on purpose so any verifier can reconstruct
/// the public key. The same seed the reference tools (tflip / axiom-receipt) use.
pub const PINNED_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Identifier of the pinned in-process receipt-signing key.
pub const PINNED_KEY_ID: &str = "corcept-pinned-ed25519-v1";

/// Default `key_id` for a deployment receipt-signing key when
/// `CORCEPT_SIGNING_KEY_ID` is unset.
pub const DEPLOYMENT_KEY_ID_DEFAULT: &str = "corcept-deployment-ed25519-v1";

/// corcept's receipt keyring: pinned dev key fallback + the `CORCEPT_*`
/// deployment env path (`CORCEPT_SIGNING_SEED_HEX` / `_SIGNING_KEY_ID`).
fn keyring() -> Keyring {
    Keyring::new(
        DeploymentKeyEnv::from_prefix("CORCEPT"),
        PINNED_SEED,
        PINNED_KEY_ID,
        DEPLOYMENT_KEY_ID_DEFAULT,
    )
}

/// The active receipt signer: a deployment key from `CORCEPT_SIGNING_SEED_HEX`
/// if configured and valid, otherwise the pinned dev key.
#[must_use]
pub fn active_signer() -> Ed25519Signer {
    keyring().active_signer().0
}

/// The `key_id` the active receipt signer stamps on receipt bodies.
#[must_use]
pub fn active_key_id() -> String {
    keyring().active_key_id().0
}

/// The [`KeyClass`] of the active receipt signer — `dev` for the pinned key,
/// `deployment` when a deployment seed is configured. Stamped into the receipt
/// body so a receipt declares whether it is origin-grade.
#[must_use]
pub fn active_key_class() -> KeyClass {
    keyring().active_key_id().1
}

/// The pinned dev signer (always available, no env). The default receipt signer
/// and the key [`crate::trail::verify_receipt`] is anchored on.
#[must_use]
pub fn pinned_signer() -> Ed25519Signer {
    keyring().pinned_signer()
}

/// Lowercase-hex of the **active** receipt signer's public key (deployment key
/// if configured, else the pinned dev key).
#[must_use]
pub fn active_public_key_hex() -> String {
    hex::encode(active_signer().verifying_key_bytes())
}
