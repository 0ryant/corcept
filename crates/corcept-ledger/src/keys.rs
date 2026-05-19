//! Operator Ed25519 signing key lifecycle (ADR-0025).

use anyhow::{Context, Result};
use corcept_types::{active_signing_key_path, trust_keys_dir};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};

use crate::signed_row::key_fingerprint;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyInfo {
    pub path: PathBuf,
    pub key_id: String,
    pub public_key_hex: String,
}

pub fn generate_operator_key(force: bool) -> Result<KeyInfo> {
    let Some(key_path) = active_signing_key_path() else {
        anyhow::bail!("operator key path unavailable (set HOME or CORCEPT_DATA_HOME)");
    };
    if key_path.exists() && !force {
        anyhow::bail!(
            "active signing key already exists at {}; pass force to rotate",
            key_path.display()
        );
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)?;
        }
    }

    if key_path.exists() {
        rotate_active_key(&key_path)?;
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    write_secret_key(&key_path, signing_key.as_bytes())?;
    publish_trust_pubkey(&signing_key.verifying_key())?;
    key_info_from_key(&key_path, &signing_key)
}

pub fn show_operator_key() -> Result<KeyInfo> {
    let key_path = active_signing_key_path()
        .filter(|p| p.exists())
        .context("no active signing key; run `corcept key generate`")?;
    let signing_key = load_signing_key(&key_path)?;
    key_info_from_key(&key_path, &signing_key)
}

pub fn load_active_signing_key() -> Result<Option<SigningKey>> {
    let Some(path) = active_signing_key_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(load_signing_key(&path)?))
}

fn key_info_from_key(path: &Path, signing_key: &SigningKey) -> Result<KeyInfo> {
    let verifying_key = signing_key.verifying_key();
    Ok(KeyInfo {
        path: path.to_path_buf(),
        key_id: key_fingerprint(&verifying_key),
        public_key_hex: hex::encode(verifying_key.as_bytes()),
    })
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = fs::read(path).with_context(|| format!("reading signing key {}", path.display()))?;
    if raw.len() != 32 {
        anyhow::bail!("signing key {} must be 32 bytes", path.display());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&seed))
}

fn write_secret_key(path: &Path, seed: &[u8; 32]) -> Result<()> {
    fs::write(path, seed).with_context(|| format!("writing signing key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn publish_trust_pubkey(pubkey: &VerifyingKey) -> Result<PathBuf> {
    let Some(trust_dir) = trust_keys_dir() else {
        anyhow::bail!("trust key directory unavailable");
    };
    fs::create_dir_all(&trust_dir)?;
    let key_id = key_fingerprint(pubkey);
    let path = trust_dir.join(format!("{key_id}.pub"));
    fs::write(&path, pubkey.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn rotate_active_key(active_path: &Path) -> Result<()> {
    let old = load_signing_key(active_path)?;
    publish_trust_pubkey(&old.verifying_key())?;
    let archive = active_path.with_extension("ed25519.bak");
    fs::rename(active_path, &archive)
        .with_context(|| format!("archiving old key to {}", archive.display()))?;
    Ok(())
}
