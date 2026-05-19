use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use corcept_types::{trust_keys_dir, LedgerEvent};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod canonical;
mod keys;
mod signed_row;

pub use canonical::{hash_event_hardened, hash_event_legacy, verify_event_hash, HASH_DOMAIN};
pub use keys::{generate_operator_key, load_active_signing_key, show_operator_key, KeyInfo};
pub use signed_row::{
    sign_event, trusted_history_enabled, verify_row_signature, VerifyFailure, VerifyFailureReason,
    VerifyReport, ATTESTATION_SCHEMA_VERSION, SIGN_DOMAIN,
};

pub fn ledger_path(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref()
        .join(".corcept")
        .join("ledger")
        .join("events.jsonl")
}

pub fn last_hash_path(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref()
        .join(".corcept")
        .join("ledger")
        .join("last_hash")
}

pub fn ensure_ledger(root: impl AsRef<Path>) -> Result<PathBuf> {
    let path = ledger_path(root.as_ref());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating ledger directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)
                .with_context(|| format!("setting permissions on {}", parent.display()))?;
        }
    }
    if !path.exists() {
        fs::write(&path, "").with_context(|| format!("creating ledger {}", path.display()))?;
    }
    let sidecar = last_hash_path(root.as_ref());
    if !sidecar.exists() {
        fs::write(&sidecar, "")
            .with_context(|| format!("creating ledger sidecar {}", sidecar.display()))?;
    }
    Ok(path)
}

pub fn hash_event(event: &LedgerEvent) -> Result<String> {
    hash_event_hardened(event)
}

pub fn read_events(root: impl AsRef<Path>) -> Result<Vec<LedgerEvent>> {
    read_events_file(ledger_path(root))
}

pub fn read_events_file(path: impl AsRef<Path>) -> Result<Vec<LedgerEvent>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading ledger {}", path.display()))?;
    read_events_document(&raw)
}

fn read_events_document(raw: &str) -> Result<Vec<LedgerEvent>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(event) = serde_json::from_str::<LedgerEvent>(trimmed) {
        return Ok(vec![event]);
    }
    if let Ok(events) = serde_json::from_str::<Vec<LedgerEvent>>(trimmed) {
        return Ok(events);
    }
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<LedgerEvent>(line).context("parsing ledger event"))
        .collect()
}

pub fn last_hash(root: impl AsRef<Path>) -> Result<Option<String>> {
    let root = root.as_ref();
    let sidecar = last_hash_path(root);
    if sidecar.exists() {
        let raw = fs::read_to_string(&sidecar)
            .with_context(|| format!("reading ledger sidecar {}", sidecar.display()))?;
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }

    let path = ledger_path(root);
    let Some(line) = last_nonempty_line(&path)? else {
        return Ok(None);
    };
    let event: LedgerEvent = serde_json::from_str(&line).context("parsing last ledger event")?;
    Ok(event.hash)
}

pub fn append_event(root: impl AsRef<Path>, mut event: LedgerEvent) -> Result<LedgerEvent> {
    let root = root.as_ref();
    let path = ensure_ledger(root)?;
    if event.id.trim().is_empty() {
        event.id = format!("evt_{}", Uuid::new_v4().simple());
    }
    if event.ts.trim().is_empty() {
        event.ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    }
    event.prev_hash = last_hash(root)?;
    event.hash = Some(hash_event(&event)?);
    if should_sign_append() {
        if let Some(signing_key) = load_active_signing_key()? {
            event.signature = Some(sign_event(&event, &signing_key)?);
        }
    }

    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    if let Some(hash) = &event.hash {
        fs::write(last_hash_path(root), hash.as_bytes())?;
    }
    Ok(event)
}

pub fn verify_hash_chain(root: impl AsRef<Path>) -> Result<bool> {
    verify_hash_chain_impl(root.as_ref(), true)
}

pub fn verify_hash_chain_readonly(root: impl AsRef<Path>) -> Result<bool> {
    verify_hash_chain_impl(root.as_ref(), false)
}

fn verify_hash_chain_impl(root: &Path, update_sidecar: bool) -> Result<bool> {
    let events = read_events(root)?;
    let mut previous: Option<String> = None;
    for event in &events {
        if event.prev_hash != previous {
            return Ok(false);
        }
        let expected = hash_event(event)?;
        if event.hash.as_deref() != Some(expected.as_str()) && !verify_event_hash(event)? {
            return Ok(false);
        }
        previous = event.hash.clone();
    }
    if update_sidecar {
        if let Some(hash) = previous {
        fs::write(last_hash_path(root), hash.as_bytes())?;
        }
    }
    Ok(true)
}

fn should_sign_append() -> bool {
    trusted_history_enabled()
        || std::env::var("CORCEPT_SIGN_LEDGER")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

pub fn verify_ledger(path: impl AsRef<Path>, require_signed: bool) -> Result<VerifyReport> {
    let path = path.as_ref();
    let events = if path.is_file() {
        read_events_file(path)?
    } else {
        read_events(path)?
    };
    let trust_dir = trust_keys_dir().unwrap_or_else(|| path.join(".corcept/keys/trust"));
    let mut failures = Vec::new();
    let mut previous: Option<String> = None;
    let mut hash_chain_valid = true;

    for (idx, event) in events.iter().enumerate() {
        let line = idx + 1;
        if event.prev_hash != previous {
            hash_chain_valid = false;
            failures.push(VerifyFailure {
                line,
                event_id: Some(event.id.clone()),
                reason: VerifyFailureReason::HashChainBreak,
            });
        }
        let expected = hash_event(event)?;
        if event.hash.as_deref() != Some(expected.as_str()) && !verify_event_hash(event)? {
            hash_chain_valid = false;
            failures.push(VerifyFailure {
                line,
                event_id: Some(event.id.clone()),
                reason: VerifyFailureReason::HashMismatch,
            });
        }
        previous = event.hash.clone();

        if require_signed {
            match verify_row_signature(event, &trust_dir)? {
                Ok(()) => {}
                Err(reason) => failures.push(VerifyFailure {
                    line,
                    event_id: Some(event.id.clone()),
                    reason,
                }),
            }
        }
    }

    let status = if failures.is_empty() && hash_chain_valid {
        "pass"
    } else {
        "fail"
    }
    .to_string();

    Ok(VerifyReport {
        status,
        hash_chain_valid,
        signed_mode: require_signed,
        rows_scanned: events.len(),
        failures,
    })
}

fn last_nonempty_line(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut file =
        File::open(path).with_context(|| format!("opening ledger {}", path.display()))?;
    let mut pos = file.metadata()?.len();
    if pos == 0 {
        return Ok(None);
    }

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let mut seen_content = false;
    while pos > 0 {
        pos -= 1;
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut byte)?;
        match byte[0] {
            b'\n' | b'\r' if !seen_content => continue,
            b'\n' | b'\r' => break,
            b => {
                seen_content = true;
                buf.push(b);
            }
        }
    }
    if buf.is_empty() {
        return Ok(None);
    }
    buf.reverse();
    Ok(Some(String::from_utf8(buf)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corcept_types::{AuthorityLevel, LEDGER_EVENT_SCHEMA};
    use std::collections::BTreeMap;

    fn event(kind: &str) -> LedgerEvent {
        LedgerEvent {
            schema: LEDGER_EVENT_SCHEMA.to_string(),
            id: String::new(),
            ts: String::new(),
            session_id: Some("s".to_string()),
            actor: "test".to_string(),
            event_type: kind.to_string(),
            authority_level: AuthorityLevel::L0Observe,
            tool: None,
            target: None,
            decision: None,
            decision_reason: None,
            evidence_refs: vec![],
            prev_hash: None,
            hash: None,
            metadata: BTreeMap::new(),
            signature: None,
        }
    }

    #[test]
    fn appends_and_verifies_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_event(dir.path(), event("session_started")).unwrap();
        append_event(dir.path(), event("prompt_submitted")).unwrap();
        assert_eq!(read_events(dir.path()).unwrap().len(), 2);
        assert!(verify_hash_chain(dir.path()).unwrap());
    }

    #[test]
    fn sidecar_tracks_last_hash() {
        let dir = tempfile::tempdir().unwrap();
        let first = append_event(dir.path(), event("session_started")).unwrap();
        assert_eq!(last_hash(dir.path()).unwrap(), first.hash);
        assert!(last_hash_path(dir.path()).exists());
    }

    #[test]
    fn readonly_verify_does_not_create_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        append_event(dir.path(), event("session_started")).unwrap();
        fs::remove_file(last_hash_path(dir.path())).unwrap();
        assert!(verify_hash_chain_readonly(dir.path()).unwrap());
        assert!(!last_hash_path(dir.path()).exists());
    }
}
