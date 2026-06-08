use anyhow::{bail, Context, Result};
use chrono::{Duration, SecondsFormat, Utc};
use corcept_types::{AcceptedMemory, MemoryCandidate, MemoryScope};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn memory_dir(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(".corcept").join("memory")
}

pub fn candidates_dir(root: impl AsRef<Path>) -> PathBuf {
    memory_dir(root).join("candidates")
}

pub fn accepted_dir(root: impl AsRef<Path>) -> PathBuf {
    memory_dir(root).join("accepted")
}

pub fn rejected_dir(root: impl AsRef<Path>) -> PathBuf {
    memory_dir(root).join("rejected")
}

pub fn ensure_dirs(root: impl AsRef<Path>) -> Result<()> {
    fs::create_dir_all(candidates_dir(&root))?;
    fs::create_dir_all(accepted_dir(&root))?;
    fs::create_dir_all(rejected_dir(root))?;
    Ok(())
}

pub fn new_candidate(
    title: impl Into<String>,
    claim: impl Into<String>,
    evidence: Vec<String>,
    proposed_by: impl Into<String>,
) -> MemoryCandidate {
    MemoryCandidate {
        id: format!("mem_{}", Uuid::new_v4().simple()),
        title: title.into(),
        claim: claim.into(),
        scope: MemoryScope::default(),
        evidence,
        confidence: "medium".to_string(),
        expiry: None,
        risk_if_wrong: None,
        proposed_by: proposed_by.into(),
        status: "candidate".to_string(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    }
}

pub fn validate_candidate(candidate: &MemoryCandidate) -> Result<()> {
    if candidate.title.trim().is_empty() {
        bail!("memory candidate title is required");
    }
    if candidate.claim.trim().is_empty() {
        bail!("memory candidate claim is required");
    }
    if candidate.evidence.is_empty() {
        bail!("memory candidate requires at least one evidence reference");
    }
    if candidate.status != "candidate" {
        bail!("memory candidate status must be `candidate`");
    }
    Ok(())
}

pub fn write_candidate(root: impl AsRef<Path>, candidate: &MemoryCandidate) -> Result<PathBuf> {
    validate_candidate(candidate)?;
    ensure_dirs(&root)?;
    let path = candidates_dir(root).join(format!("{}.yaml", candidate.id));
    fs::write(&path, serde_yaml::to_string(candidate)?)
        .with_context(|| format!("writing memory candidate {}", path.display()))?;
    Ok(path)
}

/// Validate a memory candidate id used as a filesystem component. Rejects path
/// separators, `..`, and anything outside a safe identifier charset so a
/// user-supplied id (e.g. `corcept memory promote --id <id>`) cannot escape the
/// candidates directory.
pub fn validate_candidate_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("memory candidate id is required");
    }
    if id.len() > 128 {
        bail!("memory candidate id is too long");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        bail!("invalid memory candidate id `{id}`: only [A-Za-z0-9_-] are allowed");
    }
    Ok(())
}

pub fn read_candidate(root: impl AsRef<Path>, id: &str) -> Result<MemoryCandidate> {
    validate_candidate_id(id)?;
    let path = candidates_dir(root).join(format!("{id}.yaml"));
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading memory candidate {}", path.display()))?;
    let candidate = serde_yaml::from_str(&raw)?;
    Ok(candidate)
}

pub fn list_candidates(root: impl AsRef<Path>, limit: usize) -> Result<Vec<MemoryCandidate>> {
    let candidates_dir = candidates_dir(root);
    if !candidates_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = fs::read_dir(&candidates_dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    let mut candidates = Vec::new();
    for entry in entries {
        let path = entry.path();
        let is_candidate_file = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"));
        if entry.file_type()?.is_file() && is_candidate_file {
            let raw = fs::read_to_string(entry.path())
                .with_context(|| format!("reading memory candidate {}", entry.path().display()))?;
            let candidate = serde_yaml::from_str(&raw)?;
            candidates.push(candidate);
            if candidates.len() >= limit {
                break;
            }
        }
    }
    Ok(candidates)
}

pub fn promote_candidate(
    root: impl AsRef<Path>,
    id: &str,
    approved_by: impl Into<String>,
) -> Result<AcceptedMemory> {
    let root_ref = root.as_ref();
    let candidate = read_candidate(root_ref, id)?;
    validate_candidate(&candidate)?;
    let accepted = AcceptedMemory {
        id: format!("accepted_{}", candidate.id),
        title: candidate.title,
        claim: candidate.claim,
        authority: "accepted_memory".to_string(),
        scope: candidate.scope,
        evidence: vec![candidate.id],
        approved_by: approved_by.into(),
        approved_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        review_after: Some(
            (Utc::now() + Duration::days(90))
                .format("%Y-%m-%d")
                .to_string(),
        ),
    };
    ensure_dirs(root_ref)?;
    let path = accepted_dir(root_ref).join(format!("{}.yaml", accepted.id));
    fs::write(&path, serde_yaml::to_string(&accepted)?)
        .with_context(|| format!("writing accepted memory {}", path.display()))?;
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_requires_evidence() {
        let candidate = new_candidate("title", "claim", vec![], "test");
        assert!(validate_candidate(&candidate).is_err());
    }

    #[test]
    fn writes_and_promotes_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = new_candidate(
            "Convention",
            "Use explicit errors",
            vec!["src/lib.rs:10".to_string()],
            "test",
        );
        write_candidate(dir.path(), &candidate).unwrap();
        let accepted = promote_candidate(dir.path(), &candidate.id, "user").unwrap();
        assert!(accepted.id.starts_with("accepted_mem_"));
    }

    #[test]
    fn lists_candidates_in_path_order() {
        let dir = tempfile::tempdir().unwrap();
        let first = new_candidate("A", "Claim A", vec!["a".to_string()], "test");
        let second = new_candidate("B", "Claim B", vec!["b".to_string()], "test");
        write_candidate(dir.path(), &first).unwrap();
        write_candidate(dir.path(), &second).unwrap();

        let listed = list_candidates(dir.path(), 10).unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn rejects_path_traversal_candidate_id() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "../../../../etc/passwd",
            "../accepted/x",
            "a/b",
            "a\\b",
            "..",
            "with space",
        ] {
            assert!(
                read_candidate(dir.path(), bad).is_err(),
                "id `{bad}` should be rejected"
            );
            assert!(
                validate_candidate_id(bad).is_err(),
                "id `{bad}` should be rejected by validator"
            );
            assert!(
                promote_candidate(dir.path(), bad, "user").is_err(),
                "promote with id `{bad}` should be rejected"
            );
        }
        assert!(validate_candidate_id("mem_abc123").is_ok());
    }

    #[test]
    fn list_is_read_only_when_memory_dirs_are_missing() {
        let dir = tempfile::tempdir().unwrap();
        let listed = list_candidates(dir.path(), 10).unwrap();
        assert!(listed.is_empty());
        assert!(!memory_dir(dir.path()).exists());
    }
}
