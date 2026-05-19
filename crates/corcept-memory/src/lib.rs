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

pub fn read_candidate(root: impl AsRef<Path>, id: &str) -> Result<MemoryCandidate> {
    let path = candidates_dir(root).join(format!("{id}.yaml"));
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading memory candidate {}", path.display()))?;
    let candidate = serde_yaml::from_str(&raw)?;
    Ok(candidate)
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
}
