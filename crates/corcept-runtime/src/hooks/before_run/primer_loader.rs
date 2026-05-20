//! Primer body loader.
//!
//! Resolves a primer by id + version from one of three sources, in
//! precedence order:
//!
//! 1. An explicit `engineering-doctrine` checkout path passed to
//!    [`PrimerLoader::new`].
//! 2. The `CORCEPT_ENGINEERING_DOCTRINE_PATH` environment variable.
//! 3. The vendored fallback in `crates/corcept-runtime/vendored/` (built
//!    into the binary via `include_bytes!` so the loader is never
//!    network- or disk-dependent in the failure case).
//!
//! The loader normalises CRLF to LF before returning bytes. The canonical
//! SHA-256 is computed over LF-only content (see
//! [doctrine/skills/anti-confabulation.skill.md] in `engineering-doctrine`),
//! so the normalisation is mandatory: a Windows-checkout source file with
//! CRLF would otherwise hash differently from the canonical fingerprint.
//!
//! ## Why duplicate the doctrine-mcp loader pattern?
//!
//! TODO(ADR-0005, doctrine-mcp parity): the doctrine-mcp project resolves
//! engineering-doctrine via a similar precedence chain for `prompts/list`.
//! When both projects ship, the resolution logic should be extracted into
//! a shared crate (`doctrine-source`?). For now corcept duplicates the
//! pattern cleanly to avoid a cross-repo dependency on in-flight work.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Environment variable that, if set, overrides any other engineering-doctrine
/// path discovery. Loud-not-silent: the loader emits the source kind on every
/// resolution so an unexpected override is visible in the audit log.
pub const ENGINEERING_DOCTRINE_ENV: &str = "CORCEPT_ENGINEERING_DOCTRINE_PATH";

/// Vendored fallback bytes for `anti-confab-200tok` v1.0.0.
///
/// Stored under `crates/corcept-runtime/vendored/` and marked `binary` in
/// `.gitattributes` so git never normalises EOLs. The SHA-256 hash of
/// these bytes is `c138dd966c82f7bd792684ab3fef0f50d75aa9342468db8b5d265f24f3fb35a8`
/// and matches the canonical fingerprint emitted by
/// `engineering-doctrine/doctrine/skills/anti-confabulation.skill.md`.
const VENDORED_ANTI_CONFAB_V1: &[u8] =
    include_bytes!("../../../vendored/anti-confab-primer.v1.0.0.txt");

/// Where the primer body was sourced from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Loaded from a live `engineering-doctrine` checkout on disk
    /// (operator-supplied path or `CORCEPT_ENGINEERING_DOCTRINE_PATH`).
    EngineeringDoctrineLive,
    /// Loaded from the corcept binary's compiled-in vendored copy.
    VendoredFallback,
}

/// A primer body resolved by the loader, plus provenance metadata.
#[derive(Debug, Clone)]
pub struct ResolvedPrimer {
    /// Raw bytes (LF-normalised) of the primer body. NOT NUL-terminated.
    pub body: Vec<u8>,
    /// Cached SHA-256 of `body`. Loud-not-silent: present even on the
    /// vendored path so the audit event always carries a hash.
    pub sha256_hex: String,
    /// Where the body came from.
    pub source_kind: SourceKind,
    /// The on-disk path the loader read from, when applicable.
    pub source_path: Option<PathBuf>,
}

/// Errors a primer loader can return.
#[derive(Debug, Error)]
pub enum PrimerLoaderError {
    /// The primer id/version pair is not known to the loader.
    #[error("primer {id}@{version} is not known to the corcept loader")]
    UnknownPrimer { id: String, version: String },
    /// I/O failure reading from a live engineering-doctrine checkout.
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The skill markdown was found but could not be parsed into a primer body.
    #[error("could not extract a primer body from {path}: {reason}")]
    ExtractFailed { path: PathBuf, reason: String },
}

/// Loader. Cheap to construct, holds no async/IO state.
#[derive(Debug, Clone, Default)]
pub struct PrimerLoader {
    /// Explicit engineering-doctrine path; checked before the env override.
    engineering_doctrine: Option<PathBuf>,
}

impl PrimerLoader {
    /// Construct a loader. If `engineering_doctrine` is `None`, the loader
    /// will still consult the env var on `resolve` calls.
    pub fn new(engineering_doctrine: Option<PathBuf>) -> Self {
        Self {
            engineering_doctrine,
        }
    }

    /// Resolve the primer body for `id @ version`.
    ///
    /// Resolution precedence:
    /// 1. `self.engineering_doctrine` (live checkout).
    /// 2. `$CORCEPT_ENGINEERING_DOCTRINE_PATH` (env override).
    /// 3. Vendored fallback (if id/version matches the built-in set).
    pub fn resolve(&self, id: &str, version: &str) -> Result<ResolvedPrimer, PrimerLoaderError> {
        if let Some(root) = self.engineering_doctrine.as_deref() {
            if let Some(resolved) = self.try_read_live(root, id, version)? {
                return Ok(resolved);
            }
        }
        if let Ok(env_path) = std::env::var(ENGINEERING_DOCTRINE_ENV) {
            let env_root = PathBuf::from(env_path);
            if let Some(resolved) = self.try_read_live(&env_root, id, version)? {
                return Ok(resolved);
            }
        }
        self.try_read_vendored(id, version)
    }

    /// Try to read a live engineering-doctrine checkout. Returns `Ok(None)`
    /// if the directory exists but the skill file is missing (the caller
    /// then falls through to the next source). Returns `Err` on real I/O
    /// failure or parse failure.
    fn try_read_live(
        &self,
        root: &Path,
        id: &str,
        version: &str,
    ) -> Result<Option<ResolvedPrimer>, PrimerLoaderError> {
        let skill_rel = primer_skill_relpath(id, version);
        let skill_path = root.join(&skill_rel);
        if !skill_path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(&skill_path).map_err(|e| PrimerLoaderError::Io {
            path: skill_path.clone(),
            source: e,
        })?;
        let body =
            extract_priming_block(&raw).map_err(|reason| PrimerLoaderError::ExtractFailed {
                path: skill_path.clone(),
                reason,
            })?;
        let body = normalize_eol(&body);
        let sha256_hex = hex_sha256(&body);
        Ok(Some(ResolvedPrimer {
            body,
            sha256_hex,
            source_kind: SourceKind::EngineeringDoctrineLive,
            source_path: Some(skill_path),
        }))
    }

    /// Try to satisfy the request from the compiled-in vendored corpus.
    fn try_read_vendored(
        &self,
        id: &str,
        version: &str,
    ) -> Result<ResolvedPrimer, PrimerLoaderError> {
        let body = match (id, version) {
            ("anti-confab-200tok", "1.0.0") => VENDORED_ANTI_CONFAB_V1.to_vec(),
            _ => {
                return Err(PrimerLoaderError::UnknownPrimer {
                    id: id.to_string(),
                    version: version.to_string(),
                })
            }
        };
        let body = normalize_eol(&body);
        let sha256_hex = hex_sha256(&body);
        Ok(ResolvedPrimer {
            body,
            sha256_hex,
            source_kind: SourceKind::VendoredFallback,
            source_path: None,
        })
    }
}

/// Map (id, version) to the canonical relpath inside an engineering-doctrine
/// checkout. v1.0.0 of `anti-confab-200tok` lives at
/// `doctrine/skills/anti-confabulation.skill.md`. Future primers extend this
/// match.
fn primer_skill_relpath(id: &str, _version: &str) -> PathBuf {
    let rel = match id {
        "anti-confab-200tok" => "doctrine/skills/anti-confabulation.skill.md",
        // TODO(ADR-0005): extend the map as new primers ship.
        other => {
            // Unknown id -> still construct a path so the live branch returns
            // `Ok(None)` and the vendored branch returns `UnknownPrimer`.
            return PathBuf::from(format!("doctrine/skills/{other}.skill.md"));
        }
    };
    PathBuf::from(rel)
}

/// Extract the priming block from a skill markdown file. The canonical
/// representation is the FIRST fenced code block whose opening fence is
/// the literal ```` ``` ```` (no language tag). Subsequent fenced blocks
/// are inert documentation. The block body excludes both fence lines.
///
/// Returns `Err` on any of:
/// - no opening fence found,
/// - no closing fence found,
/// - the extracted body is empty.
fn extract_priming_block(raw: &[u8]) -> Result<Vec<u8>, String> {
    // We work on bytes (not str) so a stray non-UTF8 sequence in the file
    // is reported as an extraction failure rather than a panic.
    let text = std::str::from_utf8(raw).map_err(|e| format!("non-UTF8 input: {e}"))?;
    let mut in_block = false;
    let mut out: Vec<u8> = Vec::new();
    let mut found_close = false;
    for line in text.split('\n') {
        // Trim a trailing \r so a CRLF input is treated as LF.
        let trimmed = line.strip_suffix('\r').unwrap_or(line);
        if trimmed == "```" {
            if in_block {
                found_close = true;
                break;
            } else {
                in_block = true;
                continue;
            }
        }
        if in_block {
            out.extend_from_slice(trimmed.as_bytes());
            out.push(b'\n');
        }
    }
    if !in_block {
        return Err("no opening ``` fence found".to_string());
    }
    if !found_close {
        return Err("no closing ``` fence found before EOF".to_string());
    }
    if out.is_empty() {
        return Err("priming block body is empty".to_string());
    }
    Ok(out)
}

/// Normalise any CRLF byte sequences to LF. Idempotent on LF-only input.
fn normalize_eol(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\r' && i + 1 < body.len() && body[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

/// Compute a lowercase hex SHA-256 of `bytes`.
pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const CANONICAL_HASH: &str =
        "c138dd966c82f7bd792684ab3fef0f50d75aa9342468db8b5d265f24f3fb35a8";

    #[test]
    fn vendored_anti_confab_hash_matches_canonical() {
        let loader = PrimerLoader::default();
        let resolved = loader.resolve("anti-confab-200tok", "1.0.0").unwrap();
        assert_eq!(resolved.source_kind, SourceKind::VendoredFallback);
        assert_eq!(resolved.sha256_hex, CANONICAL_HASH);
        assert_eq!(resolved.body.len(), 1444);
    }

    #[test]
    fn unknown_primer_id_returns_typed_error() {
        let loader = PrimerLoader::default();
        let err = loader.resolve("not-a-primer", "9.9.9").unwrap_err();
        assert!(matches!(err, PrimerLoaderError::UnknownPrimer { .. }));
    }

    #[test]
    fn env_override_takes_precedence_over_default() {
        // Build a fake engineering-doctrine layout and point the env var at it.
        let dir = TempDir::new().unwrap();
        let skills = dir.path().join("doctrine/skills");
        fs::create_dir_all(&skills).unwrap();
        let content = "# header\n\n```\nFAKE PRIMER BODY\n```\n\ntail\n";
        fs::write(
            skills.join("anti-confabulation.skill.md"),
            content.as_bytes(),
        )
        .unwrap();
        // Serialise tests that touch process env. std::env::set_var is
        // process-global; without the lock the env-override test would race
        // with future tests on the same key.
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(ENGINEERING_DOCTRINE_ENV, dir.path());
        let loader = PrimerLoader::default();
        let resolved = loader.resolve("anti-confab-200tok", "1.0.0").unwrap();
        std::env::remove_var(ENGINEERING_DOCTRINE_ENV);
        assert_eq!(resolved.source_kind, SourceKind::EngineeringDoctrineLive);
        assert_eq!(resolved.body, b"FAKE PRIMER BODY\n");
        let expected_hash = hex_sha256(b"FAKE PRIMER BODY\n");
        assert_eq!(resolved.sha256_hex, expected_hash);
    }

    #[test]
    fn explicit_path_falls_back_to_vendored_when_skill_missing() {
        let dir = TempDir::new().unwrap();
        // No skills file at all -> live branch returns None, fall through.
        let loader = PrimerLoader::new(Some(dir.path().to_path_buf()));
        let resolved = loader.resolve("anti-confab-200tok", "1.0.0").unwrap();
        assert_eq!(resolved.source_kind, SourceKind::VendoredFallback);
        assert_eq!(resolved.sha256_hex, CANONICAL_HASH);
    }

    #[test]
    fn extract_priming_block_picks_first_fence_pair() {
        let raw = b"prelude\n```\nbody line 1\nbody line 2\n```\nepilogue\n```\nsecond fenced block\n```\n";
        let body = extract_priming_block(raw).unwrap();
        assert_eq!(body, b"body line 1\nbody line 2\n");
    }

    #[test]
    fn extract_priming_block_normalises_crlf_input() {
        let raw = b"prelude\r\n```\r\nbody line\r\n```\r\nepilogue\r\n";
        let body = extract_priming_block(raw).unwrap();
        assert_eq!(body, b"body line\n");
    }

    #[test]
    fn extract_priming_block_errors_when_no_fence() {
        let raw = b"prelude only, no fenced block here\n";
        assert!(extract_priming_block(raw).is_err());
    }

    #[test]
    fn normalize_eol_is_idempotent() {
        let lf = b"a\nb\nc\n";
        assert_eq!(normalize_eol(lf), lf.to_vec());
        let crlf = b"a\r\nb\r\nc\r\n";
        assert_eq!(normalize_eol(crlf), lf.to_vec());
    }

    // Mutex to serialise tests that touch process env.
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
}
