//! Manifest / workspace version-skew guard.
//!
//! Backlog item 3: the McPact source manifest (`.mcpact/source.mcpact.toml`),
//! its lockfile (`.mcpact/mcpact.lock`), and the generated crate version
//! (`CARGO_PKG_VERSION`, inherited from the workspace) must agree. A skew like
//! the historical `0.5.0` manifest against the `0.6.0-pre` workspace ships an
//! adapter that advertises the wrong version to MCP hosts and breaks the
//! McPact lockfile invariant. This test fails the build on any such skew.

use sha2::{Digest, Sha256};

const SOURCE_MANIFEST: &str = include_str!("../.mcpact/source.mcpact.toml");
const LOCKFILE: &str = include_str!("../.mcpact/mcpact.lock");

/// Extract a top-level double-quoted TOML string value, e.g. `version = "x"`.
fn toml_string(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix(key)?.trim_start();
        let rest = rest.strip_prefix('=')?.trim();
        let inner = rest.strip_prefix('"')?;
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    })
}

fn manifest_version() -> String {
    // The manifest version lives under `[package]`; it is the first `version =`
    // key in the file (the manifest has no other top-level `version` key).
    toml_string(SOURCE_MANIFEST, "version").expect("manifest [package].version must be present")
}

fn lockfile_version() -> String {
    toml_string(LOCKFILE, "package_version").expect("lockfile package_version must be present")
}

#[test]
fn manifest_matches_workspace_version() {
    let crate_version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        manifest_version(),
        crate_version,
        "McPact source manifest version is skewed from the workspace crate version; \
         update .mcpact/source.mcpact.toml (and the top-level corcept.mcpact.toml) to {crate_version}"
    );
}

#[test]
fn lockfile_matches_workspace_version() {
    let crate_version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        lockfile_version(),
        crate_version,
        "McPact lockfile package_version is skewed from the workspace crate version; \
         regenerate or update .mcpact/mcpact.lock to {crate_version}"
    );
}

#[test]
fn lockfile_manifest_hash_matches_embedded_manifest() {
    // Mirrors the runtime check in server_config::verify_pack_integrity so a
    // manifest edit that forgets to re-sync the lockfile hash fails at test
    // time rather than only at server startup.
    let expected = toml_string(LOCKFILE, "source_manifest_sha256")
        .expect("lockfile source_manifest_sha256 must be present");
    let actual: String = Sha256::digest(SOURCE_MANIFEST.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual, expected,
        "embedded source manifest hash does not match the lockfile; \
         recompute source_manifest_sha256 in .mcpact/mcpact.lock"
    );
}
