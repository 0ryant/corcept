//! Standalone-portability guard (G-1).
//!
//! `corcept-mcp` must build from a clean checkout of this repository without the
//! sibling `mcpact` source tree present. That requires every `mcpact-*`
//! dependency to resolve from a registry (crates.io), never through a
//! `path = "../../../mcpact/..."` override. This test fails the build if a
//! sibling path dependency is reintroduced into the manifest.

/// The crate manifest, embedded at compile time.
const CARGO_TOML: &str = include_str!("../Cargo.toml");

#[test]
fn no_mcpact_sibling_path_dependencies() {
    let offenders: Vec<&str> = CARGO_TOML
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("mcpact-"))
        .filter(|line| line.contains("path"))
        .collect();
    assert!(
        offenders.is_empty(),
        "corcept-mcp depends on the mcpact source tree by path, which breaks the \
         G-1 standalone-portability gate; pin each to a crates.io version instead:\n  {}",
        offenders.join("\n  ")
    );
}
