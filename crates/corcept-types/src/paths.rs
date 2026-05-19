//! XDG and project path resolution (ADR-0024).

use std::env;
use std::path::{Path, PathBuf};

pub const PROJECT_DIR: &str = ".corcept";
pub const LEDGER_REL: &str = ".corcept/ledger/events.jsonl";

/// Unix owner-only directory mode (0700).
#[cfg(unix)]
pub const SECURE_DIR_MODE: u32 = 0o700;

pub fn project_ledger(root: impl AsRef<Path>) -> PathBuf {
    env_path("CORCEPT_LEDGER").unwrap_or_else(|| root.as_ref().join(LEDGER_REL))
}

pub fn project_corcept_dir(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(PROJECT_DIR)
}

pub fn project_ledger_dir(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(PROJECT_DIR).join("ledger")
}

pub fn env_path(key: &str) -> Option<PathBuf> {
    env::var(key)
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

pub fn xdg_data_home() -> Option<PathBuf> {
    env_path("CORCEPT_DATA_HOME")
        .or_else(|| env_path("XDG_DATA_HOME"))
        .or_else(|| env_path("HOME").map(|h| h.join(".local/share")))
}

pub fn xdg_state_home() -> Option<PathBuf> {
    env_path("CORCEPT_STATE_HOME")
        .or_else(|| env_path("XDG_STATE_HOME"))
        .or_else(|| env_path("HOME").map(|h| h.join(".local/state")))
}

pub fn xdg_config_home() -> Option<PathBuf> {
    env_path("CORCEPT_CONFIG_HOME")
        .or_else(|| env_path("XDG_CONFIG_HOME"))
        .or_else(|| env_path("HOME").map(|h| h.join(".config")))
}

pub fn operator_data_dir() -> Option<PathBuf> {
    xdg_data_home().map(|p| p.join("corcept"))
}

pub fn operator_state_dir() -> Option<PathBuf> {
    xdg_state_home().map(|p| p.join("corcept"))
}

pub fn operator_config_dir() -> Option<PathBuf> {
    xdg_config_home().map(|p| p.join("corcept"))
}

pub fn telemetry_path() -> Option<PathBuf> {
    env_path("CORCEPT_TELEMETRY_DIR").or_else(|| operator_state_dir().map(|p| p.join("telemetry")))
}

pub fn debug_log_path() -> Option<PathBuf> {
    env_path("CORCEPT_LOG_DIR").or_else(|| operator_state_dir().map(|p| p.join("logs/corcept.log")))
}

pub fn receipts_dir() -> Option<PathBuf> {
    env_path("CORCEPT_RECEIPTS_DIR").or_else(|| operator_data_dir().map(|p| p.join("receipts")))
}

pub fn operator_keys_dir() -> Option<PathBuf> {
    operator_data_dir().map(|p| p.join("keys"))
}

pub fn active_signing_key_path() -> Option<PathBuf> {
    operator_keys_dir().map(|p| p.join("active.ed25519"))
}

pub fn trust_keys_dir() -> Option<PathBuf> {
    operator_keys_dir().map(|p| p.join("trust"))
}

/// True when operator-scoped paths can be resolved (HOME or explicit override).
pub fn operator_paths_available() -> bool {
    env_path("CORCEPT_DATA_HOME").is_some()
        || env_path("CORCEPT_STATE_HOME").is_some()
        || env_path("HOME").is_some()
}

/// Returns true if directory is absent or owner-only on Unix.
pub fn dir_permissions_secure(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        if !meta.is_dir() {
            return false;
        }
        meta.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ledger_under_corcept() {
        let p = project_ledger("/tmp/repo");
        assert!(p.ends_with(".corcept/ledger/events.jsonl"));
    }

    #[test]
    fn xdg_overrides_win() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::env::set_var("CORCEPT_STATE_HOME", &state);
        std::env::set_var("HOME", "/should/not/be/used/for/state");
        assert_eq!(operator_state_dir(), Some(state.join("corcept")));
        std::env::remove_var("CORCEPT_STATE_HOME");
        std::env::remove_var("HOME");
    }

    #[test]
    fn env_path_rejects_empty() {
        std::env::set_var("CORCEPT_TEST_EMPTY", "");
        assert!(env_path("CORCEPT_TEST_EMPTY").is_none());
        std::env::remove_var("CORCEPT_TEST_EMPTY");
    }

    #[test]
    fn default_operator_state_via_override() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::env::set_var("CORCEPT_STATE_HOME", &state);
        assert_eq!(
            telemetry_path(),
            Some(state.join("corcept").join("telemetry"))
        );
        std::env::remove_var("CORCEPT_STATE_HOME");
    }

    #[test]
    fn secure_dir_rejects_group_writable() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(dir.path(), perms).unwrap();
            assert!(!dir_permissions_secure(dir.path()));
        }
    }
}
