//! Secret scrubbing for values persisted to the append-only ledger.
//!
//! The ledger (and its CloudEvents projection) is durable and may be exported
//! off-host, so it must honor the shipped doctrine: "Treat secrets as
//! unreadable; identify their presence only." Key-name-based redaction is not
//! enough — a Bash `command` string carries inline secrets under the benign
//! key `command`, so we must also scrub secret *patterns* out of free-text
//! values (command lines, decision reasons, targets).

use serde_json::Value;

const REDACTED: &str = "[REDACTED]";

/// Sensitive shell variable name fragments. A `NAME=VALUE` assignment whose
/// NAME contains one of these (case-insensitive) has its VALUE redacted.
const SENSITIVE_VAR_FRAGMENTS: &[&str] = &[
    "token", "secret", "password", "passwd", "pwd", "apikey", "api_key", "access_key",
    "secret_key", "private_key", "credential", "auth", "session", "cookie", "bearer",
];

/// Scrub secrets out of a free-text string (typically a shell command line or a
/// decision reason that echoes one). The original is never returned verbatim
/// when a secret-shaped substring is detected.
pub fn scrub_secrets(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for token in split_keep_whitespace(input) {
        out.push_str(&scrub_token(token));
    }
    out
}

/// Recursively scrub a JSON value. Object values whose KEY looks sensitive are
/// fully redacted; all string values (regardless of key) are run through the
/// pattern scrubber so that e.g. `{"command": "mysql -psecret"}` is cleaned.
pub fn scrub_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let scrubbed = map
                .iter()
                .map(|(key, val)| {
                    if key_is_sensitive(key) {
                        (key.clone(), Value::String(REDACTED.to_string()))
                    } else {
                        (key.clone(), scrub_value(val))
                    }
                })
                .collect();
            Value::Object(scrubbed)
        }
        Value::Array(items) => Value::Array(items.iter().map(scrub_value).collect()),
        Value::String(s) => Value::String(scrub_secrets(s)),
        other => other.clone(),
    }
}

fn key_is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("key")
}

/// Split a string into alternating whitespace and non-whitespace runs so we can
/// rebuild it preserving the original spacing.
fn split_keep_whitespace(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_ws = matches!(input.chars().next(), Some(c) if c.is_whitespace());
    for (idx, ch) in input.char_indices() {
        let is_ws = ch.is_whitespace();
        if is_ws != in_ws {
            parts.push(&input[start..idx]);
            start = idx;
            in_ws = is_ws;
        }
    }
    if start < input.len() {
        parts.push(&input[start..]);
    }
    parts
}

fn scrub_token(token: &str) -> String {
    if token.chars().all(char::is_whitespace) || token.is_empty() {
        return token.to_string();
    }

    // mysql/curl-style attached password: -p<secret>, -ppass, --password=...
    if let Some(rest) = token.strip_prefix("-p") {
        if !rest.is_empty() && !rest.starts_with('-') {
            return "-p".to_string() + REDACTED;
        }
    }

    // NAME=VALUE assignment with a sensitive name (e.g. TOKEN=..., export below).
    if let Some((name, value)) = token.split_once('=') {
        if !value.is_empty() && var_name_is_sensitive(name) {
            return format!("{name}={REDACTED}");
        }
        // Even a non-sensitive-named assignment can carry a high-entropy secret.
        if looks_like_secret(value) {
            return format!("{name}={REDACTED}");
        }
        return token.to_string();
    }

    // A bare high-entropy blob (long base64/hex run, bearer token, etc.).
    if looks_like_secret(token) {
        return REDACTED.to_string();
    }

    token.to_string()
}

fn var_name_is_sensitive(name: &str) -> bool {
    // Strip a leading shell prefix like `export ` handled at token level; here
    // `name` is the raw left side of `=`.
    let lower = name.to_ascii_lowercase();
    SENSITIVE_VAR_FRAGMENTS
        .iter()
        .any(|frag| lower.contains(frag))
}

/// Heuristic: does this substring look like a secret rather than ordinary text?
/// Conservative — only flags long, high-entropy, mostly-token-charset runs so we
/// don't mangle normal command arguments.
fn looks_like_secret(s: &str) -> bool {
    let trimmed = s.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
    if trimmed.len() < 20 {
        return false;
    }
    // Token-like charset only (base64url / hex / typical API key alphabet).
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '/' | '='))
    {
        return false;
    }
    // Require a mix of letters and digits to avoid flagging long flag words or
    // file paths made of a single class.
    let has_alpha = trimmed.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = trimmed.chars().any(|c| c.is_ascii_digit());
    // Common known prefixes are always secrets even if short of the entropy bar.
    let known_prefix = ["bearer", "ghp_", "gho_", "sk-", "xoxb-", "xoxp-", "aws_"]
        .iter()
        .any(|p| trimmed.to_ascii_lowercase().starts_with(p));
    known_prefix || (has_alpha && has_digit && trimmed.len() >= 24)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_mysql_inline_password() {
        let out = scrub_secrets("mysql -psup3rs3cretpw -h db");
        assert!(!out.contains("sup3rs3cretpw"), "{out}");
        assert!(out.contains("-p[REDACTED]"), "{out}");
        assert!(out.contains("mysql"));
        assert!(out.contains("-h db"));
    }

    #[test]
    fn redacts_sensitive_env_assignment() {
        let out = scrub_secrets("export TOKEN=abc123def && deploy");
        assert!(!out.contains("abc123def"), "{out}");
        assert!(out.contains("TOKEN=[REDACTED]"), "{out}");
        assert!(out.contains("deploy"));
    }

    #[test]
    fn redacts_bearer_token() {
        let out = scrub_secrets("curl -H 'Authorization: Bearer' ghp_0123456789abcdefghijABCD");
        assert!(!out.contains("ghp_0123456789abcdefghijABCD"), "{out}");
        assert!(out.contains("[REDACTED]"), "{out}");
    }

    #[test]
    fn redacts_high_entropy_blob() {
        let secret = "AKIA1234567890ABCDEFGHIJ0987654321";
        let out = scrub_secrets(&format!("aws s3 ls {secret}"));
        assert!(!out.contains(secret), "{out}");
    }

    #[test]
    fn leaves_ordinary_commands_intact() {
        let cmd = "git commit -m fix && cargo test --workspace";
        assert_eq!(scrub_secrets(cmd), cmd);
    }

    #[test]
    fn scrub_value_cleans_command_key() {
        let input = json!({"command": "mysql -ptopsecret123"});
        let out = scrub_value(&input);
        let cmd = out["command"].as_str().unwrap();
        assert!(!cmd.contains("topsecret123"), "{cmd}");
        assert!(cmd.contains("[REDACTED]"));
    }

    #[test]
    fn scrub_value_still_redacts_sensitive_keys() {
        let input = json!({"api_token": "whatever", "command": "ls"});
        let out = scrub_value(&input);
        assert_eq!(out["api_token"], "[REDACTED]");
        assert_eq!(out["command"], "ls");
    }
}
