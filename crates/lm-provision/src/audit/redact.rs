//! Pure redaction helpers (09-apply-report-and-ledger.md §Audit log).
//!
//! Kept string-in / string-out and side-effect free so they are directly
//! unit-testable without a `tracing` subscriber capturing output
//! (workspace/tasks/lm-provision-impl/plan.md M4-2: "tracing 出力の
//! capture は tracing-subscriber の test util か、redact 関数を pure に
//! 切って直接 test — 後者推奨"). [`crate::audit`]'s emission functions
//! call into these; nothing here touches `tracing` itself.

/// Case-insensitive substring match against the sensitive-key set
/// (09-apply-report-and-ledger.md §Inputs "the sensitive-key substring
/// set ... case-insensitive substring match on key names") — the same
/// case-folding shape [`crate::sandbox::policy::EnvPolicy`]'s own
/// `is_secret_shaped` already uses for the sibling
/// `SECRET_KEY_SUBSTRINGS` set, applied here to
/// `SENSITIVE_KEY_SUBSTRINGS`
/// ([`crate::sandbox::catalog::sensitive_key_substrings`]) instead.
pub fn is_sensitive_key(key: &str, sensitive_keys: &[String]) -> bool {
    let key_lower = key.to_lowercase();
    sensitive_keys
        .iter()
        .any(|substring| key_lower.contains(substring.to_lowercase().as_str()))
}

/// Env-key-NAME redaction (09 §Audit log "Env keys": "key names are
/// logged; a name matching the sensitive-key set is logged as `<KEY>
/// [REDACTED]`. Values are never logged, sensitive or not."). Callers
/// never pass a value in here — this function's whole contract is that
/// a value cannot leak through it, sensitive or not.
pub fn redact_env_key_name(key: &str, sensitive_keys: &[String]) -> String {
    if is_sensitive_key(key, sensitive_keys) {
        format!("{key} [REDACTED]")
    } else {
        key.to_string()
    }
}

/// The general `(key, value)` redact helper (09 §Audit log "General
/// redact helper": "any (key, value) pair surfaced into logs passes the
/// sensitive-key check; matching keys get `[REDACTED]` values"). Unlike
/// [`redact_env_key_name`] this one does accept a value — callers that
/// have a value they might otherwise log (rather than one that must
/// never be logged at all, per 09's `fs.write` / HTTP body rules) run it
/// through here first.
pub fn redact_pair(key: &str, value: &str, sensitive_keys: &[String]) -> String {
    if is_sensitive_key(key, sensitive_keys) {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

/// `SecretRef` marker rendering (09 §Audit log "Secret markers": "a
/// SecretRef renders as `[secret:NAME]` everywhere (print redirect,
/// audit fields)") — the identical literal
/// [`crate::secret::SecretRef`]'s own `tostring` metamethod produces
/// (`crates/lm-provision/src/secret/secret_ref.rs`). This is the
/// audit-side rendering for a secret *name* a caller already has in
/// hand (e.g. `fs.write`'s `content_source = "secret:<name>"`), not a
/// second `SecretRef` construction path.
pub fn secret_marker(name: &str) -> String {
    format!("[secret:{name}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sensitive_keys() -> Vec<String> {
        vec![
            "key".to_string(),
            "token".to_string(),
            "secret".to_string(),
            "password".to_string(),
            "pwd".to_string(),
            "auth".to_string(),
            "cred".to_string(),
            "apikey".to_string(),
        ]
    }

    #[test]
    fn is_sensitive_key_matches_a_substring_case_insensitively() {
        let keys = sensitive_keys();
        assert!(is_sensitive_key("MY_TOKEN", &keys));
        assert!(is_sensitive_key("myToken", &keys));
        assert!(is_sensitive_key("HF_API_KEY", &keys));
        assert!(is_sensitive_key("db_password", &keys));
    }

    #[test]
    fn is_sensitive_key_does_not_match_a_plain_name() {
        let keys = sensitive_keys();
        assert!(!is_sensitive_key("LOG_LEVEL", &keys));
        assert!(!is_sensitive_key("MY_VAR", &keys));
    }

    #[test]
    fn redact_env_key_name_flags_a_sensitive_shaped_name() {
        let keys = sensitive_keys();
        assert_eq!(
            redact_env_key_name("HF_TOKEN", &keys),
            "HF_TOKEN [REDACTED]"
        );
    }

    #[test]
    fn redact_env_key_name_passes_through_a_plain_name_unredacted() {
        let keys = sensitive_keys();
        assert_eq!(redact_env_key_name("LOG_LEVEL", &keys), "LOG_LEVEL");
    }

    #[test]
    fn redact_pair_redacts_the_value_for_a_sensitive_shaped_key() {
        let keys = sensitive_keys();
        assert_eq!(
            redact_pair("Authorization", "Bearer secret-value", &keys),
            "[REDACTED]"
        );
    }

    #[test]
    fn redact_pair_passes_through_the_value_for_a_non_sensitive_key() {
        let keys = sensitive_keys();
        assert_eq!(
            redact_pair("Content-Type", "text/plain", &keys),
            "text/plain"
        );
    }

    #[test]
    fn secret_marker_renders_the_bracketed_name() {
        assert_eq!(secret_marker("HF_TOKEN"), "[secret:HF_TOKEN]");
    }
}
