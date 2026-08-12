//! Local, read-only pipeline tools: `lm_validate` / `lm_hash` / `lm_plan`
//! (10-mcp.md §Tool set) — each a direct, in-process call into the
//! `lm-provision` library's own AST pipeline functions
//! ([`lm_provision::cli::ast_validate`] etc.), since `profile_path`
//! is a path visible to the MCP server host (10 §Inputs: "profile
//! authoring/upload is out of scope") and none of these three
//! subcommands touches an effect or a pod (07-cli.md §Invocation: "none
//! (read-only)"). Plain, `async`-free functions on purpose so tests can
//! call them directly at the function level rather than through an MCP
//! transport — mirroring [`crate::apply_tool`] /
//! [`crate::ledger_tools`].
//!
//! Each function returns `Result<serde_json::Value, String>` rather
//! than a richer error enum: 10 §Error surface only asks that
//! "precondition ... errors propagate with class preserved", and every
//! failure these three pipeline stages can raise (profile load, parse,
//! validate rejection) is precondition-class end to end — the
//! rendered message text is all a caller needs to preserve that class
//! (matching [`lm_provision::cli::RunError`]'s own `Display`, which is
//! exactly what the CLI's "final error line" already surfaces, 07
//! §Error surface).

use std::path::Path;

use lm_provision::cli::{ast_hash, ast_plan, ast_validate};

/// `lm_validate(profile_path)` (10 §Tool set). On success, mirrors the
/// CLI's own stdout shape (07 §Per-subcommand stdout:
/// `{"ok":true,"name":"<profile>"}`) — the same object
/// [`crate::pipeline`]'s doc comment above calls "JSON passthrough of
/// the CLI stdout" (10 §Outputs).
pub fn lm_validate(profile_path: &Path) -> Result<serde_json::Value, String> {
    let name = ast_validate(profile_path).map_err(|err| err.to_string())?;
    Ok(serde_json::json!({ "ok": true, "name": name }))
}

/// `lm_hash(profile_path)` (10 §Tool set / §Outputs: `{ hash: "<64-hex>" }`,
/// distinct from the bare CLI `hash` stdout line — the MCP tool wraps it
/// in an object as 10 §Outputs specifies).
pub fn lm_hash(profile_path: &Path) -> Result<serde_json::Value, String> {
    let hash = ast_hash(profile_path).map_err(|err| err.to_string())?;
    Ok(serde_json::json!({ "hash": hash }))
}

/// `lm_plan(profile_path)` (10 §Tool set / §Outputs: "the chapter 03
/// artifacts as structured tool results (JSON passthrough of the CLI
/// stdout)" — the plan artifact itself, unwrapped).
pub fn lm_plan(profile_path: &Path) -> Result<serde_json::Value, String> {
    ast_plan(profile_path).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute path to a fixture under the sibling `lm-provision`
    /// crate's own `tests/fixtures/` (shared regression fixtures; this
    /// crate deliberately does not fork a second copy).
    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!(
            "{}/../lm-provision/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
    }

    #[test]
    fn lm_validate_happy_returns_ok_true_and_the_profile_name() {
        let value = lm_validate(&fixture("valid.json")).expect("valid.json should validate");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(value["name"], serde_json::json!("demo-valid"));
    }

    #[test]
    fn lm_validate_missing_file_is_a_precondition_class_error() {
        let err = lm_validate(Path::new("/nonexistent/lm-provision-profile.json"))
            .expect_err("a missing profile file must not validate");
        assert!(
            err.contains("failed to read profile") || err.contains("No such file"),
            "error message should describe the load failure: {err}"
        );
    }

    #[test]
    fn lm_hash_returns_a_64_char_lowercase_hex_digest() {
        let value = lm_hash(&fixture("valid.json")).expect("valid.json should hash");
        let hash = value["hash"].as_str().expect("hash should be a string");
        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn lm_hash_is_deterministic_across_repeated_calls() {
        let first = lm_hash(&fixture("valid.json")).expect("first hash");
        let second = lm_hash(&fixture("valid.json")).expect("second hash");
        assert_eq!(first["hash"], second["hash"]);
    }

    #[test]
    fn lm_plan_returns_the_plan_artifact_as_a_json_object_with_steps() {
        let value = lm_plan(&fixture("valid.json")).expect("valid.json should plan");
        assert_eq!(value["profile_name"], serde_json::json!("demo-valid"));
        assert!(
            value["steps"].is_array(),
            "plan should carry a steps array: {value}"
        );
    }

    #[test]
    fn lm_plan_missing_file_is_a_precondition_class_error() {
        let err = lm_plan(Path::new("/nonexistent/lm-provision-profile.json"))
            .expect_err("a missing profile file must not plan");
        assert!(!err.is_empty());
    }

    #[test]
    fn lm_validate_rejects_a_lua_profile() {
        let err = lm_validate(Path::new("/nonexistent/profile.lua"))
            .expect_err("a .lua profile must be rejected");
        assert!(
            err.contains("Lua profiles are no longer supported"),
            "error message should describe the Lua rejection: {err}"
        );
    }
}
