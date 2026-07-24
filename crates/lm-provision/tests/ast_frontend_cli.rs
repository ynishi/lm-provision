//! End-to-end regression for the `hash` subcommand's file-format
//! routing (plan §CLI 配線): `.lua` files stay on the legacy Lua
//! pipeline, everything else goes through the AST frontend
//! ([`lm_provision::frontend::load_profile`]) and yields a
//! frontend-agnostic 64-char hex digest via
//! [`lm_provision::canonical::hash`].

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn bin() -> Command {
    Command::cargo_bin("lm-provision").expect("lm-provision binary should build")
}

fn run_hash(profile_path: &Path) -> (i32, String, String) {
    let output = bin()
        .args(["hash", profile_path.to_str().expect("utf8 path")])
        .output()
        .expect("process should run");
    let status = output.status.code().expect("process should exit normally");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    (status, stdout, stderr)
}

fn assert_hex64(hex: &str) {
    assert_eq!(
        hex.len(),
        64,
        "hash stdout must be exactly 64 hex chars (got {}: {hex:?})",
        hex.len(),
    );
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "hash stdout must be lowercase hex only: {hex:?}",
    );
}

#[test]
fn hash_of_json_profile_prints_lowercase_hex_and_exits_zero() {
    let (code, stdout, stderr) = run_hash(&fixture("ast/valid.json"));
    assert_eq!(code, 0, "stderr: {stderr}");
    let hex = stdout.trim_end();
    assert_hex64(hex);
}

#[test]
fn hash_of_text_profile_prints_lowercase_hex_and_exits_zero() {
    let (code, stdout, stderr) = run_hash(&fixture("ast/valid.txt"));
    assert_eq!(code, 0, "stderr: {stderr}");
    let hex = stdout.trim_end();
    assert_hex64(hex);
}

#[test]
fn json_and_text_frontends_hash_to_the_same_digest() {
    let (_, json_stdout, _) = run_hash(&fixture("ast/valid.json"));
    let (_, text_stdout, _) = run_hash(&fixture("ast/valid.txt"));
    assert_eq!(
        json_stdout.trim_end(),
        text_stdout.trim_end(),
        "JSON and text frontends must converge on the same AST hash",
    );
}

#[test]
fn hash_of_lua_profile_still_runs_the_legacy_pipeline_unchanged() {
    // The existing `.lua` fixture already validates through
    // `hash_pipeline`; re-run it here so a future routing regression
    // that misroutes `.lua` files onto the AST path is caught at the
    // CLI boundary rather than only inside `m2_cli.rs`.
    let (code, stdout, stderr) = run_hash(&fixture("valid.lua"));
    assert_eq!(code, 0, "stderr: {stderr}");
    let hex = stdout.trim_end();
    assert_hex64(hex);
}

#[test]
fn hash_of_missing_profile_reports_io_error_on_stderr() {
    let (code, stdout, stderr) = run_hash(&fixture("ast/does-not-exist.json"));
    assert_eq!(code, 1, "missing profile must exit 1");
    assert!(
        stdout.is_empty(),
        "07 §Per-subcommand stdout: nothing printed on failure: {stdout:?}",
    );
    assert!(
        stderr.starts_with("hash failed: "),
        "07 §Error surface literal failure-line form: {stderr:?}",
    );
}

#[test]
fn hash_of_malformed_json_reports_parse_error() {
    let scratch = std::env::temp_dir().join(format!(
        "lm-provision-ast-cli-{}-bad.json",
        std::process::id(),
    ));
    std::fs::write(&scratch, "{not: valid json,").expect("scratch write");
    let (code, stdout, stderr) = run_hash(&scratch);
    // Cleanup is best-effort — a leaked scratch file inside the OS
    // temp dir is harmless.
    let _ = std::fs::remove_file(&scratch);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(
        stderr.starts_with("hash failed: "),
        "parse failure must render through the standard failure line: {stderr:?}",
    );
}
