//! End-to-end regression for the `validate` / `hash` / `plan`
//! subcommands' file-format routing (plan §CLI 配線): every profile goes
//! through the AST frontend ([`lm_provision::frontend::load_profile`]),
//! which parses `.json` via the serde bridge and everything else via the
//! canonical text grammar, and **rejects `.lua`** outright now that the
//! legacy embedded-Lua pipeline is gone. `hash` yields a
//! frontend-agnostic 64-char hex digest via
//! [`lm_provision::canonical::hash`]; `plan` yields the plan artifact via
//! [`lm_provision::plan::expand`]; `validate` yields the `{ ok, name }`
//! envelope.

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
fn hash_of_lua_profile_is_rejected() {
    // The legacy embedded-Lua pipeline is gone: a `.lua` profile must be
    // rejected loudly (rather than silently misparsed as canonical text)
    // at the CLI boundary. The extension check precedes any file I/O, so
    // the path need not exist.
    let (code, stdout, stderr) = run_hash(&fixture("legacy.lua"));
    assert_eq!(code, 1, "a .lua profile must exit 1");
    assert!(stdout.is_empty(), "nothing printed on failure: {stdout:?}");
    assert!(
        stderr.starts_with("hash failed: ")
            && stderr.contains("Lua profiles are no longer supported"),
        "stderr must carry the Lua-unsupported failure line: {stderr:?}",
    );
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

// ---------------------------------------------------------------------
// plan subcommand routing
// ---------------------------------------------------------------------

fn run_plan(profile_path: &Path) -> (i32, String, String) {
    let output = bin()
        .args(["plan", profile_path.to_str().expect("utf8 path")])
        .output()
        .expect("process should run");
    let status = output.status.code().expect("process should exit normally");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    (status, stdout, stderr)
}

fn parse_plan(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("plan stdout should be valid JSON")
}

#[test]
fn plan_of_json_profile_prints_the_plan_artifact_and_exits_zero() {
    let (code, stdout, stderr) = run_plan(&fixture("ast/valid.json"));
    assert_eq!(code, 0, "stderr: {stderr}");
    let plan = parse_plan(&stdout);
    assert_eq!(plan["profile_name"], serde_json::json!("demo-ast"));
    let steps = plan["steps"].as_array().expect("steps must be an array");
    // valid.json declares SystemApt + PythonDeps + ShExec + FsWrite:
    // canonical order = 1_system_apt, 3_python_deps, then two direct
    // ops in the trailing zz_unknown bucket.
    let ids: Vec<&str> = steps.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        vec!["1_system_apt", "3_python_deps", "zz_unknown", "zz_unknown"],
    );
    let kinds: Vec<&str> = steps.iter().map(|s| s["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        vec!["system.apt", "python.deps", "sh.exec", "fs.write"]
    );
    let indices: Vec<u64> = steps.iter().map(|s| s["index"].as_u64().unwrap()).collect();
    assert_eq!(indices, vec![1, 2, 3, 4]);
}

#[test]
fn plan_of_text_profile_matches_the_plan_of_the_equivalent_json_profile() {
    let (json_code, json_stdout, json_stderr) = run_plan(&fixture("ast/valid.json"));
    let (text_code, text_stdout, text_stderr) = run_plan(&fixture("ast/valid.txt"));
    assert_eq!(json_code, 0, "stderr: {json_stderr}");
    assert_eq!(text_code, 0, "stderr: {text_stderr}");
    let json_plan = parse_plan(&json_stdout);
    let text_plan = parse_plan(&text_stdout);
    // The two frontends converge on the same AST, so
    // [`crate::plan::expand`] must produce the same artifact.
    assert_eq!(json_plan, text_plan);
}

#[test]
fn plan_of_lua_profile_is_rejected() {
    // Same rejection contract as `hash`, exercised through the `plan`
    // subcommand so a routing regression is caught for either read-only
    // subcommand.
    let (code, stdout, stderr) = run_plan(&fixture("legacy.lua"));
    assert_eq!(code, 1, "a .lua profile must exit 1");
    assert!(stdout.is_empty(), "nothing printed on failure: {stdout:?}");
    assert!(
        stderr.starts_with("plan failed: ")
            && stderr.contains("Lua profiles are no longer supported"),
        "stderr must carry the Lua-unsupported failure line: {stderr:?}",
    );
}

#[test]
fn plan_of_missing_profile_reports_io_error_on_stderr() {
    let (code, stdout, stderr) = run_plan(&fixture("ast/does-not-exist.json"));
    assert_eq!(code, 1);
    assert!(
        stdout.is_empty(),
        "07 §Per-subcommand stdout: nothing printed on failure: {stdout:?}",
    );
    assert!(
        stderr.starts_with("plan failed: "),
        "07 §Error surface literal failure-line form: {stderr:?}",
    );
}

#[test]
fn plan_of_malformed_text_reports_parse_error() {
    let scratch = std::env::temp_dir().join(format!(
        "lm-provision-ast-plan-cli-{}-bad.txt",
        std::process::id(),
    ));
    std::fs::write(&scratch, "not a Spec at all").expect("scratch write");
    let (code, stdout, stderr) = run_plan(&scratch);
    let _ = std::fs::remove_file(&scratch);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(
        stderr.starts_with("plan failed: "),
        "parse failure must render through the standard failure line: {stderr:?}",
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

// ---------------------------------------------------------------------
// validate subcommand routing (AST-frontend port of the m2_cli validate
// CLI coverage: happy `{ ok, name }` envelope, a validate-stage
// rejection, and a precondition load failure).
// ---------------------------------------------------------------------

fn run_validate(profile_path: &Path) -> (i32, String, String) {
    let output = bin()
        .args(["validate", profile_path.to_str().expect("utf8 path")])
        .output()
        .expect("process should run");
    let status = output.status.code().expect("process should exit normally");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    (status, stdout, stderr)
}

#[test]
fn validate_of_json_profile_prints_ok_envelope_and_exits_zero() {
    let (code, stdout, stderr) = run_validate(&fixture("valid.json"));
    assert_eq!(code, 0, "stderr: {stderr}");
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("validate stdout should be JSON");
    assert_eq!(envelope["ok"], serde_json::json!(true));
    assert_eq!(envelope["name"], serde_json::json!("demo-valid"));
}

#[test]
fn validate_of_a_rejected_profile_prints_nothing_and_an_error_on_stderr() {
    // invalid.json declares a secret-shaped env key (`MY_TOKEN`), which
    // the validate stage rejects (03 §validate check 3).
    let (code, stdout, stderr) = run_validate(&fixture("invalid.json"));
    assert_eq!(code, 1, "a rejected profile must exit 1");
    assert!(
        stdout.is_empty(),
        "07 §Per-subcommand stdout: nothing printed on failure: {stdout:?}",
    );
    assert!(
        stderr.starts_with("validate failed: "),
        "07 §Error surface literal failure-line form: {stderr:?}",
    );
}

#[test]
fn validate_of_missing_profile_reports_io_error_on_stderr() {
    let (code, stdout, stderr) = run_validate(&fixture("ast/does-not-exist.json"));
    assert_eq!(code, 1, "missing profile must exit 1");
    assert!(stdout.is_empty(), "nothing printed on failure: {stdout:?}");
    assert!(
        stderr.starts_with("validate failed: "),
        "07 §Error surface literal failure-line form: {stderr:?}",
    );
}

#[test]
fn validate_of_lua_profile_is_rejected() {
    let (code, stdout, stderr) = run_validate(&fixture("legacy.lua"));
    assert_eq!(code, 1, "a .lua profile must exit 1");
    assert!(stdout.is_empty(), "nothing printed on failure: {stdout:?}");
    assert!(
        stderr.starts_with("validate failed: ")
            && stderr.contains("Lua profiles are no longer supported"),
        "stderr must carry the Lua-unsupported failure line: {stderr:?}",
    );
}
