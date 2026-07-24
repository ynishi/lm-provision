//! End-to-end regression for the `hash` / `plan` subcommands' file-
//! format routing (plan §CLI 配線): `.lua` files stay on the legacy
//! Lua pipeline, everything else goes through the AST frontend
//! ([`lm_provision::frontend::load_profile`]) and yields either a
//! frontend-agnostic 64-char hex digest via
//! [`lm_provision::canonical::hash`] or the plan artifact via
//! [`lm_provision::plan::expand`].

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
fn plan_of_lua_profile_still_runs_the_legacy_pipeline_unchanged() {
    // valid.lua declares system.apt + comfyui.install; the legacy Lua
    // plan inserts comfyui.restart / comfyui.health at the default
    // port and carries `schema = "lm.profile/1"` (the AST plan omits
    // that field). This asserts the legacy shape survives.
    let (code, stdout, stderr) = run_plan(&fixture("valid.lua"));
    assert_eq!(code, 0, "stderr: {stderr}");
    let plan = parse_plan(&stdout);
    assert_eq!(plan["profile_name"], serde_json::json!("demo-valid"));
    assert_eq!(
        plan["schema"],
        serde_json::json!("lm.profile/1"),
        "legacy Lua plan carries a schema field; a routing regression would drop it",
    );
    let ids: Vec<&str> = plan["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "1_system_apt",
            "2_comfyui_install",
            "9_comfyui_restart",
            "10_comfyui_health",
        ],
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
