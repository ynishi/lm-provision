//! M2-5 (CLI wiring) regression tests (07-cli.md).
//!
//! Unlike the M2-1..M2-4 pipeline-stage tests, which exercise
//! `lm.validate` / `lm.canonical` / `lm.hash` / `lm.plan` directly
//! through [`lm_provision::vm::boot_vm`], this file drives the actual
//! `lm-provision` binary via `assert_cmd` — it is the only test that
//! proves the CLI's stdout / stderr / exit-code contract end to end
//! (07-cli.md §Outputs, §Error surface).

use assert_cmd::Command;

/// Absolute path to a fixture under `tests/fixtures/`.
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> Command {
    Command::cargo_bin("lm-provision").expect("lm-provision binary should build")
}

// ---------------------------------------------------------------------
// validate (07 §Per-subcommand stdout / §Exit codes)
// ---------------------------------------------------------------------

#[test]
fn validate_happy_prints_ok_json_and_exits_zero() {
    let output = bin()
        .args(["validate", &fixture("valid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["name"], serde_json::json!("demo-valid"));
}

#[test]
fn validate_fail_prints_nothing_to_stdout_and_an_error_to_stderr() {
    let output = bin()
        .args(["validate", &fixture("invalid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "07 §Per-subcommand stdout: nothing is printed to stdout on failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.starts_with("validate failed:"),
        "07 §Error surface literal failure-line form: {stderr}"
    );
    assert!(
        stderr.contains("secret-shaped"),
        "should surface the validate-stage rejection message: {stderr}"
    );
}

// ---------------------------------------------------------------------
// hash (07 §Per-subcommand stdout: "64-char lowercase hex ...
// newline. Nothing else.")
// ---------------------------------------------------------------------

#[test]
fn hash_prints_only_the_64_char_lowercase_hex_digest_and_a_trailing_newline() {
    let output = bin()
        .args(["hash", &fixture("valid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout.last(),
        Some(&b'\n'),
        "must end with a trailing newline"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert_eq!(
        stdout.matches('\n').count(),
        1,
        "nothing else may follow the digest: {stdout:?}"
    );
    let digest = stdout.trim_end();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "digest: {digest}"
    );
}

#[test]
fn hash_is_deterministic_across_repeated_invocations() {
    let first = bin()
        .args(["hash", &fixture("valid.lua")])
        .output()
        .expect("process should run")
        .stdout;
    let second = bin()
        .args(["hash", &fixture("valid.lua")])
        .output()
        .expect("process should run")
        .stdout;
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------
// plan (07 §Per-subcommand stdout: "the plan artifact ... as
// pretty-printed JSON")
// ---------------------------------------------------------------------

#[test]
fn plan_prints_the_plan_artifact_as_parseable_json() {
    let output = bin()
        .args(["plan", &fixture("valid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(value["profile_name"], serde_json::json!("demo-valid"));
    assert_eq!(value["schema"], serde_json::json!("lm.profile/1"));

    let steps = value["steps"].as_array().expect("steps should be an array");
    assert!(!steps.is_empty());
    assert_eq!(steps[0]["id"], serde_json::json!("1_system_apt"));
    assert_eq!(steps[0]["index"], serde_json::json!(1));

    let ids: Vec<&str> = steps
        .iter()
        .map(|step| step["id"].as_str().expect("id should be a string"))
        .collect();
    assert_eq!(
        ids,
        vec![
            "1_system_apt",
            "2_comfyui_install",
            "9_comfyui_restart",
            "10_comfyui_health",
        ],
        "02 §Canonical phase ordering: comfyui.install with neither \
         restart nor health declared inserts both"
    );
}

// ---------------------------------------------------------------------
// Transport errors (07 §Error surface "Transport": missing profile
// file)
// ---------------------------------------------------------------------

#[test]
fn missing_profile_file_is_exit_1_across_every_read_only_subcommand() {
    for subcommand in ["validate", "hash", "plan"] {
        let output = bin()
            .args([subcommand, "/nonexistent/lm-provision-profile.lua"])
            .output()
            .expect("process should run");
        assert_eq!(
            output.status.code(),
            Some(1),
            "{subcommand}: expected exit 1 for a missing profile file"
        );
        assert!(
            output.stdout.is_empty(),
            "{subcommand}: stdout: {:?}",
            output.stdout
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("{subcommand} failed:")),
            "{subcommand}: stderr: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------
// Usage errors (07 §Exit codes: "2 — CLI usage error")
// ---------------------------------------------------------------------

#[test]
fn unknown_subcommand_exits_2() {
    let output = bin()
        .args(["bogus", "profile.lua"])
        .output()
        .expect("process should run");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn unknown_flag_exits_2() {
    let output = bin()
        .args(["validate", "profile.lua", "--bogus"])
        .output()
        .expect("process should run");
    assert_eq!(output.status.code(), Some(2));
}
