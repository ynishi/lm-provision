//! M5 (`codegen` subcommand) regression tests (07-cli.md).
//!
//! Follows `m2_cli.rs`'s convention: drives the actual `lm-provision`
//! binary via `assert_cmd` to prove the CLI's stdout / exit-code
//! contract end to end.

use assert_cmd::Command;

/// Absolute path to a fixture under `tests/fixtures/`.
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> Command {
    Command::cargo_bin("lm-provision").expect("lm-provision binary should build")
}

#[test]
fn codegen_emits_output_for_valid_fixture() {
    let output = bin()
        .args(["codegen", &fixture("valid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(!stdout.is_empty());
    assert!(stdout.contains("---@meta"));
    assert!(stdout.contains("---@class lm.profile"));
}

#[test]
fn codegen_output_lists_all_22_phase_kinds() {
    let output = bin()
        .args(["codegen", &fixture("valid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    let block = alias_block(&stdout, "---@alias lm.phase.kind");
    assert_eq!(
        block
            .lines()
            .filter(|line| line.starts_with("---| "))
            .count(),
        22,
        "lm.phase.kind alias block: {block}"
    );
}

#[test]
fn codegen_output_lists_all_9_known_capabilities() {
    let output = bin()
        .args(["codegen", &fixture("valid.lua")])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    let block = alias_block(&stdout, "---@alias lm.capability");
    assert_eq!(
        block
            .lines()
            .filter(|line| line.starts_with("---| "))
            .count(),
        9,
        "lm.capability alias block: {block}"
    );
}

// NOTE: `tests/fixtures/invalid.lua` (rejected by `lm.validate` check 3,
// per its own doc comment) does NOT fail `codegen` — `codegen`, like
// `hash` and `plan`, deliberately does not run `lm.validate`
// (07-cli.md §Invocation: `codegen`'s pipeline-stages column is "load →
// declarations → codegen", no validate stage), so `invalid.lua` reaches
// `evaluate_profile_file` successfully and `codegen` emits output for it
// exactly as it does for `valid.lua`. The precondition-failure
// convention `m2_cli.rs` actually establishes for non-validating
// subcommands (`hash` / `plan`) is
// `missing_profile_file_is_exit_1_across_every_read_only_subcommand`
// (nonexistent path, a true load-time precondition failure) — mirrored
// here for `codegen`.
#[test]
fn codegen_fails_on_missing_profile_file() {
    let output = bin()
        .args(["codegen", "/nonexistent/lm-provision-profile.lua"])
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
        stderr.starts_with("codegen failed:"),
        "07 §Error surface literal failure-line form: {stderr}"
    );
}

/// Extract the `---| "..."` lines belonging to the alias block starting
/// at `header` (up to the next blank line or end of string).
fn alias_block<'a>(stdout: &'a str, header: &str) -> &'a str {
    let start = stdout
        .find(header)
        .unwrap_or_else(|| panic!("expected {header:?} in output: {stdout}"));
    let rest = &stdout[start..];
    match rest.find("\n\n") {
        Some(end) => &rest[..end],
        None => rest,
    }
}
