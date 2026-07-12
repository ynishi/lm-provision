//! M4-3 (`apply` CLI wiring + example-profile regression) tests
//! (07-cli.md §apply; 09-apply-report-and-ledger.md §Outputs "Apply
//! report").
//!
//! Mirrors `tests/m2_cli.rs`'s `assert_cmd`-driven pattern — the only
//! way to exercise `apply`'s stdout / stderr / exit-code contract end to
//! end. 02-phase-catalog.md §MVP scope: "the binary side ships in Phase
//! F, including a whole-directory `apply --dry-run` regression over the
//! example profiles" — the three fixtures below are that regression:
//! an sh.exec-routed kind + fs.write + a `dispatch_pending` kind
//! (`apply-sh-fs.lua`), `net.http_get` / `net.http_post` / `net.transfer`
//! download (`apply-net.lua`), and `mount.bind` / `mount.umount`
//! (`apply-mount.lua`) — every one of them dry-run-safe on any platform
//! (no process spawn, no network call, no real mount syscall; `--dry-run`
//! propagates to every dispatched op via `lm.apply`'s `effective_opts`
//! union, 09 §Semantics).

use assert_cmd::Command;

/// Absolute path to a fixture under `tests/fixtures/`.
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> Command {
    Command::cargo_bin("lm-provision").expect("lm-provision binary should build")
}

/// Runs `apply <fixture> --dry-run`, asserts exit 0, and parses stdout
/// as the apply report JSON (07-cli.md §Per-subcommand stdout `apply`).
fn apply_dry_run_report(fixture_name: &str) -> serde_json::Value {
    let output = bin()
        .args(["apply", &fixture(fixture_name), "--dry-run"])
        .output()
        .expect("process should run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{fixture_name}: expected exit 0 for an all-ok dry-run report, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    serde_json::from_str(&stdout).expect("apply stdout should be the pretty-printed report JSON")
}

fn step_ops(report: &serde_json::Value) -> Vec<&str> {
    report["steps"]
        .as_array()
        .expect("steps should be an array")
        .iter()
        .map(|step| step["op"].as_str().expect("step.op should be a string"))
        .collect()
}

fn assert_every_step_ok(report: &serde_json::Value) {
    for step in report["steps"].as_array().expect("steps array") {
        assert_eq!(step["ok"], serde_json::json!(true), "step: {step}");
    }
}

// ---------------------------------------------------------------------
// Whole-directory example-profile regression (02 §MVP scope)
// ---------------------------------------------------------------------

#[test]
fn apply_dry_run_sh_exec_fs_write_and_pending_all_report_ok() {
    let report = apply_dry_run_report("apply-sh-fs.lua");
    assert_eq!(report["ok"], serde_json::json!(true));
    assert_eq!(report["dry_run"], serde_json::json!(true));
    assert_eq!(
        report["profile_name"],
        serde_json::json!("demo-apply-sh-fs")
    );
    assert!(report.get("error").is_none());

    let ops = step_ops(&report);
    assert!(ops.contains(&"sh.exec"), "ops: {ops:?}");
    assert!(ops.contains(&"fs.write"), "ops: {ops:?}");
    assert!(ops.contains(&"dispatch_pending"), "ops: {ops:?}");
    assert_every_step_ok(&report);
}

#[test]
fn apply_dry_run_net_http_get_post_and_transfer_all_report_ok() {
    let report = apply_dry_run_report("apply-net.lua");
    assert_eq!(report["ok"], serde_json::json!(true));

    let ops = step_ops(&report);
    assert!(ops.contains(&"net.http_get"), "ops: {ops:?}");
    assert!(ops.contains(&"net.http_post"), "ops: {ops:?}");
    assert!(ops.contains(&"net.transfer"), "ops: {ops:?}");
    assert_every_step_ok(&report);
}

#[test]
fn apply_dry_run_mount_bind_and_umount_report_ok_cross_platform() {
    let report = apply_dry_run_report("apply-mount.lua");
    assert_eq!(report["ok"], serde_json::json!(true));

    let ops = step_ops(&report);
    assert!(ops.contains(&"mount.bind"), "ops: {ops:?}");
    assert!(ops.contains(&"mount.umount"), "ops: {ops:?}");
    assert_every_step_ok(&report);
}

// ---------------------------------------------------------------------
// Failure path (07 §Exit codes: "1 — any failure ... apply report
// ok = false")
// ---------------------------------------------------------------------

#[test]
fn apply_reports_ok_false_and_exits_1_for_a_step_that_fails() {
    let output = bin()
        .args(["apply", &fixture("apply-failing-step.lua"), "--dry-run"])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .expect("apply must print the report on failure too (07 §Outputs)");
    assert_eq!(report["ok"], serde_json::json!(false));
    assert!(report["error"].as_str().unwrap().contains("sh.exec"));

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.starts_with("apply failed:"),
        "07 §Error surface literal failure-line form: {stderr}"
    );
}

// ---------------------------------------------------------------------
// Precondition error (07 §Error surface "Precondition"): nothing on
// stdout, exit 1
// ---------------------------------------------------------------------

#[test]
fn apply_missing_profile_file_is_exit_1_with_nothing_on_stdout() {
    let output = bin()
        .args([
            "apply",
            "/nonexistent/lm-provision-profile.lua",
            "--dry-run",
        ])
        .output()
        .expect("process should run");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "07 §Per-subcommand stdout: nothing on a precondition failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.starts_with("apply failed:"), "stderr: {stderr}");
}

#[test]
fn apply_without_dry_run_flag_still_runs_the_pipeline_and_prints_a_report() {
    // No `--dry-run`: `apply-failing-step.lua` declares no capabilities
    // at all, so its sh.exec step fails in-report before any bridge
    // call is even attempted (register skip) — the "real" run performs
    // no effect either way. This only exercises that the non-dry-run
    // path reaches `run` and prints a report at all, not `--dry-run`'s
    // own propagation behaviour (covered above).
    let output = bin()
        .args(["apply", &fixture("apply-failing-step.lua")])
        .output()
        .expect("process should run");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply must print a report even without --dry-run");
    assert_eq!(report["dry_run"], serde_json::json!(false));
}
