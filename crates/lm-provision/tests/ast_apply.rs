//! End-to-end regression for the `apply` subcommand's AST exec path: all
//! profiles route to [`lm_provision::apply::run_apply_ast`], and a `.lua`
//! profile is rejected at the frontend (the legacy embedded-Lua pipeline
//! is gone).
//!
//! The report envelope (`{ ok, dry_run, profile_name, steps, error? }`)
//! keeps the historical apply-report field names, with the `steps` array
//! carrying the AST exec layer's own step structure — one entry per
//! direct-op phase, one per lifecycle sub-step, with honest `note` steps
//! (see `lm_provision::exec::report`).

use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::{json, Value};

/// A unique temp path stem for this process + call.
fn temp_stem(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lm-provision-ast-apply-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

/// Write `profile` (a serde JSON `Spec`) to a fresh `.json` file and
/// return its path. The `.json` extension is what routes it onto the AST
/// frontend (`is_lua_profile` is false).
fn write_json_profile(label: &str, profile: &Value) -> PathBuf {
    let path = temp_stem(label).with_extension("json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(profile).expect("profile serializes"),
    )
    .expect("write temp profile");
    path
}

fn step_ops(report: &Value) -> Vec<String> {
    report["steps"]
        .as_array()
        .expect("steps is an array")
        .iter()
        .map(|s| s["op"].as_str().expect("op is a string").to_string())
        .collect()
}

fn step_ids(report: &Value) -> Vec<String> {
    report["steps"]
        .as_array()
        .expect("steps is an array")
        .iter()
        .map(|s| s["id"].as_str().expect("id is a string").to_string())
        .collect()
}

// ---------------------------------------------------------------------
// Dry-run report shape (envelope field names + AST step structure).
// ---------------------------------------------------------------------

#[test]
fn dry_run_report_has_the_legacy_envelope_and_ast_step_structure() {
    let profile = json!({
        "type": "Spec",
        "name": "ast-apply-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": ["/tmp"],
        "phases": [
            { "type": "SystemApt", "packages": ["git"] },
            { "type": "ShExec", "argv": ["echo", "hi"] },
            { "type": "FsWrite", "path": "/tmp/ast-apply-demo-x", "content": "hello" }
        ]
    });
    let path = write_json_profile("shape", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, true)
        .expect("dry-run apply over a valid profile should produce a report");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    // Envelope is field-name compatible with lua/lm/report.lua.
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["dry_run"], json!(true));
    assert_eq!(report["profile_name"], json!("ast-apply-demo"));
    assert!(report["steps"].is_array());
    assert!(
        report.get("error").is_none(),
        "an all-ok run carries no error"
    );

    // AST step structure: system.apt expands to one sh Sh sub-step, then
    // the two direct ops in declaration order.
    assert_eq!(
        step_ids(&report),
        vec!["1_system.apt_1", "2_sh.exec", "3_fs.write"]
    );
    assert_eq!(step_ops(&report), vec!["sh.exec", "sh.exec", "fs.write"]);

    let steps = report["steps"].as_array().unwrap();
    for step in steps {
        assert_eq!(step["ok"], json!(true), "step: {step}");
        assert_eq!(step["dry_run"], json!(true), "dry-run marker: {step}");
    }
    // The lifecycle sub-step carries its composed argv (apt-get install).
    assert_eq!(steps[0]["kind"], json!("system.apt"));
    assert_eq!(steps[0]["argv"][0], json!("apt-get"));
    // fs.write reports its target path + byte count even in dry-run.
    assert_eq!(steps[2]["path"], json!("/tmp/ast-apply-demo-x"));
    assert_eq!(steps[2]["bytes"], json!(5));

    std::fs::remove_file(&path).ok();
}

#[test]
fn lifecycle_note_step_is_honest_never_dispatch_pending() {
    let profile = json!({
        "type": "Spec",
        "name": "note-demo",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "ServiceStart", "name": "llm", "platform_kind": "vllm" }
        ]
    });
    let path = write_json_profile("note", &profile);

    let report_json =
        lm_provision::apply::run_apply_ast(&path, true).expect("dry-run apply should succeed");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    let ops = step_ops(&report);
    assert!(
        ops.contains(&"note".to_string()),
        "an effectless lifecycle sub-step is an honest note step: {ops:?}"
    );
    assert!(
        !ops.contains(&"dispatch_pending".to_string()),
        "the AST path never emits the legacy dispatch_pending skip: {ops:?}"
    );
    let step = &report["steps"][0];
    assert_eq!(step["ok"], json!(true), "a note step is a success");
    assert!(step.get("note").is_some(), "the note text is carried");

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Real-mode end-to-end (harmless effects only).
// ---------------------------------------------------------------------

#[test]
fn real_mode_runs_sh_exec_and_fs_write_for_real() {
    let dir = temp_stem("real-effects");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("out.txt");
    let target_str = target.to_string_lossy().into_owned();
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "real-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": [dir_str],
        "phases": [
            { "type": "ShExec", "argv": ["true"] },
            { "type": "FsWrite", "path": target_str, "content": "written-for-real" }
        ]
    });
    let path = write_json_profile("real", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .expect("real-mode apply over a harmless profile should succeed");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["dry_run"], json!(false));

    let steps = report["steps"].as_array().unwrap();
    // Real mode carries no dry_run marker on its step entries.
    for step in steps {
        assert!(
            step.get("dry_run").is_none(),
            "real-mode steps omit the dry_run marker: {step}"
        );
    }
    // The sh.exec step captured its (empty) stdout tail structurally.
    assert_eq!(steps[0]["op"], json!("sh.exec"));
    assert!(steps[0].get("stdout").is_some());

    // The effect actually ran.
    assert_eq!(
        std::fs::read_to_string(&target).expect("target file was written"),
        "written-for-real"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// A real-mode **lifecycle** sub-step must carry what it observed —
/// exit status and captured output — not just the argv it was composed
/// from. The exec layer used to keep only the joined trace summary, so
/// these entries were strictly less informative than a direct op's
/// (spec 09 §Apply report: the per-op field table applies to lifecycle
/// sub-steps too).
#[test]
fn real_mode_lifecycle_substeps_carry_their_observations() {
    // `hooks.post_install` composes exactly one `sh.exec` sub-step out
    // of the script, so the assertion targets a lifecycle entry rather
    // than a direct op.
    let profile = json!({
        "type": "Spec",
        "name": "lifecycle-observations",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "PostInstall", "script": "echo observed-stdout" }
        ]
    });
    let path = write_json_profile("lifecycle-observations", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .expect("a post_install echo should apply cleanly");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");
    assert_eq!(report["ok"], json!(true));

    let steps = report["steps"].as_array().unwrap();
    assert_eq!(
        steps.len(),
        1,
        "post_install composes one sub-step: {steps:?}"
    );
    let step = &steps[0];

    // Lifecycle sub-step id shape, and the effect it actually ran.
    assert_eq!(step["kind"], json!("hooks.post_install"));
    assert_eq!(step["op"], json!("sh.exec"));
    assert_eq!(step["id"], json!("1_hooks.post_install_1"));

    // The declared input is still there …
    assert_eq!(step["argv"], json!(["sh", "-c", "echo observed-stdout"]));
    // … and now so are the observations.
    assert_eq!(step["status"], json!(0), "exit status: {step}");
    assert!(
        step["stdout"]
            .as_str()
            .expect("stdout tail is recorded")
            .contains("observed-stdout"),
        "captured stdout must reach the report: {step}"
    );
    assert!(step.get("stderr").is_some(), "stderr tail present: {step}");

    std::fs::remove_file(&path).ok();
}

/// The same entries under `--dry-run` carry inputs but **no**
/// observations — nothing ran, so a status/stdout there would be
/// fabricated.
#[test]
fn dry_run_lifecycle_substeps_carry_inputs_but_no_observations() {
    let profile = json!({
        "type": "Spec",
        "name": "lifecycle-dry",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "PostInstall", "script": "echo not-executed" }
        ]
    });
    let path = write_json_profile("lifecycle-dry", &profile);

    let report_json =
        lm_provision::apply::run_apply_ast(&path, true).expect("dry-run apply succeeds");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    let step = &report["steps"].as_array().unwrap()[0];
    assert_eq!(step["argv"], json!(["sh", "-c", "echo not-executed"]));
    assert_eq!(step["dry_run"], json!(true));
    assert!(
        step.get("stdout").is_none() && step.get("stderr").is_none(),
        "a dry run observed nothing: {step}"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Fail-fast step collection + the legacy error form.
// ---------------------------------------------------------------------

#[test]
fn a_failing_step_is_collected_and_stops_the_run() {
    let profile = json!({
        "type": "Spec",
        "name": "fail-demo",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "ShExec", "argv": ["sh", "-c", "exit 3"] },
            { "type": "ShExec", "argv": ["echo", "never-reached"] }
        ]
    });
    let path = write_json_profile("fail", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .expect("a step failure is captured in-report, not returned as Err");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(false));
    let error = report["error"].as_str().expect("error line is present");
    assert!(
        error.starts_with("step 1_sh.exec (sh.exec) failed:"),
        "error uses the legacy `step <id> (<kind>) failed: <reason>` form: {error}"
    );

    // Fail-fast: only the failing step appears; the second never ran.
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1, "fail-fast: later steps are absent");
    assert_eq!(steps[0]["ok"], json!(false));
    assert_eq!(
        steps[0]["status"],
        json!(3),
        "the process exit code is kept"
    );

    std::fs::remove_file(&path).ok();
}

/// A *failing* lifecycle sub-step must be as informative as a failing
/// direct op: the exit code and the captured output that accompanied the
/// failure belong in structured fields, not only quoted inside the
/// `reason` text (spec 09 §Apply report).
#[test]
fn a_failing_lifecycle_substep_carries_its_partial_observation() {
    let profile = json!({
        "type": "Spec",
        "name": "lifecycle-fail-observations",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "PostInstall",
              "script": "echo out-before-failing; echo err-before-failing 1>&2; exit 7" }
        ]
    });
    let path = write_json_profile("lifecycle-fail-observations", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .expect("a step failure is captured in-report, not returned as Err");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(false));
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1, "fail-fast: {steps:?}");
    let step = &steps[0];

    assert_eq!(step["ok"], json!(false));
    assert_eq!(step["op"], json!("sh.exec"));
    assert_eq!(
        step["status"],
        json!(7),
        "the real exit code survives instead of the pre-effect -1: {step}"
    );
    assert!(
        step["stdout"]
            .as_str()
            .expect("stdout observed before the failure")
            .contains("out-before-failing"),
        "{step}"
    );
    assert!(
        step["stderr"]
            .as_str()
            .expect("stderr observed before the failure")
            .contains("err-before-failing"),
        "{step}"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// CLI wiring: exit codes + stdout/stderr contract through the binary.
// ---------------------------------------------------------------------

fn bin() -> Command {
    Command::cargo_bin("lm-provision").expect("lm-provision binary should build")
}

#[test]
fn cli_apply_routes_a_json_profile_through_the_ast_path_exit_zero() {
    let profile = json!({
        "type": "Spec",
        "name": "cli-ok",
        "capabilities": ["sh.exec"],
        "phases": [ { "type": "ShExec", "argv": ["echo", "ok"] } ]
    });
    let path = write_json_profile("cli-ok", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is the report JSON");
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["profile_name"], json!("cli-ok"));

    std::fs::remove_file(&path).ok();
}

#[test]
fn cli_apply_of_missing_profile_is_exit_one_with_nothing_on_stdout() {
    let missing = temp_stem("cli-missing").with_extension("json");
    let _ = std::fs::remove_file(&missing);
    let output = bin()
        .args(["apply", missing.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(output.status.code(), Some(1), "missing profile must exit 1");
    assert!(
        output.stdout.is_empty(),
        "nothing printed on a precondition failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("apply failed: "),
        "stderr carries the failure line: {stderr}"
    );
}

#[test]
fn cli_apply_of_lua_profile_is_rejected() {
    // The extension check precedes any I/O, so the path need not exist.
    let output = bin()
        .args(["apply", "/nonexistent/profile.lua", "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(output.status.code(), Some(1), "a .lua profile must exit 1");
    assert!(output.stdout.is_empty(), "nothing printed on failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("apply failed: ")
            && stderr.contains("Lua profiles are no longer supported"),
        "stderr must carry the Lua-unsupported failure line: {stderr}"
    );
}

#[test]
fn cli_apply_ast_step_failure_is_exit_one_with_the_error_on_stderr() {
    let profile = json!({
        "type": "Spec",
        "name": "cli-fail",
        "capabilities": ["sh.exec"],
        "phases": [ { "type": "ShExec", "argv": ["sh", "-c", "exit 5"] } ]
    });
    let path = write_json_profile("cli-fail", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_eq!(output.status.code(), Some(1));
    // The report is still printed to stdout (printed on step failure).
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is the report JSON");
    assert_eq!(report["ok"], json!(false));
    // The final error line is echoed to stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("apply failed: step 1_sh.exec (sh.exec) failed:"),
        "stderr carries the final error line: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}
