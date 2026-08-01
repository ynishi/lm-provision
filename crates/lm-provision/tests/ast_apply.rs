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

/// `python.version_check` must actually check. Emitting `python3
/// --version` and calling itself advisory let a mismatch pass silently;
/// the assert script fails the step, and the interpreter's real version
/// reaches the report through the captured stderr.
#[test]
fn python_version_check_fails_the_run_on_a_mismatch() {
    let profile = json!({
        "type": "Spec",
        "name": "version-mismatch",
        "capabilities": ["sh.exec"],
        "phases": [
            // No interpreter reports 99.99, so this mismatches anywhere.
            { "type": "PythonVersionCheck", "want": "99.99" }
        ]
    });
    let path = write_json_profile("version-mismatch", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .expect("a step failure is captured in-report");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(false), "{report}");
    let step = &report["steps"].as_array().unwrap()[0];
    assert_eq!(step["ok"], json!(false));
    assert_ne!(
        step["status"],
        json!(0),
        "a mismatch exits non-zero: {step}"
    );
    assert!(
        step["stderr"]
            .as_str()
            .expect("stderr reaches the report")
            .contains("python version mismatch"),
        "the assert message names the mismatch: {step}"
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

/// `service.start` carries `port` / `tensor_parallel_size` as named
/// `Option<u16>` fields (dsl-kit #1 Layer 2 landed in 0.3.0; the
/// frontend registers a `SyntaxOverrides` value production for
/// `Option<u16>` so the canonical text and JSON front-ends both accept
/// them). `expand_service_start` synthesises `--port` / `--tensor-parallel-size`
/// from the named fields — this test proves the JSON front-end round
/// trip end-to-end (parse → validate → dry-run report carries `port`
/// as an integer in the plan payload).
#[test]
fn cli_apply_named_port_field_synthesises_flag_in_launch_argv() {
    let profile = json!({
        "type": "Spec",
        "name": "cli-named-port",
        "capabilities": ["sh.exec"],
        "phases": [
            {
                "type": "ServiceStart",
                "name": "llm",
                "platform_kind": "vllm",
                "model": "meta-llama/Llama-3-8B",
                "port": 9000,
                "tensor_parallel_size": 4
            }
        ]
    });
    let path = write_json_profile("cli-named-port", &profile);

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
    let step = &report["steps"].as_array().unwrap()[0];
    let argv = step["argv"].as_array().expect("argv is an array");
    let joined = argv
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    // The named fields land as their own `--port` / `--tensor-parallel-size`
    // flags in the synthesised launch line.
    assert!(
        joined.contains("--port 9000"),
        "named port must synthesise --port flag: {joined}"
    );
    assert!(
        joined.contains("--tensor-parallel-size 4"),
        "named tensor_parallel_size must synthesise its flag: {joined}"
    );

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

/// A phase-`env` `EnvRef` must resolve to the value node the profile
/// declared in `Spec.env` — a literal to its string, a secret through
/// the same host-env / `env_secrets` pipe an inline reference would go
/// through. The audit transcript still redacts what the corresponding
/// inline node would redact (spec 09).
#[test]
fn env_ref_resolves_through_spec_env_and_redacts_correctly() {
    let dir = temp_stem("env-ref");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("out.txt");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "env-ref-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": [dir_str],
        "env_secrets": ["ENV_REF_SECRET_TOKEN"],
        "env": {
            // A non-sensitive literal shared across phases.
            "SHARED_MODE": { "type": "EnvLiteral", "value": "must-not-appear-anywhere" },
            // A secret whose logical name is sensitive-shaped, so the
            // audit event redacts *and* the resolved value never leaks.
            "SHARED_TOKEN": { "type": "EnvSecret", "name": "ENV_REF_SECRET_TOKEN" }
        },
        "phases": [
            {
                "type": "ShExec",
                "argv": ["true"],
                "env": {
                    "MODE": { "type": "EnvRef", "name": "SHARED_MODE" },
                    "TOKEN": { "type": "EnvRef", "name": "SHARED_TOKEN" }
                }
            },
            { "type": "FsWrite", "path": target.to_string_lossy(), "content": "written" }
        ]
    });
    let path = write_json_profile("env-ref", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        .env(
            "ENV_REF_SECRET_TOKEN",
            "super-secret-token-value-that-must-not-leak",
        )
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Value on either side of the reference must never leak.
    assert!(
        !stderr.contains("super-secret-token-value-that-must-not-leak"),
        "resolved secret must never appear on the audit transcript: {stderr}"
    );
    assert!(
        !stderr.contains("must-not-appear-anywhere"),
        "no env value ever reaches the transcript, sensitive or not: {stderr}"
    );
    // The redaction marker applies to the *slot* key name in the
    // phase's env: `TOKEN` is sensitive-shaped, `MODE` is not.
    assert!(
        stderr.contains("TOKEN [REDACTED]"),
        "sensitive slot name still marks [REDACTED] even when the value is a reference: {stderr}"
    );
    assert!(
        stderr.contains("MODE"),
        "non-sensitive slot name appears verbatim: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// Validate rejects a phase `EnvRef` whose `name` is not declared in
/// `Spec.env` — the CLI surfaces the rejection before any effect runs.
#[test]
fn env_ref_to_an_undeclared_spec_env_key_is_rejected_at_validate() {
    let profile = json!({
        "type": "Spec",
        "name": "env-ref-bad",
        "capabilities": ["sh.exec"],
        "env": {
            "KNOWN": { "type": "EnvLiteral", "value": "yes" }
        },
        "phases": [
            {
                "type": "ShExec",
                "argv": ["true"],
                "env": {
                    "SLOT": { "type": "EnvRef", "name": "UNKNOWN" }
                }
            }
        ]
    });
    let path = write_json_profile("env-ref-bad", &profile);

    let output = bin()
        .args(["validate", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_ne!(output.status.code(), Some(0), "validate must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("UNKNOWN") && stderr.contains("Spec.env"),
        "validate error names the undeclared reference and its intended lookup surface: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Audit transcript on stderr (spec 09 §Audit log).
// ---------------------------------------------------------------------

/// Every effect invocation must emit one structured audit event on
/// stderr, and the event must never carry a secret value even when
/// the phase's env-injection map resolves one.
#[test]
fn apply_emits_a_stderr_audit_event_per_effect_and_never_a_secret_value() {
    let dir = temp_stem("audit-emit");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("out.txt");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "audit-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": [dir_str],
        "env_secrets": ["AUDIT_SECRET_TOKEN"],
        "phases": [
            // The `AUDIT_SECRET_TOKEN` name matches the sensitive-key
            // set, so it must be logged as `[REDACTED]`.
            { "type": "ShExec", "argv": ["true"],
              "env": {
                  "AUDIT_SECRET_TOKEN": { "type": "EnvSecret", "name": "AUDIT_SECRET_TOKEN" },
                  "MODE": { "type": "EnvLiteral", "value": "audit-mode-value" }
              } },
            { "type": "FsWrite", "path": target.to_string_lossy(), "content": "written" }
        ]
    });
    let path = write_json_profile("audit-emit", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        // The secret value must never appear on stderr. Set it to a
        // literal the test can grep for so a leak is unambiguous.
        .env(
            "AUDIT_SECRET_TOKEN",
            "super-secret-value-that-must-not-leak",
        )
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // (a) One audit event per effect.
    let audit_events: Vec<_> = stderr.lines().filter(|l| l.contains("audit")).collect();
    assert!(
        audit_events.len() >= 2,
        "expected at least one audit event per effect (sh.exec + fs.write), got: {stderr}"
    );
    assert!(
        stderr.contains("op=\"sh.exec\"") || stderr.contains("op=sh.exec"),
        "sh.exec event present: {stderr}"
    );
    assert!(
        stderr.contains("op=\"fs.write\"") || stderr.contains("op=fs.write"),
        "fs.write event present: {stderr}"
    );

    // (b) The secret value must never appear anywhere on stderr.
    assert!(
        !stderr.contains("super-secret-value-that-must-not-leak"),
        "secret value must never reach the audit transcript: {stderr}"
    );
    // Non-sensitive env *values* are redacted too (values are never
    // logged, sensitive or not).
    assert!(
        !stderr.contains("audit-mode-value"),
        "no env value ever reaches the transcript, sensitive or not: {stderr}"
    );

    // (c) Sensitive-named env keys are marked `[REDACTED]`; non-
    // sensitive names appear verbatim.
    assert!(
        stderr.contains("AUDIT_SECRET_TOKEN [REDACTED]"),
        "the sensitive-key marker labels a key whose value was withheld: {stderr}"
    );
    assert!(
        stderr.contains("MODE"),
        "a non-sensitive key name is logged: {stderr}"
    );

    // (d) `fs.write` carries the content_source contract (spec 09).
    assert!(
        stderr.contains("content_source=\"string\"") || stderr.contains("content_source=string"),
        "fs.write event carries content_source: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// `fs.write` `content` as a value node (spec 06 consumption point 3):
/// an `EnvSecret` content resolves from the host env and lands on
/// disk, an `EnvRef` content resolves through `Spec.env` — and the
/// audit transcript names the source (`content_source=secret:<name>` /
/// `env_ref:<name>`) without ever carrying the resolved value.
#[test]
fn fs_write_secret_and_ref_content_resolve_and_never_leak_on_the_transcript() {
    let dir = temp_stem("fs-content");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let secret_target = dir.join("token.txt");
    let ref_target = dir.join("conf.txt");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "fs-content-demo",
        "capabilities": ["fs.write"],
        "paths": [dir_str],
        "env_secrets": ["FS_CONTENT_SECRET_TOKEN"],
        "env": {
            "SHARED_CONF": { "type": "EnvLiteral", "value": "conf-value-not-logged" }
        },
        "phases": [
            {
                "type": "FsWrite",
                "path": secret_target.to_string_lossy(),
                "content": { "type": "EnvSecret", "name": "FS_CONTENT_SECRET_TOKEN" }
            },
            {
                "type": "FsWrite",
                "path": ref_target.to_string_lossy(),
                "content": { "type": "EnvRef", "name": "SHARED_CONF" }
            }
        ]
    });
    let path = write_json_profile("fs-content", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        .env(
            "FS_CONTENT_SECRET_TOKEN",
            "fs-secret-value-that-must-not-leak",
        )
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The effects ran with the *resolved* content.
    assert_eq!(
        std::fs::read_to_string(&secret_target).expect("secret-content target was written"),
        "fs-secret-value-that-must-not-leak"
    );
    assert_eq!(
        std::fs::read_to_string(&ref_target).expect("ref-content target was written"),
        "conf-value-not-logged"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The audit event names the source, never the value.
    assert!(
        stderr.contains("content_source=\"secret:FS_CONTENT_SECRET_TOKEN\"")
            || stderr.contains("content_source=secret:FS_CONTENT_SECRET_TOKEN"),
        "secret-content event names its source: {stderr}"
    );
    assert!(
        stderr.contains("content_source=\"env_ref:SHARED_CONF\"")
            || stderr.contains("content_source=env_ref:SHARED_CONF"),
        "ref-content event names its source: {stderr}"
    );
    assert!(
        !stderr.contains("fs-secret-value-that-must-not-leak"),
        "resolved secret content must never reach the transcript: {stderr}"
    );
    assert!(
        !stderr.contains("conf-value-not-logged"),
        "resolved literal content must never reach the transcript either: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// Content resolution follows spec 06 §Resolution "dry-run resolves
/// too": a secret content whose host env var is absent fails the dry
/// run identically to a real run — a passing dry run proves the
/// content plumbing.
#[test]
fn fs_write_secret_content_missing_from_the_host_env_fails_the_dry_run() {
    let dir = temp_stem("fs-content-missing");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "fs-content-missing-demo",
        "capabilities": ["fs.write"],
        "paths": [dir_str],
        "env_secrets": ["FS_CONTENT_NEVER_SET_SECRET"],
        "phases": [
            {
                "type": "FsWrite",
                "path": dir.join("out.txt").to_string_lossy(),
                "content": { "type": "EnvSecret", "name": "FS_CONTENT_NEVER_SET_SECRET" }
            }
        ]
    });
    let path = write_json_profile("fs-content-missing", &profile);

    let output = bin()
        .args(["apply", "--dry-run", path.to_str().unwrap()])
        .env_remove("FS_CONTENT_NEVER_SET_SECRET")
        .output()
        .expect("process runs");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a dry run must fail on an unresolvable secret content"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FS_CONTENT_NEVER_SET_SECRET"),
        "the failure names the logical secret, nothing else: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}
