//! M4-1 (`lm.apply` + `lm.report`, plus the `apply::run_apply` host entry
//! point) regression tests
//! (09-apply-report-and-ledger.md §Outputs "Apply report" / §Semantics).
//!
//! Most tests drive `lm.apply.run(dispatched, opts)` directly against a
//! literal dispatch-artifact table (mirrors `tests/m2_dispatch.rs`'s own
//! style: dispatch's only documented input is "the dispatch artifact",
//! so feeding it literally isolates apply's own fail-fast / per-op-field
//! logic from `lm.plan` / `lm.dispatch`'s own behaviour, already covered
//! by `m2_plan.rs` / `m2_dispatch.rs`). The bridges these dispatched op
//! steps call still need a real sandboxed VM
//! ([`lm_provision::sandbox::wire_sandboxed_profile`]) — the same
//! `sandboxed_lua` pattern `tests/m3_fs_mount.rs` already uses.
//!
//! One end-to-end test drives the full host-side entry point,
//! [`lm_provision::apply::run_apply`], to confirm the
//! `plan → dispatch → apply → report` chain composes through a real
//! profile file.

use lm_provision::apply::run_apply;
use lm_provision::sandbox::wire_sandboxed_profile;
use lm_provision::vm::eval::evaluate_profile_source;
use mlua::{Lua, Table};

// ---------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------

fn sandboxed_lua(profile_expr: &str) -> Lua {
    let source = format!(
        r#"
        local profile = require('lm.profile')
        return profile {profile_expr}
        "#
    );
    let extracted =
        evaluate_profile_source(&source, "test-profile").expect("profile should evaluate");
    let sandboxed =
        wire_sandboxed_profile(extracted).expect("sandbox wiring (steps 6-8) should succeed");
    sandboxed.extracted.lua
}

/// Evaluates `require('lm.apply').run(<dispatched_expr>, <opts_expr>)`
/// against an already-sandboxed VM.
fn run(lua: &Lua, dispatched_expr: &str, opts_expr: &str) -> Table {
    let source = format!(
        r#"
        local apply = require('lm.apply')
        local dispatched = {dispatched_expr}
        local opts = {opts_expr}
        return apply.run(dispatched, opts)
        "#
    );
    lua.load(source)
        .eval::<Table>()
        .expect("apply.run should evaluate without a Lua error")
}

fn steps(report: &Table) -> Table {
    report.get("steps").expect("steps field")
}

fn step_at(report: &Table, i: usize) -> Table {
    steps(report)
        .sequence_values::<Table>()
        .nth(i)
        .expect("step should exist")
        .expect("step table")
}

fn step_count(report: &Table) -> usize {
    steps(report).raw_len()
}

fn field<T: mlua::FromLua>(step: &Table, name: &str) -> T {
    step.get(name).unwrap_or_else(|_| panic!("{name} field"))
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-apply-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// ---------------------------------------------------------------------
// dry_run: full report shape across sh.exec + fs.write, effect skipped
// ---------------------------------------------------------------------

#[test]
fn apply_dry_run_produces_a_full_report_with_no_effect() {
    let dir = temp_dir("dry-run");
    let out_path = dir.join("out.txt");
    let out_path_str = out_path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "sh.exec", "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let report = run(
        &lua,
        &format!(
            r#"
            {{
                profile_name = "demo",
                steps = {{
                    {{ id = "1_sh", kind = "sh.exec", op = "sh.exec", argv = {{ "echo", "hi" }}, opts = {{}} }},
                    {{ id = "2_fs", kind = "fs.write", op = "fs.write", path = "{out_path_str}", content = "hello world", opts = {{}} }},
                }},
            }}
            "#
        ),
        "{ dry_run = true }",
    );

    assert!(field::<bool>(&report, "ok"));
    assert!(field::<bool>(&report, "dry_run"));
    assert_eq!(field::<String>(&report, "profile_name"), "demo");
    assert!(!report.contains_key("error").unwrap());
    assert_eq!(step_count(&report), 2);

    let sh_step = step_at(&report, 0);
    assert_eq!(field::<String>(&sh_step, "id"), "1_sh");
    assert_eq!(field::<String>(&sh_step, "kind"), "sh.exec");
    assert_eq!(field::<String>(&sh_step, "op"), "sh.exec");
    assert!(field::<bool>(&sh_step, "ok"));
    assert_eq!(field::<i64>(&sh_step, "status"), 0);
    assert!(field::<bool>(&sh_step, "dry_run"));
    let argv: Table = field(&sh_step, "argv");
    let argv: Vec<String> = argv
        .sequence_values::<String>()
        .map(|v| v.expect("argv entry"))
        .collect();
    assert_eq!(argv, vec!["echo", "hi"]);
    assert_eq!(field::<String>(&sh_step, "stdout"), "");
    assert_eq!(field::<String>(&sh_step, "stderr"), "");

    let fs_step = step_at(&report, 1);
    assert_eq!(field::<String>(&fs_step, "op"), "fs.write");
    assert!(field::<bool>(&fs_step, "ok"));
    assert_eq!(field::<i64>(&fs_step, "status"), 0);
    assert!(field::<bool>(&fs_step, "dry_run"));
    assert_eq!(field::<String>(&fs_step, "path"), out_path_str);
    assert_eq!(field::<i64>(&fs_step, "bytes"), 0);

    assert!(
        !out_path.exists(),
        "09 §Common conventions: dry_run must skip the effect entirely"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// Real effect apply: sh.exec + fs.write actually run
// ---------------------------------------------------------------------

#[test]
fn apply_real_run_executes_sh_exec_and_fs_write_and_reports_ok() {
    let dir = temp_dir("real-run");
    let out_path = dir.join("out.txt");
    let out_path_str = out_path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "sh.exec", "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let report = run(
        &lua,
        &format!(
            r#"
            {{
                profile_name = "demo",
                steps = {{
                    {{ id = "1_sh", kind = "sh.exec", op = "sh.exec", argv = {{ "echo", "hi" }}, opts = {{}} }},
                    {{ id = "2_fs", kind = "fs.write", op = "fs.write", path = "{out_path_str}", content = "hello", opts = {{}} }},
                }},
            }}
            "#
        ),
        "{}",
    );

    assert!(field::<bool>(&report, "ok"));
    assert!(!field::<bool>(&report, "dry_run"));
    assert!(!report.contains_key("error").unwrap());
    assert_eq!(step_count(&report), 2);

    let sh_step = step_at(&report, 0);
    assert!(field::<bool>(&sh_step, "ok"));
    assert_eq!(field::<i64>(&sh_step, "status"), 0);
    assert!(!field::<bool>(&sh_step, "dry_run"));
    assert_eq!(field::<String>(&sh_step, "stdout"), "hi\n");

    let fs_step = step_at(&report, 1);
    assert!(field::<bool>(&fs_step, "ok"));
    assert_eq!(field::<i64>(&fs_step, "status"), 0);
    assert!(!field::<bool>(&fs_step, "dry_run"));
    assert_eq!(field::<i64>(&fs_step, "bytes"), 5);
    assert_eq!(
        std::fs::read_to_string(&out_path).expect("written file should exist"),
        "hello"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// Fail-fast: steps after the first failure never run and do not appear
// ---------------------------------------------------------------------

#[test]
fn apply_fail_fast_stops_at_the_first_failing_step_and_omits_unreached_steps() {
    let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
    let report = run(
        &lua,
        r#"
        {
            profile_name = "demo",
            steps = {
                { id = "1", kind = "sh.exec", op = "sh.exec", argv = { "echo", "first" }, opts = {} },
                { id = "2", kind = "sh.exec", op = "sh.exec", argv = { "sh", "-c", "echo boom 1>&2; exit 3" }, opts = {} },
                { id = "3", kind = "sh.exec", op = "sh.exec", argv = { "echo", "should-not-run" }, opts = {} },
            },
        }
        "#,
        "{}",
    );

    assert!(!field::<bool>(&report, "ok"));
    assert_eq!(
        step_count(&report),
        2,
        "09 §Semantics: the failing step is the last entry; steps after it do not appear"
    );

    let first = step_at(&report, 0);
    assert!(field::<bool>(&first, "ok"));

    let failing = step_at(&report, 1);
    assert_eq!(field::<String>(&failing, "id"), "2");
    assert!(!field::<bool>(&failing, "ok"));
    assert_eq!(field::<i64>(&failing, "status"), 3);
    assert!(field::<String>(&failing, "stderr").contains("boom"));

    let error: String = report.get("error").expect("error field must be present");
    assert_eq!(error, "step 2 (sh.exec) failed: boom\n");
}

// ---------------------------------------------------------------------
// error string form (09 §Outputs `error?`): "step <id> (<kind>) failed:
// <stderr|reason>" — a dedicated, minimal check of the literal shape.
// ---------------------------------------------------------------------

#[test]
fn apply_error_message_matches_the_literal_step_failed_form() {
    let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
    let report = run(
        &lua,
        r#"
        {
            profile_name = "demo",
            steps = {
                { id = "only", kind = "sh.exec", op = "sh.exec", argv = { "sh", "-c", "exit 9" }, opts = {} },
            },
        }
        "#,
        "{}",
    );

    assert!(!field::<bool>(&report, "ok"));
    let error: String = report.get("error").expect("error field must be present");
    assert_eq!(
        error, "step only (sh.exec) failed: ",
        "09 §Outputs: 'step <id> (<kind>) failed: <stderr|reason>'"
    );
}

// ---------------------------------------------------------------------
// dispatch_pending: a visible skip, always ok = true / status = 0
// ---------------------------------------------------------------------

#[test]
fn apply_dispatch_pending_step_is_recorded_as_a_success() {
    let lua = sandboxed_lua(r#"{ name = "demo" }"#);
    let report = run(
        &lua,
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    id = "p1", kind = "comfyui.health", op = "dispatch_pending",
                    payload = { port = 8188 },
                    note = "comfyui.health has no defined dispatch mapping",
                },
            },
        }
        "#,
        "{}",
    );

    assert!(field::<bool>(&report, "ok"));
    assert_eq!(step_count(&report), 1);

    let pending = step_at(&report, 0);
    assert_eq!(field::<String>(&pending, "op"), "dispatch_pending");
    assert!(field::<bool>(&pending, "ok"));
    assert_eq!(field::<i64>(&pending, "status"), 0);
    assert_eq!(
        field::<String>(&pending, "note"),
        "comfyui.health has no defined dispatch mapping"
    );
}

// ---------------------------------------------------------------------
// Undeclared capability: in-report fail, never a crash
// ---------------------------------------------------------------------

#[test]
fn apply_step_with_undeclared_capability_fails_in_report_without_crashing() {
    // No capabilities declared at all — `sh` stays nil (register skip).
    let lua = sandboxed_lua(r#"{ name = "demo" }"#);
    let report = run(
        &lua,
        r#"
        {
            profile_name = "demo",
            steps = {
                { id = "u1", kind = "sh.exec", op = "sh.exec", argv = { "echo", "hi" }, opts = {} },
            },
        }
        "#,
        "{}",
    );

    assert!(!field::<bool>(&report, "ok"));
    assert_eq!(step_count(&report), 1);

    let step = step_at(&report, 0);
    assert!(!field::<bool>(&step, "ok"));
    assert_eq!(field::<i64>(&step, "status"), -1);
    assert!(field::<String>(&step, "stderr")
        .contains("capability 'sh.exec' not declared in profile.capabilities"));

    let error: String = report.get("error").expect("error field must be present");
    assert!(error.contains("capability 'sh.exec' not declared in profile.capabilities"));
}

// ---------------------------------------------------------------------
// End-to-end: apply::run_apply drives plan → dispatch → apply → report
// through a real profile file.
// ---------------------------------------------------------------------

#[test]
fn run_apply_drives_the_full_pipeline_and_returns_a_parseable_report() {
    let dir = temp_dir("run-apply");
    let profile_path = dir.join("profile.lua");
    std::fs::write(
        &profile_path,
        r#"
        local profile = require('lm.profile')
        return profile {
            name = "demo",
            capabilities = { "sh.exec" },
            phases = {
                { kind = "sh.exec", argv = { "echo", "hi" } },
            },
        }
        "#,
    )
    .expect("write profile file");

    let json = run_apply(&profile_path, true).expect("run_apply should succeed");
    let value: serde_json::Value = serde_json::from_str(&json).expect("report must be valid JSON");

    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["dry_run"], serde_json::json!(true));
    assert_eq!(value["profile_name"], serde_json::json!("demo"));
    let steps = value["steps"].as_array().expect("steps array");
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["op"], serde_json::json!("sh.exec"));
    assert_eq!(steps[0]["ok"], serde_json::json!(true));

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}
