//! M4-1 (`lm.report`) regression tests
//! (09-apply-report-and-ledger.md §Outputs "Apply report").
//!
//! `lm.report.build` is pure Lua (no bridge calls, no sandbox wiring), so
//! these tests drive it through the plain [`lm_provision::vm::boot_vm`]
//! path — the same style `tests/m2_dispatch.rs` already uses for the
//! other pure pipeline-stage modules.

use lm_provision::vm::boot_vm;
use mlua::{Lua, Table};

/// Returns `(lua, report)` — the VM must outlive the returned `Table`
/// (an `mlua::Table` holds only a weak reference to its owning VM, the
/// same reason `tests/m2_dispatch.rs`'s own `dispatch_plan` helper
/// returns the pair rather than the table alone).
fn build_report(opts_expr: &str) -> (Lua, Table) {
    let lua = boot_vm().expect("boot_vm should succeed");
    let source = format!(
        r#"
        local report = require('lm.report')
        return report.build({opts_expr})
        "#
    );
    let report = lua
        .load(source)
        .eval::<Table>()
        .expect("report.build should evaluate without a Lua error");
    (lua, report)
}

#[test]
fn build_reports_ok_true_and_omits_error_when_no_error_is_given() {
    let (_lua, report) = build_report(
        r#"{ profile_name = "demo", dry_run = false, steps = { { id = "1", ok = true } } }"#,
    );
    assert!(report.get::<bool>("ok").unwrap());
    assert!(!report.get::<bool>("dry_run").unwrap());
    assert_eq!(report.get::<String>("profile_name").unwrap(), "demo");
    let steps: Table = report.get("steps").unwrap();
    assert_eq!(steps.raw_len(), 1);
    assert!(
        !report.contains_key("error").unwrap(),
        "09 §Outputs: error is present iff ok = false"
    );
}

#[test]
fn build_reports_ok_false_and_carries_the_error_string_when_given() {
    let (_lua, report) = build_report(
        r#"{ profile_name = "demo", dry_run = true, steps = {}, error = "step 1 (sh.exec) failed: boom" }"#,
    );
    assert!(!report.get::<bool>("ok").unwrap());
    assert!(report.get::<bool>("dry_run").unwrap());
    let error: String = report.get("error").unwrap();
    assert_eq!(error, "step 1 (sh.exec) failed: boom");
}

#[test]
fn build_defaults_steps_to_an_empty_table_when_omitted() {
    let (_lua, report) = build_report(r#"{ profile_name = "demo", dry_run = false }"#);
    let steps: Table = report.get("steps").unwrap();
    assert_eq!(steps.raw_len(), 0);
}

#[test]
fn build_coerces_a_nil_dry_run_to_false() {
    let (_lua, report) = build_report(r#"{ profile_name = "demo", steps = {} }"#);
    assert!(!report.get::<bool>("dry_run").unwrap());
}
