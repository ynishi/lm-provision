//! Host-side apply entry point: plan → dispatch → apply → report
//! (09-apply-report-and-ledger.md; milestone M4-1).
//!
//! [`run_apply`] wires registration order steps 1-8
//! ([`crate::vm::eval::evaluate_profile_file`] +
//! [`crate::sandbox::wire_sandboxed_profile`]) onto a profile file, then
//! drives the pure-Lua `lm.plan.expand` → `lm.dispatch.dispatch` →
//! `lm.apply.run` chain (03-pipeline-stage-artifacts.md §plan / §dispatch;
//! 09 §Outputs "Apply report") to the apply report artifact, returned as a
//! JSON string. This is the same `require`-driven path
//! [`crate::cli::plan_pipeline`] already takes for `plan` — `run_apply`
//! only extends it through `dispatch` and `apply`.
//!
//! Wiring this into the `apply` CLI subcommand (07-cli.md) is milestone
//! M4-3's job; [`crate::cli::run`]'s `Apply` arm remains the M0-style
//! "not implemented" stub through this milestone.

use std::path::Path;
use std::sync::{Arc, Mutex};

use mlua::{Function, Lua, Table};

use crate::exec::{report, ExecMode};
use crate::sandbox::{wire_sandboxed_profile, SandboxError};
use crate::vm::eval::{evaluate_profile_file, EvalError};

/// Errors raised while running the apply pipeline end to end.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Profile evaluation (registration order steps 1-5) failed.
    #[error("failed to evaluate profile: {0}")]
    Eval(#[from] EvalError),

    /// Sandbox wiring (registration order steps 6-8) failed.
    #[error("failed to wire sandbox: {0}")]
    Sandbox(#[from] SandboxError),

    /// A Lua error surfaced while running `plan` / `dispatch` / `apply`
    /// (registration order step 9) or encoding the resulting report.
    ///
    /// Note this is distinct from a *step*-level failure: a step whose
    /// bridge call fails is captured in-report by `lm.apply.run` itself
    /// (09 §Semantics) and never reaches this variant. This variant is
    /// for genuine host-wiring failures — a missing `lm.*` module export,
    /// a malformed IR the earlier stages did not already reject, or (04
    /// §Error surface) a Lua error `lm.apply.run` deliberately does not
    /// catch (see `lua/lm/apply.lua`'s own module doc comment).
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),

    /// The apply report failed to serialize to JSON.
    #[error("failed to serialize apply report: {0}")]
    Json(#[from] serde_json::Error),
}

/// `require(module)` via the profile's sandboxed VM — the same
/// single-line pattern [`crate::cli::require_module`] and
/// [`crate::bridge::net`]'s own private helper each already use (no
/// `pub(crate)` accessor for it exists yet, and the call sites so far do
/// not justify inventing one).
fn require_module(lua: &Lua, module: &str) -> mlua::Result<Table> {
    let require_fn: Function = lua.globals().get("require")?;
    require_fn.call(module)
}

/// Runs `lm.plan.expand → lm.dispatch.dispatch → lm.apply.run` against
/// `profile` and returns the apply report (09 §Outputs "Apply report") as
/// a pretty-printed JSON string.
///
/// Routed through `lm.canonical.encode` for the same reason
/// [`crate::cli::plan_pipeline`]'s own doc comment already records: this
/// keeps the Lua-table-to-JSON walk in the one place
/// (`lm.canonical.encode`) that already knows the canonical encoding
/// rules, rather than duplicating a second Rust-side serializer. The
/// apply report itself never carries a raw `SecretRef` (09 §Outputs:
/// "secrets never enter the Lua side ... argv / stdout / stderr carry at
/// most the `[secret:NAME]` marker"), so this reuse is for the encoder's
/// convenience, not secret-marker correctness.
pub fn run_apply(profile: &Path, dry_run: bool) -> Result<String, ApplyError> {
    let extracted = evaluate_profile_file(profile)?;
    let sandboxed = wire_sandboxed_profile(extracted)?;
    let lua = &sandboxed.extracted.lua;
    let ir = sandboxed.extracted.ir.clone();

    let plan_mod = require_module(lua, "lm.plan")?;
    let expand_fn: Function = plan_mod.get("expand")?;
    let plan_table: Table = expand_fn.call(ir)?;

    let dispatch_mod = require_module(lua, "lm.dispatch")?;
    let dispatch_fn: Function = dispatch_mod.get("dispatch")?;
    let dispatched: Table = dispatch_fn.call(plan_table)?;

    let apply_mod = require_module(lua, "lm.apply")?;
    let run_fn: Function = apply_mod.get("run")?;
    let run_opts = lua.create_table()?;
    run_opts.set("dry_run", dry_run)?;
    let report: Table = run_fn.call((dispatched, run_opts))?;

    let canonical_mod = require_module(lua, "lm.canonical")?;
    let encode_fn: Function = canonical_mod.get("encode")?;
    let bytes: String = encode_fn.call(report)?;

    let value: serde_json::Value = serde_json::from_str(&bytes)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Errors raised before or while running the AST-path apply pipeline
/// ([`run_apply_ast`]).
///
/// Distinct from a *step*-level failure: a bridge step that fails is
/// captured in-report (`ok = false` + the fail-fast `error` line) and
/// returned as `Ok(report_json)`, exactly as the legacy pipeline does.
/// This type is only for failures that produce no report at all — a
/// profile that will not load, or a declared capability the host does
/// not implement (a precondition failure, spec 07 §Error surface).
#[derive(Debug, thiserror::Error)]
pub enum AstApplyError {
    /// The profile file could not be read / parsed into an AST.
    #[error("failed to load profile: {0}")]
    Frontend(#[from] crate::frontend::FrontendError),

    /// Building the execution context failed before any step ran — the
    /// only cause is a declared capability outside the host's known set
    /// (spec 05 §L2 / [`crate::exec::ExecContext::from_root`]).
    #[error("failed to build execution context: {0}")]
    Exec(#[from] crate::exec::ExecError),

    /// The assembled apply report failed to serialize to JSON.
    #[error("failed to serialize apply report: {0}")]
    Json(#[from] serde_json::Error),
}

/// Runs the AST exec engine over the non-`.lua` `profile` and returns the
/// apply report (`{ ok, dry_run, profile_name, steps, error? }`) as a
/// pretty-printed JSON string.
///
/// This is the AST-frontend counterpart to [`run_apply`]. It shares the
/// legacy report's **envelope** shape (field-name compatible with
/// `lua/lm/report.lua`) but reports the AST exec layer's own step
/// structure, which diverges from the legacy `lm.dispatch` op stream by
/// design (see [`crate::exec::report`]'s module doc):
///
/// - one `steps` entry per direct-op phase, and one per lifecycle
///   sub-step (`<phase_index>_<kind>[_<n>]` ids), rather than the legacy
///   `lm.dispatch` fan-out ids;
/// - lifecycle ops execute for real, so an effectless sub-step surfaces
///   as an honest `op = "note"` step rather than the legacy
///   `dispatch_pending` skip.
///
/// Like the legacy pipeline, `validate` is **not** run first (07-cli.md
/// §Invocation names only "load → declarations → gate → bridges → …" for
/// `apply`); the capability gate and the [`crate::exec::policy::EnvPolicy`]
/// enforce the security-relevant invariants at execution time. Fail-fast:
/// the first failing step ends the run, is included as the last `steps`
/// entry, and its reason drives the envelope's `error` line; no later
/// step is reached.
pub fn run_apply_ast(profile: &Path, dry_run: bool) -> Result<String, AstApplyError> {
    let root = crate::frontend::load_profile(profile)?;
    let mode = if dry_run {
        ExecMode::DryRun
    } else {
        ExecMode::Real
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let (mut engine, reports) = crate::dsl_poc::create_profile_engine_collecting(&root, mode, log)?;
    let run_result = drive(&mut engine);

    let steps = reports.lock().unwrap().clone();
    let profile_name = match &root {
        crate::dsl_poc::ProfileNode::Spec { name, .. } => name.clone(),
        // The frontend only ever produces a `Spec` root; keep total.
        _ => String::new(),
    };

    let error = match run_result {
        Ok(()) => None,
        Err(engine_error) => match steps.last() {
            // The failing op recorded its own step entry before the
            // engine surfaced the error, so it is the last entry.
            Some(step) if !step.ok => Some(format!(
                "step {} ({}) failed: {}",
                step.id,
                step.kind,
                step.failure_reason()
            )),
            // Fallback: an engine-internal error with no recorded step
            // (not expected for a frontend-produced AST).
            _ => Some(engine_error),
        },
    };

    let envelope = report::build_envelope(&profile_name, dry_run, &steps, error.as_deref());
    Ok(serde_json::to_string_pretty(&envelope)?)
}

/// Drive the engine to completion, returning `Ok(())` on `Done` or the
/// rendered engine error on the first failing step (the per-step report
/// already carries the machine-readable detail).
fn drive(engine: &mut dsl_kit::Engine<crate::dsl_poc::ProfileAst>) -> Result<(), String> {
    use dsl_kit::{StepOutcome, Stepper};

    let mut steps = 0u32;
    loop {
        match engine.step() {
            Ok(outcome) => {
                if matches!(outcome, StepOutcome::Done(_)) {
                    return Ok(());
                }
            }
            Err(err) => return Err(err.to_string()),
        }
        steps += 1;
        if steps > 100_000 {
            return Err("apply exec exceeded the step limit".to_string());
        }
    }
}
