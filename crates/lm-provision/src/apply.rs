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

use mlua::{Function, Lua, Table};

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
