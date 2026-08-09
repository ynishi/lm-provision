//! Host-side apply entry point: plan → dispatch → apply → report
//! (09-apply-report-and-ledger.md).
//!
//! [`run_apply_ast`] loads a profile file into a
//! [`crate::profile_ast::ProfileNode`] AST ([`crate::frontend::load_profile`])
//! and drives the pure-Rust [`crate::exec`] engine over it, collecting
//! one structured [`crate::exec::report::StepReport`] per executed op into
//! the apply report artifact (09 §Outputs "Apply report"), returned as a
//! JSON string.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dsl_kit::{BreakpointSet, Engine, Pending, StepOutcome, Stepper, SuspendReason, SuspensionId};
use tokio::task::JoinSet;

use crate::exec::registry::{CallError, EffectRoute, ProfileCallAst};
use crate::exec::{registry, report, ExecContext, ExecMode};
use crate::profile_ast::ProfileValue;

/// How many suspended lifecycle steps the driver resolves at the same
/// time.
///
/// **There is no measurement behind this number.** The reference
/// implementation's 28× came from `aria2c -c -x16 -s16`, and its 16 is
/// how many connections *one* file is split across — a different axis
/// from how many files are in flight, so it is not a value to borrow.
/// Nothing in this repository has measured a pod's useful download
/// concurrency, so what is written here is a bound, not a tuning: it
/// keeps a twenty-weight `models` phase from opening twenty sockets and
/// twenty file writers at once, and it is small enough that the wave the
/// driver waits on is short.
///
/// It is a host-side constant and deliberately not a profile field, for
/// the reason [`EffectRoute`] is not one either: the profile's bytes —
/// and so its hash — say nothing about how the host chooses to drive the
/// effects.
///
/// Raising it should follow a measurement on a real pod, not an argument.
const MAX_CONCURRENT_STEPS: usize = 4;

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

/// Runs the AST exec engine over `profile` and returns the apply report
/// (`{ ok, dry_run, profile_name, steps, error? }`) as a pretty-printed
/// JSON string.
///
/// The report envelope is field-name compatible with the historical
/// apply report shape (`ok` / `dry_run` / `profile_name` / `steps` /
/// `error?`), with the AST exec layer's own step structure (see
/// [`crate::exec::report`]'s module doc):
///
/// - one `steps` entry per direct-op phase, and one per lifecycle
///   sub-step (`<phase_index>_<kind>[_<n>]` ids);
/// - an effectless lifecycle sub-step surfaces as an honest
///   `op = "note"` step.
///
/// `validate` is **not** run first (07-cli.md §Invocation names only
/// "load → declarations → gate → bridges → …" for `apply`); the
/// capability gate and the [`crate::exec::policy::EnvPolicy`]
/// enforce the security-relevant invariants at execution time. Fail-fast:
/// a failing step ends the run, is included in `steps`, and its reason
/// drives the envelope's `error` line; no later phase is reached.
///
/// **A phase whose steps run together is the one place where "no later
/// step is reached" does not hold** — its siblings were already running
/// when the failure happened and are allowed to finish, so `steps` can
/// carry more than one failure and the `error` line names the first of
/// them in declaration order (see `crate::exec::registry`'s
/// `LifecycleJoin` for why they are not cancelled). Phases themselves are
/// still strictly sequential: the failure ends the run before the next
/// one starts.
///
/// # Runtime
///
/// **`async`, and a multi-threaded tokio runtime must be driving it.**
/// The effect layer's HTTP routes are async ([`crate::exec::effects`]).
/// A phase routed through [`EffectRoute::Call`], and **every lifecycle
/// step** (which is a `Call` node of its own,
/// [`crate::exec::steps`]), suspends and is awaited by [`drive`] below —
/// nothing blocks. What still needs a sibling worker is the three network
/// phases' legacy [`EffectRoute::Op`] branch: `dsl_kit`'s `Op::apply` is
/// not `async`, so those drive their future from the synchronous seam
/// ([`crate::exec::effects::block_on_effect`]).
///
/// [`drive`] spawns onto the ambient runtime, so a phase whose steps are
/// independent resolves up to [`MAX_CONCURRENT_STEPS`] of them at once.
///
/// The runtime itself is built once, at the CLI entry point
/// ([`crate::cli`]).
pub async fn run_apply_ast(profile: &Path, dry_run: bool) -> Result<String, AstApplyError> {
    run_apply_ast_routed(profile, dry_run, EffectRoute::default()).await
}

/// [`run_apply_ast`] with the single-effect ops' route named explicitly.
///
/// `route` selects which shape a `net.transfer` / `net.http_get` /
/// `net.http_post` phase takes in the engine — the legacy op, or a
/// dsl-kit `Call` resolved by [`drive`] (see
/// [`crate::exec::registry`]'s module doc). It changes nothing else: the
/// same profile run through both routes produces the same report, which
/// is what makes moving one op at a time checkable.
pub async fn run_apply_ast_routed(
    profile: &Path,
    dry_run: bool,
    route: EffectRoute,
) -> Result<String, AstApplyError> {
    // Canonical order, implicit insertion, and suppression are applied
    // to the AST before the engine sees it, so apply runs exactly the
    // steps the plan artifact renders (`02` §Canonical phase ordering,
    // [`crate::normalize`]). The profile as *written* is what `hash` /
    // `canonical` see; normalization never reaches them.
    let root = crate::normalize::normalize(&crate::frontend::load_profile(profile)?);
    let mode = if dry_run {
        ExecMode::DryRun
    } else {
        ExecMode::Real
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let ctx = Arc::new(ExecContext::from_root(&root, mode, log)?);
    let reports = ctx.reports_handle();
    // One step plan, two readers: the AST declares the per-step nodes it
    // projects and the resolver looks a suspended one back up. Building
    // a second plan here would hand out the same ids by construction,
    // but nothing would keep it doing so.
    let ast = ProfileCallAst::new(&root, route, &ctx.step_plan);
    let mut engine = Engine::new_with_ops(
        ast,
        Arc::new(registry::lifecycle_reducer_registry(&ctx.step_plan)),
        registry::profile_op_registry(Arc::clone(&ctx)),
    )
    .expect("Engine initialization should succeed");
    let run_result = drive(&mut engine, &ctx).await;

    let mut steps = reports.lock().unwrap().clone();
    // A phase whose steps ran together appended its entries as they
    // finished; the report is read in the order the profile was written.
    report::in_declaration_order(&mut steps);
    let profile_name = match &root {
        crate::profile_ast::ProfileNode::Spec { name, .. } => name.clone(),
        // The frontend only ever produces a `Spec` root; keep total.
        _ => String::new(),
    };

    let error = match run_result {
        Ok(()) => None,
        // The failing step recorded its own entry before the engine
        // surfaced the error, so the error line is built from the entry
        // rather than from the engine's sentence.
        //
        // **The first failing entry, in declaration order.** A sequential
        // run stops at its first failure, so there is exactly one and it
        // is also the last — the behaviour this replaces. A parallel
        // phase can end with several, and the one the line names is the
        // one nearest the top of the profile; the rest are in `steps`,
        // each with its own reason, which is what collecting them was
        // for.
        Err(engine_error) => match steps.iter().find(|step| !step.ok) {
            Some(step) => Some(format!(
                "step {} ({}) failed: {}",
                step.id,
                step.kind,
                step.failure_reason()
            )),
            // Fallback: an engine-internal error with no recorded step
            // (not expected for a frontend-produced AST).
            None => Some(engine_error),
        },
    };

    let envelope = report::build_envelope(&profile_name, dry_run, &steps, error.as_deref());
    Ok(serde_json::to_string_pretty(&envelope)?)
}

/// Drive the engine to completion, returning `Ok(())` on `Done` or the
/// rendered engine error on the first failing step (the per-step report
/// already carries the machine-readable detail).
///
/// ## Why this is not `dsl_kit::drive_async`
///
/// It was, until a phase's steps became a `Par`. `drive_async` resolves
/// **one suspension per loop round** and says so — "v1 resolves
/// suspensions sequentially … Concurrent fan-out resolution is
/// intentionally left to hosts with an executor opinion; the `Stepper`
/// surface remains fully public for that" (`dsl_kit::drive`). So a `Par`
/// under that loop fans out in the *engine* and still transfers one file
/// at a time: the parallelism would be entirely notional.
///
/// This is that loop with one clause changed — it resolves everything the
/// engine is blocked on, up to [`MAX_CONCURRENT_STEPS`] at a time, before
/// re-stepping. Everything else is `drive_async`'s shape: no breakpoints
/// are registered, so a non-`Call` suspension can only mean one the host
/// is not meant to answer and is reported rather than silently treated as
/// completion, and the cancellation queue is drained after every step
/// because the `Stepper` contract requires it.
///
/// **Resolving a whole wave before feeding any of it back is what makes
/// nothing get cancelled.** The engine cancels a sibling only while
/// stepping, and it is never stepped with a transfer in flight — so no
/// in-flight future is ever dropped, and `partial file left at `dst``
/// (see `registry::LifecycleJoin`) cannot arise. The join policy and the
/// driver are the same decision seen from two sides.
async fn drive(engine: &mut Engine<ProfileCallAst>, ctx: &Arc<ExecContext>) -> Result<(), String> {
    let breakpoints = BreakpointSet::new();
    loop {
        let outcome = engine
            .run_to_yield_with_breakpoints(&breakpoints)
            .map_err(|err| err.to_string())?;
        engine.take_cancellations();
        match outcome {
            StepOutcome::Done(_) => return Ok(()),
            StepOutcome::Ready => unreachable!("run_to_yield never returns Ready"),
            StepOutcome::Blocked { .. } => {
                let pending = engine.pending();
                if pending
                    .iter()
                    .any(|p| !matches!(p.reason, SuspendReason::Call { .. }))
                {
                    return Err(format!(
                        "apply halted on {} suspension(s) the host does not resolve",
                        pending.len()
                    ));
                }
                if pending.is_empty() {
                    return Err("the engine blocked with no pending suspensions".to_string());
                }
                let wave: VecDeque<Pending> = pending.iter().cloned().collect();
                for (id, result) in resolve_wave(ctx, wave).await? {
                    engine.resolve(id, result).map_err(|err| err.to_string())?;
                }
                engine.take_cancellations();
            }
        }
    }
}

/// Resolve every suspension in `wave`, at most [`MAX_CONCURRENT_STEPS`]
/// of them in flight, and return each answer beside the suspension it
/// belongs to.
///
/// The answers come back in completion order, which is fine to feed to
/// the engine — `Stepper::resolve` is order-independent — and is exactly
/// the order the report refuses to be read in
/// ([`report::in_declaration_order`]).
///
/// A step that panics ends the run with a message rather than leaving the
/// engine blocked on a suspension no one will ever answer. That path
/// abandons whatever else was in flight, and so is the one way this
/// driver can leave a partial file behind; a panicking effect is a broken
/// invariant either way.
async fn resolve_wave(
    ctx: &Arc<ExecContext>,
    mut wave: VecDeque<Pending>,
) -> Result<Vec<(SuspensionId, Result<ProfileValue, CallError>)>, String> {
    let mut answers = Vec::with_capacity(wave.len());
    let mut running: JoinSet<(SuspensionId, Result<ProfileValue, CallError>)> = JoinSet::new();
    loop {
        while running.len() < MAX_CONCURRENT_STEPS {
            let Some(pending) = wave.pop_front() else {
                break;
            };
            // Everything the effect needs is copied out of the suspension
            // here, so the spawned future borrows nothing.
            let ctx = Arc::clone(ctx);
            let id = pending.id;
            let node = pending.at.node;
            let reason: SuspendReason = pending.reason.clone();
            running.spawn(async move { (id, registry::resolve_call(&ctx, node, &reason).await) });
        }
        match running.join_next().await {
            Some(Ok(answer)) => answers.push(answer),
            Some(Err(err)) => return Err(format!("a lifecycle step did not finish: {err}")),
            None => return Ok(answers),
        }
    }
}
