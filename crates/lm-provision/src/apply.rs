//! Host-side apply entry point: plan → dispatch → apply → report
//! (09-apply-report-and-ledger.md).
//!
//! [`run_apply_ast`] loads a profile file into a
//! [`crate::profile_ast::ProfileNode`] AST ([`crate::frontend::load_profile`])
//! and drives the pure-Rust [`crate::exec`] engine over it, collecting
//! one structured [`crate::exec::report::StepReport`] per executed op into
//! the apply report artifact (09 §Outputs "Apply report"), returned as a
//! JSON string.

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dsl_kit::{
    AsyncEffectResolver, BreakpointSet, DriveOutcome, Engine, Pending, ReducerRegistry,
    SuspendReason,
};

use crate::exec::registry::{CallError, EffectRoute, ProfileCallAst};
use crate::exec::{registry, report, ExecContext, ExecMode};
use crate::profile_ast::ProfileValue;

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
/// the first failing step ends the run, is included as the last `steps`
/// entry, and its reason drives the envelope's `error` line; no later
/// step is reached.
///
/// # Runtime
///
/// **`async`, and a multi-threaded tokio runtime must be driving it.**
/// The effect layer's HTTP routes are async ([`crate::exec::effects`]).
/// A phase routed through [`EffectRoute::Call`] suspends and is awaited
/// by [`EffectResolver`] below — nothing blocks. Every other
/// async-effect-bearing op is still an `Op`, and `dsl_kit`'s
/// `Op::apply` is not `async`, so those drive their future from the
/// synchronous seam ([`crate::exec::effects::block_on_effect`]), which
/// needs a sibling worker to keep the reactor turning.
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
/// dsl-kit `Call` resolved by [`EffectResolver`] (see
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
    let mut engine = Engine::new_with_ops(
        ProfileCallAst::new(&root, route),
        Arc::new(ReducerRegistry::new()),
        registry::profile_op_registry(Arc::clone(&ctx)),
    )
    .expect("Engine initialization should succeed");
    let mut resolver = EffectResolver { ctx };
    let run_result = drive(&mut engine, &mut resolver).await;

    let steps = reports.lock().unwrap().clone();
    let profile_name = match &root {
        crate::profile_ast::ProfileNode::Spec { name, .. } => name.clone(),
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

/// The host's async effect backend: one `Call` at a time, awaited.
///
/// dsl-kit's own words for the shape this implements — "Async is a host
/// concern" (`dsl_kit::Stepper`), "Runtime-neutral — this crate never
/// touches an executor" (`dsl_kit::AsyncEffectResolver`). Whatever
/// runtime polls [`drive`] below is the backend; nothing here reaches
/// for one.
struct EffectResolver {
    /// The same context the op registry holds, so a resolved call writes
    /// its report entry into the run's collection.
    ctx: Arc<ExecContext>,
}

impl AsyncEffectResolver<ProfileCallAst> for EffectResolver {
    fn resolve(
        &mut self,
        pending: &Pending,
    ) -> impl Future<Output = Result<ProfileValue, CallError>> + Send {
        // Everything the effect needs is copied out of the suspension
        // here, so the returned future borrows neither `self` nor
        // `pending`.
        let ctx = Arc::clone(&self.ctx);
        let node = pending.at.node;
        let reason: SuspendReason = pending.reason.clone();
        async move { registry::resolve_call(&ctx, node, &reason).await }
    }
}

/// Drive the engine to completion, returning `Ok(())` on `Done` or the
/// rendered engine error on the first failing step (the per-step report
/// already carries the machine-readable detail).
///
/// `dsl_kit::drive_async` is the loop: it re-steps the engine, hands
/// each suspended `Call` to `resolver`, and feeds the result back. The
/// hand-rolled loop this replaces ignored `StepOutcome::Blocked` and
/// span until its own step ceiling, so a suspension was a hang rather
/// than an effect.
///
/// No breakpoints are registered, so a `Break` can only mean a
/// suspension the resolver is not meant to answer (`Cooperative` /
/// `User`); the engine emits none, and it is reported rather than
/// silently treated as completion.
async fn drive(
    engine: &mut Engine<ProfileCallAst>,
    resolver: &mut EffectResolver,
) -> Result<(), String> {
    match dsl_kit::drive_async(engine, resolver, &BreakpointSet::new()).await {
        Ok(DriveOutcome::Done(_)) => Ok(()),
        Ok(DriveOutcome::Break { at }) => Err(format!(
            "apply halted on {} suspension(s) the host does not resolve",
            at.len()
        )),
        Err(err) => Err(err.to_string()),
    }
}
