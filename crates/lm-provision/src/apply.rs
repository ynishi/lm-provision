//! Host-side apply entry point: plan → dispatch → apply → report
//! (09-apply-report-and-ledger.md).
//!
//! [`run_apply_ast`] loads a profile file into a
//! [`crate::profile_ast::ProfileNode`] AST ([`crate::frontend::load_profile`])
//! and drives the pure-Rust [`crate::exec`] engine over it, collecting
//! one structured [`crate::exec::report::StepReport`] per executed op into
//! the apply report artifact (09 §Outputs "Apply report"), returned as a
//! JSON string.

use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::exec::{report, ExecMode};

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
pub fn run_apply_ast(profile: &Path, dry_run: bool) -> Result<String, AstApplyError> {
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
    let (mut engine, reports) =
        crate::profile_ast::create_profile_engine_collecting(&root, mode, log)?;
    let run_result = drive(&mut engine);

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

/// Drive the engine to completion, returning `Ok(())` on `Done` or the
/// rendered engine error on the first failing step (the per-step report
/// already carries the machine-readable detail).
fn drive(engine: &mut dsl_kit::Engine<crate::profile_ast::ProfileAst>) -> Result<(), String> {
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
