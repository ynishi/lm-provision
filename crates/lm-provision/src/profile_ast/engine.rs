//! Constructors that wire a [`super::ProfileNode`] AST onto the
//! [`crate::exec`] bridge and return a dsl-kit-core [`Engine`].
//!
//! Both entry points reuse the same [`super::ProfileSemantics`] adapter
//! (defined in [`super::semantics`]); the only difference is whether the
//! caller wants the structured per-step report handle back
//! ([`create_profile_engine_collecting`]) or just the engine and the
//! flat trace log ([`create_profile_engine`]).

use std::sync::{Arc, Mutex};

use dsl_kit::{Engine, OwnedDerivedAst, ReducerRegistry};

use super::{ProfileAst, ProfileNode, ProfileSemantics};

/// Instantiates a dsl-kit-core Engine driving real execution of a
/// `ProfileNode` AST through the [`crate::exec`] bridge.
///
/// `mode` selects dry-run tracing vs real effects; `executed_log`
/// collects each op's trace line / result summary. Construction fails
/// with [`crate::exec::ExecError`] only when the profile declares a
/// capability outside [`crate::exec::capgate::KNOWN_CAPABILITIES`]; the
/// engine wiring itself is a host invariant and is asserted.
///
/// # Runtime
///
/// The returned engine is driven **synchronously** (`Stepper::step` /
/// `run_to_yield_with_breakpoints`), which is the whole reason this
/// entry point differs from [`crate::apply::run_apply_ast`]: a
/// synchronous stepper cannot resolve a `Call`, so the AST it runs is
/// the plain derived one, with lifecycle phases still on their ops.
///
/// **A multi-threaded tokio runtime must therefore be current whenever
/// the profile has a lifecycle phase** — in *both* modes. Real mode
/// always needed one (a transfer, a poll). Dry run needs one too now
/// that it answers a step's completion condition rather than describing
/// it, because observing the host is async
/// (`exec::lifecycle::dry_run_step`). Both go through
/// `exec::effects::block_on_effect`, which reports a missing or
/// single-threaded runtime as an [`crate::exec::ExecError`] naming the
/// requirement rather than panicking.
///
/// The MCP debugger host gets one from `#[tokio::main]`; a test needs
/// `#[tokio::test(flavor = "multi_thread")]`.
pub fn create_profile_engine(
    root: &ProfileNode,
    mode: crate::exec::ExecMode,
    executed_log: Arc<Mutex<Vec<String>>>,
) -> Result<Engine<ProfileAst>, crate::exec::ExecError> {
    Ok(create_profile_engine_collecting(root, mode, executed_log)?.0)
}

/// Like [`create_profile_engine`], but also returns a handle to the
/// shared structured per-step report collection
/// ([`crate::exec::report::StepReport`]) the op handlers append to as
/// they run. The AST `apply` subcommand ([`crate::apply::run_apply_ast`])
/// drives the returned engine and then reads this handle to build the
/// apply report; the plain [`create_profile_engine`] discards it for the
/// trace-log-only call sites (integration tests, the POC path).
pub fn create_profile_engine_collecting(
    root: &ProfileNode,
    mode: crate::exec::ExecMode,
    executed_log: Arc<Mutex<Vec<String>>>,
) -> Result<(Engine<ProfileAst>, crate::exec::report::SharedReports), crate::exec::ExecError> {
    let ctx = Arc::new(crate::exec::ExecContext::from_root(
        root,
        mode,
        executed_log,
    )?);
    let reports = ctx.reports_handle();
    let engine = Engine::new_with_ops(
        OwnedDerivedAst::new(root, ProfileSemantics),
        Arc::new(ReducerRegistry::new()),
        crate::exec::registry::profile_op_registry(Arc::clone(&ctx)),
    )
    .expect("Engine initialization should succeed");
    Ok((engine, reports))
}
