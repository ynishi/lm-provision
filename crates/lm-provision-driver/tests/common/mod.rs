//! What the end-to-end tests in this crate share: the lock that keeps
//! two of them from staging and running a binary at the same moment.
//!
//! Not a test target of its own — `tests/*.rs` are compiled into test
//! binaries, `tests/*/mod.rs` are not — so each binary that says
//! `mod common;` gets its own copy of the state below, which is the
//! right scope: the hazard is between threads of one process.

/// Held while a test writes an executable and then runs it.
///
/// **`ETXTBSY`: the kernel refuses to exec a file some process has
/// open for writing, and a forked child holds its parent's
/// descriptors until it execs.** These tests stage the binary (or a
/// stub CLI) into their own directory and run it, and cargo runs them
/// on parallel threads of one process. So thread A opens its staged
/// binary for writing; thread B spawns something, and B's child — in
/// the window between fork and exec — inherits A's still-open write
/// descriptor; A finishes writing, closes its own copy, and execs the
/// file, which the kernel now sees as open for writing somewhere else.
/// Unique paths per test do not help: the descriptor B's child
/// inherited is to A's file [measured: 2026-09-01, `Text file busy`
/// out of `session_e2e` and `driver_e2e` in roughly half of the runs
/// that had other crates building alongside them, and none at all
/// under `--test-threads=1`].
///
/// Serialising costs these suites nothing measurable — one slow test
/// dominates each of them either way [measured: 2026-09-01,
/// `session_e2e` 9.79s parallel, 9.79s serial].
static STAGE_AND_RUN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the lock, surviving a poisoned one: a test that panicked
/// while holding it left a directory behind, not a broken invariant,
/// and the next test should fail on its own assertion rather than on
/// a `PoisonError` naming neither.
///
/// Held for the whole test rather than just the upload: what has to
/// not overlap is one thread's write with another thread's fork, and
/// both happen inside the session this returns to.
pub fn stage_and_run() -> std::sync::MutexGuard<'static, ()> {
    STAGE_AND_RUN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
