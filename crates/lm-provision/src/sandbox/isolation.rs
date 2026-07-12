//! L2 execution control: the isolation runtime
//! (05-sandbox-layer-contract.md §L2).
//!
//! [`Isolation`] owns a sandboxed VM ([`crate::vm::boot_vm`], L1) on a
//! dedicated OS thread. The host and the VM exchange **strings only**
//! (05 §L2: "the host and the VM exchange strings only (eval results and
//! serialized JSON), never live Lua references") — every [`Isolation::eval`]
//! call sends a Lua source string across a channel and receives back
//! either the string the chunk returned or an error message, never a
//! live `mlua::Table` / `mlua::Function`. This is not merely a style
//! choice: `mlua::Lua` is `!Send` under this crate's feature set (no
//! `mlua/send`), so a `Lua` value cannot cross the channel at all — the
//! only thing that *can* cross is data the VM thread serializes down to
//! a `String` before handing it back, which is exactly the strings-only
//! contract 05 §L2 describes.
//!
//! Milestone M3-1 ships the isolation *structure* — the dedicated
//! thread, the strings-only boundary, and the cooperative-cancellation
//! hook — matching plan.md's M3-1 scope note ("L2 は isolation 構造
//! (専用 thread 駆動 + cancel hook 用意) までを M3-1 scope とし、spec
//! が stable と言う範囲のみ"). A host-level per-run wall-clock timeout
//! is explicitly **provisional** (05 §Stability) and is not implemented
//! here; `sh.exec` / `net.*` step-level timeouts (04-bridge.md) are a
//! milestone M3-2..M3-3 concern, orthogonal to this driver.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use mlua::{Debug, HookTriggers, Lua, Value, VmState};
use thiserror::Error;

use crate::vm::{boot_vm, VmError};

/// Errors raised while spawning or driving an [`Isolation`].
#[derive(Debug, Error)]
pub enum IsolationError {
    /// The VM thread failed to boot the sandboxed VM
    /// ([`crate::vm::boot_vm`], registration order steps 1-2).
    #[error("failed to boot the isolated VM: {0}")]
    Boot(String),

    /// The VM thread is no longer reachable (it has already exited,
    /// typically because [`Isolation`] is mid-[`Drop`]).
    #[error("isolation: the VM thread is gone")]
    ThreadGone,
}

/// One eval request sent across the strings-only channel boundary.
struct Request {
    source: String,
    chunk_name: String,
    reply_tx: Sender<Result<String, String>>,
}

/// An isolated Lua VM running on its own dedicated OS thread
/// (05-sandbox-layer-contract.md §L2).
///
/// One [`Isolation`] is the L2 execution-control layer for one
/// subcommand run (05 §L2: "One VM per subcommand run; nothing persists
/// between runs"). Dropping it tears the VM down: [`Drop::drop`] closes
/// the request channel (ending the VM thread's receive loop) and joins
/// the thread, so by the time `drop` returns the VM is provably gone,
/// not merely unreferenced (05 §L2: "Dropping the driver tears the VM
/// down").
pub struct Isolation {
    handle: Option<JoinHandle<()>>,
    request_tx: Option<Sender<Request>>,
    cancel: Arc<AtomicBool>,
}

impl Isolation {
    /// Spawn a dedicated thread, boot a sandboxed VM on it (L1, via
    /// [`boot_vm`]), and install the cooperative-cancellation interrupt
    /// hook (05 §L2: "Cooperative cancellation ... [is a] capabilit[y]
    /// of the isolation layer"). Blocks until the VM thread reports
    /// boot success or failure, so a caller never observes an
    /// [`Isolation`] whose VM failed to boot.
    pub fn spawn() -> Result<Self, IsolationError> {
        let (request_tx, request_rx) = mpsc::channel::<Request>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_thread = Arc::clone(&cancel);

        let handle = std::thread::spawn(move || {
            run_vm_thread(request_rx, ready_tx, cancel_for_thread);
        });

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                handle: Some(handle),
                request_tx: Some(request_tx),
                cancel,
            }),
            Ok(Err(message)) => {
                let _ = handle.join();
                Err(IsolationError::Boot(message))
            }
            Err(_) => {
                let _ = handle.join();
                Err(IsolationError::Boot(
                    "isolation VM thread exited before signalling readiness".to_string(),
                ))
            }
        }
    }

    /// Evaluate `source` on the isolated VM thread and return the
    /// string its top-level chunk returns.
    ///
    /// The host and the VM exchange strings only (05 §L2): `source` and
    /// `chunk_name` cross the channel as owned `String`s, and the
    /// result crosses back the same way. A chunk that returns anything
    /// other than a Lua string (a table, a number, `nil`, ...) is
    /// rejected — the strings-only boundary is enforced here, not left
    /// to caller discipline. Callers that need structured data return a
    /// JSON string (e.g. via `lm.canonical.encode`, 03-pipeline-stage
    /// -artifacts.md §canonical) rather than a live Lua value.
    pub fn eval(&self, source: &str, chunk_name: &str) -> Result<String, String> {
        let request_tx = self
            .request_tx
            .as_ref()
            .ok_or_else(|| IsolationError::ThreadGone.to_string())?;
        let (reply_tx, reply_rx) = mpsc::channel();
        request_tx
            .send(Request {
                source: source.to_string(),
                chunk_name: chunk_name.to_string(),
                reply_tx,
            })
            .map_err(|_| IsolationError::ThreadGone.to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "isolation: the VM thread dropped the reply channel".to_string())?
    }

    /// Request cooperative cancellation of whatever is currently (or
    /// next) running on the isolated VM. The interrupt hook installed
    /// in [`run_vm_thread`] checks this flag and aborts the running
    /// chunk with a Lua error the next time Lua's VM polls it (05 §L2
    /// "Cooperative cancellation"). Cancellation is sticky: once set,
    /// every subsequent [`Isolation::eval`] on this instance also fails
    /// immediately — a cancelled driver is meant to be dropped and
    /// replaced, not reused (05 §L2 "One VM per subcommand run").
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for Isolation {
    fn drop(&mut self) {
        // Drop the sender first: this closes the channel, ending the VM
        // thread's `for request in request_rx` receive loop even if it
        // is currently blocked waiting for the next request. Only then
        // join, so `drop` does not return until the VM thread — and the
        // `Lua` it owns — has actually exited (05 §L2: "Dropping the
        // driver tears the VM down").
        self.request_tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_vm_thread(
    request_rx: Receiver<Request>,
    ready_tx: Sender<Result<(), String>>,
    cancel: Arc<AtomicBool>,
) {
    let lua = match boot_vm() {
        Ok(lua) => lua,
        Err(err) => {
            let _ = ready_tx.send(Err(vm_error_to_string(err)));
            return;
        }
    };
    install_cancel_hook(&lua, cancel);

    if ready_tx.send(Ok(())).is_err() {
        // The spawning side already gave up waiting; nothing left to do.
        return;
    }

    for request in request_rx {
        let outcome = eval_request(&lua, &request.source, &request.chunk_name);
        let _ = request.reply_tx.send(outcome);
    }
}

fn vm_error_to_string(err: VmError) -> String {
    err.to_string()
}

/// Number of VM instructions between cancellation checks
/// ([`HookTriggers::every_nth_instruction`]). Small enough that a
/// cancelled tight loop (e.g. `while true do end`) aborts promptly;
/// `mlua`'s own docs warn a very low value "can incur a very high
/// overhead", so this is not set to 1.
const CANCEL_CHECK_INSTRUCTION_INTERVAL: u32 = 1000;

/// Install the cooperative-cancellation hook (05 §L2 "Cooperative
/// cancellation"). `Lua::set_interrupt` — the more direct analogue —
/// is Luau-only (gated `#[cfg(feature = "luau")]` in mlua); the
/// standard-Lua equivalent is a count-triggered [`Lua::set_hook`]:
/// mlua polls this callback every
/// [`CANCEL_CHECK_INSTRUCTION_INTERVAL`] VM instructions, and
/// returning `Err` aborts the running chunk with that error — how
/// [`Isolation::cancel`] interrupts an in-progress (or about-to-start)
/// eval.
fn install_cancel_hook(lua: &Lua, cancel: Arc<AtomicBool>) {
    let triggers = HookTriggers::new().every_nth_instruction(CANCEL_CHECK_INSTRUCTION_INTERVAL);
    lua.set_hook(triggers, move |_lua, _debug: Debug| {
        if cancel.load(Ordering::Relaxed) {
            Err(mlua::Error::RuntimeError(
                "isolation: execution cancelled".to_string(),
            ))
        } else {
            Ok(VmState::Continue)
        }
    });
}

/// Evaluate one chunk and coerce its return value down to the
/// strings-only boundary (05 §L2), or the error message if evaluation
/// failed.
fn eval_request(lua: &Lua, source: &str, chunk_name: &str) -> Result<String, String> {
    let result: mlua::Result<Value> = lua
        .load(source)
        .set_name(chunk_name)
        .set_mode(mlua::ChunkMode::Text)
        .eval();

    match result {
        Ok(Value::String(s)) => Ok(String::from_utf8_lossy(&s.as_bytes()).into_owned()),
        Ok(other) => Err(format!(
            "isolation eval: script must return a string (host<->VM boundary is strings-only, \
             05 §L2); got {}",
            other.type_name()
        )),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_runs_on_a_dedicated_thread_and_returns_a_string_result() {
        let isolation = Isolation::spawn().expect("isolation should spawn");
        let result = isolation
            .eval("return 'hello-from-vm'", "test-chunk")
            .expect("eval should succeed");
        assert_eq!(result, "hello-from-vm");
    }

    #[test]
    fn eval_rejects_a_non_string_return_value() {
        let isolation = Isolation::spawn().expect("isolation should spawn");
        let err = isolation
            .eval("return { 1, 2, 3 }", "test-chunk")
            .expect_err("non-string return must be rejected (strings-only boundary)");
        assert!(err.contains("strings-only"));
    }

    #[test]
    fn eval_surfaces_a_lua_error_as_a_string_message() {
        let isolation = Isolation::spawn().expect("isolation should spawn");
        let err = isolation
            .eval("error('boom')", "test-chunk")
            .expect_err("a Lua error must surface as Err");
        assert!(err.contains("boom"));
    }

    #[test]
    fn cancel_aborts_a_running_evaluation_via_the_interrupt_hook() {
        let isolation = Isolation::spawn().expect("isolation should spawn");
        isolation.cancel();
        let err = isolation
            .eval("while true do end", "test-chunk")
            .expect_err("a cancelled VM must abort the loop");
        assert!(err.contains("cancelled"));
    }

    #[test]
    fn dropping_the_driver_tears_down_the_vm_thread() {
        let isolation = Isolation::spawn().expect("isolation should spawn");
        // Drop joins the VM thread before returning (05 §L2: "Dropping
        // the driver tears the VM down") — this test's only assertion
        // is that drop completes at all rather than hanging.
        drop(isolation);
    }

    #[test]
    fn eval_after_drop_of_the_sender_side_reports_the_thread_is_gone() {
        let mut isolation = Isolation::spawn().expect("isolation should spawn");
        isolation.request_tx.take();
        let err = isolation
            .eval("return 'unreachable'", "test-chunk")
            .expect_err("eval must fail once the request channel is gone");
        assert!(err.contains("gone"));
    }
}
