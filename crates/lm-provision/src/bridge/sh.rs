//! `sh.exec` bridge (04-bridge.md §Outputs `sh.exec`; milestone M3-2).
//!
//! [`install`] registers the profile-visible `sh.exec(argv, opts)`
//! primitive. Every call re-checks the capability gate at entry
//! (04-bridge.md §Common conventions: "Every bridge re-checks the
//! capability gate at entry (defence in depth over the register
//! skip)"), decodes and validates `opts` (including host-thread
//! `SecretRef` resolution against the declared `env_secrets` allowlist,
//! 06-secret-handling.md §Inputs "Consumption points"), and — unless
//! `opts.dry_run` — spawns the child as a process-group leader so a
//! timeout's SIGTERM/SIGKILL reaches backgrounded descendants too
//! (04-bridge.md §Outputs `sh.exec` "Process-group semantics").
//!
//! [`crate::sandbox::wire_sandboxed_profile`] is the sole caller: it
//! passes this module's [`install`] to
//! [`crate::sandbox::capgate::register_if_granted`] as registration
//! order step 8 (04-bridge.md §Registration order), so `sh.exec` only
//! ever exists on a VM whose profile declared the `sh.exec` capability.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mlua::{Function, Lua, Table, Value};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::sandbox::capgate::CapabilityGate;
use crate::secret::SecretRef;

/// The capability name this bridge installs under
/// (05-sandbox-layer-contract.md §L4 `KNOWN_CAPABILITIES`).
pub const CAPABILITY: &str = "sh.exec";

/// Register `sh.exec` on `lua`'s `sh` global table.
///
/// Callers are expected to reach this only through
/// [`crate::sandbox::capgate::register_if_granted`] (the register-skip
/// half of 04-bridge.md §Registration order step 8) — `gate` is passed
/// in anyway and re-checked on every call, because 04 §Common
/// conventions requires every bridge to re-verify the gate at entry as
/// defence in depth over the register skip, not rely on the register
/// skip alone.
///
/// `env_secrets` is the profile's declared `env_secrets` allowlist
/// ([`crate::vm::eval::Declarations::env_secrets`]) — the set
/// `opts.env` `SecretRef` values are checked against before host-thread
/// resolution (06-secret-handling.md §Inputs "Consumption points").
///
/// `sensitive_keys` is
/// [`crate::sandbox::catalog::sensitive_key_substrings`]'s frozen set —
/// the audit line [`exec_entry`] emits (09-apply-report-and-ledger.md
/// §Audit log "sh.exec" / "Env keys"; milestone M4-2) redacts an
/// `opts.env` key NAME against it before logging.
pub fn install(
    lua: &Lua,
    gate: CapabilityGate,
    env_secrets: Vec<String>,
    sensitive_keys: Vec<String>,
) -> mlua::Result<()> {
    let env_secrets: HashSet<String> = env_secrets.into_iter().collect();
    let exec_fn = lua.create_function(
        move |lua, (argv, opts): (Table, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY)
                .map_err(|err| mlua::Error::RuntimeError(err.to_string()))?;
            exec_entry(lua, argv, opts, &env_secrets, &sensitive_keys)
        },
    )?;

    let sh_table = lua.create_table()?;
    sh_table.set("exec", exec_fn)?;
    lua.globals().set("sh", sh_table)?;
    Ok(())
}

/// Decoded, host-resolved `opts` (04-bridge.md §Outputs `sh.exec`
/// "opts"). `env` values have already passed the `SecretRef`
/// check-then-resolve protocol (06 §Inputs "Consumption points") by the
/// time this struct exists — resolution happens during decode so that
/// `dry_run` still fails on missing secrets (04 §Common conventions:
/// "Dry-run therefore still fails on policy violations and missing
/// secrets").
#[derive(Default)]
struct ExecOpts {
    env: Vec<(String, String)>,
    cwd: Option<String>,
    stdin: Option<String>,
    stdin_file: Option<String>,
    timeout_sec: Option<f64>,
    term_grace_sec: Option<f64>,
    on_line: Option<Function>,
    dry_run: bool,
}

/// `sh.exec(argv, opts) -> result` (04-bridge.md §Outputs `sh.exec`).
fn exec_entry(
    lua: &Lua,
    argv: Table,
    opts: Option<Table>,
    env_secrets: &HashSet<String>,
    sensitive_keys: &[String],
) -> mlua::Result<Table> {
    let argv = decode_argv(argv)?;
    let opts = decode_opts(opts, env_secrets)?;

    // Audit line before the effect (09-apply-report-and-ledger.md
    // §Audit log "sh.exec"): argv verbatim, env key NAMES only
    // (redacted per `sensitive_keys`), stdin as a byte count. Emitted
    // for a dry_run call too — the audit trail records the intended
    // invocation regardless of whether the effect itself runs.
    crate::audit::sh_exec(
        &argv,
        &opts.env,
        opts.stdin.as_deref().map(str::len).unwrap_or(0),
        sensitive_keys,
    );

    if opts.dry_run {
        // Decoding, the capability-gate re-check, and secret resolution
        // have already run above; only the effect (spawning the child)
        // is skipped (04 §Common conventions).
        return ExecResult::dry_run_echo().into_lua_table(lua);
    }

    run_child(lua, &argv, &opts)
}

/// `argv`: non-empty list of strings (04 §Outputs `sh.exec`).
fn decode_argv(argv: Table) -> mlua::Result<Vec<String>> {
    let list: Vec<String> = argv
        .sequence_values::<String>()
        .collect::<mlua::Result<_>>()?;
    if list.is_empty() {
        return Err(mlua::Error::RuntimeError(
            "sh.exec: argv must be a non-empty list of strings".to_string(),
        ));
    }
    Ok(list)
}

fn decode_opts(opts: Option<Table>, env_secrets: &HashSet<String>) -> mlua::Result<ExecOpts> {
    let Some(opts) = opts else {
        return Ok(ExecOpts::default());
    };

    let cwd: Option<String> = opts.get("cwd")?;
    let stdin: Option<String> = opts.get("stdin")?;
    let stdin_file: Option<String> = opts.get("stdin_file")?;
    if stdin.is_some() && stdin_file.is_some() {
        // 04 §Outputs `sh.exec`: "Supplying both is a Lua error."
        return Err(mlua::Error::RuntimeError(
            "sh.exec: opts.stdin and opts.stdin_file are mutually exclusive".to_string(),
        ));
    }
    let timeout_sec: Option<f64> = opts.get("timeout_sec")?;
    let term_grace_sec: Option<f64> = opts.get("term_grace_sec")?;
    let on_line: Option<Function> = opts.get("on_line")?;
    let dry_run: bool = opts.get::<Option<bool>>("dry_run")?.unwrap_or(false);
    let env = resolve_env(opts.get("env")?, env_secrets)?;

    Ok(ExecOpts {
        env,
        cwd,
        stdin,
        stdin_file,
        timeout_sec,
        term_grace_sec,
        on_line,
        dry_run,
    })
}

/// Check-then-resolve every `opts.env` entry
/// (06-secret-handling.md §Inputs "Consumption points"): a plain string
/// value passes through verbatim; a `SecretRef` value is checked against
/// `env_secrets` and resolved from the host process environment
/// (06 §Resolution — host-thread only, never returned to Lua). The
/// resolved strings this returns flow only into the child's environment
/// ([`spawn_child`]) — never back into a Lua value.
fn resolve_env(
    env_table: Option<Table>,
    env_secrets: &HashSet<String>,
) -> mlua::Result<Vec<(String, String)>> {
    let Some(env_table) = env_table else {
        return Ok(Vec::new());
    };
    let mut resolved = Vec::with_capacity(env_table.raw_len());
    for pair in env_table.pairs::<String, Value>() {
        let (name, value) = pair?;
        let resolved_value = match value {
            Value::String(s) => s.to_str()?.to_string(),
            Value::UserData(ud) if ud.is::<SecretRef>() => {
                let secret_name = ud.borrow::<SecretRef>()?.name().to_string();
                // The `env_secrets`-gated resolve half of the `SecretRef`
                // protocol (06-secret-handling.md §Error surface),
                // shared with `net.transfer`'s `auth_bearer` consumption
                // point (milestone M3-3) via [`crate::secret::resolve`]
                // rather than duplicated here.
                crate::secret::resolve(&secret_name, env_secrets)?
            }
            other => {
                return Err(mlua::Error::RuntimeError(format!(
                    "sh.exec: opts.env['{name}'] must be a string or SecretRef, got {}",
                    other.type_name()
                )));
            }
        };
        resolved.push((name, resolved_value));
    }
    Ok(resolved)
}

/// `sh.exec` result table (04-bridge.md §Outputs `sh.exec` "Result").
struct ExecResult {
    ok: bool,
    status: i64,
    stdout: String,
    stderr: String,
    dry_run: bool,
    timed_out: bool,
}

impl ExecResult {
    /// `opts.dry_run`'s echo result (04 §Common conventions:
    /// "skips the effect and returns `{ ok = true, dry_run = true,
    /// ...echo... }`"). Decoding, the gate check, and secret resolution
    /// have already succeeded by the time this is constructed — a
    /// dry-run that reaches here has nothing left to fail on.
    fn dry_run_echo() -> Self {
        Self {
            ok: true,
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
            dry_run: true,
            timed_out: false,
        }
    }

    fn into_lua_table(self, lua: &Lua) -> mlua::Result<Table> {
        let table = lua.create_table()?;
        table.set("ok", self.ok)?;
        table.set("status", self.status)?;
        table.set("stdout", self.stdout)?;
        table.set("stderr", self.stderr)?;
        table.set("dry_run", self.dry_run)?;
        table.set("timed_out", self.timed_out)?;
        Ok(table)
    }
}

/// Spawn the child, drive it to completion (streaming `on_line`,
/// enforcing `timeout_sec` / `term_grace_sec`), and build the result
/// table (04-bridge.md §Outputs `sh.exec`).
fn run_child(lua: &Lua, argv: &[String], opts: &ExecOpts) -> mlua::Result<Table> {
    let mut child = match spawn_child(argv, opts) {
        Ok(child) => child,
        Err(io_err) => {
            // Effect failure (04 §Error surface "Effect failures ...
            // syscall failure"): sh.exec's own Outputs section defines
            // no `error` field, so the failure is reported the same way
            // a failing command's own stderr would be.
            return ExecResult {
                ok: false,
                status: -1,
                stdout: String::new(),
                stderr: format!("sh.exec: failed to start '{}': {io_err}", argv[0]),
                dry_run: false,
                timed_out: false,
            }
            .into_lua_table(lua);
        }
    };

    if let Some(input) = &opts.stdin {
        if let Some(mut child_stdin) = child.stdin.take() {
            // Best-effort: a child that never reads stdin (e.g. an
            // early exit) can make this a broken pipe, which is not
            // this step's failure to report — `stdin`'s own contract is
            // "piped ... pipe closed → EOF", not "write must succeed".
            let _ = child_stdin.write_all(input.as_bytes());
            // `child_stdin` drops here, closing the pipe (EOF).
        }
    }

    // Invariant, not a runtime possibility: `spawn_child` always
    // requests `Stdio::piped()` for both streams.
    let stdout_pipe = child
        .stdout
        .take()
        .expect("stdout was piped by spawn_child");
    let stderr_pipe = child
        .stderr
        .take()
        .expect("stderr was piped by spawn_child");

    // Two channels per stream: `line_tx` carries only complete,
    // newline-terminated lines (for `on_line` + `lineno` — main-thread
    // side, since `mlua::Function` is not `Send`); `*_result_tx` carries
    // the exact raw bytes the reader thread accumulated, sent once at
    // EOF. Splitting these apart (rather than reconstructing `stdout` /
    // `stderr` from the streamed lines) is what keeps the result fields
    // byte-identical to the child's actual output — including a final
    // line with no trailing newline (04 §Outputs `sh.exec` "Result").
    let (line_tx, line_rx) = mpsc::channel::<(&'static str, String)>();
    let (stdout_result_tx, stdout_result_rx) = mpsc::channel::<String>();
    let (stderr_result_tx, stderr_result_rx) = mpsc::channel::<String>();
    let stdout_handle = spawn_reader(stdout_pipe, "stdout", line_tx.clone(), stdout_result_tx);
    let stderr_handle = spawn_reader(stderr_pipe, "stderr", line_tx.clone(), stderr_result_tx);
    drop(line_tx);

    let pid = child.id() as i32;
    let deadline = opts
        .timeout_sec
        .map(|secs| Instant::now() + Duration::from_secs_f64(secs.max(0.0)));

    let mut lineno: u64 = 0;
    let mut timed_out = false;

    loop {
        let recv_result = match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    timed_out = true;
                    break;
                }
                line_rx.recv_timeout(deadline - now)
            }
            None => line_rx
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };

        match recv_result {
            Ok((stream, line)) => record_line(stream, line, &opts.on_line, &mut lineno),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let mut terminated_gracefully = false;
    let final_status: Option<ExitStatus> = if timed_out {
        // Process-group semantics (04 §Outputs `sh.exec`): the child was
        // spawned as its own process-group leader (`spawn_child`'s
        // `process_group(0)`), so signalling the negated pid reaches
        // the whole group — backgrounded descendants included.
        let _ = kill(Pid::from_raw(-pid), Signal::SIGTERM);
        let grace = opts.term_grace_sec.unwrap_or(0.0).max(0.0);
        let grace_deadline = Instant::now() + Duration::from_secs_f64(grace);
        let status = wait_for_exit_or_deadline(&mut child, grace_deadline);
        terminated_gracefully = status.is_some();
        // Belt-and-braces SIGKILL to the whole group even when the
        // leader already exited from SIGTERM: a descendant that ignored
        // SIGTERM must not be left holding the output pipes open (04
        // §Outputs `sh.exec` "Process-group semantics").
        let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
        let status = status.or_else(|| child.wait().ok());
        drain_remaining_lines(&line_rx, &opts.on_line, &mut lineno);
        status
    } else {
        child.wait().ok()
    };

    let _ = stdout_handle.join();
    let _ = stderr_handle.join();
    let stdout_buf = stdout_result_rx.recv().unwrap_or_default();
    let mut stderr_buf = stderr_result_rx.recv().unwrap_or_default();

    let status: i64 = if timed_out {
        -1
    } else {
        final_status.map(exit_code_of).unwrap_or(-1)
    };

    if timed_out {
        if !stderr_buf.is_empty() && !stderr_buf.ends_with('\n') {
            stderr_buf.push('\n');
        }
        // 04 §Outputs `sh.exec`: "stderr is suffixed with a `timed out
        // after Ns (terminated gracefully | killed)` line."
        stderr_buf.push_str(&format!(
            "timed out after {}s ({})\n",
            opts.timeout_sec.unwrap_or(0.0),
            if terminated_gracefully {
                "terminated gracefully"
            } else {
                "killed"
            }
        ));
    }

    ExecResult {
        ok: status == 0 && !timed_out,
        status,
        stdout: stdout_buf,
        stderr: stderr_buf,
        dry_run: false,
        timed_out,
    }
    .into_lua_table(lua)
}

/// Build and spawn the child: process-group leader, `opts.env` injected
/// (already host-resolved by [`resolve_env`]), `cwd`, and exactly one of
/// piped `stdin` / file-backed `stdin_file` / no stdin at all.
fn spawn_child(argv: &[String], opts: &ExecOpts) -> std::io::Result<Child> {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    if let Some(cwd) = &opts.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &opts.env {
        command.env(key, value);
    }
    // Process-group leader (04 §Outputs `sh.exec` "Process-group
    // semantics"): `pgroup = 0` makes this child the leader of a new
    // group whose id equals its own pid.
    command.process_group(0);

    match (&opts.stdin, &opts.stdin_file) {
        (Some(_), _) => {
            command.stdin(Stdio::piped());
        }
        (None, Some(path)) => {
            let file = std::fs::File::open(path)?;
            command.stdin(Stdio::from(file));
        }
        (None, None) => {
            command.stdin(Stdio::null());
        }
    }
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    command.spawn()
}

/// Spawn a dedicated OS thread that reads `pipe` to EOF, accumulating
/// the exact raw bytes (sent once, whole, over `result_tx` at EOF —
/// this is what the `sh.exec` result's `stdout` / `stderr` fields are
/// built from) while also splitting out each complete,
/// newline-terminated line as it arrives and sending it, tagged
/// `stream`, over `line_tx` for the `on_line` callback
/// (04-bridge.md §Outputs `sh.exec` "on_line"). A final unterminated
/// fragment (no trailing `\n`) is still part of the raw accumulation
/// but is not dispatched to `on_line` as a line of its own.
///
/// `mlua::Function` / `mlua::Lua` are not `Send` under this crate's
/// mlua feature set (see [`crate::sandbox::isolation`]'s doc comment),
/// so `on_line` is never called from this thread — only the calling
/// thread (which owns the `Lua` `sh.exec` is running on) invokes it,
/// after receiving each line over `line_tx`.
fn spawn_reader<R: Read + Send + 'static>(
    mut pipe: R,
    stream: &'static str,
    line_tx: mpsc::Sender<(&'static str, String)>,
    result_tx: mpsc::Sender<String>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut raw = Vec::new();
        let mut line_start = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    while let Some(rel_pos) =
                        raw[line_start..].iter().position(|byte| *byte == b'\n')
                    {
                        let line_end = line_start + rel_pos;
                        let line = String::from_utf8_lossy(&raw[line_start..line_end]).into_owned();
                        line_start = line_end + 1;
                        if line_tx.send((stream, line)).is_err() {
                            // The main thread stopped listening (it has
                            // already moved on to the timeout-kill path
                            // and its receive loop exited) — keep
                            // draining the pipe so the child cannot
                            // block on a full pipe buffer, just stop
                            // trying to deliver individual lines.
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = result_tx.send(String::from_utf8_lossy(&raw).into_owned());
    })
}

/// Assign the next global 1-based `lineno` and invoke `on_line`,
/// logging and swallowing any Lua error it raises (04 §Outputs
/// `sh.exec`: "Callback errors are logged and swallowed — they never
/// fail the exec").
fn record_line(stream: &'static str, line: String, on_line: &Option<Function>, lineno: &mut u64) {
    *lineno += 1;
    if let Some(cb) = on_line {
        let call_result: mlua::Result<()> = cb.call((stream, line, *lineno));
        if let Err(err) = call_result {
            tracing::warn!(
                target: "lm_provision::sh_exec",
                "sh.exec on_line callback error (swallowed): {err}"
            );
        }
    }
}

/// After a timeout kill, drain any lines the reader threads had already
/// queued before the signal landed, for up to 200ms — bounded so a
/// stubborn descendant cannot make this hang, generous enough to catch
/// output produced in the brief window between the kill and the pipes
/// actually closing.
fn drain_remaining_lines(
    line_rx: &mpsc::Receiver<(&'static str, String)>,
    on_line: &Option<Function>,
    lineno: &mut u64,
) {
    let drain_deadline = Instant::now() + Duration::from_millis(200);
    loop {
        let now = Instant::now();
        if now >= drain_deadline {
            break;
        }
        match line_rx.recv_timeout(drain_deadline - now) {
            Ok((stream, line)) => record_line(stream, line, on_line, lineno),
            Err(_) => break,
        }
    }
}

/// Poll `child` until it exits or `deadline` passes, returning the exit
/// status only if it exited in time.
fn wait_for_exit_or_deadline(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

/// `status = -1 when killed` (04 §Outputs `sh.exec`); a process that
/// exited via an uncaught signal rather than our own timeout kill has
/// no portable exit code either, so it is reported the same way.
fn exit_code_of(status: ExitStatus) -> i64 {
    status.code().map(|c| c as i64).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::wire_sandboxed_profile;
    use crate::vm::eval::evaluate_profile_source;

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

    #[test]
    fn sh_is_nil_when_sh_exec_capability_is_not_declared() {
        let lua = sandboxed_lua(r#"{ name = "demo" }"#);
        let value: Value = lua.load("return sh").eval().expect("global lookup");
        assert!(
            matches!(value, Value::Nil),
            "register skip: sh must not exist for an undeclared capability"
        );
    }

    #[test]
    fn sh_exec_runs_argv_and_reports_a_zero_exit_status() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let result: Table = lua
            .load(r#"return sh.exec({ "echo", "hi" })"#)
            .eval()
            .expect("sh.exec should be callable for a declared capability");

        assert!(result.get::<bool>("ok").unwrap());
        assert_eq!(result.get::<i64>("status").unwrap(), 0);
        assert_eq!(result.get::<String>("stdout").unwrap(), "hi\n");
        assert!(!result.get::<bool>("dry_run").unwrap());
        assert!(!result.get::<bool>("timed_out").unwrap());
    }

    #[test]
    fn sh_exec_reports_a_non_zero_exit_status_as_not_ok() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let result: Table = lua
            .load(r#"return sh.exec({ "sh", "-c", "exit 7" })"#)
            .eval()
            .expect("sh.exec should evaluate");

        assert!(!result.get::<bool>("ok").unwrap());
        assert_eq!(result.get::<i64>("status").unwrap(), 7);
    }

    #[test]
    fn sh_exec_injects_a_plain_string_env_value_into_the_child() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let result: Table = lua
            .load(r#"return sh.exec({ "sh", "-c", "echo $LM_TEST_PLAIN" }, { env = { LM_TEST_PLAIN = "plain-value" } })"#)
            .eval()
            .expect("sh.exec should evaluate");

        assert!(result.get::<bool>("ok").unwrap());
        assert_eq!(result.get::<String>("stdout").unwrap(), "plain-value\n");
    }

    #[test]
    fn sh_exec_resolves_a_declared_secret_ref_env_value_into_the_child_only() {
        let var_name = format!("LM_PROVISION_TEST_SH_SECRET_{}", std::process::id());
        std::env::set_var(&var_name, "top-secret-value");

        let lua = sandboxed_lua(&format!(
            r#"{{ name = "demo", capabilities = {{ "sh.exec" }}, env_secrets = {{ "{var_name}" }} }}"#
        ));
        let result: Table = lua
            .load(format!(
                r#"return sh.exec({{ "sh", "-c", "printenv {var_name}" }}, {{ env = {{ [{var_name:?}] = env.ref("{var_name}") }} }})"#
            ))
            .eval()
            .expect("sh.exec should evaluate");

        std::env::remove_var(&var_name);

        assert!(result.get::<bool>("ok").unwrap());
        assert_eq!(
            result.get::<String>("stdout").unwrap(),
            "top-secret-value\n",
            "the child process must see the resolved secret value"
        );
        // The result table itself carries no `env` field at all (04
        // §Outputs `sh.exec` "Result"): the resolved value is never
        // handed back to Lua, only into the child's environment.
        assert!(!result.contains_key("env").unwrap());
    }

    #[test]
    fn sh_exec_rejects_an_undeclared_secret_ref_env_value() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let err = lua
            .load(r#"return sh.exec({ "echo", "hi" }, { env = { X = env.ref("UNDECLARED_SECRET") } })"#)
            .eval::<Value>()
            .expect_err("an undeclared secret name must be rejected at consumption");
        assert!(err
            .to_string()
            .contains("secret 'UNDECLARED_SECRET' is not declared in profile.env_secrets"));
    }

    #[test]
    fn sh_exec_fails_fast_when_a_declared_secret_is_missing_from_the_host_env() {
        let var_name = format!("LM_PROVISION_TEST_SH_MISSING_{}", std::process::id());
        std::env::remove_var(&var_name);

        let lua = sandboxed_lua(&format!(
            r#"{{ name = "demo", capabilities = {{ "sh.exec" }}, env_secrets = {{ "{var_name}" }} }}"#
        ));
        let err = lua
            .load(format!(
                r#"return sh.exec({{ "echo", "hi" }}, {{ env = {{ [{var_name:?}] = env.ref("{var_name}") }} }})"#
            ))
            .eval::<Value>()
            .expect_err("a declared-but-absent secret must fail fast");
        assert!(err
            .to_string()
            .contains(&format!("secret '{var_name}' missing in host env")));
    }

    #[test]
    fn sh_exec_dry_run_resolves_secrets_too_and_fails_fast_on_a_missing_one() {
        let var_name = format!("LM_PROVISION_TEST_SH_DRYRUN_MISSING_{}", std::process::id());
        std::env::remove_var(&var_name);

        let lua = sandboxed_lua(&format!(
            r#"{{ name = "demo", capabilities = {{ "sh.exec" }}, env_secrets = {{ "{var_name}" }} }}"#
        ));
        let err = lua
            .load(format!(
                r#"return sh.exec({{ "echo", "hi" }}, {{ dry_run = true, env = {{ [{var_name:?}] = env.ref("{var_name}") }} }})"#
            ))
            .eval::<Value>()
            .expect_err("dry_run must still resolve secrets and fail fast on a missing one (04 §Common conventions)");
        assert!(err
            .to_string()
            .contains(&format!("secret '{var_name}' missing in host env")));
    }

    #[test]
    fn sh_exec_rejects_supplying_both_stdin_and_stdin_file() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let err = lua
            .load(r#"return sh.exec({ "cat" }, { stdin = "a", stdin_file = "/dev/null" })"#)
            .eval::<Value>()
            .expect_err("supplying both stdin and stdin_file must be a Lua error");
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn sh_exec_dry_run_skips_the_effect_but_still_reports_ok() {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-sh-dry-run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let target = dir.join("should-not-exist.txt");

        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let result: Table = lua
            .load(format!(
                r#"return sh.exec({{ "touch", {target:?} }}, {{ dry_run = true }})"#,
                target = target.display().to_string()
            ))
            .eval()
            .expect("sh.exec dry_run should evaluate");

        assert!(result.get::<bool>("ok").unwrap());
        assert!(result.get::<bool>("dry_run").unwrap());
        assert!(
            !target.exists(),
            "dry_run must not perform the effect (04 §Common conventions)"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }

    #[test]
    fn sh_exec_times_out_and_kills_the_process_group_including_a_backgrounded_grandchild() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        let started = Instant::now();
        let result: Table = lua
            .load(
                r#"return sh.exec(
                    { "sh", "-c", "sleep 100 & wait" },
                    { timeout_sec = 0.2, term_grace_sec = 0.2 }
                )"#,
            )
            .eval()
            .expect("sh.exec should evaluate (a timeout is not a Lua error)");
        let elapsed = started.elapsed();

        assert!(result.get::<bool>("timed_out").unwrap());
        assert_eq!(result.get::<i64>("status").unwrap(), -1);
        assert!(!result.get::<bool>("ok").unwrap());
        assert!(
            result
                .get::<String>("stderr")
                .unwrap()
                .contains("timed out after"),
            "04 §Outputs `sh.exec`: stderr must carry the timeout suffix line"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the process-group kill must reach the backgrounded grandchild too, \
             so this call must return well before the grandchild's own 100s sleep: {elapsed:?}"
        );
    }

    #[test]
    fn sh_exec_streams_on_line_in_order_with_a_global_1_based_lineno() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        lua.load(
            r#"
            _G.seen = {}
            function on_line(stream, line, lineno)
                table.insert(_G.seen, { stream = stream, line = line, lineno = lineno })
            end
            "#,
        )
        .exec()
        .expect("install the on_line callback global");

        let result: Table = lua
            .load(r#"return sh.exec({ "printf", "a\nb\nc\n" }, { on_line = on_line })"#)
            .eval()
            .expect("sh.exec should evaluate");
        assert!(result.get::<bool>("ok").unwrap());
        assert_eq!(result.get::<String>("stdout").unwrap(), "a\nb\nc\n");

        let seen: Table = lua.globals().get("seen").expect("seen global");
        assert_eq!(seen.raw_len(), 3);
        for (i, expected_line) in ["a", "b", "c"].iter().enumerate() {
            let entry: Table = seen.get(i + 1).expect("seen entry");
            assert_eq!(entry.get::<String>("stream").unwrap(), "stdout");
            assert_eq!(entry.get::<String>("line").unwrap(), *expected_line);
            assert_eq!(entry.get::<i64>("lineno").unwrap(), (i + 1) as i64);
        }
    }

    #[test]
    fn sh_exec_swallows_an_on_line_callback_error_without_failing_the_exec() {
        let lua = sandboxed_lua(r#"{ name = "demo", capabilities = { "sh.exec" } }"#);
        lua.load(
            r#"
            function on_line_error(_stream, _line, _lineno)
                error("boom from on_line")
            end
            "#,
        )
        .exec()
        .expect("install the erroring on_line callback global");

        let result: Table = lua
            .load(r#"return sh.exec({ "echo", "hi" }, { on_line = on_line_error })"#)
            .eval()
            .expect("a callback error must be swallowed, not propagated (04 §Outputs `sh.exec`)");

        assert!(result.get::<bool>("ok").unwrap());
        assert_eq!(result.get::<String>("stdout").unwrap(), "hi\n");
    }
}
