//! The `aria2c` download route — one weight split across many
//! connections, with progress read back over aria2c's JSON-RPC.
//!
//! # UNREACHABLE — kept pending a decision, not in service
//!
//! **Nothing calls this.** [`super::chunked`] landed after it and takes
//! every transfer whose supplier serves ranges, which is the only kind
//! of supplier aria2c could have split anyway. What is left for this
//! route is suppliers that refuse ranges — against which it is a
//! single connection, exactly like the in-process stream, with a
//! package install and an RPC daemon in front of it.
//!
//! **It is not broken in general — it is broken against HuggingFace.**
//! aria2c resolves the redirect once and splits against the result,
//! which is exactly right for a supplier whose signed URL is not scoped
//! to a range. CivitAI is one: its R2 presign covers only the host
//! (`X-Amz-SignedHeaders=host`), so one resolved URL serves any range
//! for its 24-hour life [実測: 2026-08-11, three disjoint ranges of a
//! 2.13 GB model on one resolved URL, all `206`]. That is where the 28x
//! this route was built for was measured, and there is no reason to
//! doubt it. HuggingFace is the exception, and it is also the supplier
//! most of these profiles name.
//!
//! `chunked` covers both, because never reusing a resolved location is
//! correct everywhere and merely unnecessary where reuse would also
//! have worked.
//!
//! So this module is a deletion waiting for a decision, not a fallback.
//! It is still here because removing a route two commits after adding
//! it is the kind of change that should be asked about rather than
//! slipped in.
//!
//! # Why a second route at all
//!
//! A pod is billed for as long as it is up, so a transfer that takes 25
//! minutes is 25 minutes paid for provisioning that produced nothing.
//! Splitting one file across 16 connections took that 25 minutes to 54
//! seconds on the reference workload — $33.0 to $12.9 per shoot
//! [gravure_2609 report §5.2 / §5.3].
//!
//! That is a **different axis** from the parallelism already in
//! `exec::apply`: `MAX_CONCURRENT_STEPS` decides how many files move
//! at once, and `--split` decides how many connections carry one file.
//! Neither substitutes for the other, which is why the 16 here is not a
//! number borrowed from that constant's doc.
//!
//! **Measured here, splitting is worth roughly 2-3x, not 28x** — 293 s
//! on one connection against 64-148 s on four or more, for the same
//! 4.27 GB file [実測: 2026-08-11,
//! `workspace/tasks/aria2c-bench/results.md`]. The reference's 25
//! minutes implies single-digit MB/s at its other end, and a ratio
//! describes both of its ends.
//!
//! **The 64-148 s is not a range across settings — it is the spread at
//! *fixed* settings.** Seven runs of the same file on the same pod with
//! `split` at 8 or 16 landed anywhere in it, which is wider than any
//! difference between those two values. So: splitting beats not
//! splitting by a margin far outside that noise, and **which** split
//! count is best is not something this data can say. 16 stays because
//! nothing here argues it down, not because it was shown to win.
//!
//! # Why the gain is 2-3x and not 16x
//!
//! HuggingFace's CDN hands out presigned URLs whose policy **pins a byte
//! range** (`"ByteRange":{"ExpectedHeader":"bytes=3732930560-..."}`), and
//! aria2c resolves the redirect once and reuses that URL for every
//! split. Connections asking for other ranges are refused, and the count
//! of refusals is exactly `split - 1`, every run: 3 at `--split=4`, 7 at
//! 8, 15 at 16 [実測: same runs]. Watched live, the transfer opens 16
//! connections, peaks near 212 MB/s, then **collapses to one** as the
//! refusals land and crawls the remainder.
//!
//! So the split is real and it does help, but against this supplier it
//! is a fast opening rather than sixteen sustained streams. A route that
//! held all of them would have to re-resolve the redirect per range —
//! which is what HuggingFace's own `hf_transfer` does, and is the shape
//! to reach for if this ever needs to be faster.
//!
//! # What stays the same
//!
//! **The transcript is route-invariant.** Progress cadence — the first
//! report, then one every [`super::audit::TRANSFER_PROGRESS_INTERVAL_SEC`],
//! then the finished one — lives in [`super::audit::TransferTranscript`],
//! not in the transfer. This module's job is only to *produce*
//! [`TransferProgress`] reports at a rate the transcript can thin; the
//! decision about which of them is news is made in the same place for
//! both routes. A consumer cannot tell from the event stream which route
//! carried the bytes, and that is the point.
//!
//! # Where the numbers come from
//!
//! aria2c offers three ways to be watched and only one of them is a
//! contract:
//!
//! - the console summary (`[#2089b0 400.0KiB/33.2MiB(1%) ...]`) is
//!   human-formatted, unit-abbreviated and redrawn over itself with
//!   `\r` — scraping it means parsing a display,
//! - `--on-download-complete` and the WebSocket notifications fire on
//!   completion, which is too late to be progress,
//! - **`aria2.tellStatus` over JSON-RPC** returns `completedLength` and
//!   `totalLength` as integers.
//!
//! So the daemon goes up with `--enable-rpc` and this polls it.
//! `aria2.getFiles` also has a `completedLength`, and it is **not** the
//! same number: it counts only whole completed pieces, while
//! `tellStatus` includes the partial one. The one that moves smoothly is
//! `tellStatus`.
//!
//! # The daemon is driven, not watched
//!
//! The URL is handed over with `aria2.addUri` rather than written on the
//! command line, and that is the correction of a bug this module shipped
//! with. Passing the URL as an argument makes the obvious completion
//! signal the process exiting — but `--enable-rpc` turns aria2c into a
//! server, and **a server does not exit when its queue empties**. On a
//! real pod that read as: the file downloaded correctly and quickly, and
//! then the transfer hung forever waiting for a process that was, by
//! design, waiting for it [実測: 2026-08-11, pod rp28mal23gofv9 — 4.27 GB
//! complete on disk, aria2c and its caller both alive 10 minutes later].
//!
//! `addUri` returns a gid, which is a *handle on this download*.
//! `tellStatus(gid)` then answers for it whether it is active, waiting or
//! finished, so completion is read from the download rather than inferred
//! from the process — and `aria2.shutdown` ends the daemon when its one
//! job is done. It also closes a race the argv form could not: a download
//! that finishes between two polls never appears in `tellActive`, and
//! nothing in that reading distinguishes "not started" from "already
//! done".
//!
//! # One daemon per transfer
//!
//! The plan proposed a daemon shared by the (up to `MAX_CONCURRENT_STEPS`)
//! transfers in flight. This does the opposite, because the sharing buys
//! almost nothing and costs the hard part: a shared daemon needs a
//! registry, a refcount deciding when it may exit, a port and secret
//! threaded down to each call site, and — since one daemon would hold
//! several gids — a way to tell whose bytes are whose. A daemon per
//! transfer has none of those, and the thing it wastes is one process
//! spawn against a multi-gigabyte download.

use std::io::ErrorKind;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::effects::{ProgressSink, TransferOutcome, TransferProgress};
use super::ExecError;

/// The binary this route needs on `PATH`.
///
/// **Nothing here installs it.** The route is chosen per transfer by
/// asking whether it resolves ([`available`]), and a pod without it
/// takes the in-process route with a line saying so. Acquiring it is a
/// profile's decision, spelled with the phase that already runs
/// commands:
///
/// ```text
/// sh.exec { "apt-get update -qq && apt-get install -y -qq aria2" }
/// ```
///
/// (the binary is `aria2c`, the package is `aria2`; `update` first
/// because a freshly pulled image can have empty package lists. That
/// line takes about eight seconds on a stock pytorch image
/// [実測: 2026-08-11, Ubuntu 22.04.5, aria2 1.36.0, 7.7 s].)
///
/// Composing that install into `models` was tried and reverted — see
/// `lifecycle::cli_install_command` for why.
pub const BIN: &str = "aria2c";

/// Connections opened against one server for one file, and the number of
/// pieces that file is split into.
///
/// 16 is the reference workload's figure and it transfers to here
/// unchanged: it is a count of connections per file, measured on
/// per-file transfer time, which is exactly the quantity this route
/// controls. `split` caps the pieces and `max-connection-per-server`
/// caps the connections; both are set because a lower
/// `max-connection-per-server` silently clamps a higher `split`.
///
/// **It is not tuned, and one attempt to tune it failed to say
/// anything.** A sweep over 1 / 4 / 8 / 16 put 8 well ahead of 16 (103 s
/// against 148 s); repeating just those two put them level and then
/// reversed them (101 / 140 for 8, 99 / 64 for 16). Every value above 1
/// beat 1 by a wide margin, and nothing separated the values above 1
/// from each other [実測: 2026-08-11,
/// `workspace/tasks/aria2c-bench/results.md`]. Picking a new constant
/// off the first of those passes would have been reading noise.
const SPLIT: &str = "16";

/// The smallest piece aria2c will cut. Below this it declines to split
/// further, which keeps a small file from being carved into 16 requests
/// that each cost more in setup than they carry.
const MIN_SPLIT_SIZE: &str = "1M";

/// How often the RPC is asked where the download is.
///
/// This is **not** the transcript's cadence and does not replace it. The
/// transcript still emits at
/// [`super::audit::TRANSFER_PROGRESS_INTERVAL_SEC`]; this is the rate at
/// which it is *offered* something to emit, and it has to be well under
/// that interval or the cadence degrades to this one. A localhost POST
/// per second against a transfer measured in minutes is not a cost worth
/// tuning.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Deadline for one JSON-RPC round trip to a daemon on loopback.
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the daemon has to answer its first request before this gives
/// up on it.
///
/// Binding a port and opening a listener is sub-second work; this is
/// slack for a loaded pod, not a budget anything is expected to use. It
/// is bounded because the alternative to a deadline here is a transfer
/// that hangs when the daemon never comes up, which is the failure this
/// module already shipped once.
const RPC_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Distinguishes the RPC secrets of daemons started in the same
/// nanosecond, which two concurrent transfers can be.
static SECRET_SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether `aria2c` resolves on `PATH`.
///
/// This is the same question [`super::assert::Assert::CommandOnPath`]
/// asks of a CLI entity, asked here for a route rather than for a step's
/// condition: absence means fall back, not fail, so it cannot be an
/// assertion.
pub fn available() -> bool {
    Command::new(BIN)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// GET `url` into `dst` with `aria2c`, reporting to `progress`.
///
/// Reports carry `finished: false` while the download runs, then one
/// final `finished: true` with the size the file actually reached — the
/// same shape and the same ordering the in-process route produces,
/// because [`super::audit::TransferTranscript`] reads both.
///
/// A download that ends in `error` is an **error, not a fallback**. By
/// then aria2c has resolved the URL and tried; failing there is the
/// download failing, and retrying it in-process would only hide which
/// route is broken.
pub async fn download(
    url: &str,
    dst: &str,
    progress: ProgressSink<'_>,
) -> Result<TransferOutcome, ExecError> {
    let (dir, name) = split_dst(dst)?;
    if !dir.as_os_str().is_empty() {
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| failed(format!("create parent of '{dst}': {err}")))?;
    }

    let port = free_port()?;
    let secret = secret();

    let mut child = Command::new(BIN)
        .args(daemon_argv(port, &secret))
        .stdin(Stdio::null())
        // aria2c's own summary is the display this route is avoiding;
        // the transcript is the transfer's voice.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| match err.kind() {
            ErrorKind::NotFound => failed(format!("'{BIN}' is not on PATH")),
            _ => failed(format!("spawn '{BIN}': {err}")),
        })?;

    let driven = drive(
        &mut child,
        port,
        &secret,
        url,
        &dir.to_string_lossy(),
        &name,
        progress,
    )
    .await;

    // The daemon does not outlive this call on any path. It is asked to
    // stop first so it can flush its control file, and killed if it does
    // not — a leftover holding a port and a half-written file is the
    // worst of the states this can end in.
    stop(&mut child, port, &secret).await;

    driven?;

    let bytes = tokio::fs::metadata(dst)
        .await
        .map_err(|err| failed(format!("stat '{dst}' after transfer: {err}")))?
        .len();

    progress(TransferProgress {
        written: bytes,
        total: Some(bytes),
        finished: true,
    });

    Ok(TransferOutcome {
        bytes,
        dst: dst.to_string(),
    })
}

/// Wait for the daemon, hand it the download, and follow that one gid to
/// a terminal state.
async fn drive(
    child: &mut Child,
    port: u16,
    secret: &str,
    url: &str,
    dir: &str,
    name: &str,
    progress: ProgressSink<'_>,
) -> Result<(), ExecError> {
    let client = reqwest::Client::builder()
        .timeout(RPC_TIMEOUT)
        // The daemon is on loopback. A proxy configured for the outside
        // world has no business between this process and its own child,
        // and honouring one here would route a localhost call into
        // whatever the environment happens to name.
        .no_proxy()
        .build()
        .map_err(|err| failed(format!("build the RPC client: {err}")))?;
    let endpoint = format!("http://127.0.0.1:{port}/jsonrpc");

    await_daemon(&client, &endpoint, secret, child).await?;

    let gid = rpc(
        &client,
        &endpoint,
        secret,
        "aria2.addUri",
        vec![
            serde_json::json!([url]),
            serde_json::json!({
                "dir": dir,
                "out": name,
                "split": SPLIT,
                "max-connection-per-server": SPLIT,
                "min-split-size": MIN_SPLIT_SIZE,
                // Resume a partial file rather than restarting it, which
                // is what makes a re-applied profile cheap after an
                // interrupted run.
                "continue": "true",
                "allow-overwrite": "true",
                "auto-file-renaming": "false",
            }),
        ],
    )
    .await
    .map_err(|err| failed(format!("hand the download to '{BIN}': {err}")))?;
    let gid = gid
        .as_str()
        .ok_or_else(|| failed(format!("'{BIN}' returned no download id")))?
        .to_string();

    let mut warned = false;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        // A daemon that died takes its answer with it, and waiting out
        // the transfer for one that will never reply is the hang this
        // module is the correction of.
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(failed(format!(
                    "'{BIN}' exited during the transfer with status {}",
                    status
                        .code()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "signal".to_string())
                )));
            }
            Ok(None) => {}
            Err(err) => return Err(failed(format!("poll '{BIN}': {err}"))),
        }

        match status_of(&client, &endpoint, secret, &gid).await {
            Ok(status) => {
                progress(TransferProgress {
                    written: status.completed,
                    total: status.total,
                    finished: false,
                });
                match status.state.as_str() {
                    "complete" => return Ok(()),
                    "error" => {
                        return Err(failed(format!(
                            "'{BIN}' reported the download failed: {}",
                            status.message.as_deref().unwrap_or("no reason given")
                        )));
                    }
                    "removed" | "paused" => {
                        return Err(failed(format!(
                            "'{BIN}' left the download {}",
                            status.state
                        )));
                    }
                    _ => {}
                }
            }
            // A dropped round trip costs one report out of a cadence
            // built to tolerate gaps, so it does not end the transfer.
            // It is said out loud once, though: the first version of
            // this module swallowed these, and a transfer whose progress
            // had silently stopped being read looked exactly like one
            // that was merely slow.
            Err(err) => {
                if !warned {
                    warned = true;
                    tracing::warn!(
                        op = "net.transfer.progress",
                        route = "aria2c",
                        reason = err.as_str(),
                        "progress is degraded: the transfer continues, its reporting does not"
                    );
                }
            }
        }
    }
}

/// Poll `aria2.getVersion` until the daemon answers.
///
/// Any answer will do — this asks whether the server is listening and
/// whether this process's token is the one it wants, and getting that
/// wrong is worth knowing before a multi-gigabyte transfer rather than
/// after it.
async fn await_daemon(
    client: &reqwest::Client,
    endpoint: &str,
    secret: &str,
    child: &mut Child,
) -> Result<(), ExecError> {
    let deadline = Instant::now() + RPC_STARTUP_TIMEOUT;
    loop {
        // Kept for the deadline message: giving up is worth reporting
        // with the last reason it was still refusing, since "did not
        // answer" and "answered Unauthorized" are different bugs.
        let last = match rpc(client, endpoint, secret, "aria2.getVersion", vec![]).await {
            Ok(_) => return Ok(()),
            Err(err) => err,
        };
        if let Ok(Some(status)) = child.try_wait() {
            return Err(failed(format!(
                "'{BIN}' exited before accepting a download, with status {}",
                status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string())
            )));
        }
        if Instant::now() >= deadline {
            return Err(failed(format!(
                "'{BIN}' did not answer its RPC within {} s: {last}",
                RPC_STARTUP_TIMEOUT.as_secs()
            )));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// What `aria2.tellStatus` says about one download.
struct Status {
    /// Bytes written so far, partial piece included.
    completed: u64,
    /// The declared size, absent until aria2c has learned it.
    ///
    /// aria2c reports `0` before it knows, and that is passed on as "no
    /// declared total" rather than as zero — the same thing a supplier
    /// without `Content-Length` produces on the in-process route, so the
    /// consumer sees one shape.
    total: Option<u64>,
    /// `active` / `waiting` / `paused` / `error` / `complete` / `removed`.
    state: String,
    /// Why, when `state` is `error`.
    message: Option<String>,
}

/// One `aria2.tellStatus` for `gid`, reduced to what the transfer needs.
async fn status_of(
    client: &reqwest::Client,
    endpoint: &str,
    secret: &str,
    gid: &str,
) -> Result<Status, String> {
    let value = rpc(
        client,
        endpoint,
        secret,
        "aria2.tellStatus",
        vec![
            serde_json::json!(gid),
            serde_json::json!(["status", "completedLength", "totalLength", "errorMessage"]),
        ],
    )
    .await?;

    Ok(Status {
        completed: value
            .get("completedLength")
            .and_then(number)
            .ok_or("tellStatus returned no completedLength")?,
        total: value
            .get("totalLength")
            .and_then(number)
            .filter(|it| *it > 0),
        state: value
            .get("status")
            .and_then(|it| it.as_str())
            .ok_or("tellStatus returned no status")?
            .to_string(),
        message: value
            .get("errorMessage")
            .and_then(|it| it.as_str())
            .map(|it| it.to_string()),
    })
}

/// Ask the daemon to stop, then make sure it did.
///
/// Best effort throughout: this runs on the failure paths too, where the
/// daemon may already be gone or may never have answered, and a problem
/// shutting it down must not replace the error that got us here.
async fn stop(child: &mut Child, port: u16, secret: &str) {
    if let Ok(client) = reqwest::Client::builder()
        .timeout(RPC_TIMEOUT)
        .no_proxy()
        .build()
    {
        let endpoint = format!("http://127.0.0.1:{port}/jsonrpc");
        let _ = rpc(&client, &endpoint, secret, "aria2.shutdown", vec![]).await;
    }

    let deadline = Instant::now() + RPC_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// One JSON-RPC call, returning the `result` member.
///
/// The token is prepended to `params` here rather than at every call
/// site, since every method this module uses takes it first and
/// forgetting it reads as `Unauthorized` rather than as a mistake.
///
/// Errors come back as strings because every caller either reports them
/// verbatim or ignores them; none branches on the kind.
async fn rpc(
    client: &reqwest::Client,
    endpoint: &str,
    secret: &str,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let mut full = Vec::with_capacity(params.len() + 1);
    full.push(serde_json::json!(format!("token:{secret}")));
    full.extend(params);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "lm-provision",
        "method": method,
        "params": full,
    });

    // Serialised here rather than through `reqwest`'s `json` feature:
    // this is the only JSON request body in the crate, and a feature
    // flag carried for one call site is a dependency surface without a
    // second reader.
    let text = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).map_err(|err| err.to_string())?)
        .send()
        .await
        .map_err(|err| format!("{method}: {err}"))?
        .text()
        .await
        .map_err(|err| format!("{method}: reading the reply: {err}"))?;

    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|err| format!("{method}: {err}"))?;
    if let Some(error) = value.get("error") {
        let message = error
            .get("message")
            .and_then(|it| it.as_str())
            .unwrap_or("no message");
        return Err(format!("{method}: {message}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: the reply carried no result"))
}

/// aria2c reports byte counts as decimal **strings**, since they can
/// exceed what a JSON number is guaranteed to carry.
fn number(value: &serde_json::Value) -> Option<u64> {
    value.as_str()?.parse().ok()
}

/// The daemon's command line — **no URL**. What to download arrives over
/// the RPC, so that this process holds a gid for it.
fn daemon_argv(port: u16, secret: &str) -> Vec<String> {
    vec![
        "--enable-rpc".to_string(),
        format!("--rpc-listen-port={port}"),
        format!("--rpc-secret={secret}"),
        // The daemon exists to be asked by this process. Binding it
        // wider would put it on the pod's network for the length of the
        // transfer.
        "--rpc-listen-all=false".to_string(),
        // A backstop, not the shutdown path: `aria2.shutdown` ends it in
        // the normal case, and this is what keeps a daemon from
        // outliving a caller that was killed before it could ask.
        format!("--stop-with-process={}", std::process::id()),
        // The console summary is the display this route does not read.
        "--summary-interval=0".to_string(),
        "--console-log-level=warn".to_string(),
    ]
}

/// Split a destination into the directory aria2c writes into and the
/// name it writes, which is how its `dir` / `out` options want it.
fn split_dst(dst: &str) -> Result<(std::path::PathBuf, String), ExecError> {
    let path = Path::new(dst);
    let name = path
        .file_name()
        .ok_or_else(|| failed(format!("destination '{dst}' has no file name")))?
        .to_string_lossy()
        .into_owned();
    let dir = path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    Ok((dir, name))
}

/// A port the daemon can bind.
///
/// Asking the OS for one and letting go of it leaves a window in which
/// something else could take it; the alternative is a fixed port, which
/// collides with the concurrent transfer next to it every time rather
/// than rarely. A daemon that cannot bind is caught by
/// [`await_daemon`] rather than waited on forever.
fn free_port() -> Result<u16, ExecError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|err| failed(format!("find a free RPC port: {err}")))?;
    let port = listener
        .local_addr()
        .map_err(|err| failed(format!("read the RPC port: {err}")))?
        .port();
    Ok(port)
}

/// A token for this daemon's RPC.
///
/// The daemon listens on loopback only, but loopback on a pod is shared
/// with everything else running there, so it is not left open. This is
/// **not** a spec 06 secret: no profile declares it and nothing outside
/// this process ever sees it, so it is not something to resolve or
/// redact — it is a per-daemon nonce, and the sequence number is what
/// keeps two daemons started in the same nanosecond apart.
fn secret() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|it| it.as_nanos())
        .unwrap_or(0);
    let seq = SECRET_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}{:x}{seq:x}", std::process::id())
}

/// This route's errors all carry the same op, since the caller asked for
/// a transfer and does not need to have heard of aria2c to read them.
fn failed(message: String) -> ExecError {
    ExecError::EffectFailed {
        op: "net_transfer".to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_is_started_with_no_url() {
        // The bug this shape corrects: with the URL on the command line,
        // the only completion signal is the process exiting, and
        // `--enable-rpc` is exactly the flag that stops it from doing
        // that when the download is done.
        let argv = daemon_argv(6800, "deadbeef");
        assert!(
            !argv.iter().any(|arg| arg.contains("://")),
            "no URL belongs on the daemon's command line: {argv:?}"
        );
        assert!(!argv.iter().any(|arg| arg.starts_with("--dir=")));
        assert!(!argv.iter().any(|arg| arg.starts_with("--out=")));
    }

    #[test]
    fn the_daemon_listens_on_the_chosen_port_behind_a_secret() {
        let argv = daemon_argv(6800, "deadbeef");
        assert!(argv.contains(&"--enable-rpc".to_string()));
        assert!(argv.contains(&"--rpc-listen-port=6800".to_string()));
        assert!(argv.contains(&"--rpc-secret=deadbeef".to_string()));
        assert!(argv.contains(&"--rpc-listen-all=false".to_string()));
    }

    #[test]
    fn the_daemon_does_not_outlive_a_killed_caller() {
        let argv = daemon_argv(6800, "deadbeef");
        assert!(argv
            .iter()
            .any(|arg| arg.starts_with("--stop-with-process=")));
    }

    #[test]
    fn split_dst_separates_the_directory_from_the_name() {
        let (dir, name) = split_dst("/root/models/checkpoints/w.safetensors").unwrap();
        assert_eq!(dir.to_string_lossy(), "/root/models/checkpoints");
        assert_eq!(name, "w.safetensors");
    }

    #[test]
    fn split_dst_rejects_a_destination_that_names_no_file() {
        // A trailing slash is *not* one of these: `Path` normalises it
        // away, so `/root/models/` names `models` in `/root` — which is
        // what the in-process route would write too.
        assert!(split_dst("/").is_err());
        assert!(split_dst("").is_err());
        assert!(split_dst("..").is_err());
    }

    #[test]
    fn secrets_differ_between_daemons() {
        assert_ne!(secret(), secret());
    }

    #[test]
    fn byte_counts_are_read_from_aria2cs_decimal_strings() {
        assert_eq!(number(&serde_json::json!("3221225472")), Some(3221225472));
        // A JSON number is what aria2c does not send, and reading one
        // anyway would mean guessing at a shape that never arrives.
        assert_eq!(number(&serde_json::json!(12)), None);
    }
}
