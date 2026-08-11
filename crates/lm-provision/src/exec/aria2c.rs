//! The `aria2c` download route — one weight split across many
//! connections, with progress read back over aria2c's JSON-RPC.
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
//! # One daemon per transfer
//!
//! The plan proposed a daemon shared by the (up to `MAX_CONCURRENT_STEPS`)
//! transfers in flight. This does the opposite, because the sharing buys
//! almost nothing and costs the hard part: a shared daemon needs a
//! registry, a refcount deciding when it may exit, a port and secret
//! threaded down to each call site, and a gid to tell whose bytes are
//! whose. A daemon per transfer has none of those — `tellActive` returns
//! exactly one download, so there is nothing to disambiguate — and the
//! thing it wastes is one process spawn against a multi-gigabyte
//! download.

use std::io::ErrorKind;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
/// because a freshly pulled image can have empty package lists.)
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
/// controls. `--split` caps the pieces and `--max-connection-per-server`
/// caps the connections; both are set because a lower
/// `max-connection-per-server` silently clamps a higher `split`.
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
/// Reports carry `finished: false` until the process exits, then one
/// final `finished: true` with the size the file actually reached —
/// the same shape and the same ordering the in-process route produces,
/// because [`super::audit::TransferTranscript`] reads both.
///
/// A non-zero exit is an **error, not a fallback**. By then aria2c has
/// resolved the URL and tried; failing there is the download failing,
/// and retrying it in-process would only hide which route is broken.
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
        .args(argv(url, &dir.to_string_lossy(), &name, port, &secret))
        .stdin(Stdio::null())
        // aria2c's own summary is the display this route is avoiding;
        // the transcript is the transfer's voice.
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| match err.kind() {
            ErrorKind::NotFound => failed(format!("'{BIN}' is not on PATH")),
            _ => failed(format!("spawn '{BIN}': {err}")),
        })?;

    let outcome = watch(&mut child, port, &secret, progress).await;

    // Whatever happened, the daemon does not outlive this call. A poll
    // that failed or a caller that went away must not leave a process
    // holding a port and writing to a file nobody is waiting for.
    if outcome.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return outcome.map(|_| unreachable!());
    }

    let status = child
        .wait()
        .map_err(|err| failed(format!("wait for '{BIN}': {err}")))?;
    if !status.success() {
        let code = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(failed(format!("'{BIN}' exited with status {code}")));
    }

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

/// Poll the daemon until the child exits, offering the transcript a
/// report each time.
///
/// The child is checked **before** the RPC on each turn so a download
/// that finished between two polls is not asked about a daemon that has
/// already shut down.
async fn watch(
    child: &mut Child,
    port: u16,
    secret: &str,
    progress: ProgressSink<'_>,
) -> Result<(), ExecError> {
    let client = reqwest::Client::builder()
        .timeout(RPC_TIMEOUT)
        .build()
        .map_err(|err| failed(format!("build the RPC client: {err}")))?;
    let endpoint = format!("http://127.0.0.1:{port}/jsonrpc");

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(err) => return Err(failed(format!("poll '{BIN}': {err}"))),
        }

        // A failed poll is not a failed transfer. The daemon may not
        // have bound its port yet on the first turn, and a dropped
        // round trip costs one report out of a cadence that tolerates
        // gaps by construction.
        if let Some((written, total)) = poll(&client, &endpoint, secret).await {
            progress(TransferProgress {
                written,
                total,
                finished: false,
            });
        }
    }
}

/// One `aria2.tellActive`, reduced to the two numbers the transcript
/// needs. `None` when the daemon could not be reached or said nothing
/// useful.
///
/// `totalLength` is `0` while aria2c has not yet learned the size, and
/// that is reported as "no declared total" rather than as zero — the
/// same thing a supplier without `Content-Length` produces on the
/// in-process route, so the consumer sees one shape.
async fn poll(
    client: &reqwest::Client,
    endpoint: &str,
    secret: &str,
) -> Option<(u64, Option<u64>)> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "lm-provision",
        "method": "aria2.tellActive",
        "params": [
            format!("token:{secret}"),
            ["completedLength", "totalLength"],
        ],
    });

    // Serialised here rather than through `reqwest`'s `json` feature:
    // this is the only JSON request body in the crate, and a feature
    // flag carried for one call site is a dependency surface without a
    // second reader.
    let text = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).ok()?)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;

    let entry = value.get("result")?.as_array()?.first()?;
    let written = number(entry.get("completedLength")?)?;
    let total = entry
        .get("totalLength")
        .and_then(number)
        .filter(|it| *it > 0);
    Some((written, total))
}

/// aria2c reports byte counts as decimal **strings**, since they can
/// exceed what a JSON number is guaranteed to carry.
fn number(value: &serde_json::Value) -> Option<u64> {
    value.as_str()?.parse().ok()
}

/// The command line, as its own function so a test can read it without
/// a daemon.
fn argv(url: &str, dir: &str, name: &str, port: u16, secret: &str) -> Vec<String> {
    vec![
        "--enable-rpc".to_string(),
        format!("--rpc-listen-port={port}"),
        format!("--rpc-secret={secret}"),
        // The daemon exists to be asked one question by this process.
        // Binding it wider would put it on the pod's network for the
        // length of the transfer.
        "--rpc-listen-all=false".to_string(),
        format!("--split={SPLIT}"),
        format!("--max-connection-per-server={SPLIT}"),
        format!("--min-split-size={MIN_SPLIT_SIZE}"),
        // Resume a partial file rather than restarting it, which is what
        // makes a re-applied profile cheap after an interrupted run.
        "--continue=true".to_string(),
        "--auto-file-renaming=false".to_string(),
        "--allow-overwrite=true".to_string(),
        // aria2c exits when the download it was given is done; without
        // this the RPC daemon keeps it alive forever.
        format!("--stop-with-process={}", std::process::id()),
        // The console summary is the display this route does not read.
        "--summary-interval=0".to_string(),
        "--console-log-level=warn".to_string(),
        format!("--dir={dir}"),
        format!("--out={name}"),
        url.to_string(),
    ]
}

/// Split a destination into the directory aria2c writes into and the
/// name it writes, which is how `--dir` / `--out` want it.
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
/// than rarely. A daemon that cannot bind fails loudly at spawn.
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

    fn rendered() -> Vec<String> {
        argv(
            "https://example.test/w.safetensors",
            "/root/models",
            "w.safetensors",
            6800,
            "deadbeef",
        )
    }

    #[test]
    fn argv_splits_one_file_across_connections() {
        let argv = rendered();
        assert!(argv.contains(&format!("--split={SPLIT}")));
        assert!(argv.contains(&format!("--max-connection-per-server={SPLIT}")));
    }

    #[test]
    fn argv_enables_rpc_on_the_chosen_port_behind_a_secret() {
        let argv = rendered();
        assert!(argv.contains(&"--enable-rpc".to_string()));
        assert!(argv.contains(&"--rpc-listen-port=6800".to_string()));
        assert!(argv.contains(&"--rpc-secret=deadbeef".to_string()));
        assert!(argv.contains(&"--rpc-listen-all=false".to_string()));
    }

    #[test]
    fn argv_writes_the_destination_the_caller_asked_for() {
        let argv = rendered();
        assert!(argv.contains(&"--dir=/root/models".to_string()));
        assert!(argv.contains(&"--out=w.safetensors".to_string()));
        assert_eq!(argv.last().unwrap(), "https://example.test/w.safetensors");
    }

    #[test]
    fn argv_resumes_rather_than_restarting() {
        assert!(rendered().contains(&"--continue=true".to_string()));
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
