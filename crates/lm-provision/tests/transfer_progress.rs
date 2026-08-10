//! The stderr audit transcript's `net.transfer.progress` events
//! (09-apply-report-and-ledger.md §Audit log), end to end.
//!
//! Two things need proving in different places, so they are proved in
//! different ways:
//!
//! - **What a driver actually reads.** The events must appear on the
//!   real binary's stderr, at the default log level, in plain text —
//!   so those tests run `lm-provision apply` as a process and read the
//!   pipe. Nothing in-process can stand in for that: a captured
//!   subscriber would prove the event was emitted, not that it left the
//!   program.
//! - **What four at once looks like.** The concurrency lives in a
//!   `models` phase, whose destinations are composed under the built-in
//!   `/workspace/ComfyUI/models` root that a test cannot create — so a
//!   four-way interleave is driven at the effect layer instead, with
//!   the report ids (`1_models_<n>`) a `models` phase assigns. That the
//!   phase assigns exactly those ids is
//!   `ast_apply::a_parallel_phase_reports_every_entry_once_in_declaration_order`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::Command;
use serde_json::{json, Value};

/// A unique temp path stem for this process + call.
fn temp_stem(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lm-provision-progress-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

/// A server that dribbles `chunks` pieces of `piece` bytes with `gap`
/// between them, so a transfer lasts long enough to be reported on more
/// than once.
fn trickle_server(
    chunks: usize,
    piece: usize,
    gap: Duration,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            chunks * piece
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.flush();
        for _ in 0..chunks {
            std::thread::sleep(gap);
            let _ = stream.write_all(&vec![b'x'; piece]);
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

/// A one-phase `net.transfer` profile fetching `base_url/weight.bin`
/// into `dst`, written to a fresh `.json` file.
fn transfer_profile(label: &str, base_url: &str, dir: &str, dst: &str) -> PathBuf {
    let profile = json!({
        "type": "Spec",
        "name": format!("progress-{label}"),
        "capabilities": ["net.transfer"],
        "paths": [dir],
        "http_allowlist": [base_url],
        "phases": [
            { "type": "NetTransfer", "src": format!("{base_url}/weight.bin"), "dst": dst }
        ]
    });
    let path = temp_stem(label).with_extension("json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&profile).expect("profile serializes"),
    )
    .expect("write temp profile");
    path
}

/// Lines of `stderr` that are progress events.
fn progress_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.contains("op=\"net.transfer.progress\""))
        .collect()
}

// ---------------------------------------------------------------------
// Through the binary: what the spec-08 driver captures.
// ---------------------------------------------------------------------

/// A real `apply` prints progress for its transfer, at the default log
/// level, on stderr, without ANSI — which is the whole contract with a
/// driver reading the pipe.
#[test]
fn apply_prints_transfer_progress_on_stderr() {
    let (base_url, server) = trickle_server(4, 4096, Duration::from_millis(60));

    let dir = temp_stem("bin-real");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let dst = dir.join("weight.bin");
    let path = transfer_profile(
        "bin-real",
        &base_url,
        &dir.to_string_lossy(),
        &dst.to_string_lossy(),
    );

    let output = Command::cargo_bin("lm-provision")
        .expect("lm-provision binary should build")
        .args(["apply", path.to_str().expect("utf8 path")])
        .output()
        .expect("process should run");
    server.join().expect("server thread joins");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let events = progress_lines(&stderr);
    assert!(
        !events.is_empty(),
        "a transfer that took a quarter of a second said nothing:\n{stderr}"
    );
    assert!(
        events
            .iter()
            .all(|line| line.contains("step=\"1_net.transfer\"")),
        "every event names the step whose report id it shares:\n{stderr}"
    );
    assert!(
        events
            .iter()
            .any(|line| line.contains("state=\"done\"")
                && line.contains(&format!("bytes={}", 4 * 4096))),
        "the closing event carries the byte count the report carries:\n{stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "a captured pipe gets plain text, never an escape sequence:\n{stderr}"
    );
    assert!(
        !stderr.contains('\r'),
        "an append-only event stream never redraws a line:\n{stderr}"
    );

    // …and the run itself succeeded, so the events describe a real
    // transfer rather than a failure path.
    let report: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("report is JSON");
    assert_eq!(report["ok"], json!(true), "{report}");

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// A dry run prints none: there is no transfer, so there is no progress
/// to have. Nothing suppresses the events — the byte loop that writes
/// them never runs.
#[test]
fn a_dry_run_prints_no_transfer_progress() {
    // The server is never contacted; the profile only has to name a
    // reachable-looking URL for the dry run to describe.
    let dir = temp_stem("bin-dry");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let dst = dir.join("weight.bin");
    let path = transfer_profile(
        "bin-dry",
        "http://127.0.0.1:9",
        &dir.to_string_lossy(),
        &dst.to_string_lossy(),
    );

    let output = Command::cargo_bin("lm-provision")
        .expect("lm-provision binary should build")
        .args(["apply", path.to_str().expect("utf8 path"), "--dry-run"])
        .output()
        .expect("process should run");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        progress_lines(&stderr).is_empty(),
        "a dry run transfers nothing, so it reports no progress:\n{stderr}"
    );
    // The one pre-effect event still fires, as spec 09 requires of both
    // modes — so the absence above is about progress, not about a
    // silent dry run.
    assert!(
        stderr.contains("op=\"net.transfer\"") && stderr.contains("mode=\"dry-run\""),
        "the effect is still audited in a dry run:\n{stderr}"
    );
    assert!(
        !dst.exists(),
        "a dry run writes no destination: {}",
        dst.display()
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Four at once: is the interleaved stream separable?
// ---------------------------------------------------------------------

/// A `MakeWriter` that keeps everything the subscriber writes.
#[derive(Clone)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// One entry of a would-be `models` phase: its report id, its supplier,
/// its destination.
type Plan = (String, String, String);

/// Fetch one entry, reporting into a transcript labelled with its step
/// id — the wiring `lifecycle::run_effect` does for a `models` entry.
async fn fetch(plan: &Plan, interval: Duration) -> u64 {
    let (step, src, dst) = plan;
    let transcript =
        lm_provision::exec::audit::TransferTranscript::with_interval("models", step, dst, interval);
    let sink = transcript.sink();
    let outcome = lm_provision::exec::effects::transfer(src, dst, &sink)
        .await
        .expect("the trickled body must arrive");
    outcome.bytes
}

/// Four transfers running at the same time, each with the report id a
/// `models` phase would give it, reporting into one stream.
///
/// **What this pins is separability, not readability.** The lines are
/// interleaved in arrival order and nothing groups them; what makes the
/// stream usable is that `step` partitions it exactly, and that each
/// partition is a whole, ordered account of one transfer. The test
/// prints the transcript it captured so that the claim can be checked
/// by eye (`cargo test -- --nocapture`).
#[tokio::test(flavor = "multi_thread")]
async fn four_transfers_at_once_stay_separable_by_step() {
    use tracing::instrument::WithSubscriber as _;

    const ENTRIES: usize = 4;
    const CHUNKS: usize = 5;
    const PIECE: usize = 4096;

    let dir = temp_stem("four-way");
    std::fs::create_dir_all(&dir).expect("create temp dir");

    // Each entry gets its own supplier, dribbling at its own pace, so
    // the four streams are genuinely interleaved rather than taking
    // turns.
    let mut servers = Vec::with_capacity(ENTRIES);
    let mut plans = Vec::with_capacity(ENTRIES);
    for n in 1..=ENTRIES {
        let (url, handle) = trickle_server(CHUNKS, PIECE, Duration::from_millis(20 * n as u64));
        servers.push(handle);
        plans.push((
            format!("1_models_{n}"),
            format!("{url}/{n}.bin"),
            dir.join(format!("{n}.bin")).to_string_lossy().into_owned(),
        ));
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Captured(Arc::clone(&buffer)))
        .with_ansi(false)
        .finish();

    // A cadence a test can afford. The production one is
    // `audit::TRANSFER_PROGRESS_INTERVAL_SEC`; what is under test here
    // is the shape of the interleave, which does not depend on it.
    let interval = Duration::from_millis(25);
    // Four futures, one task, all polled by the same loop — which is
    // what makes their events interleave.
    let run = async {
        let (a, b, c, d) = tokio::join!(
            fetch(&plans[0], interval),
            fetch(&plans[1], interval),
            fetch(&plans[2], interval),
            fetch(&plans[3], interval),
        );
        [a, b, c, d]
    };
    let sizes = run.with_subscriber(subscriber).await;
    for handle in servers {
        handle.join().expect("server thread joins");
    }

    let captured = buffer.lock().unwrap_or_else(|err| err.into_inner()).clone();
    let transcript = String::from_utf8_lossy(&captured).into_owned();
    println!("---- four-way transcript ----\n{transcript}---- end ----");

    let events = progress_lines(&transcript);
    assert!(!events.is_empty(), "{transcript}");

    for (n, (step, _, dst)) in plans.iter().enumerate() {
        let mine: Vec<&&str> = events
            .iter()
            .filter(|line| line.contains(&format!("step=\"{step}\"")))
            .collect();
        assert!(
            mine.len() >= 2,
            "{step} reported {} times; a transfer with nothing to say between its \
             first byte and its last is not being followed:\n{transcript}",
            mine.len()
        );
        assert!(
            mine.iter()
                .all(|line| line.contains(&format!("dst=\"{dst}\""))),
            "every line of one partition names one destination:\n{transcript}"
        );
        assert_eq!(
            mine.iter()
                .filter(|line| line.contains("state=\"done\""))
                .count(),
            1,
            "each transfer closes exactly once:\n{transcript}"
        );
        assert_eq!(sizes[n], (CHUNKS * PIECE) as u64);
    }

    // Nothing outside the four partitions: every event belongs to
    // exactly one transfer, so partitioning by `step` loses nothing.
    let partitioned: usize = plans
        .iter()
        .map(|(step, _, _)| {
            events
                .iter()
                .filter(|line| line.contains(&format!("step=\"{step}\"")))
                .count()
        })
        .sum();
    assert_eq!(partitioned, events.len(), "{transcript}");

    std::fs::remove_dir_all(&dir).ok();
}
