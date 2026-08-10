//! Structured tracing events for the stderr audit transcript
//! (spec 09 §Audit log).
//!
//! Every effect invocation — both direct ops in [`super::registry`] and
//! lifecycle sub-steps in [`super::lifecycle`] — emits **one**
//! `tracing::info!` event through the helpers here **before the effect
//! runs**. The events go to the stderr `fmt` subscriber the binary
//! installs from `main.rs`, so `apply` produces the operational
//! transcript the driver in spec 08 collects.
//!
//! ## Redaction rules (spec 09)
//!
//! - Env keys: key **names** are logged; a name matching the
//!   sensitive-key set (spec 02 §Shared vocabulary,
//!   [`crate::validate::is_secret_shaped_key`]) is rendered as
//!   `NAME [REDACTED]` so the reader can tell a value was withheld.
//!   Values are never logged, sensitive or not. HTTP request header
//!   names go through the same [`env_keys`] rendering.
//! - `fs.write` logs path + byte count + `content_source` — `"string"`
//!   for a literal `content: String`, `"secret:<name>"` once the
//!   secret-content form lands. Content bytes are never logged.
//! - HTTP logs URL, request header names, and — for `net.http_post` —
//!   the request body's source form and byte length. Header values and
//!   body content are never logged.
//! - `sh.exec` logs argv verbatim (validate's shell-safety and the
//!   env-injection design keep secrets out of argv).
//! - `note` sub-steps log their kind + note text — they carry no
//!   effect input to redact.
//! - `net.transfer.progress` logs the destination path, byte counts and
//!   elapsed seconds — no request input at all, and deliberately not the
//!   source URL (see [`transfer_progress`]).
//!
//! ## The one event that repeats
//!
//! [`transfer_progress`] is the exception to "one event per effect": a
//! transfer is minutes or tens of minutes of one effect, and four of
//! them now run at the same time ([`crate::apply`]), so the pre-effect
//! event is followed by a report of that transfer's position every
//! [`TRANSFER_PROGRESS_INTERVAL_SEC`]. It is an **append-only event
//! stream**, never a redrawn line: what reads it is a driver capturing a
//! pipe (spec 08), where a carriage return is not a cursor move but a
//! corrupted record. [`TransferTranscript`] holds the cadence.
//!
//! Emission runs in both [`super::ExecMode::DryRun`] and
//! [`super::ExecMode::Real`], mirroring the "dry-run does policy /
//! resolves secrets too" rule (spec 06 / 07). A dry-run trace is what
//! the profile *would* run; a real trace is what it *did*. Filter with
//! `--log-level` / `RUST_LOG` (chapter 07 §Global flags).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::validate::is_secret_shaped_key;

use super::effects::TransferProgress;

/// The `mode` value on every event, so a caller filtering the stderr
/// stream can separate `dry-run` audits from `real` ones with a single
/// field match.
pub fn mode_label(mode: super::ExecMode) -> &'static str {
    match mode {
        super::ExecMode::DryRun => "dry-run",
        super::ExecMode::Real => "real",
    }
}

/// Render an env-injection map as the audit transcript sees it:
/// key names only, with a `[REDACTED]` marker appended to any name that
/// matches the sensitive-key set. Values never appear.
///
/// The rendered list is sorted (the input is a [`BTreeMap`] already, so
/// this is inherent, not a re-sort) so two runs of the same profile
/// produce byte-identical audit output — useful for diff-driven review
/// of a driver's collected stderr.
pub fn env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys()
        .map(|name| {
            if is_secret_shaped_key(name) {
                format!("{name} [REDACTED]")
            } else {
                name.clone()
            }
        })
        .collect()
}

/// `sh.exec` audit event. `argv` is the argv the effect will run,
/// verbatim; `env` is the resolved env-injection map whose *keys* the
/// event carries.
pub fn sh_exec(mode: super::ExecMode, kind: &str, argv: &[String], env: &BTreeMap<String, String>) {
    tracing::info!(
        mode = mode_label(mode),
        op = "sh.exec",
        kind = kind,
        argv = ?argv,
        env_keys = ?env_keys(env),
        "audit"
    );
}

/// `fs.write` audit event. `content_source` names where the content
/// came from without carrying it (spec 09 names-not-values):
/// `"string"` for a literal payload, `"secret:<name>"` for an
/// [`EnvSecret`](crate::profile_ast::ProfileNode::EnvSecret) content
/// node, `"env_ref:<name>"` for an
/// [`EnvRef`](crate::profile_ast::ProfileNode::EnvRef) pointing at a
/// `Spec.env` entry. Content bytes never enter the event.
pub fn fs_write(mode: super::ExecMode, kind: &str, path: &str, bytes: u64, content_source: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "fs.write",
        kind = kind,
        path = path,
        bytes = bytes,
        content_source = content_source,
        "audit"
    );
}

/// `net.http_get` audit event. `headers` is the resolved request-header
/// map whose *names* the event carries (through [`env_keys`], so a
/// sensitive name such as `Authorization` is marked `[REDACTED]`);
/// header values never enter the event.
pub fn http_get(mode: super::ExecMode, kind: &str, url: &str, headers: &BTreeMap<String, String>) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.http_get",
        kind = kind,
        url = url,
        header_names = ?env_keys(headers),
        "audit"
    );
}

/// `net.http_post` audit event. Headers follow [`http_get`]'s rule;
/// the request body is named by its *form* (`"none"` / `"body"` /
/// `"body:secret:<name>"` / `"body:env_ref:<name>"` / `"body_json"`,
/// spec 09 names-not-values) plus its byte length. The body bytes never
/// enter the event.
pub fn http_post(
    mode: super::ExecMode,
    kind: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    body_source: &str,
    body_bytes: u64,
) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.http_post",
        kind = kind,
        url = url,
        header_names = ?env_keys(headers),
        body_source = body_source,
        body_bytes = body_bytes,
        "audit"
    );
}

/// `net.transfer` audit event (direct op *and* lifecycle
/// [`super::lifecycle::Step::Transfer`]).
pub fn transfer(mode: super::ExecMode, kind: &str, src: &str, dst: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.transfer",
        kind = kind,
        src = src,
        dst = dst,
        "audit"
    );
}

/// How long a running transfer may go without saying anything.
///
/// **Time, not bytes.** A bytes-per-event rule (one event every N MiB)
/// goes quiet exactly when the news is worst: a supplier that slowed to
/// a trickle emits nothing, and a reader cannot tell it from one that
/// stopped. On a clock, silence has one meaning.
///
/// **Shorter than [`TRANSFER_READ_TIMEOUT_SEC`](super::effects) (60 s)**,
/// which is what makes silence readable at all: the events are driven by
/// arriving chunks (see [`TransferTranscript::observe`]), so a stalled
/// supplier is heard as *nothing further*, and the reader needs a
/// cadence tight enough that a missing event is news before the read
/// timeout turns the transfer into an error. At 15 s a stall is visible
/// after one missed event and hard after two, with the timeout's own
/// error arriving at 60 s to confirm it.
///
/// **Long enough that the transcript stays a transcript.** Twenty
/// minutes at this cadence is ~80 events per transfer; four at once —
/// the concurrency bound in [`crate::apply`] — is ~330 lines over those
/// twenty minutes, about one every four seconds. A driver capturing the
/// pipe (spec 08) is reading a log, not a video.
pub const TRANSFER_PROGRESS_INTERVAL_SEC: u64 = 15;

/// What a progress event prints where it has no number: an absent
/// `Content-Length` leaves both the total and the percentage unknown,
/// and saying so is not the same as printing a zero.
const UNKNOWN: &str = "unknown";

/// `net.transfer.progress` audit event — one report of a running (or
/// just-finished) transfer.
///
/// **Its own `op`**, not `net.transfer`: a consumer that partitions the
/// stream by `op` keeps getting exactly the one pre-effect event per
/// transfer it got before, and these arrive on a channel it can ignore
/// whole.
///
/// Fields beyond the usual `op` / `kind` / `mode`:
///
/// - `step` — the transfer's report id (`<phase_index>_<kind>[_<n>]`,
///   the same string the apply report's entry carries). **This is what
///   makes four transfers running at the same time readable**: without
///   it the four are one interleaved stream of numbers that do not add
///   up.
/// - `dst` — the destination path. Redaction-wise this is the safer of
///   the two ends: a source URL can be a presigned link with a
///   credential in its query, and while spec 09 does allow logging the
///   URL (the one pre-effect `net.transfer` event does), there is no
///   reason to repeat it eighty times. The `dst` is also the join back
///   to that event, which carries both ends.
/// - `bytes` / `total` / `percent` — position, not speed. `total` and
///   `percent` are [`UNKNOWN`] together when the supplier declared no
///   `Content-Length`.
/// - `elapsed_sec` — seconds since this transfer's first byte was
///   requested, so an event means something on its own even where the
///   subscriber's timestamps have been turned off.
/// - `state` — `"running"` or `"done"`. A stream that stops on
///   `"running"` did not finish; nothing else has to be inferred from
///   the absence of a later event.
///
/// **No rate and no estimated time remaining.** Both would be host
/// arithmetic dressed as an observation: an average over twenty minutes
/// lags a stall by minutes, and an ETA from it is a prediction this
/// process has no standing to make (the link's speed is not a thing the
/// pod knows). `bytes` at a known cadence is the measurement; a consumer
/// that wants a rate can difference two events, and an operator reading
/// `percent` against `elapsed_sec` has the same estimate without the
/// transcript asserting it.
///
/// `mode` is always `"real"` — a dry run performs no transfer, so no
/// stream exists to report on (spec 09's "emission runs in both modes"
/// is about the one event per effect, which still does).
pub fn transfer_progress(
    kind: &str,
    step: &str,
    dst: &str,
    bytes: u64,
    total: Option<u64>,
    elapsed_sec: u64,
    state: &str,
) {
    let (total_label, percent) = match total {
        Some(total) if total > 0 => (
            total.to_string(),
            format!("{:.1}", (bytes as f64 * 100.0) / total as f64),
        ),
        // A declared zero is not a total to divide by, and an absent one
        // is not a total at all: both are unknown.
        _ => (UNKNOWN.to_string(), UNKNOWN.to_string()),
    };
    tracing::info!(
        mode = mode_label(super::ExecMode::Real),
        op = "net.transfer.progress",
        kind = kind,
        step = step,
        dst = dst,
        bytes = bytes,
        total = total_label.as_str(),
        percent = percent.as_str(),
        elapsed_sec = elapsed_sec,
        state = state,
        "audit"
    );
}

/// Turns one transfer's [`TransferProgress`] reports into
/// [`transfer_progress`] events at [`TRANSFER_PROGRESS_INTERVAL_SEC`].
///
/// The cadence lives here rather than in
/// [`super::effects`] because it is a decision about the transcript, not
/// about the transfer: the effect reports every chunk and this decides
/// which of them is news.
///
/// One instance per transfer — it holds that transfer's identity and its
/// clock.
pub struct TransferTranscript {
    /// The phase kind, on every audit event.
    kind: String,
    /// The step's report id — what tells concurrent transfers apart.
    step: String,
    /// The destination being written.
    dst: String,
    /// How long the transfer may go without an event.
    interval: Duration,
    /// When this transfer started, for `elapsed_sec`.
    started: Instant,
    /// When the last event went out; `None` until the first one does.
    ///
    /// A [`Mutex`] because the sink is `&self` (an `&dyn Fn` handed to
    /// the effect) and the future it lives in may be moved between
    /// worker threads. It is taken for one comparison, never across an
    /// await.
    last: Mutex<Option<Instant>>,
}

impl TransferTranscript {
    /// A transcript for the transfer `step` is running into `dst`.
    pub fn new(kind: &str, step: &str, dst: &str) -> Self {
        Self::with_interval(
            kind,
            step,
            dst,
            Duration::from_secs(TRANSFER_PROGRESS_INTERVAL_SEC),
        )
    }

    /// [`Self::new`] with the cadence injected, so a test can prove the
    /// interval is honoured without spending
    /// [`TRANSFER_PROGRESS_INTERVAL_SEC`] doing it — the same seam
    /// `transfer_in` gives the read timeout.
    pub fn with_interval(kind: &str, step: &str, dst: &str, interval: Duration) -> Self {
        Self {
            kind: kind.to_string(),
            step: step.to_string(),
            dst: dst.to_string(),
            interval,
            started: Instant::now(),
            last: Mutex::new(None),
        }
    }

    /// Take one report from the effect and emit it if it is news.
    ///
    /// Three rules, in this order:
    ///
    /// 1. **The first report always goes out.** An operator learns the
    ///    step id, the destination and the declared size as soon as
    ///    bytes are moving, rather than [`TRANSFER_PROGRESS_INTERVAL_SEC`]
    ///    later — and a transfer shorter than the interval still says
    ///    something.
    /// 2. **A finished report always goes out**, whenever it arrives.
    ///    It is the only place the real byte count appears for a
    ///    supplier that declared no `Content-Length`, and it is what
    ///    closes one stream out of four.
    /// 3. Everything in between waits for the interval.
    pub fn observe(&self, progress: TransferProgress) {
        let now = Instant::now();
        // Poisoning cannot make a timestamp unusable, and dropping the
        // transcript would be a worse answer than a duplicate event.
        let mut last = self.last.lock().unwrap_or_else(|err| err.into_inner());
        if !progress.finished {
            if let Some(at) = *last {
                if now.duration_since(at) < self.interval {
                    return;
                }
            }
        }
        *last = Some(now);
        drop(last);

        transfer_progress(
            &self.kind,
            &self.step,
            &self.dst,
            progress.written,
            progress.total,
            now.duration_since(self.started).as_secs(),
            if progress.finished { "done" } else { "running" },
        );
    }

    /// The sink to hand [`super::effects::transfer`].
    pub fn sink(&self) -> impl Fn(TransferProgress) + Send + Sync + '_ {
        move |progress| self.observe(progress)
    }
}

/// `net.http_get` audit event carrying the poll deadline
/// (`comfyui.health` / `service.ready` — [`super::lifecycle::Step::HttpPoll`]).
pub fn http_poll(mode: super::ExecMode, kind: &str, url: &str, timeout_sec: u64) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.http_get",
        kind = kind,
        url = url,
        timeout_sec = timeout_sec,
        "audit"
    );
}

/// `mount.bind` audit event.
pub fn mount_bind(mode: super::ExecMode, kind: &str, src: &str, dst: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "mount.bind",
        kind = kind,
        src = src,
        dst = dst,
        "audit"
    );
}

/// `mount.umount` audit event.
pub fn mount_umount(mode: super::ExecMode, kind: &str, path: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "mount.umount",
        kind = kind,
        path = path,
        "audit"
    );
}

/// `note` audit event — the lifecycle no-op sub-step. Not an effect,
/// but the operator can still tell that a phase decided to do nothing
/// (and why, from `message`) rather than the phase being silently
/// absent from the transcript.
pub fn note(mode: super::ExecMode, kind: &str, message: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "note",
        kind = kind,
        note = message,
        "audit"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_keys_leaves_a_non_sensitive_name_alone() {
        let mut env = BTreeMap::new();
        env.insert("MODE".to_string(), "fast".to_string());
        assert_eq!(env_keys(&env), vec!["MODE".to_string()]);
    }

    #[test]
    fn env_keys_appends_redacted_marker_for_a_sensitive_name() {
        let mut env = BTreeMap::new();
        env.insert("HF_TOKEN".to_string(), "should-never-appear".to_string());
        env.insert("api_key".to_string(), "also-secret".to_string());
        let out = env_keys(&env);
        // Both are marked; the sort comes from the BTreeMap.
        assert_eq!(
            out,
            vec![
                "HF_TOKEN [REDACTED]".to_string(),
                "api_key [REDACTED]".to_string(),
            ]
        );
        // Values are never in the output regardless of the name.
        for line in &out {
            assert!(!line.contains("should-never-appear"));
            assert!(!line.contains("also-secret"));
        }
    }

    #[test]
    fn env_keys_result_is_stable_across_runs() {
        // A BTreeMap already sorts by key, so re-inserting in a
        // different order must produce the same output.
        let mut a = BTreeMap::new();
        a.insert("MODE".to_string(), "fast".to_string());
        a.insert("HF_TOKEN".to_string(), "v1".to_string());
        let mut b = BTreeMap::new();
        b.insert("HF_TOKEN".to_string(), "v2".to_string());
        b.insert("MODE".to_string(), "slow".to_string());
        assert_eq!(env_keys(&a), env_keys(&b));
    }

    #[test]
    fn mode_label_is_the_expected_string() {
        assert_eq!(mode_label(super::super::ExecMode::DryRun), "dry-run");
        assert_eq!(mode_label(super::super::ExecMode::Real), "real");
    }

    // -----------------------------------------------------------------
    // Progress events: the cadence, and what one line says.
    //
    // These assert on the **rendered text**, because that is what the
    // consumer is: a spec-08 driver capturing a pipe reads lines, not a
    // structured API. A test on the field values would pass while the
    // line a driver sees said something else.
    // -----------------------------------------------------------------

    use std::sync::Arc;

    /// A `MakeWriter` that keeps everything the subscriber writes, so a
    /// test can read the transcript a driver would have captured.
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
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

    /// Run `body` with a capturing subscriber installed and return the
    /// lines it emitted. ANSI is off, as it is for a driver reading a
    /// pipe (spec 09 §Audit log).
    fn transcript_of(body: impl FnOnce()) -> Vec<String> {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Captured(Arc::clone(&buffer)))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        let bytes = buffer.lock().unwrap_or_else(|err| err.into_inner()).clone();
        String::from_utf8_lossy(&bytes)
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn running(written: u64, total: Option<u64>) -> TransferProgress {
        TransferProgress {
            written,
            total,
            finished: false,
        }
    }

    fn finished(written: u64, total: Option<u64>) -> TransferProgress {
        TransferProgress {
            written,
            total,
            finished: true,
        }
    }

    /// The first report goes out at once — an operator learns which step
    /// is moving bytes where as soon as it is — and the ones behind it
    /// wait for the interval rather than turning a chunk loop into a
    /// firehose.
    #[test]
    fn the_first_report_is_emitted_at_once_and_the_rest_wait_for_the_interval() {
        let lines = transcript_of(|| {
            let transcript =
                TransferTranscript::with_interval("models", "1_models_2", "/m/a.bin", ONE_SECOND);
            for written in [1_000, 2_000, 3_000] {
                transcript.observe(running(written, Some(10_000)));
            }
        });
        assert_eq!(
            lines.len(),
            1,
            "three chunks inside one interval are one event: {lines:?}"
        );
        assert!(lines[0].contains("bytes=1000"), "{lines:?}");
    }

    /// …and once the interval has passed, the next report is news again.
    #[test]
    fn a_report_after_the_interval_is_emitted() {
        let lines = transcript_of(|| {
            let transcript = TransferTranscript::with_interval(
                "models",
                "1_models_2",
                "/m/a.bin",
                Duration::from_millis(30),
            );
            transcript.observe(running(1_000, Some(10_000)));
            std::thread::sleep(Duration::from_millis(60));
            transcript.observe(running(2_000, Some(10_000)));
        });
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("bytes=2000"), "{lines:?}");
    }

    /// A finished report is never held back by the interval: it is the
    /// only place an untotalled transfer's real size appears, and it is
    /// what closes one stream out of several.
    #[test]
    fn a_finished_report_is_emitted_however_soon_it_arrives() {
        let lines = transcript_of(|| {
            let transcript =
                TransferTranscript::with_interval("models", "1_models_2", "/m/a.bin", ONE_SECOND);
            transcript.observe(running(1_000, None));
            transcript.observe(finished(1_234, None));
        });
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("state=\"running\""), "{lines:?}");
        assert!(
            lines[1].contains("state=\"done\"") && lines[1].contains("bytes=1234"),
            "{lines:?}"
        );
    }

    /// An absent `Content-Length` prints as `unknown`, not as a zero: a
    /// total of nothing and a total nobody declared are different pieces
    /// of news, and a `0%` that never moves is the worse of the two to
    /// read at 3 a.m.
    #[test]
    fn an_undeclared_total_prints_unknown_rather_than_a_number() {
        let lines = transcript_of(|| {
            let transcript =
                TransferTranscript::with_interval("models", "1_models_1", "/m/a.bin", ONE_SECOND);
            transcript.observe(running(4_096, None));
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("total=\"unknown\"") && lines[0].contains("percent=\"unknown\""),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("bytes=4096"),
            "what *is* known is still there: {lines:?}"
        );
    }

    /// A declared total gives a percentage, and it is arithmetic over
    /// two measured numbers rather than a prediction.
    #[test]
    fn a_declared_total_prints_the_position_reached() {
        let lines = transcript_of(|| {
            let transcript =
                TransferTranscript::with_interval("models", "1_models_1", "/m/a.bin", ONE_SECOND);
            transcript.observe(running(2_500, Some(10_000)));
        });
        assert!(
            lines[0].contains("total=\"10000\"") && lines[0].contains("percent=\"25.0\""),
            "{lines:?}"
        );
    }

    /// **The parallel case.** Two transfers reporting into one stream are
    /// separable by `step`, which is the report id their apply-report
    /// entries carry — so a reader can partition the interleaved lines
    /// and get each transfer's own sequence back.
    #[test]
    fn concurrent_transfers_stay_separable_by_their_step_id() {
        let lines = transcript_of(|| {
            let first =
                TransferTranscript::with_interval("models", "1_models_1", "/m/a.bin", ONE_SECOND);
            let second =
                TransferTranscript::with_interval("models", "1_models_2", "/m/b.bin", ONE_SECOND);
            // Interleaved the way two running transfers arrive.
            first.observe(running(1_000, Some(4_000)));
            second.observe(running(2_000, Some(8_000)));
            second.observe(finished(8_000, Some(8_000)));
            first.observe(finished(4_000, Some(4_000)));
        });

        let of_step = |step: &str| -> Vec<String> {
            lines
                .iter()
                .filter(|line| line.contains(&format!("step=\"{step}\"")))
                .cloned()
                .collect()
        };
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(of_step("1_models_1").len(), 2, "{lines:?}");
        assert_eq!(of_step("1_models_2").len(), 2, "{lines:?}");
        // Each partition carries its own destination, so the step id
        // never has to be looked up against the plan to be useful.
        assert!(
            of_step("1_models_1")
                .iter()
                .all(|line| line.contains("dst=\"/m/a.bin\"")),
            "{lines:?}"
        );
        assert!(
            of_step("1_models_2")
                .iter()
                .all(|line| line.contains("dst=\"/m/b.bin\"")),
            "{lines:?}"
        );
    }

    /// The source URL stays out: a presigned link carries its credential
    /// in the query, and repeating one eighty times a transfer is a
    /// leak surface the destination path does not have.
    #[test]
    fn a_progress_event_does_not_repeat_the_source_url() {
        let lines = transcript_of(|| {
            let transcript = TransferTranscript::with_interval(
                "models",
                "1_models_1",
                "/m/a.bin",
                Duration::from_secs(1),
            );
            transcript.observe(running(1, Some(2)));
        });
        assert!(!lines[0].contains("http"), "{lines:?}");
        assert!(!lines[0].contains("src="), "{lines:?}");
    }

    /// A cadence long enough to hold every report in a test that does
    /// not want a second one.
    const ONE_SECOND: Duration = Duration::from_secs(1);
}
