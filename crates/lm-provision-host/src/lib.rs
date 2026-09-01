//! # lm-provision-host
//!
//! The control plane: the process that keeps running after an apply
//! returns. Enforcing a pod's TTL means noticing that it expired,
//! which no one-shot CLI invocation is around to do; holding custody
//! of the acquisition and apply ledgers means being the one writer
//! that outlives every driver run. That daemon — self-hostable, so an
//! operator's machines and the record of what was spent on them stay
//! on their own hardware — is what this crate is becoming.
//!
//! **What it is today: the scheduler around `sweep`.** The driver can
//! give back every machine whose lease has run out
//! (`lm-provision-driver sweep`, 08 §Acquisitions and sweep), but only
//! when somebody runs it — which is the forgotten-machine problem one
//! level up. This daemon runs it on a timer and answers one question
//! about itself over HTTP: [`Config`] says what to run and how often,
//! [`tick`] runs it once, [`Status`] is what the runs added up to, and
//! [`health`] is that state as the document the endpoint returns.
//!
//! ## Exec, not link
//!
//! The daemon **runs the `lm-provision-driver` binary** rather than
//! calling driver code as a library. The CLI is the frozen contract —
//! the specs are the normative surface, and 08 §Acquisitions and sweep
//! defines sweep's single stdout artifact — and the driver already
//! treats "run the other program and capture its streams" as how one
//! side drives another (its own releases shell out to the platform's
//! CLI). It also keeps this crate free of any dependency on the
//! permissive ones: the boundary below is not merely unviolated, there
//! is nothing on this side that could violate it.
//!
//! ## Enforcing is the default here
//!
//! `--dry-run` defaults to **false**, the opposite of the driver
//! CLI's. That flip is deliberate: on the CLI, an operator asking
//! which machines would be released must not find out by them being
//! gone. Installing a long-lived TTL-enforcement service is the
//! opposite act — it *is* the consent to release expired machines, and
//! a daemon that defaulted to observing would be the forgotten-machine
//! problem wearing a uniform. `--dry-run true` remains available as an
//! observation mode. Either way the release gate inside `sweep` still
//! refuses a machine whose work has not been collected; nothing here
//! can force past it.
//!
//! **It is AGPL-3.0-or-later** (declared in its own manifest, not
//! inherited from the workspace's MIT / Apache-2.0). The boundary was
//! cut while the crate was still empty because relicensing afterwards
//! needs a CLA or DCO signature from every outside contributor, one at
//! a time, and any one refusal is final.
//!
//! ## The dependency rule
//!
//! **No other crate in this workspace may depend on this one.** The
//! engine crates (`lm-provision`, `lm-provision-driver`,
//! `lm-provision-mcp`) and the neutral `lm-provision-protocol` are
//! dual-licensed MIT / Apache-2.0 permanently; a dependency edge from
//! any of them to an AGPL crate would put their users under the AGPL's
//! terms, which is precisely what the permissive promise rules out.
//! Types both sides need go in `lm-provision-protocol`, which is
//! permissive and may be depended on from either direction.
//!
//! The rule is machine-checked rather than remembered:
//! `no_permissive_crate_depends_on_the_agpl_host` in this crate's test
//! module reads the four permissive manifests and fails if any of them
//! names this crate.

#![warn(missing_docs)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Mutex;

/// What the daemon was told to sweep, and how often.
///
/// The bind address is not here: it is read once at startup to make a
/// listener and never consulted again, while every field below is
/// either an argument of the next child process or an answer the
/// health document owes its reader.
#[derive(Debug, Clone)]
pub struct Config {
    /// Seconds between sweeps.
    pub interval_secs: u64,
    /// The driver binary to run. A bare name is looked up on `PATH`.
    pub driver: PathBuf,
    /// The acquisitions record to sweep, passed through verbatim when
    /// set; when unset the driver picks its own default, which is the
    /// one the operator's `acquire` runs already wrote to.
    pub acquisitions: Option<PathBuf>,
    /// The ledger the release gate reads, passed through verbatim when
    /// set; unset defers to the driver's default for the same reason.
    pub ledger: Option<PathBuf>,
    /// Whether the sweeps only name what they would release.
    ///
    /// **False by default** — see the crate docs: running this daemon
    /// is the consent the CLI's `--dry-run true` default withholds.
    pub dry_run: bool,
}

/// What the sweeps so far added up to — the daemon's whole memory.
#[derive(Debug, Clone)]
pub struct Status {
    /// When the daemon started, as an RFC 3339 timestamp.
    pub started_at: String,
    /// How many sweeps have finished, failed ones included.
    pub ticks: u64,
    /// When the newest sweep finished.
    pub last_tick_at: Option<String>,
    /// Whether the newest sweep produced an artifact this daemon could
    /// read. `None` until the first one finishes.
    pub last_tick_ok: Option<bool>,
    /// Why the newest sweep did not, when it did not.
    pub last_tick_error: Option<String>,
    /// The newest sweep's artifact, verbatim (08 §Acquisitions and
    /// sweep: `dry_run`, `expired`, `released`, `refused`, `failed`).
    ///
    /// Kept as an opaque [`serde_json::Value`] on purpose. The daemon
    /// counts three of its fields for a log line and otherwise passes
    /// it through, so a field added to the artifact reaches a health
    /// reader without a release of this crate.
    pub last_artifact: Option<serde_json::Value>,
}

impl Status {
    /// A daemon that has started and swept nothing yet.
    pub fn started(at: String) -> Self {
        Self {
            started_at: at,
            ticks: 0,
            last_tick_at: None,
            last_tick_ok: None,
            last_tick_error: None,
            last_artifact: None,
        }
    }
}

/// The status the health endpoint and the sweep loop share.
pub type SharedStatus = Arc<Mutex<Status>>;

/// Why a sweep produced no artifact.
///
/// Each variant is a distinct thing for an operator to fix — a driver
/// that is not on `PATH`, a sweep that ran and failed, a sweep whose
/// stdout was not the document the contract promises — and the whole
/// value is what the health endpoint hands back as `last_tick_error`.
#[derive(Debug, thiserror::Error)]
pub enum TickFailure {
    /// The child could not be started at all.
    #[error("could not run `{program}`: {source}")]
    Spawn {
        /// The binary that was going to be run.
        program: String,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },
    /// The child ran and ended badly. A sweep exits non-zero only when
    /// a machine that expired could not be released — a gate refusal
    /// exits 0 — so this is always a machine still billing.
    #[error("`{program} sweep` exited with {status}")]
    Exit {
        /// The binary that was run.
        program: String,
        /// How it ended, as the platform reports it.
        status: String,
    },
    /// The child's stdout was not the artifact the contract promises
    /// (07 §Stream split: exactly one machine-readable document there).
    #[error("`{program} sweep` did not write a JSON artifact to stdout: {source}")]
    Unparseable {
        /// The binary that was run.
        program: String,
        /// Where the parse gave up.
        #[source]
        source: serde_json::Error,
    },
}

/// The command one sweep runs.
///
/// `--dry-run` is always passed explicitly rather than left to the
/// child's default, because the two defaults disagree on purpose (see
/// the crate docs): a daemon that omitted the flag would silently
/// observe where its operator asked it to enforce. The optional paths
/// are passed through verbatim and omitted when unset, so "unset" here
/// means the driver's default rather than a second copy of it that
/// could drift.
///
/// [`OsString`] rather than [`String`]: these are paths the operator
/// typed, and a path is not required to be UTF-8. Lossy conversion
/// here would hand the child a file name that does not exist.
pub fn sweep_argv(config: &Config) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        config.driver.clone().into_os_string(),
        "sweep".into(),
        "--dry-run".into(),
        if config.dry_run { "true" } else { "false" }.into(),
    ];
    if let Some(path) = &config.acquisitions {
        argv.push("--acquisitions".into());
        argv.push(path.clone().into_os_string());
    }
    if let Some(path) = &config.ledger {
        argv.push("--ledger".into());
        argv.push(path.clone().into_os_string());
    }
    argv
}

/// Read a finished sweep: its artifact, or why there is none.
///
/// A non-zero exit is refused before the stdout is looked at. The
/// driver does emit its artifact on failure paths, but a sweep that
/// exited 1 is reporting a machine it could not release, and recording
/// that document as a healthy tick would be the daemon telling its
/// operator that enforcement is working while it is not.
pub fn interpret_sweep(
    program: &str,
    status: std::process::ExitStatus,
    stdout: &[u8],
) -> Result<serde_json::Value, TickFailure> {
    if !status.success() {
        return Err(TickFailure::Exit {
            program: program.to_string(),
            status: status.to_string(),
        });
    }
    serde_json::from_slice(stdout).map_err(|source| TickFailure::Unparseable {
        program: program.to_string(),
        source,
    })
}

/// What the child said, one line each, prefixed with the program that
/// said it.
///
/// `program: message` is the GNU convention for a non-interactive
/// program's messages [documented:
/// <https://www.gnu.org/prep/standards/html_node/Errors.html>], and
/// the program here is the driver rather than this one — the operator
/// is being shown somebody else's words and needs to know it, all the
/// more so because the driver's stderr already carries the platform
/// CLI's own attributed lines nested inside.
///
/// Written out here rather than imported from the driver: importing it
/// would mean depending on a permissive crate from this AGPL one,
/// which is the edge the boundary exists to keep empty. Ten lines is
/// the price.
///
/// **Silence is not reported.** "When a program has nothing surprising
/// to say, it should say nothing" [documented: Raymond, *The Art of
/// Unix Programming*, Rule of Silence]. The driver's `""` special case
/// is not carried over: that is what a platform CLI returns from a
/// release, and what this program runs is the driver, which never says
/// it.
pub fn attributed(program: &str, bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    text.lines()
        .map(|line| format!("{program}: {line}"))
        .collect()
}

/// Fold one finished sweep into the status the endpoint reports.
///
/// A failure clears the artifact rather than leaving the last good one
/// in place: `last_artifact` beside `last_tick_at` reads as "this is
/// what the last sweep did", and a stale document under a fresh
/// timestamp would say that about a sweep that never ran.
pub fn record(status: &mut Status, at: String, outcome: Result<serde_json::Value, String>) {
    status.ticks += 1;
    status.last_tick_at = Some(at);
    match outcome {
        Ok(artifact) => {
            status.last_tick_ok = Some(true);
            status.last_tick_error = None;
            status.last_artifact = Some(artifact);
        }
        Err(reason) => {
            status.last_tick_ok = Some(false);
            status.last_tick_error = Some(reason);
            status.last_artifact = None;
        }
    }
}

/// The document the health endpoint returns.
///
/// Borrowed from the [`Status`] it describes: it is rendered while the
/// lock is held and written after, and cloning the artifact to cross
/// that boundary would copy the one field with no size bound.
#[derive(Debug, serde::Serialize)]
pub struct Health<'a> {
    /// Whether the newest sweep produced an artifact — the one
    /// question this endpoint exists to answer. True before the first
    /// sweep finishes: the daemon is up and nothing has gone wrong
    /// yet, and `ticks: 0` beside it says which of the two it is.
    pub ok: bool,
    /// Whether the sweeps are enforcing or only observing.
    pub dry_run: bool,
    /// Seconds between sweeps, so a reader can tell a stale
    /// `last_tick_at` from a slow one.
    pub interval_secs: u64,
    /// When the daemon started.
    pub started_at: &'a str,
    /// How many sweeps have finished.
    pub ticks: u64,
    /// When the newest sweep finished; null before the first.
    pub last_tick_at: Option<&'a str>,
    /// Whether it produced an artifact; null before the first.
    pub last_tick_ok: Option<bool>,
    /// Why it did not. Absent — not null — when the newest sweep was
    /// fine, so a reader scanning for the key finds it only when there
    /// is something to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_tick_error: Option<&'a str>,
    /// The newest sweep's artifact, verbatim. Absent for the same
    /// reason when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_artifact: Option<&'a serde_json::Value>,
}

/// The health document for this configuration and this status.
pub fn health<'a>(config: &Config, status: &'a Status) -> Health<'a> {
    Health {
        ok: status.last_tick_ok.unwrap_or(true),
        dry_run: config.dry_run,
        interval_secs: config.interval_secs,
        started_at: &status.started_at,
        ticks: status.ticks,
        last_tick_at: status.last_tick_at.as_deref(),
        last_tick_ok: status.last_tick_ok,
        last_tick_error: status.last_tick_error.as_deref(),
        last_artifact: status.last_artifact.as_ref(),
    }
}

/// The whole HTTP response for one health request.
///
/// Hand-rolled over a raw socket rather than served by a framework:
/// there is one endpoint, one method's worth of behaviour, and one
/// document, so a router and its dependency tree would buy nothing
/// over the lines below.
///
/// `Connection: close` because the daemon answers and hangs up — a
/// keep-alive connection would need the request framing this handler
/// deliberately does not do — and `Content-Length` so a reader knows
/// the body ended without waiting for the close to prove it.
pub fn health_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// The health document as the body bytes to send.
///
/// The fallback is unreachable — every field is a scalar or an
/// already-parsed JSON value — and is there rather than a panic
/// because a health endpoint that kills the daemon it reports on is
/// worse than one that answers badly.
pub fn health_body(config: &Config, status: &Status) -> String {
    serde_json::to_string(&health(config, status)).unwrap_or_else(|_| r#"{"ok":false}"#.to_string())
}

/// Run one sweep and record what it did.
///
/// **This never fails the caller.** A sweep that could not be
/// spawned, exited non-zero, or wrote something other than its
/// artifact is recorded as a failed tick carrying the reason, and the
/// loop goes back to waiting: a TTL enforcer that exits on the first
/// bad tick protects nothing for the rest of the week. The failure is
/// visible in two places an operator already watches — the log, and
/// `ok: false` at the health endpoint.
pub async fn tick(config: &Config, state: &SharedStatus) {
    let argv = sweep_argv(config);
    // Lossy is right here and nowhere else: this string is only ever
    // shown to a person (log lines, the `program:` prefix, the reason
    // in the health document), while the child is spawned from the
    // OsString beside it.
    let program = config.driver.to_string_lossy().into_owned();

    let outcome = match tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        // Captured, not inherited, for the reason the driver captures
        // (07 §Stream split): the child's artifact is a document this
        // daemon reads, and its diagnostics are relayed below with an
        // attribution the operator can act on.
        .output()
        .await
    {
        Ok(output) => {
            for line in attributed(&program, &output.stderr) {
                tracing::info!("{line}");
            }
            interpret_sweep(&program, output.status, &output.stdout)
        }
        Err(source) => Err(TickFailure::Spawn {
            program: program.clone(),
            source,
        }),
    };

    let outcome = match outcome {
        Ok(artifact) => {
            // The three counts, on one line: what was given back, what
            // the gate held, and what is still billing with nothing
            // able to stop it. Everything else in the artifact is at
            // the health endpoint.
            tracing::info!(
                released = count(&artifact, "released"),
                refused = count(&artifact, "refused"),
                failed = count(&artifact, "failed"),
                dry_run = artifact["dry_run"].as_bool().unwrap_or(config.dry_run),
                "sweep finished"
            );
            Ok(artifact)
        }
        Err(failure) => {
            tracing::error!("sweep failed: {failure}");
            Err(failure.to_string())
        }
    };

    let mut status = state.lock().await;
    record(&mut status, jiff::Timestamp::now().to_string(), outcome);
}

/// How many entries an artifact's array field holds, for the summary
/// line. A field that is not an array counts as none: the summary is a
/// convenience, and a driver whose artifact grew a different shape is
/// something the health endpoint's verbatim copy will show better than
/// a log line arguing with it.
fn count(artifact: &serde_json::Value, field: &str) -> usize {
    artifact[field].as_array().map_or(0, Vec::len)
}

/// Answer health requests on `listener` until the process ends.
///
/// The handler is deliberately dumb: it reads the request head, throws
/// it away, and returns the one document. There is no routing and no
/// method parsing because there is one consumer asking one question —
/// "is this daemon still enforcing?" — and a 404 table would only give
/// that consumer new ways to be told nothing. The head is read rather
/// than ignored so the client is not answered mid-send, which some
/// clients report as a reset connection instead of showing the body.
pub async fn serve_health(
    listener: tokio::net::TcpListener,
    config: Arc<Config>,
    state: SharedStatus,
) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // A refused connection is not a reason to stop
                // enforcing TTLs; the loop is the daemon's only way
                // back to a working endpoint.
                tracing::warn!("health endpoint could not accept a connection: {err}");
                continue;
            }
        };
        let response = {
            let status = state.lock().await;
            health_response(&health_body(&config, &status))
        };
        tokio::spawn(async move {
            let mut head = [0_u8; 1024];
            if let Err(err) = stream.read(&mut head).await {
                tracing::debug!("health request from {peer} could not be read: {err}");
            }
            if let Err(err) = stream.write_all(response.as_bytes()).await {
                tracing::debug!("health response to {peer} could not be written: {err}");
                return;
            }
            // Best effort: the response is written, and a client that
            // has already hung up cannot be told about it again.
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attributed, health, health_body, health_response, interpret_sweep, record, sweep_argv,
        Config, Status,
    };

    fn config() -> Config {
        Config {
            interval_secs: 300,
            driver: "lm-provision-driver".into(),
            acquisitions: None,
            ledger: None,
            dry_run: false,
        }
    }

    fn argv_of(config: &Config) -> Vec<String> {
        sweep_argv(config)
            .iter()
            .map(|it| it.to_string_lossy().into_owned())
            .collect()
    }

    /// **The daemon's default reaches the child as an explicit
    /// `false`.** The driver's own `--dry-run` defaults to true, so a
    /// sweep run without the flag observes; this daemon exists to
    /// enforce, and the flag is the only thing standing between those
    /// two behaviours.
    #[test]
    fn the_sweep_command_always_says_which_dry_run_it_means() {
        assert_eq!(
            argv_of(&config()),
            ["lm-provision-driver", "sweep", "--dry-run", "false"],
            "the enforcing default is passed, not left to the child's opposite one"
        );

        let observing = Config {
            dry_run: true,
            ..config()
        };
        assert_eq!(
            argv_of(&observing),
            ["lm-provision-driver", "sweep", "--dry-run", "true"],
            "and observation mode says so just as explicitly"
        );
    }

    /// The two record paths are passed through verbatim when set, and
    /// omitted when not — an omitted flag means the driver's default,
    /// which is the file the operator's own `acquire` runs wrote to.
    #[test]
    fn the_record_paths_are_passed_through_or_left_to_the_driver() {
        let both = Config {
            driver: "/opt/bin/lm-provision-driver".into(),
            acquisitions: Some("/srv/acquisitions.jsonl".into()),
            ledger: Some("/srv/ledger.jsonl".into()),
            ..config()
        };
        assert_eq!(
            argv_of(&both),
            [
                "/opt/bin/lm-provision-driver",
                "sweep",
                "--dry-run",
                "false",
                "--acquisitions",
                "/srv/acquisitions.jsonl",
                "--ledger",
                "/srv/ledger.jsonl",
            ]
        );

        let ledger_only = Config {
            ledger: Some("/srv/ledger.jsonl".into()),
            ..config()
        };
        assert!(
            !argv_of(&ledger_only).contains(&"--acquisitions".to_string()),
            "an unset path is absent, not guessed at"
        );
    }

    #[cfg(unix)]
    fn exit(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;
        // The wait status encoding: the exit code sits in the high
        // byte, a signal number in the low one.
        std::process::ExitStatus::from_raw(code << 8)
    }

    #[cfg(unix)]
    #[test]
    fn a_finished_sweep_is_read_as_its_artifact() {
        let stdout =
            br#"{"dry_run":false,"expired":2,"released":["pod-a"],"refused":[],"failed":[]}"#;
        let artifact = interpret_sweep("lm-provision-driver", exit(0), stdout)
            .expect("a zero exit with the contract's document is a good tick");
        assert_eq!(artifact["expired"], 2);
        assert_eq!(artifact["released"][0], "pod-a");
    }

    /// A sweep exits non-zero only when a machine that expired could
    /// not be released (a gate refusal exits 0), so the tick is failed
    /// before its stdout is even looked at — the alternative is a
    /// daemon reporting healthy enforcement over a machine that is
    /// still billing.
    #[cfg(unix)]
    #[test]
    fn a_nonzero_sweep_is_a_failed_tick_whatever_it_printed() {
        let stdout = br#"{"dry_run":false,"expired":1,"released":[],"refused":[],"failed":[{"id":"pod-a","reason":"no credential"}]}"#;
        let failure = interpret_sweep("lm-provision-driver", exit(1), stdout)
            .expect_err("exit 1 means a machine is still running");
        assert!(
            failure.to_string().contains("exited with"),
            "the reason names how it ended: {failure}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stdout_that_is_not_the_artifact_is_a_failed_tick_that_says_so() {
        let failure = interpret_sweep("lm-provision-driver", exit(0), b"Killed\n")
            .expect_err("the contract promises one JSON document there");
        assert!(
            failure
                .to_string()
                .contains("did not write a JSON artifact"),
            "the reason distinguishes a broken pipe from a failed sweep: {failure}"
        );
    }

    #[test]
    fn only_what_the_driver_actually_said_is_relayed() {
        assert!(attributed("lm-provision-driver", b"").is_empty());
        assert!(attributed("lm-provision-driver", b"  \n").is_empty());
        assert_eq!(
            attributed("lm-provision-driver", b"acquired pod-a\nreleased pod-a\n"),
            [
                "lm-provision-driver: acquired pod-a",
                "lm-provision-driver: released pod-a",
            ],
            "every line carries the attribution, not just the first"
        );
    }

    /// Before anything has swept, the daemon is up and nothing has
    /// gone wrong: `ok` is true and `ticks` is what says which of the
    /// two it is. The two keys that only exist when there is something
    /// to read are absent rather than null.
    #[test]
    fn the_health_document_before_the_first_sweep() {
        let status = Status::started("2026-09-01T00:00:00Z".to_string());
        let doc: serde_json::Value = serde_json::from_str(&health_body(&config(), &status))
            .expect("the health body is JSON");
        assert_eq!(doc["ok"], true);
        assert_eq!(doc["ticks"], 0);
        assert_eq!(doc["dry_run"], false);
        assert_eq!(doc["interval_secs"], 300);
        assert_eq!(doc["started_at"], "2026-09-01T00:00:00Z");
        assert_eq!(doc["last_tick_at"], serde_json::Value::Null);
        assert_eq!(doc["last_tick_ok"], serde_json::Value::Null);
        assert!(doc.get("last_tick_error").is_none());
        assert!(doc.get("last_artifact").is_none());
    }

    #[test]
    fn a_recorded_sweep_shows_up_verbatim() {
        let artifact = serde_json::json!({
            "dry_run": false,
            "expired": 1,
            "released": ["pod-a"],
            "refused": [],
            "failed": [],
        });
        let mut status = Status::started("2026-09-01T00:00:00Z".to_string());
        record(
            &mut status,
            "2026-09-01T00:05:00Z".to_string(),
            Ok(artifact.clone()),
        );

        let doc: serde_json::Value = serde_json::from_str(&health_body(&config(), &status))
            .expect("the health body is JSON");
        assert_eq!(doc["ok"], true);
        assert_eq!(doc["ticks"], 1);
        assert_eq!(doc["last_tick_at"], "2026-09-01T00:05:00Z");
        assert_eq!(doc["last_tick_ok"], true);
        assert_eq!(
            doc["last_artifact"], artifact,
            "the sweep's own document, not a summary of it"
        );
    }

    /// A failed tick is the whole point of the endpoint: `ok` false,
    /// the reason readable, and no stale artifact left under the fresh
    /// timestamp claiming a sweep happened.
    #[test]
    fn a_failed_sweep_replaces_the_last_good_one() {
        let mut status = Status::started("2026-09-01T00:00:00Z".to_string());
        record(
            &mut status,
            "2026-09-01T00:05:00Z".to_string(),
            Ok(serde_json::json!({ "released": ["pod-a"] })),
        );
        record(
            &mut status,
            "2026-09-01T00:10:00Z".to_string(),
            Err("could not run `lm-provision-driver`: No such file".to_string()),
        );

        let rendered = health(&config(), &status);
        assert!(!rendered.ok);
        assert_eq!(rendered.ticks, 2);
        assert_eq!(rendered.last_tick_at, Some("2026-09-01T00:10:00Z"));
        assert!(rendered.last_artifact.is_none());
        assert_eq!(
            rendered.last_tick_error,
            Some("could not run `lm-provision-driver`: No such file")
        );
    }

    #[test]
    fn the_response_frames_the_body_it_carries() {
        let body = r#"{"ok":true}"#;
        let response = health_response(body);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: application/json\r\n"));
        assert!(response.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(
            response.contains("Connection: close\r\n"),
            "the daemon answers and hangs up; nothing here frames a second request"
        );
        assert!(
            response.ends_with(&format!("\r\n\r\n{body}")),
            "one blank line, then the document"
        );
    }

    /// **The engine → host dependency direction is empty, and stays
    /// empty.** The license boundary is the crate boundary (there is
    /// no finer line a compiler can check), so the boundary holds only
    /// as long as no permissive manifest names this crate. That is a
    /// property of four files, and reading four files is cheaper than
    /// trusting four reviews.
    ///
    /// The check is textual on purpose: it fails on a `[dependencies]`
    /// entry, a dev-dependency, a build-dependency, an optional feature
    /// edge, and on a commented-out one that is about to be
    /// uncommented — all of which are the same mistake.
    #[test]
    fn no_permissive_crate_depends_on_the_agpl_host() {
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the host crate lives under crates/");

        for permissive in [
            "lm-provision",
            "lm-provision-driver",
            "lm-provision-mcp",
            "lm-provision-protocol",
        ] {
            let manifest = crates_dir.join(permissive).join("Cargo.toml");
            let text = std::fs::read_to_string(&manifest)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", manifest.display()));
            assert!(
                !text.contains("lm-provision-host"),
                "{} names lm-provision-host. {permissive} is dual-licensed MIT/Apache-2.0 \
                 and lm-provision-host is AGPL-3.0-or-later, so this edge relicenses \
                 {permissive}'s users. The fix is to remove the dependency — move whatever \
                 is needed across into lm-provision-protocol, which is permissive and \
                 exists for exactly this — not to edit this test.",
                manifest.display()
            );
        }
    }
}
