//! `lm-provision-host` — the TTL-enforcement daemon: run
//! `lm-provision-driver sweep` on a timer, and answer one question
//! about itself over HTTP.
//!
//! ```sh
//! lm-provision-host --interval-secs 300 --bind 127.0.0.1:7909
//! # observation mode: --dry-run true
//! ```
//!
//! **`--dry-run` defaults to `false` here**, the opposite of the
//! driver CLI's default. Running this daemon is the operator's consent
//! to release expired machines; the reasoning is in the library's
//! crate docs, and the flag's help text repeats it where an operator
//! will actually meet it.
//!
//! This file is the wiring only — flags, the listener, the loop. What
//! a sweep is and what the health document says lives in the library
//! beside it, where it is reachable by tests that do not need a
//! process.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use lm_provision_host::{Config, SharedStatus, Status};

#[derive(Parser)]
#[command(
    name = "lm-provision-host",
    about = "Enforce recorded pod leases without being invoked: run `lm-provision-driver sweep` every interval and report what it did"
)]
struct Cli {
    /// Seconds between sweeps.
    ///
    /// Leases are hour-grained (`acquire --ttl-hours`), so checking by
    /// the minute is already tight against them; the cost of a sweep
    /// that finds nothing is one process that reads one file.
    ///
    /// Zero is refused rather than accepted as "continuously": a timer
    /// with no period is a loop spawning the driver as fast as it can
    /// exit.
    #[arg(long = "interval-secs", default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    interval_secs: u64,

    /// The driver binary to run. A bare name is looked up on `PATH`.
    ///
    /// The daemon runs the driver rather than linking it: the CLI is
    /// the contract, and exec is what keeps this AGPL binary from
    /// depending on the permissive crates (crate docs, §Exec, not
    /// link).
    #[arg(long = "driver", default_value = "lm-provision-driver")]
    driver: PathBuf,

    /// The acquisitions record to sweep; passed to the driver
    /// verbatim. Left out, the driver uses its own default — the file
    /// this host's `acquire` runs already wrote to.
    #[arg(long = "acquisitions")]
    acquisitions: Option<PathBuf>,

    /// The ledger the release gate reads; passed to the driver
    /// verbatim, and defaulted by it for the same reason.
    #[arg(long = "ledger")]
    ledger: Option<PathBuf>,

    /// Only name what would be released, and release nothing.
    ///
    /// **Defaults to false, unlike `lm-provision-driver sweep`, whose
    /// default is true.** On the CLI, an operator asking which
    /// machines would go must not find out by them being gone.
    /// Installing a long-lived TTL-enforcement service is the opposite
    /// act: it is the consent to release expired machines, and a
    /// daemon that defaulted to observing would be the
    /// forgotten-machine problem wearing a uniform. `--dry-run true`
    /// is the observation mode. Either way the release gate inside
    /// sweep still refuses a machine whose work has not been
    /// collected.
    #[arg(long = "dry-run", default_value_t = false, action = clap::ArgAction::Set)]
    dry_run: bool,

    /// Where the health endpoint listens.
    ///
    /// Loopback by default: the document names machines and says
    /// whether enforcement is working, which is nobody else's
    /// business until an operator puts a proxy in front of it.
    #[arg(long = "bind", default_value = "127.0.0.1:7909")]
    bind: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Diagnostics on stderr, the same split the rest of the workspace
    // contracts (07 §Stream split). `info` when the environment says
    // nothing: a TTL enforcer whose default is silence gives an
    // operator no way to see it working, and the whole point of the
    // process is that nobody is watching it closely.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let bind = cli.bind.clone();
    let config = Arc::new(Config {
        interval_secs: cli.interval_secs,
        driver: cli.driver,
        acquisitions: cli.acquisitions,
        ledger: cli.ledger,
        dry_run: cli.dry_run,
    });

    // The whole configuration, once, at the top of the log. An
    // operator reading a machine's disappearance out of a log file a
    // week later needs to know what this process was told to do, and
    // the flags are on somebody's shell history at best.
    tracing::info!(
        driver = %config.driver.display(),
        interval_secs = config.interval_secs,
        dry_run = config.dry_run,
        acquisitions = config.acquisitions.as_ref().map(|it| it.display().to_string()),
        ledger = config.ledger.as_ref().map(|it| it.display().to_string()),
        bind = %bind,
        "lm-provision-host starting"
    );
    if config.dry_run {
        tracing::warn!(
            "--dry-run true: expired machines will be named and left running; \
             this daemon is not enforcing anything"
        );
    }

    // The listener first, and fail loud if the port is taken. A daemon
    // that swept but could not be asked whether it was sweeping is
    // worse than one that refuses to start: the operator who wired the
    // health check would have no way to find out it never answers.
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!("could not listen on {bind}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let state: SharedStatus = Arc::new(tokio::sync::Mutex::new(Status::started(
        jiff::Timestamp::now().to_string(),
    )));
    tokio::spawn(lm_provision_host::serve_health(
        listener,
        Arc::clone(&config),
        Arc::clone(&state),
    ));

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(config.interval_secs));
    // A sweep that overran its interval is not followed by a burst of
    // catch-up sweeps: the machines it would find are the ones the
    // slow sweep is already dealing with.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // The first tick of a tokio interval completes
            // immediately, which is the startup sweep: an operator
            // restarting this after a week with the laptop closed
            // wants enforcement now, not at the top of the next
            // interval.
            _ = ticker.tick() => lm_provision_host::tick(&config, &state).await,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("stopping; machines already released stay released");
                return ExitCode::SUCCESS;
            }
        }
    }
}
