//! `lm-provision` binary entry point (07-cli.md).
//!
//! This is the same binary the push driver ships into the pod
//! (08-push-driver-protocol.md) — the CLI contract *is* the pod-side
//! invocation contract.

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use lm_provision::cli::{self, Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(err) = init_tracing(&cli::resolve_log_filter(&cli.log_level)) {
        eprintln!("lm-provision: failed to initialize logging: {err:#}");
        return ExitCode::from(1);
    }

    cli::run(&cli.command)
}

/// Initialize the stderr tracing subscriber from the resolved filter
/// string (07-cli.md §Global flags: `RUST_LOG` precedence is already
/// applied by [`cli::resolve_log_filter`]).
fn init_tracing(filter: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let env_filter =
        EnvFilter::try_new(filter).with_context(|| format!("invalid log filter '{filter}'"))?;
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|err| anyhow::anyhow!("tracing subscriber already initialized: {err}"))?;
    Ok(())
}
