//! `lm-provision-driver` — the reference implementation of the
//! session contract (08-push-driver-protocol.md §Session contract):
//! one invocation converges a reachable pod (steps 0-5), with
//! per-step gates as flags.
//!
//! ```sh
//! lm-provision-driver apply \
//!   --ssh root@<host>:<port> --key ~/.ssh/<key> \
//!   --profile profile.json \
//!   --artifact target/x86_64-unknown-linux-musl/release/lm-provision
//! # gates: --dry-run | --validate-only, --skip-install,
//! #        --skip-verify, --no-ledger
//! ```
//!
//! Exit code mirrors the collected apply (0 = report ok, 1 = any
//! failure, 2 = usage via clap); the collected report JSON goes to
//! stdout, the pod's stderr transcript is relayed to stderr — the
//! same stream split the binary itself contracts (chapter 07).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use lm_provision_driver::session::{self, InvokeMode, StepPlan};
use lm_provision_driver::ssh::SshTransport;

#[derive(Parser)]
#[command(
    name = "lm-provision-driver",
    about = "Push-driver session (08): ensure-binary → place-profile → hash-verify → invoke → collect → ledger"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one driver session against a pod over SSH.
    Apply(ApplyArgs),
}

#[derive(Args)]
struct ApplyArgs {
    /// SSH target as [user@]host:port (user defaults to root).
    #[arg(long = "ssh")]
    ssh: String,

    /// Identity file — explicit, no default-key fallback.
    #[arg(long = "key")]
    key: PathBuf,

    /// Local profile path (canonical text or JSON).
    #[arg(long = "profile")]
    profile: PathBuf,

    /// Local musl artifact for the ensure-binary push strategy.
    /// Required unless --skip-install.
    #[arg(long = "artifact", required_unless_present = "skip_install")]
    artifact: Option<PathBuf>,

    /// Remote directory the binary / profile land in.
    #[arg(long = "remote-dir", default_value = "/root")]
    remote_dir: PathBuf,

    /// Ledger pod_id context; defaults to the SSH host.
    #[arg(long = "pod-id")]
    pod_id: Option<String>,

    /// Gate step 0 off (binary already on the pod).
    #[arg(long = "skip-install")]
    skip_install: bool,

    /// Gate step 2 (hash-verify) off.
    #[arg(long = "skip-verify")]
    skip_verify: bool,

    /// Invoke `apply --dry-run` (Terraform-plan-like preview).
    #[arg(long = "dry-run", conflicts_with = "validate_only")]
    dry_run: bool,

    /// Invoke `validate` only (no secrets consumed, no ledger row).
    #[arg(long = "validate-only")]
    validate_only: bool,

    /// Gate step 5 (ledger append) off.
    #[arg(long = "no-ledger")]
    no_ledger: bool,

    /// Ledger file path.
    #[arg(long = "ledger")]
    ledger: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Apply(args) => run_apply(args),
    }
}

fn run_apply(args: ApplyArgs) -> ExitCode {
    let (user, host, port) = match parse_ssh_target(&args.ssh) {
        Ok(parts) => parts,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let mode = if args.validate_only {
        InvokeMode::ValidateOnly
    } else if args.dry_run {
        InvokeMode::DryRun
    } else {
        InvokeMode::Apply
    };
    let ledger = if args.no_ledger {
        None
    } else {
        Some(args.ledger.unwrap_or_else(default_ledger_path))
    };
    let plan = StepPlan {
        skip_install: args.skip_install,
        skip_verify: args.skip_verify,
        mode,
        ledger,
    };

    // With --skip-install the artifact may be absent; the session
    // still needs a local file name to derive the pod path from, so
    // fall back to the canonical binary name.
    let artifact = args
        .artifact
        .unwrap_or_else(|| PathBuf::from("lm-provision"));
    let pod_id = args.pod_id.unwrap_or_else(|| host.clone());
    let transport = SshTransport::new(host, port, user, args.key, args.remote_dir);

    match session::run(&transport, &plan, &artifact, &args.profile, &pod_id) {
        Ok(output) => {
            // Same stream split as the binary itself (chapter 07):
            // report on stdout, transcript on stderr.
            eprint!("{}", output.collected.stderr);
            println!("{}", output.collected.report);
            let ok = output.collected.report["ok"] == serde_json::Value::Bool(true);
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

/// `[user@]host:port` (user defaults to root; port is mandatory —
/// RunPod maps a per-pod external port, there is no useful default).
fn parse_ssh_target(target: &str) -> Result<(String, String, u16), String> {
    let (user, rest) = match target.split_once('@') {
        Some((user, rest)) => (user.to_string(), rest),
        None => ("root".to_string(), target),
    };
    let (host, port) = rest
        .split_once(':')
        .ok_or_else(|| format!("--ssh target {target:?} must be [user@]host:port"))?;
    if host.is_empty() {
        return Err(format!("--ssh target {target:?} has an empty host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("--ssh target {target:?} has a non-numeric port"))?;
    Ok((user, host.to_string(), port))
}

fn default_ledger_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home)
            .join(".lm-provision")
            .join("ledger.jsonl"),
        None => PathBuf::from("lm-provision-ledger.jsonl"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ssh_target;

    #[test]
    fn parse_ssh_target_accepts_user_host_port_and_defaults_root() {
        assert_eq!(
            parse_ssh_target("root@1.2.3.4:2222").unwrap(),
            ("root".to_string(), "1.2.3.4".to_string(), 2222)
        );
        assert_eq!(
            parse_ssh_target("1.2.3.4:22").unwrap(),
            ("root".to_string(), "1.2.3.4".to_string(), 22)
        );
    }

    #[test]
    fn parse_ssh_target_rejects_missing_or_bad_port_and_empty_host() {
        assert!(parse_ssh_target("1.2.3.4").is_err());
        assert!(parse_ssh_target("1.2.3.4:abc").is_err());
        assert!(parse_ssh_target("root@:22").is_err());
    }
}
