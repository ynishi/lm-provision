//! `lm-provision-driver` — the reference implementation of the
//! session contract (08-push-driver-protocol.md §Session contract),
//! plus the machine side around it. Four subcommands: `apply`
//! converges a reachable pod (steps 0-5) with per-step gates as
//! flags, `acquire` obtains a machine that meets a profile's
//! requirements, `release` gives one back, `check` judges an
//! existing machine against a profile.
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
//! Exit codes, across all subcommands: 0 = the run produced its
//! artifact (an apply report, an acquisition, a release, a satisfied
//! verdict); 1 = the run failed, or `check` found the machine
//! wanting; 2 = the input could not be used (usage via clap, an
//! unreadable or invalid profile, a description that is not JSON, an
//! unrenderable acquisition); 3 = `acquire` refused at admission,
//! before anything was spent; 4 = a credential was missing (`acquire`
//! before creating; `release` while the machine keeps running and
//! billing). The artifact JSON goes to stdout, diagnostics and the
//! pod's stderr transcript to stderr — the same stream split the
//! binary itself contracts (chapter 07).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use lm_provision_driver::credentials;
use lm_provision_driver::infra::{self, Infra as _, RunPodAdapter};
use lm_provision_driver::session::{self, InvokeMode, StepPlan};
use lm_provision_driver::ssh::{SshTransport, DEFAULT_REMOTE_DIR, DEFAULT_SSH_USER};

#[derive(Parser)]
#[command(
    name = "lm-provision-driver",
    about = "Obtain a machine a profile requires (acquire / release / check), and converge one over SSH (apply: ensure-binary → place-profile → hash-verify → invoke → collect → ledger)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one driver session against a pod over SSH.
    Apply(ApplyArgs),
    /// Obtain a machine that meets a profile's requirements.
    ///
    /// **This spends money.** It is a subcommand of its own rather than
    /// a flag on `apply` so that acquiring is something asked for, never
    /// something that happens on the way to something else.
    Acquire(AcquireArgs),
    /// Give a machine back.
    Release(ReleaseArgs),
    /// Judge a machine that already exists against a profile.
    ///
    /// Reads a description the service gave and says, requirement by
    /// requirement, whether the machine is what the profile asked for.
    /// Nothing is created and nothing is destroyed.
    Check(CheckArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// The profile whose requirements to judge against.
    #[arg(long = "profile")]
    profile: PathBuf,

    /// A file holding what the service said about the machine.
    #[arg(long = "inspected")]
    inspected: PathBuf,
}

#[derive(Args)]
struct AcquireArgs {
    /// Path to the profile whose requirements describe the machine.
    #[arg(long = "profile")]
    profile: PathBuf,

    /// Show the request that would be sent, and send nothing.
    ///
    /// The default, because the other behaviour creates something
    /// billable: an operator asking what this would do should not find
    /// out by it having happened.
    #[arg(long = "dry-run", default_value_t = true, action = clap::ArgAction::Set)]
    dry_run: bool,
}

#[derive(Args)]
struct ReleaseArgs {
    /// The identifier the service gave the machine.
    #[arg(long = "id")]
    id: String,

    /// The profile the machine was acquired from, which is where the
    /// release command comes from.
    #[arg(long = "profile")]
    profile: PathBuf,
}

#[derive(Args)]
struct ApplyArgs {
    /// SSH target as `[user@]host:port` (user defaults to
    /// [`DEFAULT_SSH_USER`]).
    ///
    /// The `--help` text is built from that constant rather than
    /// spelling the default a second time, so the documented default
    /// and [`parse_ssh_target`]'s fallback cannot drift apart.
    #[arg(long = "ssh", help = ssh_help())]
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
    #[arg(long = "remote-dir", default_value = DEFAULT_REMOTE_DIR)]
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
    // Before the command runs, so every subcommand sees the same
    // environment — a key that works for `acquire` and not for
    // `release` would strand a machine.
    credentials::load();

    let cli = Cli::parse();
    match cli.command {
        Command::Apply(args) => run_apply(args),
        Command::Acquire(args) => run_acquire(args),
        Command::Release(args) => run_release(args),
        Command::Check(args) => run_check(args),
    }
}

fn run_check(args: CheckArgs) -> ExitCode {
    let (required, _) = match requirements_of(&args.profile) {
        Ok(parts) => parts,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let text = match std::fs::read_to_string(&args.inspected) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: reading {}: {err}", args.inspected.display());
            return ExitCode::from(2);
        }
    };
    let inspected: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("error: {} is not JSON: {err}", args.inspected.display());
            return ExitCode::from(2);
        }
    };

    let state = RunPodAdapter.read_state(&inspected);
    let findings = lm_provision::machine::observe(&required, &state);
    let verdict = lm_provision::machine::verdict(&findings);
    println!(
        "{}",
        serde_json::json!({
            "verdict": format!("{verdict:?}"),
            "findings": findings
                .iter()
                .map(|it| serde_json::json!({
                    "requirement": it.requirement,
                    "outcome": format!("{:?}", it.outcome),
                }))
                .collect::<Vec<_>>(),
        })
    );
    match verdict {
        lm_provision::machine::Outcome::Satisfied => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Read a profile and render what its requirements ask of a machine.
///
/// Validate runs first, so an unreadable requirement is refused here
/// rather than after a machine exists to be refused against.
fn requirements_of(
    profile: &std::path::Path,
) -> Result<
    (
        lm_provision::machine::Requirements,
        BTreeMap<String, String>,
    ),
    String,
> {
    let root = lm_provision::frontend::load_profile(profile).map_err(|err| err.to_string())?;
    lm_provision::validate::validate(&root).map_err(|err| err.to_string())?;
    let lm_provision::profile_ast::ProfileNode::Spec {
        requires_ports,
        requires_gpu,
        requires_disk,
        requires_image,
        provider,
        ..
    } = &root
    else {
        return Err("the profile's root is not a Spec".to_string());
    };
    let required = lm_provision::machine::Requirements::from_slots(
        requires_ports,
        requires_gpu,
        requires_disk,
        requires_image.as_deref(),
    )
    .map_err(|err| err.to_string())?;
    Ok((required, provider.clone()))
}

fn run_acquire(args: AcquireArgs) -> ExitCode {
    let (required, provider) = match requirements_of(&args.profile) {
        Ok(parts) => parts,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let adapter = RunPodAdapter;
    // Admission before anything is spent: a target that could never
    // satisfy this should say so while the bill is still zero.
    if let Err(refusal) = lm_provision::machine::admit(&required, &adapter.capability()) {
        eprintln!("error: {refusal}");
        return ExitCode::from(3);
    }

    let acquisition = match adapter.acquisition(&required, &provider) {
        Ok(acquisition) => acquisition,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    if args.dry_run {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": true,
                "create": acquisition.create,
                "body": acquisition.body,
                "release": acquisition.release,
            })
        );
        return ExitCode::SUCCESS;
    }

    // Past the dry-run branch, so rendering a request never demands a
    // key — and before anything runs, so a missing one costs nothing.
    // Discovering it half way through an acquisition means discovering
    // it after the machine exists.
    if let Err(missing) = credentials::require(adapter.provider_namespace(), adapter.credentials())
    {
        eprintln!("error: {missing}");
        return ExitCode::from(4);
    }

    let mut acquired = match infra::acquire(acquisition) {
        Ok(acquired) => acquired,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // The id goes out before anything else can fail. A machine that
    // exists and whose identifier was never printed is a bill nobody can
    // stop.
    //
    // On stderr, because it is a trace and not the artifact: 08 §Outputs
    // gives stdout "exactly one JSON apply report", and this line used to
    // make acquire the one subcommand that emitted two documents there
    // [measured: 2026-08-12, a successful acquire printed `{"id":...}` and
    // then the verdict object]. The id is in the artifact too, so nothing
    // is lost for a caller that gets that far; what this covers is the
    // caller that does not.
    eprintln!("acquired {}", acquired.id);

    if let Err(err) = acquired.inspect() {
        eprintln!(
            "warning: created {} but could not inspect it: {err}",
            acquired.id
        );
        return ExitCode::FAILURE;
    }

    let state = adapter.read_state(&acquired.inspected);
    let findings = lm_provision::machine::observe(&required, &state);
    let verdict = lm_provision::machine::verdict(&findings);
    println!(
        "{}",
        serde_json::json!({
            "id": acquired.id,
            "verdict": format!("{verdict:?}"),
            "findings": findings
                .iter()
                .map(|it| serde_json::json!({
                    "requirement": it.requirement,
                    "outcome": format!("{:?}", it.outcome),
                }))
                .collect::<Vec<_>>(),
            "release": acquired.id,
        })
    );

    match verdict {
        lm_provision::machine::Outcome::Satisfied => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn run_release(args: ReleaseArgs) -> ExitCode {
    let (required, provider) = match requirements_of(&args.profile) {
        Ok(parts) => parts,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let acquisition = match RunPodAdapter.acquisition(&required, &provider) {
        Ok(acquisition) => acquisition,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    // The worst place to be short a credential. Acquiring without one
    // fails and costs nothing; releasing without one leaves a machine
    // running and billing, so say so plainly rather than through the
    // service CLI's exit status.
    if let Err(missing) = credentials::require(
        RunPodAdapter.provider_namespace(),
        RunPodAdapter.credentials(),
    ) {
        eprintln!("error: {missing}");
        eprintln!("note: {} is still running", args.id);
        return ExitCode::from(4);
    }

    let argv: Vec<String> = acquisition
        .release
        .iter()
        .map(|it| it.replace("{id}", &args.id))
        .collect();

    // Captured, not inherited. Letting the service CLI write to this
    // process's stdout put its output in the artifact stream: a release
    // printed the service's `""` and then this command's own JSON, two
    // documents where 07-cli.md §Stream split allows "exactly one
    // machine-readable artifact per run" [measured: 2026-08-12, a release
    // against a real pod].
    match std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
    {
        Ok(output) if output.status.success() => {
            relay(&output.stdout);
            relay(&output.stderr);
            println!("{}", serde_json::json!({ "released": args.id }));
            ExitCode::SUCCESS
        }
        Ok(output) => {
            relay(&output.stdout);
            relay(&output.stderr);
            eprintln!("error: release exited with {}", output.status);
            eprintln!("note: {} may still be running", args.id);
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("error: could not run the release: {err}");
            eprintln!("note: {} is still running", args.id);
            ExitCode::FAILURE
        }
    }
}

/// Put what the service said on stderr, if it said anything.
fn relay(bytes: &[u8]) {
    for line in attributed(bytes) {
        eprintln!("{line}");
    }
}

/// What the service said, one line each, prefixed with the program that
/// said it.
///
/// `program: message` is the GNU convention for a non-interactive
/// program's messages [documented:
/// <https://www.gnu.org/prep/standards/html_node/Errors.html>], and the
/// program here is the service CLI rather than this one — the operator
/// is being shown somebody else's words and needs to know it. Both of
/// the child's streams get the same prefix: which of its two streams a
/// line came out of is this program's plumbing, not information about
/// the release.
///
/// The bracketed and pipe-delimited forms (`[pod/name] line`,
/// `service-1 | line`) belong to multiplexers, where the prefix picks
/// one source out of several [documented: kubectl `--prefix`, Docker
/// Compose logs]. There is one source here.
///
/// **Silence is not reported.** "When a program has nothing surprising
/// to say, it should say nothing" [documented: Raymond, *The Art of Unix
/// Programming*, Rule of Silence] — a line on every release announcing
/// that the service returned nothing would spend the operator's
/// attention to repeat what the exit status already said.
fn attributed(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    // `""` is what the service returns from a release: a JSON document
    // holding an empty string, which is a body with nothing in it.
    if text.is_empty() || text == "\"\"" {
        return Vec::new();
    }
    text.lines()
        .map(|line| format!("runpod-cli: {line}"))
        .collect()
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
            // 09 §Error surface's "do not swallow" is discharged here:
            // the session hands a failed step-5 append back as a
            // warning (it will not throw the report away), and this is
            // the caller that has to make the missing row visible.
            if let Some(warning) = &output.ledger_warning {
                eprintln!("error: ledger append failed: {warning}");
            }
            let ok = output.collected.report["ok"] == serde_json::Value::Bool(true);
            ExitCode::from(exit_status(ok, output.ledger_warning.as_deref()))
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

/// The exit code a completed session maps to: `0` only when the apply
/// reported `ok` **and** step 5 recorded it.
///
/// An unrecorded apply is not a success to report as one (09 §Error
/// surface: "an apply is not 'unrecorded-successful' — drivers must
/// treat append failure as an operational error to retry"), so a
/// `ledger_warning` costs the zero exit even when the report itself is
/// `ok`. The report still goes to stdout: an operator retrying the
/// append needs to know what it was.
fn exit_status(report_ok: bool, ledger_warning: Option<&str>) -> u8 {
    if report_ok && ledger_warning.is_none() {
        0
    } else {
        1
    }
}

/// `--ssh` help text, built from [`DEFAULT_SSH_USER`] so the CLI's
/// documented default is the same value [`parse_ssh_target`] falls
/// back to.
fn ssh_help() -> String {
    format!("SSH target as [user@]host:port (user defaults to {DEFAULT_SSH_USER})")
}

/// `[user@]host:port` (user defaults to [`DEFAULT_SSH_USER`]; port is
/// mandatory — RunPod maps a per-pod external port, there is no useful
/// default).
fn parse_ssh_target(target: &str) -> Result<(String, String, u16), String> {
    let (user, rest) = match target.split_once('@') {
        Some((user, rest)) => (user.to_string(), rest),
        None => (DEFAULT_SSH_USER.to_string(), target),
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
    use super::{attributed, exit_status, parse_ssh_target, ssh_help, Cli, Command, PathBuf};
    use clap::Parser as _;
    use lm_provision_driver::ssh::{DEFAULT_REMOTE_DIR, DEFAULT_SSH_USER};

    /// **What the service says goes to stderr, in `program: message`
    /// form, and only when it says something.**
    ///
    /// 07-cli.md §Stream split gives stdout "exactly one
    /// machine-readable artifact per run", so a subprocess's output
    /// cannot go there — a release used to print the service's `""`
    /// and then this command's own JSON, two documents in the artifact
    /// stream [measured: 2026-08-12, a release against a real pod].
    #[test]
    fn only_what_the_service_actually_said_is_relayed() {
        assert!(attributed(b"").is_empty());
        assert!(attributed(b"   \n").is_empty());
        assert!(
            attributed(b"\"\"\n").is_empty(),
            "an empty JSON string is a body with nothing in it"
        );

        assert_eq!(
            attributed(b"warning: pod was already gone\n"),
            vec!["runpod-cli: warning: pod was already gone"],
            "the GNU form: the program that said it, a colon, the message"
        );
        assert_eq!(
            attributed(b"first\nsecond\n"),
            vec!["runpod-cli: first", "runpod-cli: second"],
            "every line carries the attribution, not just the first"
        );
    }

    /// The CLI's two "default" spellings — `--remote-dir`'s clap
    /// default and `--ssh`'s user fallback — must be the very
    /// constants the SSH transport publishes, not copies of them: the
    /// MCP pod target registry fills the same two holes from the same
    /// source, and a drifting copy here would put a driver session and
    /// a registry entry on different remote directories / users while
    /// both claim the "default".
    #[test]
    fn cli_defaults_are_the_shared_ssh_constants() {
        let cli = Cli::parse_from([
            "lm-provision-driver",
            "apply",
            "--ssh",
            "1.2.3.4:22",
            "--key",
            "/k",
            "--profile",
            "profile.json",
            "--skip-install",
        ]);
        let Command::Apply(args) = cli.command else {
            panic!("the parsed subcommand is `apply`");
        };
        assert_eq!(args.remote_dir, PathBuf::from(DEFAULT_REMOTE_DIR));

        let (user, _, _) = parse_ssh_target("1.2.3.4:22").expect("host:port parses");
        assert_eq!(user, DEFAULT_SSH_USER);
        assert!(
            ssh_help().contains(DEFAULT_SSH_USER),
            "--help must document the same default it applies"
        );
    }

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

    /// The session no longer fails when step 5's append fails — it
    /// returns the report plus a warning. This is where that warning
    /// stops being swallowable: an `ok` report whose ledger row is
    /// missing exits `1`, so a caller scripting the driver sees the
    /// unrecorded apply without having to parse stderr.
    #[test]
    fn an_ok_report_with_a_failed_ledger_append_still_exits_nonzero() {
        assert_eq!(exit_status(true, None), 0);
        assert_eq!(exit_status(true, Some("ledger i/o error: no such file")), 1);
        assert_eq!(exit_status(false, None), 1);
        assert_eq!(
            exit_status(false, Some("ledger i/o error: no such file")),
            1
        );
    }
}
