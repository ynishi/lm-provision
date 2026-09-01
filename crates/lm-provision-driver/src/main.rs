//! `lm-provision-driver` — the reference implementation of the
//! session contract (08-push-driver-protocol.md §Session contract),
//! plus the machine side around it. Five subcommands: `apply`
//! converges a reachable pod (steps 0-5) with per-step gates as
//! flags, `acquire` obtains a machine that meets a profile's
//! requirements, `release` gives one back, `sweep` gives back every
//! machine whose lease has run out — from the platform's own list of
//! what it is running with `--provider`, and from the acquisitions
//! record either way — `check` judges an existing machine against a
//! profile.
//!
//! ```sh
//! lm-provision-driver apply \
//!   --ssh root@<host>:<port> --key ~/.ssh/<key> \
//!   --profile profile.json \
//!   --artifact target/x86_64-unknown-linux-musl/release/lm-provision
//! # gates: --dry-run | --validate-only, --skip-install,
//! #        --skip-verify, --no-artifacts, --no-ledger
//! ```
//!
//! Exit codes, across all subcommands: 0 = the run produced its
//! artifact (an apply report, an acquisition, a release, a satisfied
//! verdict); 1 = the run failed, or `check` found the machine
//! wanting; 2 = the input could not be used (usage via clap, an
//! unreadable or invalid profile, a description that is not JSON, an
//! unrenderable acquisition); 3 = a refusal before anything was spent
//! or destroyed (`acquire` at admission; `release` while the ledger
//! records uncollected artifacts on the machine); 4 = a credential
//! was missing (`acquire` before creating; `release` while the
//! machine keeps running and billing). `sweep` deals with many
//! machines in one run and so reports per machine rather than by exit
//! class: 0 when every expired machine was released or refused by the
//! gate, 1 when one of them could not be released. The artifact JSON goes to
//! stdout, diagnostics and the pod's stderr transcript to stderr —
//! the same stream split the binary itself contracts (chapter 07).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use lm_provision_driver::acquisition::{self as record, AcquisitionRow};
use lm_provision_driver::credentials;
use lm_provision_driver::infra::{self, Infra, RunPodAdapter, VastAdapter};
use lm_provision_driver::session::{self, InvokeMode, StepPlan};
use lm_provision_driver::ssh::{SshTransport, DEFAULT_REMOTE_DIR, DEFAULT_SSH_USER};

#[derive(Parser)]
#[command(
    name = "lm-provision-driver",
    about = "Obtain a machine a profile requires (acquire / release / sweep / check), and converge one over SSH (apply: ensure-binary → place-profile → hash-verify → invoke → collect → pull-artifacts → ledger)"
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
    /// Give back every machine whose lease has run out.
    ///
    /// With `--provider`, the platform's own list is the inventory and
    /// the lease is read off each machine's name — so a machine this
    /// host has no record of is still found. Without it, the
    /// acquisitions record is the list, which is what still reaches
    /// machines created before leases were stamped onto them.
    Sweep(SweepArgs),
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

    /// Which platform's adapter reads the description (`runpod`,
    /// `vast`) — each service writes its own field names.
    #[arg(long = "provider", default_value = "runpod")]
    provider: String,
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

    /// Which platform to buy from (`runpod`, `vast`).
    ///
    /// The operator's choice, not the profile's: the profile says what
    /// the machine must be, and where to buy one meeting it is decided
    /// at acquisition time — today's prices and today's stock are not
    /// facts a profile could carry.
    #[arg(long = "provider", default_value = "runpod")]
    provider: String,

    /// How long the machine is being bought for, in hours.
    ///
    /// **Recorded, not enforced by this command**, which exits long
    /// before the hours pass — what acts on it is a later `sweep`
    /// (08 §Acquisitions and sweep).
    ///
    /// There is no way to acquire without one: the fleet is ephemeral
    /// by design, and an opt-out flag would be a machine nothing ever
    /// comes back for. A longer lease is a number, not a special case.
    #[arg(long = "ttl-hours", default_value_t = 24)]
    ttl_hours: u64,

    /// The acquisitions record this machine is written to
    /// (09 §Acquisitions record); defaults to
    /// `~/.lm-provision/acquisitions.jsonl`.
    #[arg(long = "acquisitions")]
    acquisitions: Option<PathBuf>,
}

#[derive(Args)]
struct SweepArgs {
    /// Ask this platform what it is running, and judge those machines
    /// by the lease stamped on each one (`runpod`, `vast`). Repeatable.
    ///
    /// **This is the inventory when it is given.** A machine whose
    /// acquisitions row was never written, was written on another host,
    /// or was lost is still on the platform's list, and the expiry is
    /// on the machine's own name — so anything holding the account's
    /// key can enforce the lease with no file to keep in step.
    ///
    /// A machine carrying no `lmp-exp-` stamp is **reported and never
    /// released**: this tool did not create it, and a sweeper deleting
    /// what it does not recognise is the accident, not the enforcement.
    ///
    /// Listing needs the platform's credential even under
    /// `--dry-run true` — the key buys the question here, not the kill.
    #[arg(long = "provider")]
    providers: Vec<String>,

    /// The acquisitions record to sweep (09 §Acquisitions record);
    /// defaults to `~/.lm-provision/acquisitions.jsonl`.
    ///
    /// Read whether or not `--provider` is given: it is the audit trail
    /// of what this host bought, and it is what still reaches machines
    /// created before the lease was stamped onto the machine itself.
    #[arg(long = "acquisitions")]
    acquisitions: Option<PathBuf>,

    /// Ledger the release gate reads for each expired machine
    /// (08 §Release gate).
    #[arg(long = "ledger")]
    ledger: Option<PathBuf>,

    /// Name what would be released, and release nothing.
    ///
    /// The default, for the reason `acquire`'s is: this command
    /// destroys machines, and an operator asking which ones should not
    /// find out by them being gone.
    #[arg(long = "dry-run", default_value_t = true, action = clap::ArgAction::Set)]
    dry_run: bool,
}

#[derive(Args)]
struct ReleaseArgs {
    /// The identifier the service gave the machine.
    #[arg(long = "id")]
    id: String,

    /// The platform the machine was acquired from (`runpod`, `vast`).
    #[arg(long = "provider", default_value = "runpod")]
    provider: String,

    /// The profile the machine was acquired from, which is where the
    /// release command comes from.
    #[arg(long = "profile")]
    profile: PathBuf,

    /// Ledger the release gate reads (08 §Release gate): the newest
    /// real apply recorded for this machine must have every declared
    /// artifact collected, or the release is refused.
    #[arg(long = "ledger")]
    ledger: Option<PathBuf>,

    /// Release even though the ledger records uncollected artifacts.
    /// What is still on the machine is deleted with it.
    #[arg(long = "force")]
    force: bool,

    /// The acquisitions record the correction row is appended to
    /// (09 §Acquisitions record); defaults to
    /// `~/.lm-provision/acquisitions.jsonl`.
    #[arg(long = "acquisitions")]
    acquisitions: Option<PathBuf>,
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

    /// Operator-host directory declared artifacts are pulled under
    /// (step 4b lands each at `<dir>/<pod-id>/<pod path>`).
    #[arg(long = "artifacts-dir", default_value = "artifacts")]
    artifacts_dir: PathBuf,

    /// Gate step 4b (pull-artifacts) off. The profile's declared
    /// artifacts are still recorded on the ledger row as uncollected —
    /// the release gate stays armed until something pulls them.
    #[arg(long = "no-artifacts")]
    no_artifacts: bool,
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
        Command::Sweep(args) => run_sweep(args),
        Command::Check(args) => run_check(args),
    }
}

fn run_check(args: CheckArgs) -> ExitCode {
    let ProfileFacts { required, .. } = match requirements_of(&args.profile) {
        Ok(facts) => facts,
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

    let adapter = match adapter_named(&args.provider) {
        Ok(adapter) => adapter,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let state = adapter.read_state(&inspected);
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

/// The adapter sold under `name`, or which names would have worked.
///
/// A static reference rather than a box because the adapters are unit
/// structs: there is nothing to construct, only one of two vocabularies
/// to speak.
fn adapter_named(name: &str) -> Result<&'static dyn Infra, String> {
    match name {
        "runpod" => Ok(&RunPodAdapter),
        "vast" => Ok(&VastAdapter),
        other => Err(format!("unknown provider `{other}` (runpod, vast)")),
    }
}

/// What the machine-side subcommands read out of a profile before
/// touching a provider.
struct ProfileFacts {
    /// What the profile asks of a machine.
    required: lm_provision::machine::Requirements,
    /// The target-specific settings the profile carries.
    provider: BTreeMap<String, String>,
    /// The profile's canonical hash (03 §hash) — the same digest a
    /// ledger row stamps, so an acquisitions row can say what the
    /// machine was bought to run.
    hash: String,
}

/// Read a profile and render what its requirements ask of a machine.
///
/// Validate runs first, so an unreadable requirement is refused here
/// rather than after a machine exists to be refused against.
///
/// The hash comes back with the requirements rather than from a second
/// read: they are two answers to one question about one file, and a
/// caller re-loading the profile to get the digest could stamp a row
/// with a hash of bytes that changed in between.
fn requirements_of(profile: &std::path::Path) -> Result<ProfileFacts, String> {
    let root = lm_provision::frontend::load_profile(profile).map_err(|err| err.to_string())?;
    lm_provision::validate::validate(&root).map_err(|err| err.to_string())?;
    let hash = lm_provision::canonical::hash(&root);
    let lm_provision::profile_ast::ProfileNode::Spec {
        requires_ports,
        requires_gpu,
        requires_disk,
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
    )
    .map_err(|err| err.to_string())?;
    Ok(ProfileFacts {
        required,
        provider: provider.clone(),
        hash,
    })
}

fn run_acquire(args: AcquireArgs) -> ExitCode {
    let ProfileFacts {
        required,
        provider,
        hash: profile_hash,
    } = match requirements_of(&args.profile) {
        Ok(facts) => facts,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    // The lease is turned into a span here, at the input, rather than
    // where the row is stamped: a `--ttl-hours` too large to add to a
    // timestamp is a usage error, and the one place it must not
    // surface is after the machine exists.
    let ttl = match i64::try_from(args.ttl_hours)
        .map_err(|err| err.to_string())
        .and_then(|hours| {
            jiff::Span::new()
                .try_hours(hours)
                .map_err(|err| err.to_string())
        }) {
        Ok(ttl) => ttl,
        Err(message) => {
            eprintln!(
                "error: --ttl-hours {} is not a lease: {message}",
                args.ttl_hours
            );
            return ExitCode::from(2);
        }
    };

    let adapter = match adapter_named(&args.provider) {
        Ok(adapter) => adapter,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    // Admission before anything is spent: a target that could never
    // satisfy this should say so while the bill is still zero.
    if let Err(refusal) = lm_provision::machine::admit(&required, &adapter.capability()) {
        eprintln!("error: {refusal}");
        return ExitCode::from(3);
    }

    // The lease is read off the clock **here**, before the request is
    // rendered, because the machine and the record have to carry the
    // same one: the create call writes `expires_at` onto the machine as
    // its name (08 §Acquisitions and sweep), and the row below writes
    // the same instant down. Two clock readings would be two leases
    // disagreeing by however long the create took, and the sweeper
    // believes the one on the machine.
    let acquired_at = jiff::Timestamp::now();
    let expires_at = match acquired_at.checked_add(ttl) {
        Ok(expires_at) => expires_at,
        Err(err) => {
            // Validated at the input, so reaching this means the clock
            // is somewhere no lease can be added to. An expiry equal to
            // the acquisition is a machine a sweep will offer to
            // release, which is the safe way to be wrong here.
            eprintln!(
                "warning: could not stamp an expiry {} hours out: {err}",
                args.ttl_hours
            );
            acquired_at
        }
    };

    let acquisition = match adapter.acquisition(&required, &provider, Some(expires_at)) {
        Ok(acquisition) => acquisition,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    if args.dry_run {
        println!("{}", dry_run_artifact(&acquisition));
        // Nothing was created, so nothing is recorded: an acquisitions
        // row for a machine that does not exist would put a sweep on a
        // hunt for it.
        return ExitCode::SUCCESS;
    }

    // Kept before [`infra::acquire`] takes the acquisition, because the
    // row this run must leave behind carries the release template
    // verbatim — a sweep weeks from now releases the machine from what
    // was recorded at purchase, not from re-rendering a profile that may
    // have moved on since.
    let release_template = acquisition.release.clone();

    // The image's registry is asked before the machine exists to pull
    // it and fail: a platform that accepts a create naming a manifest
    // that is not there leaves a host retrying `manifest unknown`
    // forever, on billing [measured: 2026-08-30, instance 49228600].
    // Only a definitive "not there" refuses — a registry this check
    // cannot ask (private auth, no network) is noted and stepped past,
    // because refusing over an unanswerable question would cost more
    // than the failure it prevents.
    if let Some(image) = adapter.image_key().and_then(|key| provider.get(key)) {
        match lm_provision_driver::image::manifest_check(image) {
            lm_provision_driver::image::Manifest::Present => {}
            lm_provision_driver::image::Manifest::Absent { registry } => {
                eprintln!(
                    "error: image {image} is not in {registry} (manifest unknown); a machine \
                     created for it would retry the pull forever while billing"
                );
                return ExitCode::from(3);
            }
            lm_provision_driver::image::Manifest::Undetermined { reason } => {
                eprintln!("note: could not preflight image {image}: {reason}; proceeding");
            }
        }
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

    // Recorded here, before the wait below — which can run twenty
    // minutes and can be interrupted at any point in them. The row is
    // the audit trail: who bought this, when, under what profile, and
    // how it was given back. What *enforces* the lease is the stamp the
    // create call above put on the machine, so a row that fails to land
    // no longer means a machine nothing will come back for.
    let acquisitions_path = args
        .acquisitions
        .clone()
        .unwrap_or_else(default_acquisitions_path);
    let row = AcquisitionRow {
        id: acquired.id.clone(),
        provider: args.provider.clone(),
        acquired_at: acquired_at.to_string(),
        expires_at: expires_at.to_string(),
        profile_hash,
        release: release_template,
        released_at: None,
    };
    if let Err(err) = record_acquisition(&acquisitions_path, &row) {
        // Not an exit code, and not a failure: the machine exists and
        // billing has started, and a command that reported that as a
        // failure would invite a caller to treat it as "nothing
        // happened". What the operator needs is the id and the reason
        // the host does not have it, on the stream that survives a
        // caller reading only stdout.
        eprintln!(
            "error: could not record {} in {}: {err}",
            acquired.id,
            acquisitions_path.display()
        );
        // The whole command, with this run's own arguments in it: the
        // operator reading this has a machine to give back and no
        // record to give it back from, and a half-written example
        // would cost them another round trip to find the rest.
        eprintln!(
            "note: {} is running and unrecorded — no sweep will find it; \
             release it with `lm-provision-driver release --id {} --provider {} --profile {}`",
            acquired.id,
            acquired.id,
            args.provider,
            args.profile.display()
        );
    }

    // A failed first inspection is boot-time raggedness until the
    // deadline says otherwise — a description asked for seconds after
    // create can be an error or empty on a machine that answers
    // moments later. Warned and carried into the wait below, which
    // retries; the machine is not condemned on one unanswered question
    // while the loop built to tolerate exactly this has not run.
    if let Err(err) = acquired.inspect() {
        eprintln!(
            "warning: created {} but could not inspect it yet; retrying while waiting: {err}",
            acquired.id
        );
    }

    // Wait until the platform has answered for every declared port —
    // bounded, so a machine that never comes up still ends in a report.
    // Two reasons this wait is the driver's and not the caller's:
    // the address is part of the acquire artifact (a caller re-deriving
    // it has to arrange the service credential in its own shell for a
    // fact the driver already paid to learn), and a verdict judged
    // mid-boot refuses machines that were merely still starting
    // [measured: 2026-08-30, a CPU pod inspected right after create
    // exited 1 and reported no address; the same pod answered both a
    // few minutes later].
    let started = std::time::Instant::now();
    let deadline = started + ACQUIRE_REACHABILITY_TIMEOUT;
    let cap = started + ACQUIRE_MATERIALIZING_CAP;
    let mut extended = false;
    let mut connection = adapter.connection(&acquired.inspected);
    while !connection_covers(&required.ports, &connection) {
        let now = std::time::Instant::now();
        if now >= deadline {
            // The deadline is for a machine that went quiet, and a
            // machine the platform still calls *loading* is not quiet —
            // it is answering, with "not yet". Judging it at the base
            // deadline reported NotChecked on hardware that was merely
            // mid-pull [measured: 2026-08-30, a multi-gigabyte image was
            // still loading at 300s]. The cap keeps the extension from
            // becoming an unbounded bill when loading never ends.
            if now < cap && adapter.still_materializing(&acquired.inspected) {
                if !extended {
                    extended = true;
                    eprintln!(
                        "note: {} says it is still materializing after {}s; \
                         waiting up to {}s for it",
                        acquired.id,
                        ACQUIRE_REACHABILITY_TIMEOUT.as_secs(),
                        ACQUIRE_MATERIALIZING_CAP.as_secs()
                    );
                }
            } else {
                eprintln!(
                    "warning: {} still has unanswered ports after {}s; reporting what is known",
                    acquired.id,
                    now.duration_since(started).as_secs()
                );
                break;
            }
        }
        std::thread::sleep(ACQUIRE_REACHABILITY_POLL);
        if let Err(err) = acquired.inspect() {
            // Warned per attempt and retried until the deadline, the
            // same tolerance the port wait extends: a transient error
            // is indistinguishable from a machine mid-boot, and the
            // loop is already bounded.
            eprintln!(
                "warning: {} answered inspection with an error; retrying: {err}",
                acquired.id
            );
            continue;
        }
        connection = adapter.connection(&acquired.inspected);
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
            "connection": connection,
            "release": acquired.id,
        })
    );

    match verdict {
        lm_provision::machine::Outcome::Satisfied => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// How long `acquire` waits for the machine to answer for its declared
/// ports before reporting what is known. Generous against the minute
/// or two a pod takes to come up [measured: 2026-08-30, two fresh
/// pods each answered for port 22 within ~2 minutes of create],
/// bounded so a machine that never answers still ends in a report
/// rather than a hang.
const ACQUIRE_REACHABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The interval between inspections while waiting.
const ACQUIRE_REACHABILITY_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// How long the wait may run in total while the platform itself says
/// the machine is still materializing (`Infra::still_materializing`) —
/// the bound on trusting that claim, so a machine stuck at "loading"
/// forever is still a bounded bill. Sized for a multi-gigabyte image
/// pulled by a marketplace host that has never seen it [measured:
/// 2026-08-30, a pytorch image was still loading when the base 300s
/// expired; such pulls run minutes, not tens of minutes].
const ACQUIRE_MATERIALIZING_CAP: std::time::Duration = std::time::Duration::from_secs(1200);

/// What `acquire --dry-run` puts on stdout: the request, exactly as it
/// would be sent.
///
/// **Including the lease stamped onto the machine** — the `name` in the
/// body or the `--label` in the argv (08 §Acquisitions and sweep). An
/// operator asking what this would do is asking about the request, and
/// the part of the request that decides whether the machine can ever be
/// found again by a sweeper is the part that most needs showing.
fn dry_run_artifact(acquisition: &infra::Acquisition) -> serde_json::Value {
    serde_json::json!({
        "dry_run": true,
        "discover": acquisition.discover,
        "create": acquisition.create,
        "body": acquisition.body,
        "release": acquisition.release,
    })
}

/// Whether the platform has answered for every port the profile
/// declared — the condition `acquire` waits on. No declared ports is
/// covered by definition: there is nothing to wait for.
fn connection_covers(
    required: &[lm_provision::machine::PortRequirement],
    connection: &infra::Connection,
) -> bool {
    required
        .iter()
        .all(|it| connection.endpoints.contains_key(&it.port))
}

fn run_release(args: ReleaseArgs) -> ExitCode {
    // The release gate (08 §Release gate), before anything else: a
    // machine whose newest real apply left declared artifacts
    // uncollected still carries the run's work product, and deleting
    // it deletes them. Refused at admission — nothing has been
    // destroyed yet, hence exit 3, the same "refused before spending"
    // class `acquire` uses.
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);
    match uncollected_artifacts(&ledger_path, &args.id) {
        Ok(uncollected) if !uncollected.is_empty() => {
            for path in &uncollected {
                eprintln!("error: artifact not collected: {path}");
            }
            if args.force {
                eprintln!(
                    "warning: releasing {} anyway (--force); the artifacts above are deleted \
                     with it",
                    args.id
                );
            } else {
                eprintln!(
                    "error: refusing to release {}: the newest apply recorded in {} left the \
                     artifacts above on the machine (re-run apply to collect them, or pass \
                     --force to delete them with it)",
                    args.id,
                    ledger_path.display()
                );
                return ExitCode::from(3);
            }
        }
        Ok(_) => {}
        Err(err) => {
            // An unreadable ledger cannot say the machine is clean.
            // Refusing on it (absent --force) keeps the gate a gate:
            // fail-open here would make a corrupt ledger the easiest
            // way through it.
            eprintln!(
                "error: release gate could not read {}: {err}",
                ledger_path.display()
            );
            if !args.force {
                eprintln!("note: pass --force to release without the gate");
                return ExitCode::from(3);
            }
        }
    }

    let ProfileFacts {
        required,
        provider,
        hash: profile_hash,
    } = match requirements_of(&args.profile) {
        Ok(facts) => facts,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let adapter = match adapter_named(&args.provider) {
        Ok(adapter) => adapter,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    // No lease to stamp: this rendering is wanted for its release
    // template, and nothing is being bought.
    let acquisition = match adapter.acquisition(&required, &provider, None) {
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
    if let Err(missing) = credentials::require(adapter.provider_namespace(), adapter.credentials())
    {
        eprintln!("error: {missing}");
        eprintln!("note: {} is still running", args.id);
        return ExitCode::from(4);
    }

    let argv = substitute(&acquisition.release, &args.id);

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
            relay(&argv[0], &output.stdout);
            relay(&argv[0], &output.stderr);
            let acquisitions_path = args
                .acquisitions
                .clone()
                .unwrap_or_else(default_acquisitions_path);
            let correction = correction_row(
                &acquisitions_path,
                &args.id,
                &args.provider,
                &acquisition.release,
                &profile_hash,
            );
            if let Err(err) = record_acquisition(&acquisitions_path, &correction) {
                // The machine is gone either way, so this does not cost
                // the zero exit — but an unwritten correction leaves the
                // id outstanding forever, and the next sweep will spend
                // a release call on a machine that no longer exists.
                // Cheap, and only cheap because it is said here.
                eprintln!(
                    "error: released {} but could not record it in {}: {err}",
                    args.id,
                    acquisitions_path.display()
                );
            }
            println!("{}", serde_json::json!({ "released": args.id }));
            ExitCode::SUCCESS
        }
        Ok(output) => {
            relay(&argv[0], &output.stdout);
            relay(&argv[0], &output.stderr);
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

/// What a sweep decided about one outstanding machine, before anything
/// was run against the provider.
#[derive(Debug, PartialEq, Eq)]
enum Due {
    /// The lease has not run out. Nothing to do, and nothing to report:
    /// a sweep that listed every machine it left alone would bury the
    /// ones it acted on.
    Live,
    /// The lease has run out and the release gate is clear.
    Expired,
    /// The lease has run out and the gate said no. Reported, not
    /// released, and not a failure — see [`sweep_exit`].
    Refused(String),
    /// The row cannot be acted on at all, so the machine it names may
    /// be running and billing with nothing able to stop it. Not the
    /// same as refused: a refusal is this host deciding, and this is
    /// this host unable to.
    Failed(String),
}

/// Judge one outstanding row against the clock and the release gate.
///
/// Split out from [`run_sweep`] because it is the whole decision and
/// none of the effects: a test can hand it a crafted record and ledger
/// and read back what a sweep would do, without a provider, a
/// credential, or a machine.
fn due(row: &AcquisitionRow, now: jiff::Timestamp, ledger_path: &std::path::Path) -> Due {
    let expires_at = match row.expires_at.parse::<jiff::Timestamp>() {
        Ok(expires_at) => expires_at,
        Err(err) => {
            return Due::Failed(format!(
                "expires_at {:?} is not a timestamp: {err}",
                row.expires_at
            ))
        }
    };
    if expires_at > now {
        return Due::Live;
    }
    match gate(ledger_path, &row.id) {
        Gate::Clear => Due::Expired,
        Gate::Holding(reason) => Due::Refused(reason),
        Gate::Unreadable(reason) => Due::Failed(reason),
    }
}

/// What the release gate said about one machine.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// Nothing uncollected: the machine may go.
    Clear,
    /// The newest apply left work on the machine. A decision, and the
    /// gate working — reported as refused, exit 0.
    Holding(String),
    /// The ledger could not be read, so no decision was made at all.
    /// Not a refusal: a refusal is this host deciding, and this is this
    /// host unable to — the same line [`Due`] draws, and it lands in
    /// `failed` (exit 1), because a corrupt ledger that read as a
    /// refusal would hold every expired machine forever behind a zero
    /// exit that cron and the health endpoint both read as fine.
    Unreadable(String),
}

/// The release gate for one machine (08 §Release gate), whichever half
/// of the sweep found it.
///
/// The same gate `release` applies, read the same way. There is no
/// `--force` here: forcing is a statement that the work still on the
/// machine may be deleted with it, and a sweep is the least informed
/// thing in the system about whether that is true. The operator
/// escalates by hand.
///
/// An unreadable ledger holds the machine rather than passing it, for
/// the reason `release`'s does: a gate that fails open makes a corrupt
/// ledger the easiest way through it. But it holds as [`Gate::Unreadable`],
/// not as a refusal — the exit code has to say something is wrong.
fn gate(ledger_path: &std::path::Path, id: &str) -> Gate {
    match uncollected_artifacts(ledger_path, id) {
        Ok(uncollected) if !uncollected.is_empty() => Gate::Holding(format!(
            "the newest apply left {} on the machine (collect them, or release --force)",
            uncollected.join(", ")
        )),
        Ok(_) => Gate::Clear,
        Err(err) => Gate::Unreadable(format!(
            "the release gate could not read {}: {err}",
            ledger_path.display()
        )),
    }
}

/// What a platform's own list says about one machine it is running.
///
/// The lease is read off the machine, so this needs no record, no
/// profile and no memory of having created it — which is the whole
/// point: a machine whose row was lost is judged exactly like one whose
/// row is intact.
#[derive(Debug, PartialEq, Eq)]
enum Standing {
    /// Stamped, and the lease has not run out.
    Live,
    /// Stamped, and it has.
    Expired,
    /// Carrying no `lmp-exp-` stamp at all.
    ///
    /// **Reported, and never released on this evidence.** This tool
    /// did not name it, so the *listing* has no idea what it is —
    /// somebody else's work, another tool's machine, one created
    /// before leases were stamped onto machines. The record half may
    /// still release it when a recorded lease names its id: that is
    /// the pre-stamp path, and the machine then appears in the
    /// artifact both as `unknown` (what the listing saw) and as
    /// `released` (what the record knew).
    /// Janitor Monkey's answer to this is to mark the resource and warn
    /// its owner before deleting it; that needs an owner to warn and a
    /// mark to keep, and neither is in this MVP, so the answer here
    /// stops at telling the operator it is there.
    Unknown,
}

/// Read one listed machine's own account of its lease.
fn standing(machine: &infra::Machine, now: jiff::Timestamp) -> Standing {
    match machine.name.as_deref().and_then(infra::expiry_of) {
        None => Standing::Unknown,
        Some(expires_at) if expires_at > now => Standing::Live,
        // Reached, not merely passed — the same comparison `due` makes
        // of the recorded lease: the hours it was bought for are gone.
        Some(_) => Standing::Expired,
    }
}

/// What the record half of a sweep does with one outstanding row, once
/// the platforms themselves have spoken.
#[derive(Debug, PartialEq, Eq)]
enum Bookkeeping {
    /// A platform already dealt with this machine this run. Acting
    /// again would be a second release call against something that is
    /// already gone.
    Handled,
    /// The row's platform was asked, and this machine was not in the
    /// answer. It is not running, whatever the row says — the bill has
    /// ended, and the audit trail should say so.
    Gone,
    /// Nothing else knows about it: judge it by the recorded lease.
    /// This is the whole of a sweep run without `--provider`, and it is
    /// what still reaches machines created before the stamp existed.
    Judge,
}

/// Place one outstanding row against what the listings said.
fn bookkeeping(
    row: &AcquisitionRow,
    handled: &BTreeSet<String>,
    listed: &BTreeMap<String, BTreeSet<String>>,
) -> Bookkeeping {
    if handled.contains(&row.id) {
        return Bookkeeping::Handled;
    }
    match listed.get(&row.provider) {
        // Absent from a list that was actually taken. A platform that
        // could not be asked leaves no such conclusion to draw, which
        // is why this turns on the listing existing rather than on the
        // id being missing from an empty map.
        Some(present) if !present.contains(&row.id) => Bookkeeping::Gone,
        _ => Bookkeeping::Judge,
    }
}

/// What one sweep did, which is what its artifact reports.
#[derive(Debug, Default)]
struct SweepOutcome {
    /// Whether anything was actually released.
    dry_run: bool,
    /// How many machines this run found due — the ones whose lease it
    /// could read, from either the machine's own stamp or the record,
    /// and found run out. Counted once per machine however many halves
    /// of the sweep saw it. A lease it could not read is in `failed`
    /// and counted nowhere else: the sweep does not know that it was
    /// due.
    expired: usize,
    /// The machines released — or, under `--dry-run`, the ones that
    /// would be. The field names what the operator is deciding about,
    /// and `dry_run` beside it says whether it happened.
    released: Vec<String>,
    /// The machines the gate refused, with why.
    refused: Vec<(String, String)>,
    /// The machines still running that this sweep could not release,
    /// with why — and the platforms it could not ask, under their own
    /// name, since a plane nobody could list may be billing for
    /// anything.
    failed: Vec<(String, String)>,
    /// The listed machines carrying no lease stamp, with whatever they
    /// are named — reported so an operator knows what is on the
    /// account, and never released on the listing's evidence alone. An
    /// id here can also be in `released` when the record knew its
    /// lease (see [`Standing::Unknown`] — the pre-stamp path).
    unknown: Vec<(String, String)>,
}

/// The one JSON document a sweep puts on stdout (07-cli.md §Stream
/// split: one machine-readable artifact per run; everything the
/// provider said went to stderr on the way here).
fn sweep_artifact(outcome: &SweepOutcome) -> serde_json::Value {
    let pairs = |entries: &[(String, String)]| {
        entries
            .iter()
            .map(|(id, reason)| serde_json::json!({ "id": id, "reason": reason }))
            .collect::<Vec<_>>()
    };
    serde_json::json!({
        "dry_run": outcome.dry_run,
        "expired": outcome.expired,
        "released": outcome.released,
        "refused": pairs(&outcome.refused),
        "failed": pairs(&outcome.failed),
        "unknown": outcome
            .unknown
            .iter()
            .map(|(id, name)| serde_json::json!({ "id": id, "name_or_label": name }))
            .collect::<Vec<_>>(),
    })
}

/// `0` unless a machine that was due could not be released.
///
/// **A gate refusal is not a sweep failure.** The gate refusing is the
/// system working: the machine is still there because work on it has
/// not been collected, and the operator's next move is an apply or a
/// forced release, neither of which a non-zero exit from a scheduled
/// sweep would help with. A machine that expired and could not be
/// released is the opposite — nobody decided that, it is still
/// billing, and the exit code is the only thing a cron line reads.
fn sweep_exit(outcome: &SweepOutcome) -> u8 {
    if outcome.failed.is_empty() {
        0
    } else {
        1
    }
}

fn run_sweep(args: SweepArgs) -> ExitCode {
    let acquisitions_path = args.acquisitions.unwrap_or_else(default_acquisitions_path);
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);

    // An unreadable record is the whole command's failure, not one
    // machine's: a sweep that cannot read what this host bought has not
    // found that it bought nothing.
    let outstanding = match record::outstanding(&acquisitions_path) {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!(
                "error: could not read the acquisitions record {}: {err}",
                acquisitions_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    // One clock reading for the whole run, so two machines with the
    // same expiry are judged the same way.
    let now = jiff::Timestamp::now();
    let mut outcome = SweepOutcome {
        dry_run: args.dry_run,
        ..SweepOutcome::default()
    };

    // The provider-as-truth half, first: what each named platform says
    // it is running, judged by the lease each machine carries. What it
    // settles here is then what the record half must not do again.
    let mut handled = BTreeSet::new();
    let mut listed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for name in args.providers.iter().collect::<BTreeSet<_>>() {
        let (fleet, machines) = match listing(name) {
            Ok(listing) => listing,
            Err(reason) => {
                // Under the platform's own name in the `id` slot: what
                // could not be read is the whole plane, not one
                // machine, and a plane nobody could list is a tick that
                // failed — it may be billing for anything.
                outcome.failed.push((name.clone(), reason));
                continue;
            }
        };
        let mut present = BTreeSet::new();
        for machine in machines {
            present.insert(machine.id.clone());
            match standing(&machine, now) {
                // The machine's own stamp outranks any row about it,
                // here and in `Expired` below: the machine is the thing
                // being billed and the row is a note about it.
                Standing::Live => {
                    handled.insert(machine.id);
                }
                Standing::Unknown => {
                    outcome
                        .unknown
                        .push((machine.id, machine.name.unwrap_or_default()));
                }
                Standing::Expired => {
                    outcome.expired += 1;
                    handled.insert(machine.id.clone());
                    match gate(&ledger_path, &machine.id) {
                        Gate::Clear => {}
                        Gate::Holding(reason) => {
                            outcome.refused.push((machine.id, reason));
                            continue;
                        }
                        Gate::Unreadable(reason) => {
                            outcome.failed.push((machine.id, reason));
                            continue;
                        }
                    }
                    if args.dry_run {
                        outcome.released.push(machine.id);
                        continue;
                    }
                    match run_release_argv(&substitute(&fleet.release, &machine.id)) {
                        Ok(()) => {
                            // The audit trail catches up if it has
                            // something to catch up on. A machine this
                            // host has no row for is still released —
                            // that is the point of reading the platform
                            // — and inventing a row for it would put a
                            // purchase in the record that this host
                            // cannot describe.
                            if let Some(row) = outstanding.iter().find(|it| it.id == machine.id) {
                                retire(row, &acquisitions_path);
                            }
                            outcome.released.push(machine.id);
                        }
                        Err(reason) => outcome.failed.push((machine.id, reason)),
                    }
                }
            }
        }
        listed.insert(name.clone(), present);
    }

    // The record half. It runs whether or not a platform was asked:
    // without `--provider` it is the whole sweep, and with one it is
    // what reaches the machines the listing could not judge — the ones
    // created before leases were stamped onto them.
    for row in &outstanding {
        match bookkeeping(row, &handled, &listed) {
            Bookkeeping::Handled => {}
            Bookkeeping::Gone => {
                // Under `--dry-run` this run writes nothing anywhere,
                // including here: an operator asking what a sweep would
                // do is not asking for their record to be edited. The
                // note is still worth saying — the row is wrong now and
                // will be wrong at the next sweep too.
                eprintln!(
                    "note: {} is not in {}'s list of running machines; it is gone{}",
                    row.id,
                    row.provider,
                    if args.dry_run {
                        ", and the record would be corrected to say so"
                    } else {
                        ", and the record is being corrected to say so"
                    }
                );
                if !args.dry_run {
                    retire(row, &acquisitions_path);
                }
            }
            Bookkeeping::Judge => match due(row, now, &ledger_path) {
                Due::Live => {}
                Due::Failed(reason) => outcome.failed.push((row.id.clone(), reason)),
                Due::Refused(reason) => {
                    outcome.expired += 1;
                    outcome.refused.push((row.id.clone(), reason));
                }
                Due::Expired => {
                    outcome.expired += 1;
                    if args.dry_run {
                        // Nothing is spawned and no credential is asked
                        // for: showing an operator what would happen
                        // must not demand the key that would let it
                        // happen. (Asking a platform for its list does
                        // need one — there the key buys the question.)
                        outcome.released.push(row.id.clone());
                        continue;
                    }
                    match release_recorded(row, &acquisitions_path) {
                        Ok(()) => outcome.released.push(row.id.clone()),
                        Err(reason) => outcome.failed.push((row.id.clone(), reason)),
                    }
                }
            },
        }
    }

    println!("{}", sweep_artifact(&outcome));
    ExitCode::from(sweep_exit(&outcome))
}

/// Ask one platform what it is running.
///
/// The credential is required first, as everywhere else: a listing
/// without one is the platform CLI's own error in the middle of a
/// sweep, and this way the refusal names the variable and where it was
/// looked for.
///
/// Comes back with the [`infra::Fleet`] it was read through, so a
/// machine that has to be released is released from the same
/// description the listing came from rather than from a second lookup.
fn listing(name: &str) -> Result<(infra::Fleet, Vec<infra::Machine>), String> {
    let adapter = adapter_named(name)?;
    credentials::require(adapter.provider_namespace(), adapter.credentials())
        .map_err(|missing| missing.to_string())?;
    let fleet = adapter
        .fleet()
        .ok_or_else(|| format!("{name} cannot be asked what it is running"))?;
    let listing = infra::list(&fleet).map_err(|err| err.to_string())?;
    relay(
        fleet.list.first().map(String::as_str).unwrap_or(name),
        &listing.said,
    );
    Ok((fleet, listing.machines))
}

/// Release one recorded machine and write the correction that retires
/// it.
///
/// The release runs from the row's own argv, not from a profile: the
/// profile that bought this machine may have changed, moved, or gone,
/// and none of that should stand between an expired machine and its
/// deletion.
///
/// **A correction that fails to write does not make this an error.**
/// The machine is gone, which is what the caller asked for; the cost of
/// the missing row is that the next sweep spends one release call on a
/// machine that no longer exists. Said on stderr, and not allowed to
/// turn a released machine into a reported failure — `failed` means
/// "still running".
fn release_recorded(
    row: &AcquisitionRow,
    acquisitions_path: &std::path::Path,
) -> Result<(), String> {
    let adapter = adapter_named(&row.provider)?;
    credentials::require(adapter.provider_namespace(), adapter.credentials())
        .map_err(|missing| missing.to_string())?;
    run_release_argv(&substitute(&row.release, &row.id))?;
    retire(row, acquisitions_path);
    Ok(())
}

/// Run one release and relay what the platform said about it.
///
/// **Nothing here reads the platform's words to decide anything.** A
/// machine that is already gone is not detected by matching "not
/// found" against somebody's error text — text that differs per
/// platform, per version, and per locale, and whose exact spelling this
/// code would then depend on. It converges instead: the next tick lists
/// the machine, does not find it, and the sweep is done with it. A
/// concurrent double release can therefore cost one plane one failed
/// entry for one tick, which is the shape every enumerate-and-kill
/// reaper settles for (`aws-nuke` re-runs until the account comes back
/// empty).
///
/// Captured, not inherited, for the reason `release` captures
/// (07-cli.md §Stream split): this run's one artifact is the sweep
/// report, and a service CLI writing to the same stream would make it
/// two documents.
fn run_release_argv(argv: &[String]) -> Result<(), String> {
    let Some(program) = argv.first() else {
        return Err("the release names no command to run".to_string());
    };
    let output = std::process::Command::new(program)
        .args(&argv[1..])
        .output()
        .map_err(|err| format!("could not run `{program}`: {err}"))?;
    relay(program, &output.stdout);
    relay(program, &output.stderr);
    if !output.status.success() {
        return Err(format!("`{program}` exited with {}", output.status));
    }
    Ok(())
}

/// `{id}` replaced throughout — the placeholder a recorded release and
/// a fleet's release template both carry.
fn substitute(argv: &[String], id: &str) -> Vec<String> {
    argv.iter().map(|it| it.replace("{id}", id)).collect()
}

/// Append the row that retires an id: the acquisition's own account of
/// the machine, now carrying the moment it stopped running.
///
/// **A correction that fails to write is reported and not raised.** The
/// machine is gone either way, and the audit trail being one row short
/// costs the next sweep at most one wasted release call — which is
/// cheap, and only cheap because it is said here.
fn retire(row: &AcquisitionRow, acquisitions_path: &std::path::Path) {
    let correction = AcquisitionRow {
        released_at: Some(jiff::Timestamp::now().to_string()),
        ..row.clone()
    };
    if let Err(err) = record_acquisition(acquisitions_path, &correction) {
        eprintln!(
            "error: {} is no longer running but could not be recorded in {}: {err}",
            row.id,
            acquisitions_path.display()
        );
    }
}

/// Put what the service said on stderr, if it said anything.
fn relay(program: &str, bytes: &[u8]) {
    for line in attributed(program, bytes) {
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
///
/// `program` is the argv the release was run from rather than a
/// constant: with two platforms wired and a sweep that releases
/// whatever a row names, a fixed prefix would attribute one service's
/// words to another — which is the one thing the prefix is there to
/// get right.
fn attributed(program: &str, bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    // `""` is what the service returns from a release: a JSON document
    // holding an empty string, which is a body with nothing in it.
    if text.is_empty() || text == "\"\"" {
        return Vec::new();
    }
    text.lines()
        .map(|line| format!("{program}: {line}"))
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
        artifacts_dir: if args.no_artifacts {
            None
        } else {
            Some(args.artifacts_dir)
        },
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
            // Same duty for step 4b: an uncollected artifact rides back
            // in the output rather than failing the session, and this
            // is where it has to become visible and cost the zero exit.
            let uncollected = output.artifacts.iter().filter(|it| !it.collected).count();
            for it in output.artifacts.iter().filter(|it| !it.collected) {
                eprintln!(
                    "error: artifact not collected: {}: {}",
                    it.path,
                    it.error.as_deref().unwrap_or("unknown")
                );
            }
            let ok = output.collected.report["ok"] == serde_json::Value::Bool(true);
            ExitCode::from(exit_status(
                ok,
                output.ledger_warning.as_deref(),
                uncollected,
            ))
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

/// The exit code a completed session maps to: `0` only when the apply
/// reported `ok`, step 5 recorded it, **and** step 4b collected every
/// declared artifact.
///
/// An unrecorded apply is not a success to report as one (09 §Error
/// surface: "an apply is not 'unrecorded-successful' — drivers must
/// treat append failure as an operational error to retry"), so a
/// `ledger_warning` costs the zero exit even when the report itself is
/// `ok`. The report still goes to stdout: an operator retrying the
/// append needs to know what it was. An uncollected artifact costs it
/// for the sibling reason: the run's work product is still only on
/// the pod, and a zero here is what lets a script move on to the
/// delete that loses it (08 §Release gate).
fn exit_status(report_ok: bool, ledger_warning: Option<&str>, uncollected_artifacts: usize) -> u8 {
    if report_ok && ledger_warning.is_none() && uncollected_artifacts == 0 {
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

/// The declared-but-uncollected artifact paths on the newest **real**
/// apply recorded for `pod_id` — the row the release gate judges by.
///
/// Dry-run rows are skipped: a dry run produces nothing, records no
/// artifacts, and must not stand in for the real apply behind it
/// (session step 4b already records nothing for them; skipping by the
/// report's own `dry_run` flag keeps the gate honest against rows
/// other drivers append). No row at all is a pass — the gate can only
/// weigh what an apply recorded, which is why `apply` wants the
/// machine id as its `--pod-id` (08 §Release gate).
fn uncollected_artifacts(
    ledger_path: &std::path::Path,
    pod_id: &str,
) -> Result<Vec<String>, lm_provision_driver::ledger::LedgerError> {
    let newest_real_apply = lm_provision_driver::ledger::list(ledger_path)?
        .into_iter()
        .find(|row| row.pod_id == pod_id && row.report["dry_run"] != serde_json::Value::Bool(true));
    Ok(newest_real_apply
        .map(|row| {
            row.artifacts
                .into_iter()
                .filter(|it| !it.collected)
                .map(|it| it.path)
                .collect()
        })
        .unwrap_or_default())
}

fn default_ledger_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home)
            .join(".lm-provision")
            .join("ledger.jsonl"),
        None => PathBuf::from("lm-provision-ledger.jsonl"),
    }
}

/// Where the acquisitions record lives when nothing says otherwise —
/// beside the ledger, and falling back the same way, because the two
/// files are read together (a sweep judges a row from the record
/// against the gate in the ledger).
fn default_acquisitions_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home)
            .join(".lm-provision")
            .join("acquisitions.jsonl"),
        None => PathBuf::from("lm-provision-acquisitions.jsonl"),
    }
}

/// Append a row to the acquisitions record, making the directory it
/// lives in first.
///
/// The directory is this function's business and not the record
/// module's: appending is the record's contract, and where an operator
/// host keeps the file is the driver's. The first acquire on a fresh
/// host is exactly when `~/.lm-provision` does not exist yet, and it is
/// also exactly when losing the row costs the most — the machine is new
/// and nothing else on the host knows its id.
fn record_acquisition(
    path: &std::path::Path,
    row: &AcquisitionRow,
) -> Result<(), record::AcquisitionError> {
    if let Some(parent) = path.parent().filter(|it| !it.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    record::append(path, row)
}

/// The correction row a successful release appends (09 §Acquisitions
/// record): the same id, now carrying a `released_at`.
///
/// **The lease facts are carried from what was recorded, not from this
/// run.** The machine was bought for a profile, from a platform, under
/// a lease — and the release that gives it back is a different
/// invocation with its own `--profile` and `--provider`, which may or
/// may not be the ones it was bought with. Copying the recorded row
/// keeps the file's account of the machine consistent from purchase to
/// return.
///
/// A release for a machine this record never acquired still writes a
/// row: the one thing that must be true afterwards is that no sweep
/// believes the machine is running. Its lease fields are then the
/// moment of release, twice — a lease nobody recorded is not one this
/// row may invent.
fn correction_row(
    path: &std::path::Path,
    id: &str,
    provider: &str,
    release: &[String],
    profile_hash: &str,
) -> AcquisitionRow {
    let released_at = jiff::Timestamp::now().to_string();
    // The newest row naming this id, outstanding or not: a machine
    // released twice should not have its lease forgotten by the second
    // correction.
    let recorded = match record::list(path) {
        Ok(rows) => rows.into_iter().find(|row| row.id == id),
        Err(err) => {
            eprintln!(
                "warning: could not read {} for {id}'s acquisition; the correction will carry \
                 only what this release knows: {err}",
                path.display()
            );
            None
        }
    };
    match recorded {
        Some(row) => AcquisitionRow {
            released_at: Some(released_at),
            ..row
        },
        None => AcquisitionRow {
            id: id.to_string(),
            provider: provider.to_string(),
            acquired_at: released_at.clone(),
            expires_at: released_at.clone(),
            profile_hash: profile_hash.to_string(),
            release: release.to_vec(),
            released_at: Some(released_at),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attributed, exit_status, parse_ssh_target, record, ssh_help, AcquisitionRow, Cli, Command,
        PathBuf,
    };
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
        assert!(attributed("runpod-cli", b"").is_empty());
        assert!(attributed("runpod-cli", b"   \n").is_empty());
        assert!(
            attributed("runpod-cli", b"\"\"\n").is_empty(),
            "an empty JSON string is a body with nothing in it"
        );

        assert_eq!(
            attributed("runpod-cli", b"warning: pod was already gone\n"),
            vec!["runpod-cli: warning: pod was already gone"],
            "the GNU form: the program that said it, a colon, the message"
        );
        assert_eq!(
            attributed("runpod-cli", b"first\nsecond\n"),
            vec!["runpod-cli: first", "runpod-cli: second"],
            "every line carries the attribution, not just the first"
        );
        assert_eq!(
            attributed("vastai", b"destroyed\n"),
            vec!["vastai: destroyed"],
            "the prefix is whichever service spoke — a sweep releases \
             machines from two platforms in one run"
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
        assert_eq!(exit_status(true, None, 0), 0);
        assert_eq!(
            exit_status(true, Some("ledger i/o error: no such file"), 0),
            1
        );
        assert_eq!(exit_status(false, None, 0), 1);
        assert_eq!(
            exit_status(false, Some("ledger i/o error: no such file"), 0),
            1
        );
    }

    /// The step-4b sibling of the ledger rule above: an `ok` report
    /// whose declared artifacts were not all pulled exits `1` — a zero
    /// here is what lets a script move on to the delete that loses
    /// them (08 §Release gate).
    #[test]
    fn an_ok_report_with_an_uncollected_artifact_still_exits_nonzero() {
        assert_eq!(exit_status(true, None, 1), 1);
        assert_eq!(exit_status(true, None, 0), 0);
    }

    /// **The wait condition is the declared ports, all of them, and
    /// nothing when none were declared.** A machine is "reachable" for
    /// this command exactly when the platform has answered for every
    /// port the profile asked to expose — not when SSH alone is up
    /// (a profile may declare none) and not before the health-check
    /// port has a mapping.
    #[test]
    fn acquire_waits_on_exactly_the_declared_ports() {
        use lm_provision::machine::{Exposure, PortRequirement};
        use lm_provision_driver::infra::Connection;

        let declared = [
            PortRequirement {
                port: 22,
                exposure: Exposure::RawTcp,
            },
            PortRequirement {
                port: 8188,
                exposure: Exposure::PublicHttp,
            },
        ];
        let mut connection = Connection::default();
        assert!(!super::connection_covers(&declared, &connection));
        connection
            .endpoints
            .insert(22, "203.0.113.10:22016".to_string());
        assert!(!super::connection_covers(&declared, &connection));
        connection
            .endpoints
            .insert(8188, "203.0.113.10:80".to_string());
        assert!(super::connection_covers(&declared, &connection));

        assert!(
            super::connection_covers(&[], &Connection::default()),
            "no declared ports leaves nothing to wait for"
        );
    }

    /// **The release gate judges by the newest real apply for the
    /// machine** (08 §Release gate): a later dry-run row does not
    /// stand in for it, other machines' rows do not reach it, and a
    /// machine with no recorded apply passes — the gate can only
    /// weigh what an apply recorded.
    #[test]
    fn the_release_gate_reads_the_newest_real_apply_row() {
        use lm_provision_driver::ledger::{self, ArtifactRow, LedgerRow};

        let path = std::env::temp_dir().join(format!(
            "lm-provision-driver-release-gate-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let row = |pod_id: &str, dry_run: bool, artifacts: Vec<ArtifactRow>| LedgerRow {
            pod_id: pod_id.to_string(),
            profile_hash: "h".repeat(64),
            report: serde_json::json!({ "ok": true, "dry_run": dry_run }),
            collected_at: "2026-08-30T00:00:00Z".to_string(),
            artifacts,
        };
        let uncollected_row = ArtifactRow {
            path: "/workspace/out".to_string(),
            collected: false,
            dest: None,
            error: Some("scp failed".to_string()),
        };

        // Oldest → newest: a real apply that left a debt, a clean real
        // apply on another machine, then a dry run on this one.
        ledger::append(&path, &row("pod-a", false, vec![uncollected_row.clone()]))
            .expect("append 1");
        ledger::append(&path, &row("pod-b", false, Vec::new())).expect("append 2");
        ledger::append(&path, &row("pod-a", true, Vec::new())).expect("append 3");

        assert_eq!(
            super::uncollected_artifacts(&path, "pod-a").expect("gate reads the ledger"),
            vec!["/workspace/out".to_string()],
            "the dry-run row must not mask the real apply's debt"
        );
        assert!(super::uncollected_artifacts(&path, "pod-b")
            .expect("gate reads the ledger")
            .is_empty());
        assert!(super::uncollected_artifacts(&path, "pod-never-applied")
            .expect("gate reads the ledger")
            .is_empty());

        // A re-apply that collected everything clears the gate: it is
        // now the newest real row.
        ledger::append(
            &path,
            &row(
                "pod-a",
                false,
                vec![ArtifactRow {
                    collected: true,
                    dest: Some("artifacts/pod-a/workspace/out".to_string()),
                    error: None,
                    ..uncollected_row
                }],
            ),
        )
        .expect("append 4");
        assert!(super::uncollected_artifacts(&path, "pod-a")
            .expect("gate reads the ledger")
            .is_empty());

        std::fs::remove_file(&path).ok();
    }

    /// A scratch path nothing else is using, in the shape the ledger's
    /// own tests use.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-driver-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn recorded(id: &str, expires_at: &str) -> AcquisitionRow {
        AcquisitionRow {
            id: id.to_string(),
            provider: "runpod".to_string(),
            acquired_at: "2026-09-01T00:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            profile_hash: "h".repeat(64),
            release: vec![
                "runpod-cli".to_string(),
                "pods".to_string(),
                "delete-pod".to_string(),
                "{id}".to_string(),
            ],
            released_at: None,
        }
    }

    /// **A sweep releases what the clock says is over and the gate says
    /// is finished with** (08 §Acquisitions and sweep): the lease
    /// decides whether the machine is due, and the release gate — the
    /// same one `release` applies — decides whether a due machine may
    /// go. A machine whose expiry is exactly now is due: the lease ran
    /// for the hours it was bought for and they are gone.
    #[test]
    fn a_sweep_is_due_at_the_lease_and_refused_by_the_release_gate() {
        use lm_provision_driver::ledger::{self, ArtifactRow, LedgerRow};

        let ledger_path = scratch("sweep-gate");
        let now: jiff::Timestamp = "2026-09-02T00:00:00Z".parse().expect("a fixed clock");

        assert_eq!(
            super::due(
                &recorded("pod-live", "2026-09-02T00:00:01Z"),
                now,
                &ledger_path
            ),
            super::Due::Live,
            "a lease with a second left is a machine the sweep leaves alone"
        );
        assert_eq!(
            super::due(
                &recorded("pod-due", "2026-09-02T00:00:00Z"),
                now,
                &ledger_path
            ),
            super::Due::Expired,
            "expiry is reached, not merely passed — and no recorded apply is no debt"
        );

        // The gate's own condition: the newest real apply for the
        // machine left a declared artifact on it.
        ledger::append(
            &ledger_path,
            &LedgerRow {
                pod_id: "pod-owing".to_string(),
                profile_hash: "h".repeat(64),
                report: serde_json::json!({ "ok": true, "dry_run": false }),
                collected_at: "2026-09-01T12:00:00Z".to_string(),
                artifacts: vec![ArtifactRow {
                    path: "/workspace/out".to_string(),
                    collected: false,
                    dest: None,
                    error: Some("scp failed".to_string()),
                }],
            },
        )
        .expect("seed the ledger");
        let super::Due::Refused(reason) = super::due(
            &recorded("pod-owing", "2026-09-01T00:00:00Z"),
            now,
            &ledger_path,
        ) else {
            panic!("an expired machine still holding work is refused, not released");
        };
        assert!(
            reason.contains("/workspace/out"),
            "the refusal names what is still on it: {reason}"
        );

        // A lease that cannot be read is not a lease this command may
        // act on, and the machine it names may be billing — which is a
        // failure to report, not a refusal to shrug at.
        assert!(matches!(
            super::due(&recorded("pod-unreadable", "whenever"), now, &ledger_path),
            super::Due::Failed(_)
        ));

        std::fs::remove_file(&ledger_path).ok();
    }

    /// **A ledger the gate cannot read is a failed machine, not a
    /// refused one.** A refusal is this host deciding and exits 0; a
    /// corrupt ledger is this host unable to decide, and if it read as
    /// a refusal, every expired machine would sit behind a zero exit —
    /// billing — while cron and the health endpoint both reported the
    /// sweep fine.
    #[test]
    fn a_corrupt_ledger_fails_the_machine_rather_than_refusing_it() {
        let ledger_path = scratch("sweep-corrupt-ledger");
        std::fs::write(&ledger_path, "not a ledger row\n").expect("seed the corruption");
        let now: jiff::Timestamp = "2026-09-02T00:00:00Z".parse().expect("a fixed clock");

        let super::Due::Failed(reason) = super::due(
            &recorded("pod-due", "2026-09-01T00:00:00Z"),
            now,
            &ledger_path,
        ) else {
            panic!("an unreadable ledger is a failure the exit code must carry");
        };
        assert!(
            reason.contains("could not read"),
            "the reason names the gate's problem, not the machine's: {reason}"
        );

        std::fs::remove_file(&ledger_path).ok();
    }

    /// **A refused machine is not a failed sweep, and a machine left
    /// billing is.** The gate refusing is the system working; a due
    /// machine that could not be released is the accident this
    /// subcommand exists to catch, and the exit code is all a cron line
    /// reads.
    #[test]
    fn only_a_machine_left_running_costs_the_sweep_its_zero_exit() {
        let refused = super::SweepOutcome {
            dry_run: false,
            expired: 1,
            released: Vec::new(),
            refused: vec![("pod-owing".to_string(), "artifacts uncollected".to_string())],
            failed: Vec::new(),
            unknown: Vec::new(),
        };
        assert_eq!(super::sweep_exit(&refused), 0);
        assert_eq!(
            super::sweep_artifact(&refused)["refused"][0]["id"],
            serde_json::json!("pod-owing"),
            "the refusal is in the artifact even though the exit is zero"
        );

        let failed = super::SweepOutcome {
            failed: vec![("pod-stuck".to_string(), "credential missing".to_string())],
            ..refused
        };
        assert_eq!(super::sweep_exit(&failed), 1);

        let nothing = super::SweepOutcome::default();
        assert_eq!(super::sweep_exit(&nothing), 0);
        assert_eq!(
            super::sweep_artifact(&nothing),
            serde_json::json!({
                "dry_run": false,
                "expired": 0,
                "released": [],
                "refused": [],
                "failed": [],
                "unknown": [],
            }),
            "an empty sweep still emits the one artifact, with every field present"
        );
    }

    /// **The correction carries the acquisition's account of the
    /// machine forward**, so the record reads the same about it from
    /// purchase to return — the release invocation's own `--provider`
    /// and `--profile` describe how this operator reached the machine
    /// today, not what it was bought as.
    #[test]
    fn a_correction_row_carries_the_recorded_lease_and_retires_the_id() {
        let path = scratch("correction");
        super::record_acquisition(&path, &recorded("pod-1", "2026-09-02T00:00:00Z"))
            .expect("seed an acquisition");

        let correction = super::correction_row(
            &path,
            "pod-1",
            "vast",
            &["vastai".to_string(), "destroy".to_string()],
            &"z".repeat(64),
        );
        assert_eq!(correction.provider, "runpod");
        assert_eq!(correction.profile_hash, "h".repeat(64));
        assert_eq!(correction.acquired_at, "2026-09-01T00:00:00Z");
        assert_eq!(correction.expires_at, "2026-09-02T00:00:00Z");
        assert!(correction.released_at.is_some());

        super::record_acquisition(&path, &correction).expect("append the correction");
        assert!(
            record::outstanding(&path)
                .expect("the record reads back")
                .is_empty(),
            "nothing is believed to be running once the correction lands"
        );
        assert_eq!(
            record::list(&path).expect("the record reads back").len(),
            2,
            "the acquisition row is still there: corrections are new rows"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A release for a machine this record never acquired still writes
    /// a row — the point is that no sweep believes it is running — and
    /// it invents no lease it was not told about.
    #[test]
    fn a_correction_for_an_unrecorded_machine_stands_on_what_the_release_knows() {
        let path = scratch("correction-orphan");
        let correction = super::correction_row(
            &path,
            "pod-elsewhere",
            "vast",
            &[
                "vastai".to_string(),
                "destroy".to_string(),
                "{id}".to_string(),
            ],
            &"z".repeat(64),
        );

        assert_eq!(correction.provider, "vast");
        assert_eq!(correction.profile_hash, "z".repeat(64));
        assert_eq!(
            Some(&correction.acquired_at),
            correction.released_at.as_ref(),
            "the moment of release stands in for a lease nobody recorded"
        );
        assert_eq!(correction.acquired_at, correction.expires_at);
        assert!(!path.exists(), "reading a missing record creates nothing");
    }

    /// **The spend guards are the defaults.** `sweep` deletes machines
    /// and `acquire` buys one, so both start from the harmless side and
    /// `--dry-run false` is the operator saying otherwise. The TTL has
    /// no opt-out: every acquire records a lease.
    #[test]
    fn sweep_and_acquire_default_to_doing_nothing_and_to_a_recorded_lease() {
        let cli = Cli::parse_from(["lm-provision-driver", "sweep"]);
        let Command::Sweep(args) = cli.command else {
            panic!("the parsed subcommand is `sweep`");
        };
        assert!(
            args.dry_run,
            "a sweep that was not asked to release, does not"
        );

        let cli = Cli::parse_from([
            "lm-provision-driver",
            "acquire",
            "--profile",
            "profile.json",
        ]);
        let Command::Acquire(args) = cli.command else {
            panic!("the parsed subcommand is `acquire`");
        };
        assert!(args.dry_run);
        assert_eq!(args.ttl_hours, 24, "a day, the fleet's ephemeral default");
    }

    /// **What a sweep does with a machine it found by asking the
    /// platform** — no record, no profile, nothing but the name the
    /// machine carries. The two row shapes are the two platforms': a
    /// wrapped object of pods with a `name`, a bare array of instances
    /// with a numeric id and a `label`.
    #[test]
    fn a_listed_machine_is_judged_by_the_stamp_it_carries() {
        use lm_provision_driver::infra::{self, Infra as _, RunPodAdapter, VastAdapter};

        let now: jiff::Timestamp = "2026-09-02T00:00:00Z".parse().expect("a fixed clock");

        let pods = RunPodAdapter.fleet().expect("this target can be asked");
        let listed = serde_json::json!({
            "pods": [
                { "id": "pod-over", "name": "lmp-exp-20260901T235959Z" },
                { "id": "pod-due", "name": "lmp-exp-20260902T000000Z" },
                { "id": "pod-live", "name": "lmp-exp-20260903T000000Z" },
                { "id": "pod-someone-elses", "name": "jupyter-scratch" },
                { "id": "pod-nameless" },
            ]
        });
        let judged: Vec<(String, super::Standing)> = infra::machines(&listed, &pods)
            .expect("rows carrying the id key are the fleet")
            .into_iter()
            .map(|it| (it.id.clone(), super::standing(&it, now)))
            .collect();
        assert_eq!(
            judged,
            vec![
                ("pod-over".to_string(), super::Standing::Expired),
                // Reached is over, as the recorded lease is judged.
                ("pod-due".to_string(), super::Standing::Expired),
                ("pod-live".to_string(), super::Standing::Live),
                // Not this tool's machines as far as anything here can
                // tell. Reported; never released.
                ("pod-someone-elses".to_string(), super::Standing::Unknown),
                ("pod-nameless".to_string(), super::Standing::Unknown),
            ]
        );

        let instances = VastAdapter.fleet().expect("this target can be asked");
        let listed = serde_json::json!([
            { "id": 49227715, "label": "lmp-exp-20260901T120000Z" },
            { "id": 49228600, "label": "lmp-exp-20260930T120000Z" },
            { "id": 49229000, "label": null },
        ]);
        let judged: Vec<(String, super::Standing)> = infra::machines(&listed, &instances)
            .expect("a bare array is the rows")
            .into_iter()
            .map(|it| (it.id.clone(), super::standing(&it, now)))
            .collect();
        assert_eq!(
            judged,
            vec![
                ("49227715".to_string(), super::Standing::Expired),
                ("49228600".to_string(), super::Standing::Live),
                ("49229000".to_string(), super::Standing::Unknown),
            ]
        );
    }

    /// **One machine, one release call.** A machine both halves of a
    /// sweep see — the platform lists it and the record still names it
    /// — is dealt with by the platform half, and the record half must
    /// leave it alone: the second call would be against something
    /// already gone.
    #[test]
    fn a_machine_both_halves_see_is_released_once() {
        let handled: std::collections::BTreeSet<String> =
            ["pod-1".to_string()].into_iter().collect();
        let listed: super::BTreeMap<String, std::collections::BTreeSet<String>> = [(
            "runpod".to_string(),
            ["pod-1".to_string()].into_iter().collect(),
        )]
        .into_iter()
        .collect();

        assert_eq!(
            super::bookkeeping(
                &recorded("pod-1", "2026-09-02T00:00:00Z"),
                &handled,
                &listed
            ),
            super::Bookkeeping::Handled
        );

        // Listed, but the platform half could not read a lease off it
        // (no stamp) — so it was never handled, and the record is the
        // only thing that knows when it expires. This is how a machine
        // created before leases were stamped still gets released.
        let unstamped_but_listed: super::BTreeMap<String, std::collections::BTreeSet<String>> = [(
            "runpod".to_string(),
            ["pod-old".to_string()].into_iter().collect(),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            super::bookkeeping(
                &recorded("pod-old", "2026-09-02T00:00:00Z"),
                &std::collections::BTreeSet::new(),
                &unstamped_but_listed,
            ),
            super::Bookkeeping::Judge
        );

        // A platform nobody asked draws no conclusion at all: without
        // `--provider` every row is judged by its recorded lease.
        assert_eq!(
            super::bookkeeping(
                &recorded("pod-2", "2026-09-02T00:00:00Z"),
                &std::collections::BTreeSet::new(),
                &super::BTreeMap::new(),
            ),
            super::Bookkeeping::Judge
        );
    }

    /// **A machine that is not on its platform's list is not running**,
    /// whatever the record says — somebody released it by hand, or a
    /// correction was lost. The bill has ended and the audit trail is
    /// made to say so, without a release call being spent on it.
    #[test]
    fn an_outstanding_row_absent_from_its_platforms_list_is_retired() {
        let listed: super::BTreeMap<String, std::collections::BTreeSet<String>> = [(
            "runpod".to_string(),
            ["pod-other".to_string()].into_iter().collect(),
        )]
        .into_iter()
        .collect();
        let row = recorded("pod-gone", "2036-09-02T00:00:00Z");
        assert_eq!(
            super::bookkeeping(&row, &std::collections::BTreeSet::new(), &listed),
            super::Bookkeeping::Gone,
            "a lease with ten years left does not keep a machine that is not there"
        );

        let path = scratch("gone");
        super::record_acquisition(&path, &row).expect("seed an acquisition");
        super::retire(&row, &path);
        assert!(
            record::outstanding(&path)
                .expect("the record reads back")
                .is_empty(),
            "nothing is believed to be running once the correction lands"
        );
        assert_eq!(
            record::list(&path).expect("the record reads back").len(),
            2,
            "corrections are new rows here as everywhere else"
        );

        std::fs::remove_file(&path).ok();
    }

    /// **A dry run shows the lease the machine would carry.** The
    /// stamped name is what decides whether a sweeper can ever find the
    /// machine again, so it is the last part of the request that should
    /// be invisible in the preview of it.
    #[test]
    fn a_dry_run_shows_the_lease_the_machine_would_carry() {
        use lm_provision_driver::infra::{self, Infra as _, RunPodAdapter, VastAdapter};

        let expires_at: jiff::Timestamp = "2026-09-02T06:30:00Z".parse().expect("a fixed lease");
        let stamp = infra::expiry_stamp(expires_at);

        let ports = [("22".to_string(), "raw_tcp".to_string())]
            .into_iter()
            .collect();
        let gpu = [("count".to_string(), "1".to_string())]
            .into_iter()
            .collect();
        let required =
            lm_provision::machine::Requirements::from_slots(&ports, &gpu, &super::BTreeMap::new())
                .expect("well-formed fixture");

        let pod_provider: super::BTreeMap<String, String> =
            [("runpod.imageName".to_string(), "some/image:1".to_string())]
                .into_iter()
                .collect();
        let artifact = super::dry_run_artifact(
            &RunPodAdapter
                .acquisition(&required, &pod_provider, Some(expires_at))
                .expect("an image was declared"),
        );
        assert_eq!(artifact["dry_run"], serde_json::json!(true));
        assert!(
            artifact["body"]
                .as_str()
                .is_some_and(|it| it.contains(&stamp)),
            "the request an operator is shown carries the lease: {artifact}"
        );

        let instance_provider: super::BTreeMap<String, String> =
            [("vast.image".to_string(), "some/image:1".to_string())]
                .into_iter()
                .collect();
        let artifact = super::dry_run_artifact(
            &VastAdapter
                .acquisition(&required, &instance_provider, Some(expires_at))
                .expect("an image was declared"),
        );
        assert!(
            artifact["create"]
                .as_array()
                .is_some_and(|argv| argv.iter().any(|it| it == &serde_json::json!(stamp))),
            "and so does the argv on the target that takes one: {artifact}"
        );
    }

    /// The record sits beside the ledger under the same home directory:
    /// a sweep reads both, and splitting them across two conventions
    /// would make "where is the fleet" two questions.
    #[test]
    fn the_record_defaults_beside_the_ledger() {
        let acquisitions = super::default_acquisitions_path();
        let ledger = super::default_ledger_path();
        assert_eq!(acquisitions.parent(), ledger.parent());
        assert!(acquisitions.file_name().is_some_and(
            |it| it == "acquisitions.jsonl" || it == "lm-provision-acquisitions.jsonl"
        ));
    }
}
