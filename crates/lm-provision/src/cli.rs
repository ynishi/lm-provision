//! CLI subcommand surface and pipeline wiring (07-cli.md).
//!
//! `validate` / `hash` / `plan` each run the read-only pipeline stages
//! 07-cli.md §Invocation names for that subcommand over the
//! [`crate::profile_ast::ProfileNode`] AST produced by
//! [`crate::frontend::load_profile`] — no effect is run for these three
//! subcommands, matching their "none (read-only)" effects column in 07
//! §Invocation. `apply` (07 §Invocation: "load → declarations → gate →
//! bridges → plan → dispatch → apply") wires [`crate::apply::run_apply_ast`]
//! instead.
//!
//! The input format is chosen purely by file extension inside
//! [`crate::frontend::load_profile`] (`.json` → JSON serde bridge,
//! anything else → canonical text grammar, `.lua` → an explicit
//! `Lua profiles are no longer supported` error). The legacy embedded-Lua
//! authoring frontend and its VM pipeline have been removed.

use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// `lm-provision <subcommand> <profile-path> [flags]`
/// (07-cli.md §Invocation).
#[derive(Debug, Parser)]
#[command(name = "lm-provision", version, about, propagate_version = true)]
pub struct Cli {
    /// Tracing filter for the human-readable stderr stream. `RUST_LOG`
    /// takes precedence when set (07-cli.md §Global flags).
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    /// Reserved for forward compatibility; stdout is already
    /// machine-readable by default (07-cli.md §Global flags).
    #[arg(long, global = true)]
    pub json: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommand surface (07-cli.md §Invocation table). The four MVP
/// subcommands: `validate` / `hash` / `plan` / `apply`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// load → declarations → validate (read-only, no effects).
    Validate {
        /// Path to the profile file.
        profile: std::path::PathBuf,
    },
    /// load → declarations → canonical → hash (read-only, no effects).
    Hash {
        /// Path to the profile file.
        profile: std::path::PathBuf,
    },
    /// load → declarations → plan (read-only, no effects).
    Plan {
        /// Path to the profile file.
        profile: std::path::PathBuf,
    },
    /// load → declarations → gate → bridges → plan → dispatch → apply.
    Apply {
        /// Path to the profile file.
        profile: std::path::PathBuf,
        /// Decode + policy + secret resolution only, no effects
        /// (04-bridge.md dry-run convention).
        #[arg(long)]
        dry_run: bool,
    },
}

/// Resolve the effective tracing filter: `RUST_LOG` env var takes
/// precedence over `--log-level` when set (07-cli.md §Global flags).
pub fn resolve_log_filter(cli_log_level: &str) -> String {
    resolve_log_filter_from(cli_log_level, std::env::var("RUST_LOG").ok())
}

fn resolve_log_filter_from(cli_log_level: &str, rust_log_env: Option<String>) -> String {
    rust_log_env.unwrap_or_else(|| cli_log_level.to_string())
}

/// Run the resolved subcommand.
///
/// Usage errors (unknown subcommand / flag, 07-cli.md §Exit codes "2")
/// never reach this function: `clap`'s `Parser::parse()` (`main.rs`)
/// exits the process directly before `run` is called.
pub fn run(command: &Command) -> ExitCode {
    match command {
        Command::Validate { profile } => run_validate(profile),
        Command::Hash { profile } => run_hash(profile),
        Command::Plan { profile } => run_plan(profile),
        Command::Apply { profile, dry_run } => run_apply(profile, *dry_run),
    }
}

/// The error type every read-only pipeline function below returns.
/// Carries only a rendered message rather than the source error so the
/// single "final error line" 07-cli.md §Error surface needs is all a
/// caller has to preserve.
///
/// `pub` (rather than crate-private) so `lm-provision-mcp`'s MCP tool
/// wrappers can surface the same message text
/// `print_failure` renders to stderr without depending on the underlying
/// error types directly (10-mcp.md §Error surface "precondition ... class
/// preserved").
#[derive(Debug)]
pub struct RunError(String);

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<crate::frontend::FrontendError> for RunError {
    fn from(err: crate::frontend::FrontendError) -> Self {
        RunError(err.to_string())
    }
}

impl From<crate::validate::ValidateError> for RunError {
    fn from(err: crate::validate::ValidateError) -> Self {
        RunError(err.to_string())
    }
}

/// The `Result` alias every read-only pipeline function below returns.
/// `pub` for the same reason [`RunError`] is.
pub type PipelineResult<T> = std::result::Result<T, RunError>;

/// Print `<subcommand> failed: <err>` to stderr (07-cli.md §Error
/// surface's literal failure-line form) and return exit code 1
/// (07 §Exit codes "1 — any failure").
fn print_failure(subcommand: &str, err: impl std::fmt::Display) -> ExitCode {
    eprintln!("{subcommand} failed: {err}");
    ExitCode::from(1)
}

/// Pretty-print `value` as the run's sole stdout artifact (07-cli.md
/// §Outputs: "stdout carries exactly one machine-readable artifact per
/// run").
fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("serde_json::Value serialization is infallible")
    );
}

/// `validate <profile>` pipeline (07-cli.md §Invocation: load →
/// declarations → validate). Load the profile into a
/// [`crate::profile_ast::ProfileNode`] AST, run the AST validate checks
/// ([`crate::validate::validate`], the port of the legacy
/// `lm.validate.validate`), and return the validated profile name read
/// off the `Spec` node. A successful validate guarantees the root is a
/// [`crate::profile_ast::ProfileNode::Spec`].
///
/// `pub` so `lm-provision-mcp`'s `lm_validate` tool
/// can reuse this exact pipeline in-process (10-mcp.md §Tool set).
pub fn ast_validate(profile: &Path) -> PipelineResult<String> {
    let node = crate::frontend::load_profile(profile)?;
    crate::validate::validate(&node)?;
    let name = match &node {
        crate::profile_ast::ProfileNode::Spec { name, .. } => name.clone(),
        // Unreachable: `validate` returns `Err(NotSpec)` for any other
        // root, so `?` above already returned. Kept total.
        _ => String::new(),
    };
    Ok(name)
}

fn run_validate(profile: &Path) -> ExitCode {
    match ast_validate(profile) {
        Ok(name) => {
            print_json(&serde_json::json!({ "ok": true, "name": name }));
            ExitCode::from(0)
        }
        Err(err) => print_failure("validate", err),
    }
}

/// `hash <profile>` pipeline (07-cli.md §Invocation: load → declarations
/// → canonical → hash). Deliberately does **not** run validate first —
/// 07 §Invocation's pipeline-stages column for `hash` names only load →
/// declarations → canonical → hash. Returns the 64-character lowercase
/// hex digest via the frontend-agnostic [`crate::canonical::hash`] (see
/// `tests/canonical_frontend_parity.rs`).
///
/// `pub` so `lm-provision-mcp`'s `lm_hash` tool
/// can reuse this exact pipeline in-process (10-mcp.md §Tool set).
pub fn ast_hash(profile: &Path) -> PipelineResult<String> {
    let node = crate::frontend::load_profile(profile)?;
    Ok(crate::canonical::hash(&node))
}

fn run_hash(profile: &Path) -> ExitCode {
    match ast_hash(profile) {
        Ok(hex) => {
            println!("{hex}");
            ExitCode::from(0)
        }
        Err(err) => print_failure("hash", err),
    }
}

/// `plan <profile>` pipeline (07-cli.md §Invocation: load → declarations
/// → plan — no validate step, for the same reason as [`ast_hash`]).
/// Load the profile into an AST and expand it into the plan artifact
/// ([`crate::plan::expand`], the port of the legacy `lm.plan.expand`),
/// returned as a `serde_json::Value` ready to pretty-print.
///
/// `pub` so `lm-provision-mcp`'s `lm_plan` tool
/// can reuse this exact pipeline in-process (10-mcp.md §Tool set).
pub fn ast_plan(profile: &Path) -> PipelineResult<serde_json::Value> {
    let node = crate::frontend::load_profile(profile)?;
    Ok(crate::plan::expand(&node))
}

fn run_plan(profile: &Path) -> ExitCode {
    match ast_plan(profile) {
        Ok(value) => {
            print_json(&value);
            ExitCode::from(0)
        }
        Err(err) => print_failure("plan", err),
    }
}

/// `apply <profile> [--dry-run]` (07-cli.md §Invocation: load →
/// declarations → gate → bridges → plan → dispatch → apply). Runs the
/// AST exec engine ([`crate::apply::run_apply_ast`]) over the profile
/// and prints its report JSON to stdout.
///
/// Two distinct failure shapes map onto 07 §Exit codes' single "1 — any
/// failure" bucket:
///
/// - A precondition failure before the pipeline produces a report
///   (profile load / capability-gate build error) — nothing is printed
///   to stdout, matching every other subcommand's failure path
///   ([`print_failure`]); 07 §Error surface "Precondition: ... nothing
///   executed."
/// - A report with `ok = false` (fail-fast, a step failed) — the report
///   is still printed to stdout (07 §Per-subcommand stdout `apply`:
///   "printed on both success and step failure"), and the report's own
///   `error` string is echoed to stderr as the "final error line" 07
///   §Error surface's literal form calls for (`"apply failed: <message>"`).
///
/// The tokio runtime the effect layer needs is built **here**, at the
/// one entry point that needs it, rather than by putting `#[tokio::main]`
/// on `main`: `validate` / `hash` / `plan` run no effects, and giving
/// them a runtime they never use would make every subcommand pay for
/// `apply`'s requirement. A failure to build one is a precondition
/// failure like any other — nothing is printed to stdout (07 §Error
/// surface).
fn run_apply(profile: &Path, dry_run: bool) -> ExitCode {
    // This `block_on` is the only one in the process: the engine is
    // driven by `dsl_kit::drive_async` from here down, and a phase on
    // the `Call` route is awaited rather than blocked on.
    //
    // Multi-threaded on purpose all the same: the ops that have not
    // moved onto the `Call` route yet drive their async effect from the
    // synchronous `Op::apply` seam (`exec::effects::block_on_effect`),
    // which blocks its own worker and needs a sibling to keep the
    // reactor turning. `Runtime::new` is the multi-threaded builder with
    // every driver enabled.
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => return print_failure("apply", err),
    };
    let report_json = match runtime.block_on(crate::apply::run_apply_ast(profile, dry_run)) {
        Ok(report_json) => report_json,
        Err(err) => return print_failure("apply", err),
    };

    println!("{report_json}");

    let report: serde_json::Value = serde_json::from_str(&report_json)
        .expect("the apply report is always valid JSON (09 §Outputs)");
    let ok = report
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !ok {
        if let Some(error) = report.get("error").and_then(serde_json::Value::as_str) {
            eprintln!("apply failed: {error}");
        }
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_validate_subcommand() {
        let cli = Cli::try_parse_from(["lm-provision", "validate", "profile.json"])
            .expect("validate should parse");
        assert!(matches!(cli.command, Command::Validate { .. }));
    }

    #[test]
    fn parses_hash_subcommand() {
        let cli = Cli::try_parse_from(["lm-provision", "hash", "profile.json"])
            .expect("hash should parse");
        assert!(matches!(cli.command, Command::Hash { .. }));
    }

    #[test]
    fn parses_plan_subcommand() {
        let cli = Cli::try_parse_from(["lm-provision", "plan", "profile.json"])
            .expect("plan should parse");
        assert!(matches!(cli.command, Command::Plan { .. }));
    }

    #[test]
    fn parses_apply_with_dry_run() {
        let cli = Cli::try_parse_from(["lm-provision", "apply", "profile.json", "--dry-run"])
            .expect("apply --dry-run should parse");
        match cli.command {
            Command::Apply { dry_run, .. } => assert!(dry_run),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn apply_without_dry_run_flag_defaults_to_false() {
        let cli = Cli::try_parse_from(["lm-provision", "apply", "profile.json"])
            .expect("apply without --dry-run should parse");
        match cli.command {
            Command::Apply { dry_run, .. } => assert!(!dry_run),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        let result = Cli::try_parse_from(["lm-provision", "bogus", "profile.json"]);
        assert!(result.is_err(), "unknown subcommand must be a parse error");
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        let result = Cli::try_parse_from(["lm-provision", "validate", "profile.json", "--bogus"]);
        assert!(result.is_err(), "unknown flag must be a parse error");
    }

    #[test]
    fn log_level_defaults_to_info() {
        let cli = Cli::try_parse_from(["lm-provision", "validate", "profile.json"])
            .expect("should parse with default log-level");
        assert_eq!(cli.log_level, "info");
    }

    #[test]
    fn rust_log_env_takes_precedence_over_log_level_flag() {
        let filter = resolve_log_filter_from("info", Some("lm_provision=trace".to_string()));
        assert_eq!(filter, "lm_provision=trace");
    }

    #[test]
    fn log_level_flag_is_used_when_rust_log_unset() {
        let filter = resolve_log_filter_from("debug", None);
        assert_eq!(filter, "debug");
    }
}
