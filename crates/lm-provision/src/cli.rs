//! CLI subcommand surface and pipeline wiring (07-cli.md).
//!
//! `validate` / `hash` / `plan` each run the pipeline-stages column
//! 07-cli.md §Invocation names for that subcommand, reached through the
//! same sandboxed VM + `require('lm.*')` path a profile author's own
//! code takes (registration order steps 1-5, 04-bridge.md §Registration
//! order, via [`crate::vm::eval::evaluate_profile_file`]) — no bridge
//! primitive is registered for these subcommands, matching their
//! "none (read-only)" effects column in 07 §Invocation. `apply` (07
//! §Invocation: "load → declarations → gate → bridges → plan → dispatch
//! → apply") wires [`crate::apply::run_apply`] (milestone M4-1) instead —
//! see [`run_apply`] below (milestone M4-3).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mlua::{Function, Lua, Table};

use crate::batteries;
use crate::vm::eval::{evaluate_profile_file, EvalError};

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

/// The four MVP subcommands (07-cli.md §Invocation table).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// load → declarations → validate (read-only, no effects).
    Validate {
        /// Path to the profile file.
        profile: PathBuf,
    },
    /// load → declarations → canonical → hash (read-only, no effects).
    Hash {
        /// Path to the profile file.
        profile: PathBuf,
    },
    /// load → declarations → plan (read-only, no effects).
    Plan {
        /// Path to the profile file.
        profile: PathBuf,
    },
    /// load → declarations → gate → bridges → plan → dispatch → apply.
    Apply {
        /// Path to the profile file.
        profile: PathBuf,
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
/// Carries only a rendered message rather than the source error: `mlua
/// ::Error`'s `ExternalError` variant boxes a plain `dyn
/// std::error::Error` (not `Send + Sync`), so it cannot flow through a
/// `Send + Sync`-bounded error type such as `anyhow::Error` — capturing
/// the `Display` output immediately sidesteps that, and is all
/// 07-cli.md §Error surface's "final error line" needs.
///
/// `pub` (rather than crate-private) so [`lm-provision-mcp`'s MCP tool
/// wrappers][../../lm-provision-mcp] can surface the same message text
/// `print_failure` renders to stderr without depending on `mlua` /
/// `serde_json` error types directly (10-mcp.md §Error surface
/// "precondition ... class preserved"). Widening this visibility does
/// not change any CLI behavior — [`run_validate`], [`run_hash`], and
/// [`run_plan`] below are untouched.
#[derive(Debug)]
pub struct RunError(String);

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<EvalError> for RunError {
    fn from(err: EvalError) -> Self {
        RunError(err.to_string())
    }
}

impl From<mlua::Error> for RunError {
    fn from(err: mlua::Error) -> Self {
        RunError(err.to_string())
    }
}

impl From<serde_json::Error> for RunError {
    fn from(err: serde_json::Error) -> Self {
        RunError(err.to_string())
    }
}

/// The `Result` alias every read-only pipeline function below returns.
/// `pub` for the same reason [`RunError`] is (milestone M6, see there).
pub type PipelineResult<T> = std::result::Result<T, RunError>;

/// `require(module)` via the profile's sandboxed VM — the same path a
/// profile author's own `require('lm.<x>')` call takes
/// (05-sandbox-layer-contract.md §L1).
fn require_module(lua: &Lua, module: &str) -> mlua::Result<Table> {
    let require_fn: Function = lua.globals().get("require")?;
    require_fn.call(module)
}

/// `validate <profile>` pipeline (07-cli.md §Invocation: load →
/// declarations → validate). Returns the validated profile name on
/// success. A validate-stage rejection (`{ ok = false, error }`,
/// 03-pipeline-stage-artifacts.md §validate) and any earlier-stage
/// error (profile load / Lua eval, 07 §Error surface "Precondition")
/// both surface as `Err` here — 07's exit-code mapping collapses every
/// failure to exit code 1 regardless of which one it was; the message
/// on stderr is what distinguishes them for a human reader.
pub fn validate_pipeline(profile: &Path) -> PipelineResult<String> {
    let extracted = evaluate_profile_file(profile)?;

    let validate_mod = require_module(&extracted.lua, "lm.validate")?;
    let validate_fn: Function = validate_mod.get("validate")?;
    let result: Table = validate_fn.call(extracted.ir.clone())?;

    let ok: bool = result.get("ok")?;
    if !ok {
        let message: String = result.get("error")?;
        return Err(RunError(message));
    }
    Ok(result.get("name")?)
}

/// `hash <profile>` pipeline (07-cli.md §Invocation: load →
/// declarations → canonical → hash). Deliberately does **not** run
/// `lm.validate` first — 07 §Invocation's pipeline-stages column for
/// `hash` names only load → declarations → canonical → hash, and
/// 03-pipeline-stage-artifacts.md §Error surface confirms canonical /
/// hash "raise only on malformed stage input", i.e. content-level
/// validation is validate's job, not a precondition of these two
/// stages. Returns the 64-character lowercase hex digest.
pub fn hash_pipeline(profile: &Path) -> PipelineResult<String> {
    let extracted = evaluate_profile_file(profile)?;
    batteries::hash::install(&extracted.lua)?;

    let canonical_mod = require_module(&extracted.lua, "lm.canonical")?;
    let encode_fn: Function = canonical_mod.get("encode")?;
    let bytes: mlua::String = encode_fn.call(extracted.ir.clone())?;

    let hash_mod = require_module(&extracted.lua, "lm.hash")?;
    let sha256_hex_fn: Function = hash_mod.get("sha256_hex")?;
    Ok(sha256_hex_fn.call(bytes)?)
}

/// `plan <profile>` pipeline (07-cli.md §Invocation: load →
/// declarations → plan — no validate step, for the same reason as
/// [`hash_pipeline`]). Returns the plan artifact as a
/// `serde_json::Value`, ready to pretty-print.
///
/// Routed through `lm.canonical.encode` rather than a bespoke Lua-table
/// -> JSON walk on the Rust side: a plan step's `payload` can carry a
/// `SecretRef` userdata verbatim (e.g. an `env.ref(...)` value used as
/// `fs.write.content`, passed through unresolved by every read-only
/// stage), and `lm.canonical` is the module that already knows how to
/// encode that opaquely as `{"__secret":"NAME"}`
/// (03-pipeline-stage-artifacts.md §canonical) — reusing it here avoids
/// duplicating that rule (or worse, leaking a userdata's raw
/// representation) in a second, Rust-side serializer. The resulting
/// object-key order is `lm.canonical`'s lexicographic order, not the
/// field order 03 §plan's Lua-table example happens to list them in;
/// JSON object key order carries no meaning, so this is not a shape
/// deviation from the frozen contract (03 §Stability: "plan artifact
/// shape ... stable").
pub fn plan_pipeline(profile: &Path) -> PipelineResult<serde_json::Value> {
    let extracted = evaluate_profile_file(profile)?;

    let plan_mod = require_module(&extracted.lua, "lm.plan")?;
    let expand_fn: Function = plan_mod.get("expand")?;
    let plan_table: Table = expand_fn.call(extracted.ir.clone())?;

    let canonical_mod = require_module(&extracted.lua, "lm.canonical")?;
    let encode_fn: Function = canonical_mod.get("encode")?;
    let bytes: String = encode_fn.call(plan_table)?;

    Ok(serde_json::from_str(&bytes)?)
}

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

fn run_validate(profile: &Path) -> ExitCode {
    match validate_pipeline(profile) {
        Ok(name) => {
            print_json(&serde_json::json!({ "ok": true, "name": name }));
            ExitCode::from(0)
        }
        Err(err) => print_failure("validate", err),
    }
}

fn run_hash(profile: &Path) -> ExitCode {
    match hash_pipeline(profile) {
        Ok(hex) => {
            println!("{hex}");
            ExitCode::from(0)
        }
        Err(err) => print_failure("hash", err),
    }
}

fn run_plan(profile: &Path) -> ExitCode {
    match plan_pipeline(profile) {
        Ok(value) => {
            print_json(&value);
            ExitCode::from(0)
        }
        Err(err) => print_failure("plan", err),
    }
}

/// `apply <profile> [--dry-run]` (07-cli.md §Invocation: load →
/// declarations → gate → bridges → plan → dispatch → apply; milestone
/// M4-3). Delegates the pipeline itself to
/// [`crate::apply::run_apply`] (milestone M4-1) — the report JSON that
/// function returns is already pretty-printed
/// (09-apply-report-and-ledger.md §Outputs "Apply report" via
/// `lm.canonical.encode`, see that function's own doc comment), so it is
/// printed to stdout verbatim rather than re-serialized through
/// [`print_json`].
///
/// Two distinct failure shapes map onto 07 §Exit codes' single "1 — any
/// failure" bucket:
///
/// - A precondition failure before the pipeline even produces a report
///   (profile load / Lua eval / sandbox wiring error,
///   [`crate::apply::ApplyError`]) — nothing is printed to stdout,
///   matching every other subcommand's failure path
///   ([`print_failure`]); 07 §Error surface "Precondition: ... nothing
///   executed."
/// - A report with `ok = false` (09 §Semantics: fail-fast, a bridge step
///   failed) — the report is still printed to stdout (07 §Per-subcommand
///   stdout `apply`: "printed on both success and step failure"), and
///   the report's own `error` string is echoed to stderr as the "final
///   error line" 07 §Error surface's literal form calls for elsewhere
///   (`"apply failed: <message>"`).
fn run_apply(profile: &Path, dry_run: bool) -> ExitCode {
    let report_json = match crate::apply::run_apply(profile, dry_run) {
        Ok(report_json) => report_json,
        Err(err) => return print_failure("apply", err),
    };

    println!("{report_json}");

    let report: serde_json::Value = serde_json::from_str(&report_json)
        .expect("crate::apply::run_apply always returns valid JSON (09 §Outputs)");
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
        let cli = Cli::try_parse_from(["lm-provision", "validate", "profile.lua"])
            .expect("validate should parse");
        assert!(matches!(cli.command, Command::Validate { .. }));
    }

    #[test]
    fn parses_hash_subcommand() {
        let cli = Cli::try_parse_from(["lm-provision", "hash", "profile.lua"])
            .expect("hash should parse");
        assert!(matches!(cli.command, Command::Hash { .. }));
    }

    #[test]
    fn parses_plan_subcommand() {
        let cli = Cli::try_parse_from(["lm-provision", "plan", "profile.lua"])
            .expect("plan should parse");
        assert!(matches!(cli.command, Command::Plan { .. }));
    }

    #[test]
    fn parses_apply_with_dry_run() {
        let cli = Cli::try_parse_from(["lm-provision", "apply", "profile.lua", "--dry-run"])
            .expect("apply --dry-run should parse");
        match cli.command {
            Command::Apply { dry_run, .. } => assert!(dry_run),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn apply_without_dry_run_flag_defaults_to_false() {
        let cli = Cli::try_parse_from(["lm-provision", "apply", "profile.lua"])
            .expect("apply without --dry-run should parse");
        match cli.command {
            Command::Apply { dry_run, .. } => assert!(!dry_run),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        let result = Cli::try_parse_from(["lm-provision", "bogus", "profile.lua"]);
        assert!(result.is_err(), "unknown subcommand must be a parse error");
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        let result = Cli::try_parse_from(["lm-provision", "validate", "profile.lua", "--bogus"]);
        assert!(result.is_err(), "unknown flag must be a parse error");
    }

    #[test]
    fn log_level_defaults_to_info() {
        let cli = Cli::try_parse_from(["lm-provision", "validate", "profile.lua"])
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
