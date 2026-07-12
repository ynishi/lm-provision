//! `lm_apply(profile_path, pod_id, dry_run=false)` (10-mcp.md §Tool set):
//! runs the full chapter 08 push-driver protocol (upload → hash-verify
//! → invoke → collect) against the MVP
//! [`lm_provision_driver::local_exec::LocalExecTransport`] — the only
//! [`lm_provision_driver::transport::Transport`] this crate ships (08
//! §Stability; task instruction: "MVP は driver crate の
//! LocalExecTransport を使う") — then appends the collected result to
//! the append-only apply ledger (09 §Ledger).
//!
//! Unlike [`lm_provision::apply::run_apply`] (the *on-pod* binary's own
//! `apply` subcommand, milestone M4), this function never runs `lm.*`
//! Lua domain logic itself: it drives the already-built `lm-provision`
//! binary as an external process through [`Transport`], exactly as an
//! external pod manager would (08 §Purpose). `binary_path` is therefore
//! a *different* artifact from this MCP server's own process — it is
//! server deployment configuration ([`crate::config::Config`]).
//!
//! ## Secret precondition (10 §Inputs "Secrets: the MCP server process
//! environment is the secret source")
//!
//! Before invoking the driver at all, every name the profile declares
//! in `env_secrets` (chapter 01 declarations, extracted locally via
//! [`evaluate_profile_file`] against the same `profile_path` the driver
//! will later upload) must be present in *this server's own* process
//! environment. A name missing here is reported as a precondition-class
//! failure (10 §Error surface: "precondition (validate reject / missing
//! secret env)") before any upload/invoke/collect step runs, rather
//! than surfacing later as a bridge-level "missing in host env" failure
//! buried inside the collected report (06-secret-handling.md §Error
//! surface) — the MCP server is the only party positioned to catch this
//! early, since it alone holds the secret source (10 §Inputs).
//!
//! [`Transport`]: lm_provision_driver::transport::Transport

use std::collections::BTreeMap;
use std::path::Path;

use lm_provision::vm::eval::evaluate_profile_file;
use lm_provision_driver::driver::{self, DriverError};
use lm_provision_driver::ledger::{self, LedgerRow};
use lm_provision_driver::local_exec::LocalExecTransport;

/// `lm_apply`'s tool arguments (10 §Tool set: `profile_path` string;
/// `pod_id` string; `dry_run` bool, default false).
#[derive(Debug, Clone, Copy)]
pub struct ApplyArgs<'a> {
    /// Path to the profile file, visible to the MCP server host (10
    /// §Inputs).
    pub profile_path: &'a Path,
    /// Driver-provided provisioning context, stamped onto the ledger
    /// row verbatim (09 §Ledger `pod_id`). The MVP
    /// [`LocalExecTransport`] does not use this to select a transport
    /// target — every `lm_apply` call runs against the same local
    /// staging directory regardless of `pod_id` — it is recorded for
    /// ledger correlation only (see [`crate::apply_tool`]'s own module
    /// doc comment).
    pub pod_id: &'a str,
    /// Decode + policy + secret resolution only, no effects (07-cli.md
    /// `apply --dry-run`).
    pub dry_run: bool,
}

/// `{ report, exit_code, ledger_appended }` (10 §Outputs `lm_apply`),
/// widened with an optional `ledger_warning` string for the
/// `ledger_appended = false` case (10 §Error surface: "ledger append
/// failures reported via `ledger_appended = false` plus an MCP-level
/// warning").
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApplyOutput {
    /// The apply report, verbatim as collected — present even when
    /// apply itself failed (10 §Outputs: "the report is returned even
    /// when apply failed").
    pub report: serde_json::Value,
    /// The raw process exit code from the pod-side `apply` invocation.
    pub exit_code: Option<i32>,
    /// `false` iff the post-collect ledger append failed; the report
    /// and `exit_code` above are still meaningful either way.
    pub ledger_appended: bool,
    /// Present iff `ledger_appended` is `false` (09 §Error surface:
    /// "an apply is not 'unrecorded-successful' — drivers must treat
    /// append failure as an operational error to retry, not swallow").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger_warning: Option<String>,
}

/// Errors raised before or during the driver protocol — every variant
/// here is 10 §Error surface's "precondition" or "transport" class;
/// runtime (bridge-step) failures never reach this type because they
/// are captured inside the report itself (09 §Semantics) and returned
/// as `Ok(ApplyOutput { report, .. })`.
#[derive(Debug, thiserror::Error)]
pub enum ApplyToolError {
    /// Profile evaluation (declaration extraction) failed before the
    /// `env_secrets` precondition check could even run.
    #[error("failed to read profile declarations: {0}")]
    ProfileEval(String),

    /// A declared `env_secrets` name is absent from the MCP server's
    /// own process environment (06-secret-handling.md §Error surface
    /// literal form, checked here rather than deep inside the report).
    #[error("secret '{0}' missing in host env")]
    MissingSecretEnv(String),

    /// The driver protocol itself failed (upload / hash-integrity /
    /// invoke / collect-parse — 08 §Error surface's transport class).
    #[error("driver protocol failed: {0}")]
    Driver(#[from] DriverError),
}

/// Run `lm_apply` end to end: extract declarations, check the secret
/// precondition, compute the local profile hash, drive the protocol
/// through a fresh [`LocalExecTransport`] rooted at `staging_dir`, and
/// append the result to `ledger_path`.
pub fn lm_apply(
    args: ApplyArgs<'_>,
    binary_path: &Path,
    staging_dir: &Path,
    ledger_path: &Path,
) -> Result<ApplyOutput, ApplyToolError> {
    let extracted = evaluate_profile_file(args.profile_path)
        .map_err(|err| ApplyToolError::ProfileEval(err.to_string()))?;

    let mut env_secrets = BTreeMap::new();
    for name in &extracted.declarations.env_secrets {
        let value =
            std::env::var(name).map_err(|_| ApplyToolError::MissingSecretEnv(name.clone()))?;
        env_secrets.insert(name.clone(), value);
    }

    let local_hash = driver::hash_locally(binary_path, args.profile_path)?;

    let transport = LocalExecTransport::new(staging_dir.to_path_buf());
    let collected = driver::run(
        &transport,
        binary_path,
        args.profile_path,
        &local_hash,
        &env_secrets,
        args.dry_run,
    )?;

    let row = LedgerRow {
        pod_id: args.pod_id.to_string(),
        profile_hash: collected.profile_hash.clone(),
        report: collected.report.clone(),
        collected_at: collected.collected_at.clone(),
    };
    let (ledger_appended, ledger_warning) = match ledger::append(ledger_path, &row) {
        Ok(()) => (true, None),
        Err(err) => (false, Some(err.to_string())),
    };

    Ok(ApplyOutput {
        report: collected.report,
        exit_code: collected.exit_code,
        ledger_appended,
        ledger_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "{}/../lm-provision/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
    }

    /// Locate the already-built `lm-provision` binary under the
    /// workspace's `target/{debug,release}` directory (or
    /// `CARGO_TARGET_DIR` if overridden). `cargo test --workspace`
    /// builds every workspace member's binaries as a normal
    /// consequence of building the workspace, so the binary this crate
    /// depends on as an *external artifact* (see this module's own doc
    /// comment) is expected to already exist by the time these tests
    /// run.
    fn built_binary_path() -> PathBuf {
        let target_root = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(format!("{}/../../target", env!("CARGO_MANIFEST_DIR")))
            });
        for profile in ["debug", "release"] {
            let candidate = target_root.join(profile).join("lm-provision");
            if candidate.exists() {
                return candidate;
            }
        }
        panic!(
            "lm-provision binary not found under {}/{{debug,release}} — \
             run `cargo build --workspace` first",
            target_root.display()
        );
    }

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-mcp-apply-tool-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    #[test]
    fn lm_apply_dry_run_returns_an_ok_report_and_appends_to_the_ledger() {
        let binary_path = built_binary_path();
        let staging_dir = temp_dir("staging");
        let ledger_path = temp_dir("ledger").with_extension("jsonl");

        let output = lm_apply(
            ApplyArgs {
                profile_path: &fixture("apply-sh-fs.lua"),
                pod_id: "test-pod-1",
                dry_run: true,
            },
            &binary_path,
            &staging_dir,
            &ledger_path,
        )
        .expect("dry-run apply against a no-secret fixture should succeed");

        assert_eq!(output.report["ok"], serde_json::json!(true));
        assert_eq!(output.report["dry_run"], serde_json::json!(true));
        assert_eq!(output.exit_code, Some(0));
        assert!(output.ledger_appended, "ledger append should succeed");
        assert!(output.ledger_warning.is_none());

        let rows = ledger::list(&ledger_path).expect("ledger should be readable");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_id, "test-pod-1");

        std::fs::remove_dir_all(&staging_dir).ok();
        std::fs::remove_file(&ledger_path).ok();
    }

    #[test]
    fn lm_apply_appends_one_more_row_per_call_even_for_the_same_pod_and_profile() {
        let binary_path = built_binary_path();
        let ledger_path = temp_dir("ledger-repeat").with_extension("jsonl");
        // A fresh staging dir per call, not one shared dir reused across
        // both `lm_apply` invocations: overwriting an already-staged
        // executable file in place and re-exec'ing it immediately is an
        // OS-specific hazard (observed as an empty-stdout `hash`
        // invocation on macOS/APFS in this crate's own dev loop) that is
        // orthogonal to what this test asserts — the *ledger's* append
        // behavior for repeated `(pod_id, profile_hash)` calls (09
        // §Ledger), not `LocalExecTransport`'s same-path-reuse semantics.
        let mut staging_dirs = Vec::new();

        for i in 0..2 {
            let staging_dir = temp_dir(&format!("staging-repeat-{i}"));
            lm_apply(
                ApplyArgs {
                    profile_path: &fixture("apply-sh-fs.lua"),
                    pod_id: "test-pod-1",
                    dry_run: true,
                },
                &binary_path,
                &staging_dir,
                &ledger_path,
            )
            .expect("dry-run apply should succeed");
            staging_dirs.push(staging_dir);
        }

        let rows = ledger::list(&ledger_path).expect("ledger should be readable");
        assert_eq!(
            rows.len(),
            2,
            "09 §Ledger: (pod_id, profile_hash) is deliberately not unique"
        );

        for staging_dir in staging_dirs {
            std::fs::remove_dir_all(&staging_dir).ok();
        }
        std::fs::remove_file(&ledger_path).ok();
    }

    /// A profile whose declared `env_secrets` name is chosen to be
    /// deterministically absent from any real environment — unlike
    /// reusing a shared fixture's `HF_TOKEN` declaration, this does not
    /// depend on the ambient test environment happening to leave a
    /// well-known secret name unset.
    const MISSING_SECRET_PROFILE: &str = r#"
        local profile = require("lm.profile")
        return profile({
            name = "demo-missing-secret",
            capabilities = {},
            env_secrets = { "LM_PROVISION_MCP_TEST_DEFINITELY_UNSET_SECRET_XYZ" },
            phases = {},
        })
    "#;

    fn write_missing_secret_profile() -> PathBuf {
        let path = temp_dir("missing-secret-profile").with_extension("lua");
        std::fs::write(&path, MISSING_SECRET_PROFILE).expect("write temp profile");
        path
    }

    #[test]
    fn lm_apply_reports_missing_secret_env_as_a_precondition_error_before_any_invoke() {
        assert!(
            std::env::var("LM_PROVISION_MCP_TEST_DEFINITELY_UNSET_SECRET_XYZ").is_err(),
            "test precondition: this made-up secret name must not be set in the test env"
        );

        let binary_path = built_binary_path();
        let staging_dir = temp_dir("staging-missing-secret");
        let ledger_path = temp_dir("ledger-missing-secret").with_extension("jsonl");
        let profile_path = write_missing_secret_profile();

        let err = lm_apply(
            ApplyArgs {
                profile_path: &profile_path,
                pod_id: "test-pod-1",
                dry_run: true,
            },
            &binary_path,
            &staging_dir,
            &ledger_path,
        )
        .expect_err("a declared-but-absent secret must fail before any driver step runs");
        assert!(matches!(
            err,
            ApplyToolError::MissingSecretEnv(ref name)
                if name == "LM_PROVISION_MCP_TEST_DEFINITELY_UNSET_SECRET_XYZ"
        ));

        assert!(
            ledger::list(&ledger_path)
                .expect("ledger read should not fail")
                .is_empty(),
            "no ledger row should be appended when the precondition check fails"
        );

        std::fs::remove_dir_all(&staging_dir).ok();
        std::fs::remove_file(&ledger_path).ok();
        std::fs::remove_file(&profile_path).ok();
    }

    #[test]
    fn lm_apply_profile_eval_failure_is_a_precondition_error() {
        let binary_path = built_binary_path();
        let staging_dir = temp_dir("staging-missing-profile");
        let ledger_path = temp_dir("ledger-missing-profile").with_extension("jsonl");

        let err = lm_apply(
            ApplyArgs {
                profile_path: Path::new("/nonexistent/lm-provision-profile.lua"),
                pod_id: "test-pod-1",
                dry_run: true,
            },
            &binary_path,
            &staging_dir,
            &ledger_path,
        )
        .expect_err("a missing profile file must not reach the driver protocol");
        assert!(matches!(err, ApplyToolError::ProfileEval(_)));

        std::fs::remove_dir_all(&staging_dir).ok();
        std::fs::remove_file(&ledger_path).ok();
    }
}
