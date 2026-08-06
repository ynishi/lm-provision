//! `lm_apply(profile_path, pod_id, dry_run=false)` (10-mcp.md §Tool set):
//! runs one driver session ([`session::run`], 08 §Session steps 0-5)
//! against the [`Transport`] the caller supplies — ensure-binary →
//! place-profile → hash-verify → invoke → collect → ledger append (09
//! §Ledger).
//!
//! ## Why the session contract and not the 2026-07 middle
//!
//! This tool used to drive the driver crate's pre-session three-step
//! middle directly, and compute the profile hash by running `<binary>
//! hash <profile>` as a subprocess *on this server's host*. That could not
//! work outside a test: `binary_path` is the pod's artifact (08
//! §Inputs: an `x86_64-unknown-linux-musl` build), and an operator host
//! that could execute it would be a coincidence, not the contract. The
//! session layer computes the hash in-process
//! ([`lm_provision::canonical::hash`]) for exactly that reason, so
//! moving onto it is what makes an apply against a real pod possible —
//! nothing this function does now spawns a process on the server host.
//!
//! Two behaviours come with the move. The profile is `validate`d before
//! anything is transferred, so a profile that decodes but does not
//! validate is rejected here as a precondition failure rather than
//! surfacing as a failed apply report from the pod. And every step gate
//! [`StepPlan`] offers is left off: 10 §Tool set gives `lm_apply` no
//! argument to skip installing the binary or to skip the integrity
//! check, and a gate this layer turned on by itself would be a promise
//! the caller never made.
//!
//! The transport is an argument rather than something this function
//! constructs: which pod an apply runs against is decided by resolving
//! `pod_id` in the pod target registry ([`crate::targets`]), and that
//! lookup belongs to the layer that holds the registry
//! ([`crate::server`]). Consequently this function never observes an
//! unregistered `pod_id` — by the time it is called, the `pod_id` has
//! already been proven to name a destination.
//!
//! Unlike [`lm_provision::apply::run_apply_ast`] (the *on-pod* binary's
//! own `apply` subcommand), this function never runs the provisioning
//! engine itself: it drives the already-built `lm-provision`
//! binary as an external process through [`Transport`], exactly as an
//! external pod manager would (08 §Purpose). `binary_path` is therefore
//! a *different* artifact from this MCP server's own process — it is
//! server deployment configuration ([`crate::config::Config`]).
//!
//! ## Secret precondition (10 §Inputs "Secrets: the MCP server process
//! environment is the secret source")
//!
//! Before anything is transferred, every name the profile declares in
//! `env_secrets` (chapter 01 declarations) must be present in *this
//! server's own* process environment. The session's operator-side
//! preflight is that check, and "the operator host" here *is* this
//! server process — [`std::env::var`] reads the same environment 10
//! §Inputs names as the secret source. A name missing there is a
//! precondition-class failure (10 §Error surface: "precondition
//! (validate reject / missing secret env)") raised before any
//! upload/invoke/collect step runs, rather than surfacing later as a
//! bridge-level "missing in host env" failure buried inside the
//! collected report (06-secret-handling.md §Error surface) — the MCP
//! server is the only party positioned to catch this early, since it
//! alone holds the secret source (10 §Inputs).
//!
//! [`Transport`]: lm_provision_driver::transport::Transport

use std::path::Path;

use lm_provision_driver::session::{self, InvokeMode, SessionError, StepPlan};
use lm_provision_driver::transport::Transport;

/// `lm_apply`'s tool arguments (10 §Tool set: `profile_path` string;
/// `pod_id` string; `dry_run` bool, default false).
#[derive(Debug, Clone, Copy)]
pub struct ApplyArgs<'a> {
    /// Path to the profile file, visible to the MCP server host (10
    /// §Inputs).
    pub profile_path: &'a Path,
    /// Driver-provided provisioning context, stamped onto the ledger
    /// row verbatim (09 §Ledger `pod_id`). It is also the key
    /// [`crate::server`] resolved in the pod target registry to obtain
    /// the `transport` argument, so the row records a destination this
    /// server is configured for rather than an unchecked string.
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
    /// The driver session failed before it could collect a report.
    ///
    /// One variant, because 10 §Error surface's two classes are the
    /// wrapped error's own distinction and re-splitting them here would
    /// duplicate it: [`SessionError::Profile`] /
    /// [`SessionError::SecretMissing`] are the precondition class,
    /// [`SessionError::Transport`] the transport class, and the
    /// integrity / remote-hash / parse variants are the session's own
    /// collect-side failures. [`crate::server`] maps all of them to
    /// `invalid_params` today; the class survives in the value for
    /// whenever that mapping is refined.
    #[error("apply session failed: {0}")]
    Session(#[from] SessionError),
}

/// Run `lm_apply` end to end: one driver session (08 §Session steps
/// 0-5) against `transport`, recording the collected apply in
/// `ledger_path`.
///
/// Nothing here is a step of its own — the operator-side preflight
/// (load / validate / in-process hash / secret resolution), the four
/// pod-directed steps, and the ledger append all belong to
/// [`session::run`]. This function's whole job is turning `lm_apply`'s
/// three tool arguments into that session's [`StepPlan`] and its output
/// back into [`ApplyOutput`].
pub fn lm_apply(
    transport: &dyn Transport,
    binary_path: &Path,
    ledger_path: &Path,
    args: ApplyArgs<'_>,
) -> Result<ApplyOutput, ApplyToolError> {
    let plan = StepPlan {
        // No tool argument gates either step (see this module's doc).
        skip_install: false,
        skip_verify: false,
        // 10 §Tool set exposes `dry_run` only. `InvokeMode::ValidateOnly`
        // is deliberately unreachable from here: `lm_validate` already
        // performs that check in-process, without a pod.
        mode: if args.dry_run {
            InvokeMode::DryRun
        } else {
            InvokeMode::Apply
        },
        ledger: Some(ledger_path.to_path_buf()),
    };

    let output = session::run(
        transport,
        &plan,
        binary_path,
        args.profile_path,
        args.pod_id,
    )?;

    Ok(ApplyOutput {
        report: output.collected.report,
        exit_code: output.collected.exit_code,
        ledger_appended: output.ledger_appended,
        // 09 §Error surface's "do not swallow": the session hands a
        // failed append back next to the report instead of discarding
        // both, and this is where it becomes visible to the client (10
        // §Error surface's `ledger_appended = false` plus a warning).
        ledger_warning: output.ledger_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use lm_provision_driver::ledger;
    use lm_provision_driver::local_exec::LocalExecTransport;
    use lm_provision_driver::transport::{ExecOutput, PodPaths, TransportError};

    use crate::targets::{RegistrySource, TargetRegistry};

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

    /// A [`Transport`] that touches nothing and records the name of
    /// every call it receives, so a test can assert both *that* the pod
    /// was reached and *that it was not*.
    ///
    /// The driver crate has a mock of its own, but it is private to its
    /// own test module (a `#[cfg(test)]` item is not part of the
    /// dependency's public surface), so this crate needs its own.
    struct MockTransport {
        calls: RefCell<Vec<String>>,
        /// What the pod's `hash` invocation answers — set to the
        /// profile's real digest to let the integrity check pass.
        hash_stdout: String,
        /// What the pod's `apply` invocation answers on stdout.
        apply_stdout: String,
    }

    impl MockTransport {
        fn new(hash_stdout: impl Into<String>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                hash_stdout: hash_stdout.into(),
                apply_stdout: r#"{"ok":true,"dry_run":true,"profile_name":"demo","steps":[]}"#
                    .to_string(),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn record(&self, call: &str) {
            self.calls.borrow_mut().push(call.to_string());
        }
    }

    impl Transport for MockTransport {
        fn dest_binary(&self, _local_binary: &Path) -> Result<PathBuf, TransportError> {
            self.record("dest_binary");
            Ok(PathBuf::from("/pod/lm-provision"))
        }

        fn dest_profile(&self, _local_profile: &Path) -> Result<PathBuf, TransportError> {
            self.record("dest_profile");
            Ok(PathBuf::from("/pod/profile.json"))
        }

        fn ensure_binary(&self, _local_binary: &Path) -> Result<PathBuf, TransportError> {
            self.record("ensure_binary");
            Ok(PathBuf::from("/pod/lm-provision"))
        }

        fn place_profile(&self, _local_profile: &Path) -> Result<PathBuf, TransportError> {
            self.record("place_profile");
            Ok(PathBuf::from("/pod/profile.json"))
        }

        fn exec(
            &self,
            _paths: &PodPaths,
            args: &[String],
            _env: &BTreeMap<String, String>,
        ) -> Result<ExecOutput, TransportError> {
            let subcommand = args.first().map(String::as_str).unwrap_or("<none>");
            self.record(&format!("exec {subcommand}"));
            let stdout = if subcommand == "hash" {
                self.hash_stdout.clone()
            } else {
                self.apply_stdout.clone()
            };
            Ok(ExecOutput {
                stdout,
                stderr: String::new(),
                exit_code: Some(0),
            })
        }
    }

    /// The digest the session computes in-process for `profile_path`
    /// (`lm_provision::canonical::hash`), so a mock pod can answer the
    /// integrity check with the value that matches.
    fn profile_hash(profile_path: &Path) -> String {
        let node = lm_provision::frontend::load_profile(profile_path).expect("fixture loads");
        lm_provision::canonical::hash(&node)
    }

    /// A registered `pod_id` runs where its entry says it does: the
    /// transport comes from resolving `test-pod-1` in a registry, and
    /// the artifacts land in that entry's `staging_dir` — so the ledger
    /// row's `pod_id` names an observed destination, not a claim.
    #[test]
    fn lm_apply_dry_run_through_the_registry_returns_an_ok_report_and_appends_to_the_ledger() {
        let binary_path = built_binary_path();
        let staging_dir = temp_dir("staging");
        let ledger_path = temp_dir("ledger").with_extension("jsonl");

        let registry_json = serde_json::json!({
            "targets": [
                { "pod_id": "test-pod-1", "kind": "local-exec", "staging_dir": staging_dir }
            ]
        })
        .to_string();
        let registry = TargetRegistry::load(
            RegistrySource::FromFile(PathBuf::from("/etc/lm-provision/targets.json")),
            &registry_json,
            Path::new("/this-default-must-not-be-used"),
        )
        .expect("registry loads");
        let transport = registry
            .resolve("test-pod-1")
            .expect("the pod_id is registered")
            .to_transport();

        let output = lm_apply(
            transport.as_ref(),
            &binary_path,
            &ledger_path,
            ApplyArgs {
                profile_path: &fixture("apply-sh-fs.json"),
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect("dry-run apply against a no-secret fixture should succeed");

        assert_eq!(output.report["ok"], serde_json::json!(true));
        assert_eq!(output.report["dry_run"], serde_json::json!(true));
        assert_eq!(output.exit_code, Some(0));
        assert!(output.ledger_appended, "ledger append should succeed");
        assert!(output.ledger_warning.is_none());
        assert!(
            staging_dir.join("lm-provision").exists(),
            "the apply must run against the destination the registry entry names"
        );

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
                &LocalExecTransport::new(&staging_dir),
                &binary_path,
                &ledger_path,
                ApplyArgs {
                    profile_path: &fixture("apply-sh-fs.json"),
                    pod_id: "test-pod-1",
                    dry_run: true,
                },
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
    const MISSING_SECRET_PROFILE: &str = r#"{
        "type": "Spec",
        "name": "demo-missing-secret",
        "env_secrets": ["LM_PROVISION_MCP_TEST_DEFINITELY_UNSET_SECRET_XYZ"]
    }"#;

    fn write_missing_secret_profile() -> PathBuf {
        let path = temp_dir("missing-secret-profile").with_extension("json");
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
            &LocalExecTransport::new(&staging_dir),
            &binary_path,
            &ledger_path,
            ApplyArgs {
                profile_path: &profile_path,
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect_err("a declared-but-absent secret must fail before any driver step runs");
        assert!(
            matches!(
                err,
                ApplyToolError::Session(SessionError::SecretMissing(ref name))
                    if name == "LM_PROVISION_MCP_TEST_DEFINITELY_UNSET_SECRET_XYZ"
            ),
            "expected the session's secret preflight to reject it, got: {err:?}"
        );

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
            &LocalExecTransport::new(&staging_dir),
            &binary_path,
            &ledger_path,
            ApplyArgs {
                profile_path: Path::new("/nonexistent/lm-provision-profile.json"),
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect_err("a missing profile file must not reach the driver protocol");
        assert!(
            matches!(err, ApplyToolError::Session(SessionError::Profile(_))),
            "expected a profile precondition failure, got: {err:?}"
        );

        std::fs::remove_dir_all(&staging_dir).ok();
        std::fs::remove_file(&ledger_path).ok();
    }

    /// The point of moving onto the session contract: `binary_path` is
    /// the *pod's* artifact (08 §Inputs: a musl build), and this server
    /// never runs it. Here it is a file this host cannot execute at all
    /// — the shape a real deployment always has — and the apply still
    /// completes, because the profile hash is computed in-process and
    /// every other use of the binary goes through the transport.
    ///
    /// The previous implementation spawned `<binary_path> hash
    /// <profile>` on this host, so this case could not get past its
    /// first step; the `Command` assertion below is that old step,
    /// failing.
    #[test]
    fn a_binary_path_this_host_cannot_execute_still_reaches_the_transport() {
        let binary_path = temp_dir("not-an-executable").with_extension("bin");
        std::fs::write(&binary_path, b"this is not an executable image\n")
            .expect("write the stand-in artifact");
        assert!(
            std::process::Command::new(&binary_path)
                .arg("hash")
                .output()
                .is_err(),
            "test precondition: this artifact must not be runnable on the test host"
        );

        let profile_path = fixture("apply-sh-fs.json");
        let ledger_path = temp_dir("ledger-unrunnable-binary").with_extension("jsonl");
        let transport = MockTransport::new(profile_hash(&profile_path));

        let output = lm_apply(
            &transport,
            &binary_path,
            &ledger_path,
            ApplyArgs {
                profile_path: &profile_path,
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect("an artifact this host cannot execute must not stop the session");

        assert_eq!(output.report["ok"], serde_json::json!(true));
        assert!(output.ledger_appended);
        assert_eq!(
            transport.calls(),
            vec!["ensure_binary", "place_profile", "exec hash", "exec apply"],
            "every use of the binary must be a transport call (08 §Session steps 0-4)"
        );

        std::fs::remove_file(&binary_path).ok();
        std::fs::remove_file(&ledger_path).ok();
    }

    /// A profile that decodes but does not validate: `paths` must be
    /// absolute (03 §validate check 5). The session validates on the
    /// operator host before step 0, so this is a precondition failure
    /// with nothing transferred — where the pre-session implementation
    /// only ran `load_profile` and would have shipped it to the pod to
    /// find out.
    #[test]
    fn a_profile_that_fails_validate_never_reaches_the_transport() {
        let profile_path = temp_dir("invalid-profile").with_extension("json");
        std::fs::write(
            &profile_path,
            serde_json::json!({
                "type": "Spec",
                "name": "relative-path-profile",
                "paths": ["workspace/models"]
            })
            .to_string(),
        )
        .expect("write the profile");
        let ledger_path = temp_dir("ledger-invalid-profile").with_extension("jsonl");
        let transport = MockTransport::new("0".repeat(64));

        let err = lm_apply(
            &transport,
            Path::new("/nonexistent/lm-provision"),
            &ledger_path,
            ApplyArgs {
                profile_path: &profile_path,
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect_err("a profile that fails validate must not be applied");

        assert!(
            matches!(err, ApplyToolError::Session(SessionError::Profile(_))),
            "expected a profile precondition failure, got: {err:?}"
        );
        assert!(
            transport.calls().is_empty(),
            "nothing may be transferred or run: {:?}",
            transport.calls()
        );
        assert!(
            !ledger_path.exists(),
            "a rejected profile must not leave a ledger row"
        );

        std::fs::remove_file(&profile_path).ok();
    }

    /// The apply already ran on the pod by the time the ledger append
    /// is attempted, so a failed append must not take the report down
    /// with it (09 §Error surface: the row is missing, but the caller
    /// still has to be told what it is missing a row *for*). The
    /// unwritable path here is a file under a directory that does not
    /// exist.
    #[test]
    fn a_failed_ledger_append_still_returns_the_report_with_a_warning() {
        let profile_path = fixture("apply-sh-fs.json");
        let ledger_path = temp_dir("ledger-unwritable")
            .join("no-such-directory")
            .join("ledger.jsonl");
        assert!(!ledger_path.exists());
        let transport = MockTransport::new(profile_hash(&profile_path));

        let output = lm_apply(
            &transport,
            Path::new("/nonexistent/lm-provision"),
            &ledger_path,
            ApplyArgs {
                profile_path: &profile_path,
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect("a failed append is not a failed apply");

        assert_eq!(output.report["ok"], serde_json::json!(true));
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.ledger_appended);
        assert!(
            output
                .ledger_warning
                .as_deref()
                .is_some_and(|warning| !warning.is_empty()),
            "the unrecorded apply must be reported, not swallowed: {:?}",
            output.ledger_warning
        );
    }
}
