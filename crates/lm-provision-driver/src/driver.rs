//! The driver protocol proper (08-push-driver-protocol.md §Driver
//! steps): upload → (hash integrity check) → invoke → collect, driven
//! against any [`Transport`] implementation.
//!
//! [`run`] never spawns a process itself — every pod-directed action
//! goes through the [`Transport`] it is given, so unit tests below
//! exercise the full sequencing and error mapping against an in-memory
//! [`Transport`] mock, with no real binary involved. The one exception
//! is [`hash_locally`], which is deliberately *not* part of [`run`]'s
//! own call graph (08 §Driver steps: "the driver may run ... `hash`
//! ... locally first" is an operator-side action that happens before
//! any pod interaction, not a step [`Transport`] mediates) — callers
//! run it once up front and pass the resulting digest into [`run`].

use std::collections::BTreeMap;
use std::path::Path;

use crate::transport::{PodPaths, Transport, TransportError};

/// Errors raised while running the driver's upload → invoke → collect
/// sequence (08 §Error surface).
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The operator-side `hash` invocation ([`hash_locally`]) failed
    /// before the driver protocol even started.
    #[error("failed to compute the local profile hash: {0}")]
    LocalHash(String),

    /// Step 1 failed (08 §Error surface "Transport failures": "upload
    /// incomplete ... driver-side; retryable").
    #[error("upload failed: {0}")]
    Upload(#[source] TransportError),

    /// The post-upload `hash` invocation against the pod's own copy of
    /// the profile failed at the transport level.
    #[error("hash invocation on the pod failed: {0}")]
    RemoteHash(#[source] TransportError),

    /// The pre- and post-upload profile hashes disagree (08 §Driver
    /// steps: "`hash` before and after upload doubles as a
    /// profile-integrity check").
    #[error(
        "profile integrity check failed: local hash {local} != pod hash {remote} \
         (08-push-driver-protocol.md \u{a7}Driver steps)"
    )]
    IntegrityMismatch {
        /// The hash [`hash_locally`] computed before upload.
        local: String,
        /// The hash the pod's own `hash` invocation reported after
        /// upload.
        remote: String,
    },

    /// Step 2 failed at the transport level (08 §Error surface
    /// "Invoke-time precondition failures" collapse into this when the
    /// transport itself could not even run the command).
    #[error("apply invocation failed: {0}")]
    Invoke(#[source] TransportError),

    /// Step 3's collected stdout did not parse as the apply report JSON
    /// (08 §Error surface "Collect-time parse failure": "it indicates
    /// transport corruption or a host crash, never a normal apply
    /// failure").
    #[error("collected stdout did not parse as an apply report: {0}")]
    ReportParse(#[source] serde_json::Error),
}

/// One completed upload → invoke → collect round trip (08 §Outputs).
///
/// [`run`] returns this even when the pod-side apply itself failed
/// (`report["ok"] == false`) — only transport-level failures (upload,
/// hash mismatch, unparseable stdout) surface as [`DriverError`] (08
/// §Error surface: "the driver must treat 'exit 1 + parseable report'
/// as a richer signal than the exit code alone").
#[derive(Debug, Clone)]
pub struct CollectedApply {
    /// The profile hash [`run`] verified against the pod (09 §Ledger
    /// `profile_hash`).
    pub profile_hash: String,
    /// The parsed apply report, verbatim as collected (09 §Outputs
    /// "Apply report").
    pub report: serde_json::Value,
    /// stderr transcript (08 §Outputs: "human-readable transcript").
    pub stderr: String,
    /// The raw process exit code from the `apply` invocation.
    pub exit_code: Option<i32>,
    /// RFC 3339 UTC, stamped by this function immediately after
    /// collection (09 §Ledger `collected_at`: "driver clock").
    pub collected_at: String,
}

/// Run `<binary> hash <profile>` on the operator's own host (08 §Driver
/// steps: "The driver may run `validate` / `hash` / `plan` remotely or
/// locally first — the binary is the same and the artifacts are
/// identical"). The digest this returns is what [`run`] verifies
/// against the pod's own post-upload `hash` invocation and is the
/// `profile_hash` a caller stamps onto a ledger row (09 §Ledger).
///
/// Deliberately does not go through a [`Transport`] — computing this
/// hash is an operator-side action that happens before any pod
/// interaction, unlike every call [`run`] itself makes.
pub fn hash_locally(binary: &Path, profile: &Path) -> Result<String, DriverError> {
    let output = std::process::Command::new(binary)
        .args(["hash", &profile.display().to_string()])
        .output()
        .map_err(|source| {
            DriverError::LocalHash(format!("failed to spawn {}: {source}", binary.display()))
        })?;
    if !output.status.success() {
        return Err(DriverError::LocalHash(format!(
            "{} hash exited with {:?}: {}",
            binary.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_string())
        .map_err(|err| DriverError::LocalHash(format!("hash stdout was not utf-8: {err}")))
}

/// Run the driver protocol (08 §Driver steps) against `transport`:
/// upload the binary + profile, verify the pod's own post-upload
/// `hash` matches `local_profile_hash` (the integrity check 08
/// describes), then invoke `apply [--dry-run]` with `env_secrets`
/// exported into the invocation's process environment — never into the
/// command line, the profile file, or stdout/stderr (08 §Driver steps:
/// "Secrets never appear in the command line, in the profile file, or
/// on stdout/stderr") — and collect the report.
pub fn run(
    transport: &dyn Transport,
    local_binary: &Path,
    local_profile: &Path,
    local_profile_hash: &str,
    env_secrets: &BTreeMap<String, String>,
    dry_run: bool,
) -> Result<CollectedApply, DriverError> {
    let paths = transport
        .upload(local_binary, local_profile)
        .map_err(DriverError::Upload)?;

    let hash_output = transport
        .exec(&paths, &hash_args(&paths), &BTreeMap::new())
        .map_err(DriverError::RemoteHash)?;
    let remote_hash = hash_output.stdout.trim().to_string();
    if remote_hash != local_profile_hash {
        return Err(DriverError::IntegrityMismatch {
            local: local_profile_hash.to_string(),
            remote: remote_hash,
        });
    }

    let apply_output = transport
        .exec(&paths, &apply_args(&paths, dry_run), env_secrets)
        .map_err(DriverError::Invoke)?;

    let report: serde_json::Value =
        serde_json::from_str(&apply_output.stdout).map_err(DriverError::ReportParse)?;

    Ok(CollectedApply {
        profile_hash: local_profile_hash.to_string(),
        report,
        stderr: apply_output.stderr,
        exit_code: apply_output.exit_code,
        collected_at: jiff::Timestamp::now().to_string(),
    })
}

/// `hash <pod-profile-path>` (08 §Driver steps: the profile-integrity
/// check runs the same `hash` subcommand the operator ran locally).
fn hash_args(paths: &PodPaths) -> Vec<String> {
    vec!["hash".to_string(), paths.profile.display().to_string()]
}

/// `apply <pod-profile-path> [--dry-run]` (08 §Driver steps step 2).
/// Never includes a secret value — secrets flow through `env`
/// ([`run`]'s `env_secrets` parameter) only.
fn apply_args(paths: &PodPaths, dry_run: bool) -> Vec<String> {
    let mut args = vec!["apply".to_string(), paths.profile.display().to_string()];
    if dry_run {
        args.push("--dry-run".to_string());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    /// One recorded [`Transport::exec`] call: the args and env it was
    /// invoked with.
    type RecordedCall = (Vec<String>, BTreeMap<String, String>);

    /// Records every [`Transport::exec`] call it receives and answers
    /// with pre-scripted responses keyed on the first argument (`hash`
    /// vs `apply`) — enough to drive [`run`] end to end with no real
    /// process spawned.
    struct MockTransport {
        calls: RefCell<Vec<RecordedCall>>,
        hash_response: String,
        apply_response: crate::transport::ExecOutput,
    }

    impl Transport for MockTransport {
        fn upload(&self, _binary: &Path, _profile: &Path) -> Result<PodPaths, TransportError> {
            Ok(PodPaths {
                binary: PathBuf::from("/pod/lm-provision"),
                profile: PathBuf::from("/pod/profile.lua"),
            })
        }

        fn exec(
            &self,
            _paths: &PodPaths,
            args: &[String],
            env: &BTreeMap<String, String>,
        ) -> Result<crate::transport::ExecOutput, TransportError> {
            self.calls.borrow_mut().push((args.to_vec(), env.clone()));
            if args.first().map(String::as_str) == Some("hash") {
                Ok(crate::transport::ExecOutput {
                    stdout: self.hash_response.clone(),
                    stderr: String::new(),
                    exit_code: Some(0),
                })
            } else {
                Ok(self.apply_response.clone())
            }
        }
    }

    fn ok_apply_response() -> crate::transport::ExecOutput {
        crate::transport::ExecOutput {
            stdout: r#"{"ok":true,"dry_run":true,"profile_name":"demo","steps":[]}"#.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }
    }

    #[test]
    fn run_exports_secrets_only_via_env_never_via_argv() {
        let mut env_secrets = BTreeMap::new();
        env_secrets.insert("HF_TOKEN".to_string(), "s3cr3t-value".to_string());

        let transport = MockTransport {
            calls: RefCell::new(Vec::new()),
            hash_response: "a".repeat(64),
            apply_response: ok_apply_response(),
        };

        let result = run(
            &transport,
            Path::new("/local/lm-provision"),
            Path::new("/local/profile.lua"),
            &"a".repeat(64),
            &env_secrets,
            true,
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let calls = transport.calls.borrow();
        assert_eq!(calls.len(), 2, "hash call then apply call");

        let (hash_call_args, hash_call_env) = &calls[0];
        assert_eq!(hash_call_args[0], "hash");
        assert!(
            hash_call_env.is_empty(),
            "the integrity-check hash invocation carries no secrets"
        );
        assert!(!hash_call_args.iter().any(|a| a.contains("s3cr3t-value")));

        let (apply_call_args, apply_call_env) = &calls[1];
        assert_eq!(apply_call_args[0], "apply");
        assert!(
            !apply_call_args.iter().any(|a| a.contains("s3cr3t-value")),
            "secret value must never appear in argv: {apply_call_args:?}"
        );
        assert_eq!(
            apply_call_env.get("HF_TOKEN"),
            Some(&"s3cr3t-value".to_string()),
            "secret must be exported via the env map"
        );
    }

    #[test]
    fn run_propagates_dry_run_flag_into_apply_args() {
        let transport = MockTransport {
            calls: RefCell::new(Vec::new()),
            hash_response: "b".repeat(64),
            apply_response: ok_apply_response(),
        };

        run(
            &transport,
            Path::new("/local/lm-provision"),
            Path::new("/local/profile.lua"),
            &"b".repeat(64),
            &BTreeMap::new(),
            true,
        )
        .expect("run should succeed");

        let calls = transport.calls.borrow();
        let (apply_call_args, _) = &calls[1];
        assert!(apply_call_args.contains(&"--dry-run".to_string()));
    }

    #[test]
    fn run_returns_integrity_mismatch_when_pod_hash_differs_from_local_hash() {
        let transport = MockTransport {
            calls: RefCell::new(Vec::new()),
            hash_response: "different-hash".to_string(),
            apply_response: ok_apply_response(),
        };

        let err = run(
            &transport,
            Path::new("/local/lm-provision"),
            Path::new("/local/profile.lua"),
            &"a".repeat(64),
            &BTreeMap::new(),
            false,
        )
        .expect_err("mismatched hashes must be rejected");
        assert!(matches!(err, DriverError::IntegrityMismatch { .. }));

        // The mismatch is detected before the apply step ever runs.
        assert_eq!(transport.calls.borrow().len(), 1);
    }

    #[test]
    fn run_returns_report_parse_error_when_apply_stdout_is_not_json() {
        let transport = MockTransport {
            calls: RefCell::new(Vec::new()),
            hash_response: "c".repeat(64),
            apply_response: crate::transport::ExecOutput {
                stdout: "not json".to_string(),
                stderr: "transport went sideways".to_string(),
                exit_code: None,
            },
        };

        let err = run(
            &transport,
            Path::new("/local/lm-provision"),
            Path::new("/local/profile.lua"),
            &"c".repeat(64),
            &BTreeMap::new(),
            false,
        )
        .expect_err("unparseable stdout must be a collect-time error");
        assert!(matches!(err, DriverError::ReportParse(_)));
    }

    #[test]
    fn run_returns_ok_when_pod_side_apply_fails_but_report_parses_richer_signal() {
        let transport = MockTransport {
            calls: RefCell::new(Vec::new()),
            hash_response: "d".repeat(64),
            apply_response: crate::transport::ExecOutput {
                stdout: r#"{"ok":false,"dry_run":true,"profile_name":"demo","steps":[],"error":"step 1 (sh.exec) failed: boom"}"#
                    .to_string(),
                stderr: String::new(),
                exit_code: Some(1),
            },
        };

        let collected = run(
            &transport,
            Path::new("/local/lm-provision"),
            Path::new("/local/profile.lua"),
            &"d".repeat(64),
            &BTreeMap::new(),
            false,
        )
        .expect(
            "exit 1 + parseable report is a richer signal, not a driver error (08 §Error surface)",
        );

        assert_eq!(collected.report["ok"], serde_json::json!(false));
        assert_eq!(collected.exit_code, Some(1));
    }

    #[test]
    fn collected_at_is_a_parseable_rfc3339_utc_timestamp() {
        let transport = MockTransport {
            calls: RefCell::new(Vec::new()),
            hash_response: "e".repeat(64),
            apply_response: ok_apply_response(),
        };

        let collected = run(
            &transport,
            Path::new("/local/lm-provision"),
            Path::new("/local/profile.lua"),
            &"e".repeat(64),
            &BTreeMap::new(),
            false,
        )
        .expect("run should succeed");

        collected
            .collected_at
            .parse::<jiff::Timestamp>()
            .expect("collected_at must round-trip as an RFC 3339 UTC timestamp");
    }

    #[test]
    fn apply_args_never_smuggles_a_secret_and_omits_dry_run_flag_by_default() {
        let paths = PodPaths {
            binary: PathBuf::from("/pod/lm-provision"),
            profile: PathBuf::from("/pod/profile.lua"),
        };
        assert_eq!(
            apply_args(&paths, false),
            vec!["apply".to_string(), "/pod/profile.lua".to_string()]
        );
        assert_eq!(
            apply_args(&paths, true),
            vec![
                "apply".to_string(),
                "/pod/profile.lua".to_string(),
                "--dry-run".to_string()
            ]
        );
    }

    #[test]
    fn hash_args_targets_the_pod_profile_path() {
        let paths = PodPaths {
            binary: PathBuf::from("/pod/lm-provision"),
            profile: PathBuf::from("/pod/profile.lua"),
        };
        assert_eq!(
            hash_args(&paths),
            vec!["hash".to_string(), "/pod/profile.lua".to_string()]
        );
    }
}
