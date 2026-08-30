//! The driver session (08-push-driver-protocol.md §Session contract):
//! [`run`] owns everything between "the caller supplied connectivity,
//! a profile, and secret values" and "a collected report plus a
//! ledger row" — steps 0-5 with per-step gates ([`StepPlan`]).
//!
//! The 2026-07 middle (upload → hash-verify → invoke → collect,
//! [`crate::driver::run`]) survives inside this flow; the session
//! layer adds what first real-pod usage showed was contract-relevant:
//! binary delivery (step 0, gateable), secret preflight before any
//! connection, an in-process profile hash (the operator host cannot
//! run the musl artifact it is about to push), and the ledger append
//! duty (step 5).
//!
//! Step 5 is the one step whose failure does not fail the session: the
//! apply has already run by then, so the append failure is reported as
//! [`SessionOutput::ledger_warning`] alongside the collected report
//! rather than in place of it. 09 §Error surface's "do not swallow" is
//! then the caller's duty — every caller of [`run`] must surface that
//! string (the CLI prints it and exits non-zero).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lm_provision::profile_ast::ProfileNode;

use crate::driver::CollectedApply;
use crate::ledger::{self, ArtifactRow, LedgerRow};
use crate::transport::{PodPaths, Transport, TransportError};

/// Which subcommand form step 3 invokes (08 §Session steps step 3's
/// gate: "dry-run / validate-only select the subcommand form").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InvokeMode {
    /// `apply <profile>` — the declarative one-shot base shape.
    #[default]
    Apply,
    /// `apply <profile> --dry-run` — the Terraform-`plan`-like
    /// preview; still resolves secrets (chapter 06 "dry-run resolves
    /// too").
    DryRun,
    /// `validate <profile>` — shape checks only; no secret is
    /// consumed, so the secret preflight is skipped.
    ValidateOnly,
}

/// Per-step gates + strategies (08 §Session steps). Every step
/// defaults to on; a gate is an explicit "this work is not wanted",
/// never an implicit promise it happened elsewhere.
#[derive(Debug, Clone, Default)]
pub struct StepPlan {
    /// Gate for step 0 ensure-binary (`--skip-install`). With the
    /// step off the session still derives the expected pod path; a
    /// missing binary then surfaces at the first exec as a
    /// precondition failure.
    pub skip_install: bool,
    /// Gate for step 2 hash-verify (`--skip-verify`).
    pub skip_verify: bool,
    /// Step 3 subcommand form.
    pub mode: InvokeMode,
    /// Step 4b pull-artifacts: the operator-host directory declared
    /// artifacts land under, as `<dir>/<pod_id>/<pod path>`; `None`
    /// gates the pull off (`--no-artifacts`). Gating the pull off does
    /// **not** erase the declaration: the profile's artifacts are
    /// still recorded on the ledger row as uncollected, so the
    /// release gate keeps refusing until something actually pulls
    /// them — a skipped step is never an implicit promise the work
    /// happened elsewhere (08 §Session steps).
    pub artifacts_dir: Option<PathBuf>,
    /// Step 5: append to this ledger file; `None` gates the step off
    /// (`--no-ledger`).
    pub ledger: Option<PathBuf>,
}

/// What a completed session hands back (08 §Session contract Output).
#[derive(Debug, Clone)]
pub struct SessionOutput {
    /// The pod-local paths the session used (derived even for
    /// gated-off steps).
    pub paths: PodPaths,
    /// The collected invocation (report / transcript / exit code).
    pub collected: CollectedApply,
    /// Step 4b's per-artifact outcomes (08 §Session steps
    /// pull-artifacts) — empty when the profile declared none or the
    /// mode ran no apply. A `collected = false` entry does not fail
    /// the session, for the ledger's reason: the apply already
    /// happened, and the report plus the recorded debt is worth more
    /// than an error in their place. The CLI turns any uncollected
    /// entry into a non-zero exit (the same duty `ledger_warning`
    /// puts on it).
    pub artifacts: Vec<ArtifactRow>,
    /// Whether step 5 appended a ledger row.
    pub ledger_appended: bool,
    /// Why step 5 did not append, when it was supposed to — `Some` iff
    /// `ledger_appended` is `false` *and* the plan asked for an append.
    ///
    /// A failed append does not fail the session: by the time step 5
    /// runs the apply has already happened on the pod, and returning
    /// `Err` here would discard the one record of what it did, leaving
    /// a caller with neither the report nor a way to reconstruct it.
    /// 09 §Error surface's "an apply is not 'unrecorded-successful' —
    /// drivers must treat append failure as an operational error to
    /// retry, not swallow" is met by handing the failure back next to
    /// the output rather than by throwing the output away; **not
    /// swallowing it is the caller's duty** — surfacing this string is
    /// what makes the missing row visible (the CLI prints it and exits
    /// non-zero; `lm_apply` returns it as `ledger_warning`).
    pub ledger_warning: Option<String>,
}

/// Session-level failures. Transport-class errors stay retryable per
/// 08 §Error surface; everything else is a precondition or collect
/// failure of its own class.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The profile failed to load or validate on the operator host —
    /// nothing was transferred or run (08 §Error surface
    /// "invoke-time precondition", pulled forward to before any
    /// connection).
    #[error("profile precondition failed: {0}")]
    Profile(String),

    /// A consumed secret name is absent from the driver host
    /// environment (08 §Session contract: "a missing name fails
    /// before any connection").
    #[error("secret '{0}' missing in driver host env")]
    SecretMissing(String),

    /// A transport call failed (08 §Error surface "Transport
    /// failures": driver-side, retryable).
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// The pod's post-upload `hash` did not match the operator-side
    /// hash (step 2).
    #[error("profile integrity mismatch: local {local} != remote {remote}")]
    IntegrityMismatch {
        /// Hash computed in-process on the operator host.
        local: String,
        /// Hash the pod's own `hash` invocation printed.
        remote: String,
    },

    /// Step 2's remote `hash` exited non-zero — with `skip_install`
    /// this is the canonical "gated-off step's missing postcondition"
    /// surface (08 §Error surface).
    #[error("remote hash invocation failed (exit {exit_code:?}): {stderr}")]
    RemoteHash {
        /// Remote exit code, if the process exited normally.
        exit_code: Option<i32>,
        /// Remote stderr tail for diagnosis.
        stderr: String,
    },

    /// Step 4's collected stdout did not parse as a report (08 §Error
    /// surface "Collect-time parse failure": transport corruption or
    /// a host crash, never a normal apply failure).
    #[error("collected stdout did not parse as a report: {0}")]
    ReportParse(#[source] serde_json::Error),
    // Step 5's append failure is deliberately *not* a variant here: it
    // happens after the pod-side apply, so failing the session would
    // discard the collected report. It travels back as
    // [`SessionOutput::ledger_warning`] instead.
}

/// Run one driver session (08 §Session steps 0-5) against `transport`.
///
/// `pod_id` is the caller's provisioning context (09 §Ledger) — the
/// session cannot derive it because pod lifecycle lives outside the
/// contract.
pub fn run(
    transport: &dyn Transport,
    plan: &StepPlan,
    local_binary: &Path,
    local_profile: &Path,
    pod_id: &str,
) -> Result<SessionOutput, SessionError> {
    // Operator-side preflight: load + validate + hash in-process, and
    // resolve every consumed secret from the driver host env — all
    // before the first transport call.
    let node = lm_provision::frontend::load_profile(local_profile)
        .map_err(|err| SessionError::Profile(err.to_string()))?;
    lm_provision::validate::validate(&node)
        .map_err(|err| SessionError::Profile(err.to_string()))?;
    let local_hash = lm_provision::canonical::hash(&node);
    let env_secrets = match plan.mode {
        InvokeMode::ValidateOnly => BTreeMap::new(),
        InvokeMode::Apply | InvokeMode::DryRun => resolve_secrets(&node)?,
    };

    // Step 0 ensure-binary (gate: skip_install) + step 1 place-profile.
    let binary_path = if plan.skip_install {
        transport.dest_binary(local_binary)?
    } else {
        transport.ensure_binary(local_binary)?
    };
    let profile_path = transport.place_profile(local_profile)?;
    let paths = PodPaths {
        binary: binary_path,
        profile: profile_path,
    };

    // Step 2 hash-verify (gate: skip_verify).
    if !plan.skip_verify {
        let hash_args = vec!["hash".to_string(), paths.profile.display().to_string()];
        let output = transport.exec(&paths, &hash_args, &BTreeMap::new())?;
        if output.exit_code != Some(0) {
            return Err(SessionError::RemoteHash {
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        let remote_hash = output.stdout.trim().to_string();
        if remote_hash != local_hash {
            return Err(SessionError::IntegrityMismatch {
                local: local_hash,
                remote: remote_hash,
            });
        }
    }

    // Step 3 invoke + step 4 collect.
    let args = invoke_args(plan.mode, &paths);
    let output = transport.exec(&paths, &args, &env_secrets)?;
    let report: serde_json::Value =
        serde_json::from_str(&output.stdout).map_err(SessionError::ReportParse)?;
    let collected = CollectedApply {
        profile_hash: local_hash.clone(),
        report: report.clone(),
        stderr: output.stderr,
        exit_code: output.exit_code,
        collected_at: jiff::Timestamp::now().to_string(),
    };

    // Step 4b pull-artifacts: only a real apply has produced anything
    // to pull — a dry run or a validate leaves the declaration
    // unexercised and records nothing, so it cannot arm the release
    // gate against work that never existed.
    let artifacts = match plan.mode {
        InvokeMode::Apply => pull_artifacts(transport, &node, plan, pod_id),
        InvokeMode::DryRun | InvokeMode::ValidateOnly => Vec::new(),
    };

    // Step 5 ledger (gate: ledger = None). A validate-only session
    // records nothing — no apply happened. A failed append leaves a
    // warning next to the output instead of replacing it (see
    // [`SessionOutput::ledger_warning`]).
    let (ledger_appended, ledger_warning) = match (&plan.ledger, plan.mode) {
        (Some(path), InvokeMode::Apply | InvokeMode::DryRun) => {
            let row = LedgerRow {
                pod_id: pod_id.to_string(),
                profile_hash: local_hash,
                report,
                collected_at: collected.collected_at.clone(),
                artifacts: artifacts.clone(),
            };
            match ledger::append(path, &row) {
                Ok(()) => (true, None),
                Err(err) => (false, Some(err.to_string())),
            }
        }
        _ => (false, None),
    };

    Ok(SessionOutput {
        paths,
        collected,
        artifacts,
        ledger_appended,
        ledger_warning,
    })
}

/// Step 4b: pull every declared artifact to
/// `<artifacts_dir>/<pod_id>/<pod path>` (08 §Session steps
/// pull-artifacts). Total — a failed pull becomes a
/// `collected = false` row rather than an error, because the apply
/// has already run and the record of the debt is the whole point;
/// the same holds for a gated-off pull (`artifacts_dir = None`),
/// which records every declared artifact as uncollected.
fn pull_artifacts(
    transport: &dyn Transport,
    node: &ProfileNode,
    plan: &StepPlan,
    pod_id: &str,
) -> Vec<ArtifactRow> {
    let ProfileNode::Spec { artifacts, .. } = node else {
        return Vec::new();
    };
    artifacts
        .iter()
        .map(|path| match &plan.artifacts_dir {
            None => ArtifactRow {
                path: path.clone(),
                collected: false,
                dest: None,
                error: Some("pull gated off (--no-artifacts)".to_string()),
            },
            Some(dir) => {
                // Mirror the full pod path under the per-pod directory
                // (validate pinned it absolute, chapter 03 check 5b),
                // so two artifacts can never collide on a file name.
                let dest = dir
                    .join(pod_id)
                    .join(path.strip_prefix('/').unwrap_or(path));
                match transport.download(Path::new(path), &dest) {
                    Ok(()) => ArtifactRow {
                        path: path.clone(),
                        collected: true,
                        dest: Some(dest.display().to_string()),
                        error: None,
                    },
                    Err(err) => ArtifactRow {
                        path: path.clone(),
                        collected: false,
                        dest: None,
                        error: Some(err.to_string()),
                    },
                }
            }
        })
        .collect()
}

/// Every consumed secret name (the profile's `env_secrets` list),
/// resolved from the driver host environment — fail-fast on the first
/// missing name, before any connection (08 §Session contract).
fn resolve_secrets(node: &ProfileNode) -> Result<BTreeMap<String, String>, SessionError> {
    let ProfileNode::Spec { env_secrets, .. } = node else {
        return Err(SessionError::Profile(
            "profile root is not a Spec".to_string(),
        ));
    };
    let mut resolved = BTreeMap::new();
    for name in env_secrets {
        let value = std::env::var(name).map_err(|_| SessionError::SecretMissing(name.clone()))?;
        resolved.insert(name.clone(), value);
    }
    Ok(resolved)
}

/// Step 3's argv (08 §Session steps: the invoke command form is the
/// stable 2026-07 contract, `--dry-run` / `validate` select the form).
fn invoke_args(mode: InvokeMode, paths: &PodPaths) -> Vec<String> {
    let profile = paths.profile.display().to_string();
    match mode {
        InvokeMode::Apply => vec!["apply".to_string(), profile],
        InvokeMode::DryRun => vec!["apply".to_string(), profile, "--dry-run".to_string()],
        InvokeMode::ValidateOnly => vec!["validate".to_string(), profile],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use crate::transport::ExecOutput;

    /// A pod that answers the hash probe correctly, applies "ok", and
    /// scripts step 4b: each declared path either "exists" (download
    /// succeeds and is recorded) or does not (download errors).
    struct ArtifactPod {
        hash: String,
        missing: Vec<String>,
        downloads: RefCell<Vec<(PathBuf, PathBuf)>>,
    }

    impl Transport for ArtifactPod {
        fn dest_binary(&self, _local: &Path) -> Result<PathBuf, TransportError> {
            Ok(PathBuf::from("/pod/lm-provision"))
        }

        fn dest_profile(&self, _local: &Path) -> Result<PathBuf, TransportError> {
            Ok(PathBuf::from("/pod/profile.json"))
        }

        fn ensure_binary(&self, local: &Path) -> Result<PathBuf, TransportError> {
            self.dest_binary(local)
        }

        fn place_profile(&self, local: &Path) -> Result<PathBuf, TransportError> {
            self.dest_profile(local)
        }

        fn exec(
            &self,
            _paths: &PodPaths,
            args: &[String],
            _env: &BTreeMap<String, String>,
        ) -> Result<ExecOutput, TransportError> {
            let stdout = if args.first().map(String::as_str) == Some("hash") {
                format!("{}\n", self.hash)
            } else {
                r#"{"ok":true,"dry_run":false,"profile_name":"demo","steps":[]}"#.to_string()
            };
            Ok(ExecOutput {
                stdout,
                stderr: String::new(),
                exit_code: Some(0),
            })
        }

        fn download(&self, remote: &Path, local: &Path) -> Result<(), TransportError> {
            if self.missing.iter().any(|m| Path::new(m) == remote) {
                return Err(TransportError::Io(std::io::Error::other(format!(
                    "no such file: {}",
                    remote.display()
                ))));
            }
            self.downloads
                .borrow_mut()
                .push((remote.to_path_buf(), local.to_path_buf()));
            Ok(())
        }
    }

    fn artifact_fixture(dir_label: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-driver-session-test-{dir_label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        let profile = dir.join("profile.json");
        std::fs::write(
            &profile,
            serde_json::json!({
                "type": "Spec",
                "name": "artifact-session",
                "artifacts": ["/workspace/out", "/workspace/run.log"],
                "phases": []
            })
            .to_string(),
        )
        .expect("write profile");
        (dir, profile)
    }

    fn pod_for(profile: &Path, missing: &[&str]) -> ArtifactPod {
        let node = lm_provision::frontend::load_profile(profile).expect("fixture parses");
        ArtifactPod {
            hash: lm_provision::canonical::hash(&node),
            missing: missing.iter().map(|s| (*s).to_string()).collect(),
            downloads: RefCell::new(Vec::new()),
        }
    }

    /// **Step 4b pulls each declared artifact to
    /// `<artifacts_dir>/<pod_id>/<pod path>`, records a failed pull as
    /// an uncollected row instead of failing the session, and step 5
    /// writes the outcomes onto the ledger row.**
    #[test]
    fn declared_artifacts_are_pulled_recorded_and_ledgered() {
        let (dir, profile) = artifact_fixture("pull");
        let pod = pod_for(&profile, &["/workspace/run.log"]);
        let ledger_path = dir.join("ledger.jsonl");
        let plan = StepPlan {
            artifacts_dir: Some(dir.join("artifacts")),
            ledger: Some(ledger_path.clone()),
            ..StepPlan::default()
        };

        let output = run(&pod, &plan, Path::new("lm-provision"), &profile, "pod-9")
            .expect("an uncollected artifact must not fail the session");

        // Declared order is the recorded order; the pull destination
        // mirrors the pod path under the per-pod directory.
        assert_eq!(output.artifacts.len(), 2);
        assert_eq!(output.artifacts[0].path, "/workspace/out");
        assert!(output.artifacts[0].collected);
        assert_eq!(
            output.artifacts[0].dest.as_deref(),
            Some(dir.join("artifacts/pod-9/workspace/out").to_str().unwrap())
        );
        assert!(!output.artifacts[1].collected);
        assert!(output.artifacts[1]
            .error
            .as_deref()
            .expect("an uncollected row carries its reason")
            .contains("/workspace/run.log"));
        assert_eq!(pod.downloads.borrow().len(), 1);

        // The ledger row carries the same outcomes — the record the
        // release gate reads.
        let rows = ledger::list(&ledger_path).expect("ledger readable");
        assert_eq!(rows[0].artifacts, output.artifacts);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// **Gating the pull off records the debt rather than erasing it**:
    /// every declared artifact rides the ledger row as uncollected, so
    /// the release gate stays armed (08 §Session steps: a skipped step
    /// is never an implicit promise the work happened elsewhere).
    #[test]
    fn a_gated_off_pull_still_records_every_declared_artifact_as_uncollected() {
        let (dir, profile) = artifact_fixture("gated");
        let pod = pod_for(&profile, &[]);
        let plan = StepPlan {
            artifacts_dir: None,
            ..StepPlan::default()
        };

        let output = run(&pod, &plan, Path::new("lm-provision"), &profile, "pod-9")
            .expect("the session itself succeeds");
        assert_eq!(output.artifacts.len(), 2);
        assert!(output.artifacts.iter().all(|it| !it.collected));
        assert!(pod.downloads.borrow().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// **A dry run records no artifacts**: nothing was produced, so a
    /// dry-run row must not arm the release gate — nor stand in for
    /// the real apply behind it (the gate skips dry-run rows for the
    /// same reason).
    #[test]
    fn a_dry_run_records_no_artifacts() {
        let (dir, profile) = artifact_fixture("dry");
        let pod = pod_for(&profile, &[]);
        let plan = StepPlan {
            mode: InvokeMode::DryRun,
            artifacts_dir: Some(dir.join("artifacts")),
            ..StepPlan::default()
        };

        let output = run(&pod, &plan, Path::new("lm-provision"), &profile, "pod-9")
            .expect("dry run succeeds");
        assert!(output.artifacts.is_empty());
        assert!(pod.downloads.borrow().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
