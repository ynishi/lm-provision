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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lm_provision::profile_ast::ProfileNode;

use crate::driver::CollectedApply;
use crate::ledger::{self, LedgerRow};
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
    /// Whether step 5 appended a ledger row.
    pub ledger_appended: bool,
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

    /// Step 5's append failed (09 §Error surface: retry, do not
    /// swallow — the apply is not "unrecorded-successful").
    #[error("ledger append failed: {0}")]
    Ledger(#[from] ledger::LedgerError),
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

    // Step 5 ledger (gate: ledger = None). A validate-only session
    // records nothing — no apply happened.
    let ledger_appended = match (&plan.ledger, plan.mode) {
        (Some(path), InvokeMode::Apply | InvokeMode::DryRun) => {
            ledger::append(
                path,
                &LedgerRow {
                    pod_id: pod_id.to_string(),
                    profile_hash: local_hash,
                    report,
                    collected_at: collected.collected_at.clone(),
                },
            )?;
            true
        }
        _ => false,
    };

    Ok(SessionOutput {
        paths,
        collected,
        ledger_appended,
    })
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
