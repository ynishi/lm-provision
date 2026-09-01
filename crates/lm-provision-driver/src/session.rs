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
//! The preflight also owns the resolve stage (spec
//! `11-fragment-import.md` §Resolution: `load → resolve → validate →
//! canonical / hash`). A profile that imports a fragment is not a
//! profile the pod could judge on its own — the fragment may live in
//! the operator's working tree, and the identity the session compares
//! in step 2 is the *expanded* canonical hash (spec 11 §Identity, the
//! same hash the pod's `lm-provision hash` computes because it too
//! resolves first). So the session expands here, and step 1 places the
//! expanded payload rather than the source text whenever the source
//! carried an `Import` ([`place_profile`]). A profile with no `Import`
//! uploads its own file unchanged, as every session did before spec 11.
//!
//! Step 5 is the one step whose failure does not fail the session: the
//! apply has already run by then, so the append failure is reported as
//! [`SessionOutput::ledger_warning`] alongside the collected report
//! rather than in place of it. 09 §Error surface's "do not swallow" is
//! then the caller's duty — every caller of [`run`] must surface that
//! string (the CLI prints it and exits non-zero).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// The profile failed to load, resolve or validate on the operator
    /// host — nothing was transferred or run (08 §Error surface
    /// "invoke-time precondition", pulled forward to before any
    /// connection).
    ///
    /// A resolve rejection (spec 11 §Error surface — an unreachable
    /// fragment, a pin that did not match, a merge collision) lands
    /// here rather than in a variant of its own, for the reason load
    /// and validate already share one: 08 §Error surface names a single
    /// precondition class, and every member of it says the same two
    /// things — the profile as supplied cannot be applied, and nothing
    /// has happened to the pod. The distinction a caller needs is
    /// carried by the message, which spec 11 requires to name the
    /// import chain that produced it.
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
    // Operator-side preflight: load + resolve + validate + hash
    // in-process, and resolve every consumed secret from the driver
    // host env — all before the first transport call.
    let source = lm_provision::frontend::load_profile(local_profile)
        .map_err(|err| SessionError::Profile(err.to_string()))?;
    // Asked before expansion, because afterwards there is nothing left
    // to ask: resolve's whole job is removing these nodes.
    let imported = carries_import(&source);
    let node = lm_provision::resolve::resolve(source, local_profile)
        .map_err(|err| SessionError::Profile(err.to_string()))?;
    lm_provision::validate::validate(&node)
        .map_err(|err| SessionError::Profile(err.to_string()))?;
    // The expanded AST is the identity (spec 11 §Identity), so this is
    // the number step 2 compares the pod's answer against — and the
    // number the pod will compute, since its own `hash` resolves first.
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
    let profile_path = place_profile(transport, local_profile, &node, imported)?;
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

/// Session step 1 place-profile (08 §Session steps), carrying spec 11's
/// one consequence for it: what the pod re-parses has to be what the
/// operator hashed.
///
/// A document that carried an `Import` is no longer the profile this
/// session judged — resolve expanded it, `local_hash` came off the
/// expansion (spec 11 §Identity), and validate ran on it. Uploading the
/// source text would ask the pod to redo that expansion: to reach a
/// fragment that may only exist in the operator's working tree, from a
/// machine whose network the resolve stage never governed (spec 11
/// §Resolution: "fetching happens on the operator host at resolve
/// time"). So `expanded` is serialized back through the JSON bridge
/// ([`lm_provision::to_bridge_json`], whose one required invariant is
/// `hash(parse(serialize(ast))) == hash(ast)` — spec 11 §Cache last
/// paragraph) and that payload is placed. The pod's side of the
/// contract does not change at all: it re-parses and re-hashes what it
/// receives, as it always has, and step 2 compares two hashes of the
/// same document.
///
/// **A document with no `Import` places its own file, byte for byte.**
/// The serializer is hash-faithful, not byte-faithful, so routing every
/// profile through it would rewrite the uploaded text of profiles that
/// needed no expansion — for nothing (spec 11 §Stability guarantee 1's
/// philosophy: a profile without imports is untouched by this chapter).
fn place_profile(
    transport: &dyn Transport,
    local_profile: &Path,
    expanded: &ProfileNode,
    imported: bool,
) -> Result<PathBuf, SessionError> {
    if !imported {
        return Ok(transport.place_profile(local_profile)?);
    }
    // The staged file lives exactly as long as this call: `staged`
    // deletes it on the way out, including out of the `?` below.
    let staged = StagedPayload::write(local_profile, expanded).map_err(TransportError::Io)?;
    Ok(transport.place_profile(&staged.path)?)
}

/// Whether `node` carries an [`ProfileNode::Import`] anywhere resolve
/// would expand one — the question that decides whether step 1 uploads
/// an expanded payload or the operator's own file.
///
/// Written here rather than reused: `validate`'s check 0b walks the
/// same nodes but is an inline loop that returns an error, and it looks
/// at the top-level phase list only, which is all *it* needs (it runs
/// after resolve, where a surviving `Import` anywhere is already the
/// bug it reports). This walk descends into `Fragment.phases` too, so a
/// document whose root is a fragment answers honestly instead of
/// answering "no" and having its imports quietly shipped to the pod.
fn carries_import(node: &ProfileNode) -> bool {
    match node {
        ProfileNode::Import { .. } => true,
        ProfileNode::Spec { phases, .. } | ProfileNode::Fragment { phases, .. } => {
            phases.iter().any(carries_import)
        }
        _ => false,
    }
}

/// Per-process counter in a staging directory's name. `pid` alone is
/// not enough: an MCP server runs sessions concurrently in one process
/// (`lm_apply`), and two of them staging into one directory could
/// delete each other's payload mid-upload — the collision
/// [`lm_provision::resolve`]'s cache writer names for the same reason.
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// The expanded payload [`place_profile`] uploads, and the directory it
/// was staged in — removed together when this value drops.
///
/// The hygiene rules are `lm_provision::fetch`'s (its `admit` documents
/// them): create exclusively under a per-process name, so no parallel
/// run, leftover file or planted symlink is ever written through, and
/// leave nothing behind on any path out. Here the cleanup is a `Drop`
/// rather than a call on each early return, because the caller's early
/// returns are the transport's and would each have to remember.
struct StagedPayload {
    /// The directory holding the payload; removed with it.
    dir: PathBuf,
    /// The payload file itself, the path handed to the transport.
    path: PathBuf,
}

impl StagedPayload {
    /// Serialize `expanded` into a fresh staging directory and return
    /// the guard owning it.
    ///
    /// The file is named `<profile stem>.json` inside a directory
    /// unique to this call, rather than uniquely named itself: the pod
    /// path a transport derives is the file's name (see
    /// [`Transport::dest_profile`]), so an importing profile lands at
    /// the same pod path its source text would have, and re-running a
    /// session overwrites that one file instead of accumulating a
    /// per-run pile on the machine. The `.json` extension is
    /// load-bearing — the frontend picks its parser by extension alone
    /// (07-cli.md §Profile input format), and the payload is bridge
    /// JSON whatever the source document was written in.
    fn write(local_profile: &Path, expanded: &ProfileNode) -> Result<Self, std::io::Error> {
        let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-driver-expanded-{}-{seq}",
            std::process::id()
        ));
        // `create_dir` refuses an existing entry, so a leftover from a
        // killed run surfaces here with its path named rather than
        // being silently reused.
        std::fs::create_dir(&dir)?;
        // From here the directory is owned: every failure below returns
        // through this guard's `Drop`, which removes it.
        let stem = local_profile
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("profile");
        let staged = Self {
            path: dir.join(format!("{stem}.json")),
            dir,
        };
        let bytes = serde_json::to_vec(&lm_provision::to_bridge_json::to_bridge_json(expanded))
            .map_err(std::io::Error::other)?;
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create_new(&staged.path)?;
            file.write_all(&bytes)?;
        }
        Ok(staged)
    }
}

impl Drop for StagedPayload {
    fn drop(&mut self) {
        // Best effort: the payload has already been uploaded (or the
        // upload has already failed), so a directory that resists
        // removal is a temp-directory question, not a session one.
        std::fs::remove_dir_all(&self.dir).ok();
    }
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

    /// A pod that keeps whatever step 1 placed and answers step 2 the
    /// way a real one does — by hashing the document it actually
    /// received (`<bin> hash <file>`, which resolves first, spec 11
    /// §Identity) rather than a number the test handed it in advance.
    /// That makes the integrity check a real comparison: if the session
    /// uploaded a document that hashes to something other than
    /// `local_hash`, the session fails here instead of the test having
    /// to notice.
    struct RecordingPod {
        scratch: PathBuf,
        placed: RefCell<Option<(PathBuf, Vec<u8>)>>,
    }

    impl RecordingPod {
        fn new(scratch: &Path) -> Self {
            Self {
                scratch: scratch.to_path_buf(),
                placed: RefCell::new(None),
            }
        }

        /// What step 1 handed over: the operator-host path and the
        /// bytes read from it at that moment (the staging file is gone
        /// by the time a test looks).
        fn received(&self) -> (PathBuf, Vec<u8>) {
            self.placed
                .borrow()
                .clone()
                .expect("step 1 must have placed a profile")
        }

        /// The pod's own `hash` answer: parse and hash the bytes it was
        /// given, through the same pipeline the binary runs.
        fn remote_hash(&self) -> String {
            let (_, bytes) = self.received();
            let path = self.scratch.join("received-by-pod.json");
            std::fs::write(&path, bytes).expect("write the received payload");
            lm_provision::cli::ast_hash(&path).expect("the pod must be able to hash what it got")
        }
    }

    impl Transport for RecordingPod {
        fn dest_binary(&self, _local: &Path) -> Result<PathBuf, TransportError> {
            Ok(PathBuf::from("/pod/lm-provision"))
        }

        fn dest_profile(&self, local: &Path) -> Result<PathBuf, TransportError> {
            let name = local
                .file_name()
                .ok_or_else(|| TransportError::InvalidPath(local.to_path_buf()))?;
            Ok(PathBuf::from("/pod").join(name))
        }

        fn ensure_binary(&self, local: &Path) -> Result<PathBuf, TransportError> {
            self.dest_binary(local)
        }

        fn place_profile(&self, local: &Path) -> Result<PathBuf, TransportError> {
            let bytes = std::fs::read(local)?;
            *self.placed.borrow_mut() = Some((local.to_path_buf(), bytes));
            self.dest_profile(local)
        }

        fn exec(
            &self,
            _paths: &PodPaths,
            args: &[String],
            _env: &BTreeMap<String, String>,
        ) -> Result<ExecOutput, TransportError> {
            let stdout = if args.first().map(String::as_str) == Some("hash") {
                format!("{}\n", self.remote_hash())
            } else {
                r#"{"ok":true,"dry_run":false,"profile_name":"demo","steps":[]}"#.to_string()
            };
            Ok(ExecOutput {
                stdout,
                stderr: String::new(),
                exit_code: Some(0),
            })
        }

        fn download(&self, _remote: &Path, _local: &Path) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// A profile importing a local fragment, next to the fragment it
    /// imports — the shape spec 11 §Source forms calls a relative path,
    /// resolved against the importing document's own location.
    fn import_fixture(dir_label: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-driver-session-test-{dir_label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        std::fs::write(
            dir.join("fragment.json"),
            serde_json::json!({
                "type": "Fragment",
                "name": "session-fragment",
                "capabilities": ["sh.exec"],
                "phases": [{ "type": "ShExec", "argv": ["echo", "from-fragment"] }]
            })
            .to_string(),
        )
        .expect("write fragment");
        let profile = dir.join("profile.json");
        std::fs::write(
            &profile,
            serde_json::json!({
                "type": "Spec",
                "name": "importing-session",
                "phases": [
                    { "type": "Import", "src": "./fragment.json" },
                    { "type": "ShExec", "argv": ["echo", "after"] }
                ]
            })
            .to_string(),
        )
        .expect("write profile");
        (dir, profile)
    }

    /// **An importing profile uploads its expansion, and the pod
    /// arrives at the same hash from it.** The session resolves before
    /// it hashes (spec 11 §Resolution), so what step 1 places has to be
    /// the expanded document: the pod re-parses and re-hashes what it
    /// receives (08 §Session steps 1-2), and a source text still
    /// carrying an `Import` would either hash to something else or ask
    /// the pod to fetch a fragment the operator resolved locally.
    #[test]
    fn an_importing_profile_uploads_the_expansion_the_pod_can_hash_for_itself() {
        let (dir, profile) = import_fixture("import");
        let pod = RecordingPod::new(&dir);

        let output = run(
            &pod,
            &StepPlan::default(),
            Path::new("lm-provision"),
            &profile,
            "pod-11",
        )
        .expect("an importing profile must survive the operator-side preflight");

        // The session's identity is the expanded canonical hash — the
        // number `lm-provision hash` prints for the same document.
        let expanded_hash =
            lm_provision::cli::ast_hash(&profile).expect("the fixture resolves and hashes");
        assert_eq!(output.collected.profile_hash, expanded_hash);

        // What the pod got: bridge JSON, with the import spliced out
        // and the fragment's phase in its place.
        let (placed_path, payload) = pod.received();
        assert_ne!(
            placed_path, profile,
            "the source text is not what the pod may re-hash"
        );
        let payload_path = dir.join("payload.json");
        std::fs::write(&payload_path, &payload).expect("write the payload back out");
        let payload_ast = lm_provision::frontend::load_profile(&payload_path)
            .expect("the payload parses as JSON");
        assert!(
            !carries_import(&payload_ast),
            "an expanded payload carries no Import node"
        );
        assert_eq!(lm_provision::canonical::hash(&payload_ast), expanded_hash);
        let ProfileNode::Spec { phases, .. } = &payload_ast else {
            panic!("the payload's root is a Spec");
        };
        assert_eq!(phases.len(), 2, "the fragment's phase replaced the Import");

        // The staging file is gone: the session leaves nothing on the
        // operator host but what it was given.
        assert!(
            !placed_path.exists(),
            "the staged payload must be removed: {}",
            placed_path.display()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// **A profile with no `Import` places its own file, byte for
    /// byte.** Resolve expands such a document to itself (spec 11
    /// §Stability guarantee 1), so there is nothing to serialize and no
    /// reason to hand the pod bytes it did not have before — every
    /// profile that exists today keeps the upload it has always had.
    #[test]
    fn a_profile_without_imports_places_the_operators_own_file_unchanged() {
        let (dir, profile) = artifact_fixture("no-import");
        let pod = RecordingPod::new(&dir);

        let output = run(
            &pod,
            &StepPlan::default(),
            Path::new("lm-provision"),
            &profile,
            "pod-11",
        )
        .expect("an import-free session still completes");

        let (placed_path, payload) = pod.received();
        assert_eq!(placed_path, profile, "the transport sees the profile path");
        assert_eq!(
            payload,
            std::fs::read(&profile).expect("read the fixture back"),
            "the uploaded bytes are the file's own"
        );
        assert_eq!(
            output.collected.profile_hash,
            lm_provision::cli::ast_hash(&profile).expect("the fixture hashes")
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
