//! Transport abstraction (08-push-driver-protocol.md §Driver steps):
//! the byte-transport-agnostic upload / exec seam [`crate::driver::run`]
//! drives. 08 names SSH, a provider exec API, and `docker exec` as
//! transports that all satisfy the same protocol; this crate ships two
//! ([`crate::ssh::SshTransport`] and
//! [`crate::local_exec::LocalExecTransport`]) and keeps [`Transport`]
//! itself as the extension point for the rest (08
//! §Stability: "Driver implementation home ... internal — the
//! protocol, not the caller, is the contract").

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Pod-local paths [`Transport::upload`] chose for the uploaded
/// artifacts (08 §Driver steps step 1: "place the binary and the
/// profile file on the pod (any byte-transport; paths are the driver's
/// choice)").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodPaths {
    /// Where the provisioner binary landed on the pod.
    pub binary: PathBuf,
    /// Where the profile file landed on the pod.
    pub profile: PathBuf,
}

/// The result of one `<bin> <args...>` invocation against the uploaded
/// artifacts (08 §Driver steps step 3: "capture stdout (the apply
/// report JSON), stderr (the audit/progress transcript), and the exit
/// code").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Captured stdout (08 §Outputs: "exactly one JSON apply report").
    pub stdout: String,
    /// Captured stderr (08 §Outputs: "human-readable transcript").
    pub stderr: String,
    /// The process exit code, if the process ran to completion and
    /// exited normally (`None` if it was terminated by a signal).
    pub exit_code: Option<i32>,
}

/// Errors a [`Transport`] implementation may raise (08 §Error surface
/// "Transport failures": "upload incomplete, exec channel dropped,
/// stdout truncated ... driver-side; retryable").
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// An I/O failure while staging, spawning, or reading the uploaded
    /// artifacts.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A path passed to [`Transport::upload`] has no file name
    /// component to derive a pod-local destination name from.
    #[error("path has no file name component: {0}")]
    InvalidPath(PathBuf),

    /// Captured process output was not valid UTF-8.
    #[error("process output was not valid utf-8: {0}")]
    NonUtf8Output(#[from] std::string::FromUtf8Error),
}

/// The transport-agnostic seam of the session contract (08 §Session
/// steps): "any byte-transport (SSH, provider exec API, `docker exec`)
/// satisfies it" — implementations own how bytes and commands actually
/// reach the pod; [`crate::driver::run`] and [`crate::session::run`]
/// only ever call through this trait.
///
/// The finer `dest_*` / `ensure_binary` / `place_profile` seams exist
/// so the session layer can gate the ensure-binary step off
/// (`skip-install`, 08 §Session steps) while still knowing where the
/// binary is expected to live; [`Transport::upload`] is the composed
/// form the pre-session [`crate::driver::run`] flow keeps using.
pub trait Transport {
    /// The pod-local path where `ensure_binary` would (or did) place
    /// the binary — deterministic, callable without any transfer, so a
    /// gated-off install still yields the invoke path (08 §Session
    /// steps: a skipped step is "never an implicit promise that the
    /// work happened elsewhere" — the exec against this path is what
    /// surfaces the missing postcondition).
    fn dest_binary(&self, local_binary: &Path) -> Result<PathBuf, TransportError>;

    /// The pod-local path where `place_profile` would (or did) place
    /// the profile.
    fn dest_profile(&self, local_profile: &Path) -> Result<PathBuf, TransportError>;

    /// Session step 0 (08 §Session steps "ensure-binary",
    /// push-local-artifact strategy): make the binary exist at
    /// [`Self::dest_binary`] and be executable. Idempotent by content:
    /// when the destination already carries byte-identical content the
    /// transfer is skipped, so re-running a session is re-convergence,
    /// not re-transfer.
    fn ensure_binary(&self, local_binary: &Path) -> Result<PathBuf, TransportError>;

    /// Session step 1 (08 §Session steps "place-profile"): put the
    /// profile at [`Self::dest_profile`], overwriting (it is small and
    /// the hash-verify step vouches for its content).
    fn place_profile(&self, local_profile: &Path) -> Result<PathBuf, TransportError>;

    /// The composed steps 0+1 (the 2026-07 contract's "upload"):
    /// ensure the binary, place the profile, return both pod paths.
    fn upload(&self, binary: &Path, profile: &Path) -> Result<PodPaths, TransportError> {
        Ok(PodPaths {
            binary: self.ensure_binary(binary)?,
            profile: self.place_profile(profile)?,
        })
    }

    /// Run `<paths.binary> <args...>` with `env` exported into the
    /// invocation's process environment (08 §Session steps step 3's
    /// env-injection contract, generalized to any subcommand so the
    /// same primitive drives both the `hash` profile-integrity check
    /// and the `apply` invocation proper), then capture stdout /
    /// stderr / exit code (step 4). Implementations must honor 08
    /// §Secret delivery: an `env` value never appears on a command
    /// line (the SSH transport feeds values over stdin).
    fn exec(
        &self,
        paths: &PodPaths,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<ExecOutput, TransportError>;
}
