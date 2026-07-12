//! Transport abstraction (08-push-driver-protocol.md §Driver steps):
//! the byte-transport-agnostic upload / exec seam [`crate::driver::run`]
//! drives. 08 names SSH, a provider exec API, and `docker exec` as
//! transports that all satisfy the same protocol; this crate ships one
//! implementation ([`crate::local_exec::LocalExecTransport`]) and keeps
//! [`Transport`] itself as the extension point for the others (08
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

/// The transport-agnostic upload / exec seam (08 §Driver steps): "any
/// byte-transport (SSH, provider exec API, `docker exec`) satisfies
/// it" — implementations own how bytes and commands actually reach the
/// pod; [`crate::driver::run`] only ever calls through this trait.
pub trait Transport {
    /// Step 1 (08 §Driver steps): place `binary` and `profile` on the
    /// pod, returning the pod-local paths this transport chose.
    fn upload(&self, binary: &Path, profile: &Path) -> Result<PodPaths, TransportError>;

    /// Run `<paths.binary> <args...>` with `env` exported into the
    /// invocation's process environment (08 §Driver steps step 2's
    /// env-injection contract, generalized to any subcommand so the
    /// same primitive drives both the `hash` profile-integrity check
    /// and the `apply` invocation proper), then capture stdout /
    /// stderr / exit code (step 3).
    fn exec(
        &self,
        paths: &PodPaths,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<ExecOutput, TransportError>;
}
