//! # lm-provision-driver
//!
//! ## Architecture
//!
//! The operator / pod-manager half of the push driver protocol
//! (08-push-driver-protocol.md) plus the append-only apply ledger it
//! feeds (09-apply-report-and-ledger.md §Ledger) — the Phase G build
//! target. The crate split from `lm-provision` itself is an
//! implementation judgment 08 §Stability leaves open ("driver
//! implementation home ... internal — the protocol, not the caller, is
//! the contract").
//!
//! **Applying a profile happens on the pod, never here.** That is
//! driven through the already-frozen CLI contract (07-cli.md) of the
//! Phase F `lm-provision` binary, from the outside, over the
//! transport-agnostic upload / invoke / collect shape 08 defines — so
//! no effect this crate causes is an effect it performs.
//!
//! What it does read from the library is the part an operator host has
//! to know before it connects: [`session`] parses, validates and hashes
//! the profile in process, because the host cannot run the musl
//! artifact it is about to push and the hash has to be comparable to
//! the pod's; [`infra`] reads the profile's machine requirements to
//! decide what to acquire. Both are questions about a profile rather
//! than execution of one.
//!
//! ## Modules
//!
//! - [`transport`] — the [`transport::Transport`] trait plus the shared
//!   [`transport::PodPaths`] / [`transport::ExecOutput`] /
//!   [`transport::TransportError`] types every implementation shares
//!   (08 §Driver steps: "transport-agnostic ... SSH, provider exec API,
//!   `docker exec` all satisfy it").
//!   Two implementations ship: [`local_exec`] and [`ssh`]. A
//!   `docker exec` transport is a documented extension point and is
//!   not among them.
//! - [`local_exec`] — [`local_exec::LocalExecTransport`], which runs
//!   the provisioner binary on the driver's own host.
//! - [`driver`] — [`driver::run`], the upload → hash-integrity-check →
//!   invoke → collect sequence (08 §Driver steps) driven against any
//!   [`transport::Transport`], plus [`driver::hash_locally`] for the
//!   operator-side pre-upload hash 08 describes running "locally
//!   first".
//! - [`ledger`] — the append-only ledger (09-apply-report-and-ledger.md
//!   §Ledger): [`ledger::append`] / [`ledger::list`] / [`ledger::get`].
//! - [`ssh`] — [`ssh::SshTransport`], the SSH realization of the seam
//!   (08 §Session contract `ConnectionSpec`): scp upload, explicit
//!   identity file, secrets over stdin (08 §Secret delivery).
//! - [`session`] — [`session::run`], the session contract's steps 0-5
//!   with per-step gates ([`session::StepPlan`]); the shape the
//!   `lm-provision-driver` binary exposes as a one-shot CLI.
//! - [`infra`] — [`infra::Infra`], the target a machine is placed on,
//!   with one implementation per target: what it can provide, the
//!   request that would obtain a machine meeting a profile's
//!   requirements, and how to read one back and give it up.
//! - [`credentials`] — where a target's credential is resolved from,
//!   and what is reported when it is not there.

#![warn(missing_docs)]

pub mod credentials;
pub mod driver;
pub mod infra;
pub mod ledger;
pub mod local_exec;
pub mod session;
pub mod ssh;
pub mod transport;

/// The content digest of a local artifact this driver is about to push.
///
/// Both transports answer the same question before uploading — "is what
/// is already over there the same bytes as this?" (08 §Session steps
/// "ensure-binary") — and both now answer it through
/// [`lm_provision::digest`], the workspace's single content-digest
/// implementation. Before this they answered it two different ways: a
/// local `format!("{:x}")` hash in [`ssh`], a whole-file `Vec<u8>`
/// equality in [`local_exec`].
///
/// **An absent artifact is an error here, not a digest that fails to
/// match.** The path names the binary the operator asked to push; if it
/// is not there, nothing this function could return would be true, and
/// the failure belongs at the input rather than downstream as a
/// surprising re-upload.
pub(crate) fn local_digest(path: &std::path::Path) -> Result<String, transport::TransportError> {
    lm_provision::digest::of_file(path)?.ok_or_else(|| {
        transport::TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no local artifact at {}", path.display()),
        ))
    })
}
