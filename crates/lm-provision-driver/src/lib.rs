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
//! the contract"; plan.md §Workspace / crate 構成).
//!
//! This crate never touches `lm.*` Lua domain logic or the sandboxed
//! VM those modules run in — it only drives the already-frozen CLI
//! contract (07-cli.md) of the Phase F `lm-provision` binary from the
//! outside, through the transport-agnostic upload / invoke / collect
//! shape 08 defines. Domain logic stays 100% on the Phase F side of
//! that boundary (00 §Boundary and stack).
//!
//! ## Modules
//!
//! - [`transport`] — the [`transport::Transport`] trait plus the shared
//!   [`transport::PodPaths`] / [`transport::ExecOutput`] /
//!   [`transport::TransportError`] types every implementation shares
//!   (08 §Driver steps: "transport-agnostic ... SSH, provider exec API,
//!   `docker exec` all satisfy it").
//! - [`local_exec`] — [`local_exec::LocalExecTransport`], the one
//!   [`transport::Transport`] implementation this crate ships: runs the
//!   provisioner binary on the driver's own host. SSH / `docker exec`
//!   transports are documented extension points, not shipped here.
//! - [`driver`] — [`driver::run`], the upload → hash-integrity-check →
//!   invoke → collect sequence (08 §Driver steps) driven against any
//!   [`transport::Transport`], plus [`driver::hash_locally`] for the
//!   operator-side pre-upload hash 08 describes running "locally
//!   first".
//! - [`ledger`] — the append-only ledger (09-apply-report-and-ledger.md
//!   §Ledger): [`ledger::append`] / [`ledger::list`] / [`ledger::get`].

#![warn(missing_docs)]

pub mod driver;
pub mod ledger;
pub mod local_exec;
pub mod transport;
