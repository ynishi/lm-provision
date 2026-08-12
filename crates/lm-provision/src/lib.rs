//! # lm-provision
//!
//! ## Architecture
//!
//! A spec-first pod provisioner built entirely in Rust around a typed
//! [`profile_ast::ProfileNode`] AST. A profile is authored as JSON or the
//! canonical text form, parsed into the AST by the [`frontend`], and then
//! run through the read-only pipeline stages (validate / canonical / hash
//! / plan) or the effectful [`exec`] engine (apply). There is no embedded
//! scripting runtime: the earlier embedded-Lua authoring frontend and its
//! VM / sandbox / bridge stack have been removed in favour of the single
//! AST pipeline.
//!
//! ## Modules
//!
//! - [`frontend`] — parse a profile file (`.json` → serde bridge,
//!   canonical text → PEG grammar, `.lua` → explicit rejection) into a
//!   [`profile_ast::ProfileNode`] AST.
//! - [`profile_ast`] — the `ProfileNode` AST (spec + the phase catalog
//!   kinds), the semantics adapter (`ProfileSemantics` / `ProfileValue`),
//!   and the dsl-kit engine wiring that drives execution.
//! - [`validate`] — the AST validate stage (03-pipeline-stage-artifacts.md
//!   §validate).
//! - [`canonical`] — deterministic byte encoder + SHA-256 profile hash
//!   over the [`profile_ast::ProfileNode`] AST
//!   (03-pipeline-stage-artifacts.md §canonical / §hash). Frontend-
//!   independent by construction: `NodeId` is excluded, declared lists
//!   are sorted, phase order preserved.
//! - [`plan`] — the AST plan stage: expand a profile into the plan
//!   artifact (03-pipeline-stage-artifacts.md §plan).
//! - [`resource`] — what a phase creates (`produces`) and what it needs
//!   already there (`requires` / `assumes`), and the forward fold that
//!   decides whether a profile is well-formed under that. Every
//!   ComfyUI-relative path is derived here from one declared root
//!   instead of being a host constant.
//! - [`digest`] — the crate's single SHA-256 implementation, shared by
//!   the profile hash, the Assert model's content predicate, and the
//!   driver's `ensure-binary` check.
//! - [`exec`] — the mlua-free execution layer: the capability gate, the
//!   declaration-derived path / HTTP / secret policies, the pure-Rust
//!   effect implementations, and the per-step report builder
//!   (05-sandbox-layer-contract.md, 09-apply-report-and-ledger.md).
//! - [`apply`] — host-side `plan → dispatch → apply → report` entry point
//!   ([`apply::run_apply_ast`], 09-apply-report-and-ledger.md).
//! - [`cli`] — subcommand / flag surface (07-cli.md).
//!
//! ## Static binary
//!
//! Build a musl static binary requiring zero preinstalled dependencies on
//! the target pod (08-push-driver-protocol.md §Inputs):
//!
//! ```text
//! rustup target add x86_64-unknown-linux-musl
//! cargo build --release --target x86_64-unknown-linux-musl
//! ```

#![warn(missing_docs)]

pub mod apply;
pub mod canonical;
pub mod cli;
pub mod derive;
pub mod digest;
pub mod exec;
pub mod frontend;
pub mod machine;
pub mod normalize;
pub mod plan;
pub mod profile_ast;
pub mod resource;
pub mod validate;
