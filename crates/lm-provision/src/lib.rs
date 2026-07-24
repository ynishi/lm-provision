//! # lm-provision
//!
//! ## Architecture
//!
//! Rust host / Lua domain 100% split: all provisioning domain logic
//! (profile parsing, IR construction, validation, canonicalization,
//! hashing, planning, dispatch, apply, reporting) lives in the `lm.*`
//! Lua modules embedded via [`embed`] and resolved through the L1
//! `require` allowlist ([`vm::require`]). The Rust host carries zero
//! domain vocabulary; it implements exactly the sandbox layers
//! (05-sandbox-layer-contract.md), the effectful bridge primitives
//! (04-bridge.md, later milestones), and the CLI operator contract
//! ([`cli`], 07-cli.md).
//!
//! ## Modules
//!
//! - [`vm`] — VM boot, stdlib strip, custom `require`, print redirect,
//!   and the profile evaluation loop (registration steps 1-5 of
//!   04-bridge.md §Registration order).
//! - [`bridge`] — effectful bridge primitives (04-bridge.md). M1-3 ships
//!   only the `env.ref` factory; `sh` / `net` / `fs` / `mount` land in M3.
//! - [`secret`] — the `SecretRef` opacity contract
//!   (06-secret-handling.md).
//! - [`batteries`] — host-provided pure-function primitives outside the
//!   declaration-gated `std.*` battery surface (04-bridge.md
//!   §Registration order step 6, milestone M3); M2 ships only the
//!   sha256 hash provider `lm.hash` calls into.
//! - [`sandbox`] — the four-layer sandbox (05-sandbox-layer-contract.md):
//!   L2 execution-control isolation, L3 declaration-derived policies,
//!   L4 the capability gate, wired onto an [`vm::eval::ExtractedProfile`]
//!   by [`sandbox::wire_sandboxed_profile`] (registration order steps
//!   6-7, milestone M3-1).
//! - [`apply`] — host-side `plan → dispatch → apply → report` entry point
//!   ([`apply::run_apply`], 09-apply-report-and-ledger.md; milestone
//!   M4-1), wired onto the `apply` CLI subcommand in milestone M4-3.
//! - [`audit`] — structured tracing + redaction for every bridge
//!   invocation (09-apply-report-and-ledger.md §Audit log; milestone
//!   M4-2).
//! - [`embed`] — compile-time `include_str!` of the `lm.*` module set.
//! - [`cli`] — subcommand / flag surface (07-cli.md).
//! - [`codegen`] — `.d.lua` EmmyLua annotation emitter for the `codegen`
//!   subcommand (07-cli.md), reading `lm.catalog_data`'s shared
//!   vocabulary at codegen time rather than duplicating it in Rust.
//!
//! ## Static binary
//!
//! Build a musl static binary with the vendored Lua runtime baked in:
//!
//! ```text
//! rustup target add x86_64-unknown-linux-musl
//! cargo build --release --target x86_64-unknown-linux-musl
//! ```
//!
//! The resulting binary embeds every `lm.*` module (`include_str!`) and
//! requires zero preinstalled dependencies on the target pod
//! (08-push-driver-protocol.md §Inputs).

#![warn(missing_docs)]

pub mod apply;
pub mod audit;
pub mod batteries;
pub mod bridge;
pub mod cli;
pub mod codegen;
pub mod dsl_poc;
pub mod embed;
pub mod exec;
pub mod sandbox;
pub mod secret;
pub mod vm;
