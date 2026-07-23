//! # lm-provision-mcp
//!
//! ## Architecture
//!
//! The MCP server that exposes `lm-provision` to MCP clients
//! (10-mcp.md) — in particular an external pod manager that delegates
//! its provisioning half to this server while keeping pod lifecycle on
//! its own side (08-push-driver-protocol.md §Purpose). Milestone M6 /
//! Phase H, the last layer in plan.md's rollout: F (01-06, on-pod
//! apply) → G (07-09, driver + ledger) → H (10, this crate).
//!
//! Six tools (10 §Tool set), split across two call shapes:
//!
//! - **Local, read-only** ([`pipeline`]): `lm_validate` / `lm_hash` /
//!   `lm_plan` call straight into the `lm-provision` library
//!   in-process — `profile_path` is a path visible to this server's
//!   own host (10 §Inputs), and none of the three touches a bridge or
//!   a pod (07-cli.md §Invocation: "none (read-only)").
//! - **Driver-mediated** ([`apply_tool`], [`ledger_tools`]): `lm_apply`
//!   runs the full chapter 08 protocol against
//!   [`lm_provision_driver::local_exec::LocalExecTransport`] (the MVP
//!   transport this crate wires) and appends the result to the
//!   append-only ledger (09 §Ledger); `lm_ledger_list` /
//!   `lm_ledger_get` read that same ledger back.
//!
//! [`server`] wires all six as MCP tools via `rmcp`'s
//! `#[tool_router]` / `#[tool]` macros over the plain functions in
//! [`pipeline`] / [`apply_tool`] / [`ledger_tools`] — those functions
//! are deliberately `rmcp`-free and directly testable at the function
//! level (task instruction), independent of any MCP transport.
//! [`config`] resolves the server's deployment configuration (binary
//! path, staging directory, ledger path — 10 §Inputs: "Pod transport
//! configuration ... is server deployment configuration, not tool
//! arguments") once at startup.
//!
//! ## Secrets (10 §Inputs)
//!
//! "The MCP server process environment is the secret source ...
//! Secrets: ... Tool arguments never carry secret values; a tool call
//! cannot inject env." No tool parameter type in [`server`] carries a
//! secret value or a raw env map; [`apply_tool::lm_apply`] reads every
//! declared `env_secrets` name directly from `std::env` (see that
//! module's own doc comment for the precondition check this implies).

#![warn(missing_docs)]

pub mod apply_tool;
pub mod config;
pub mod ledger_tools;
pub mod pipeline;
pub mod profile_host;
pub mod server;

