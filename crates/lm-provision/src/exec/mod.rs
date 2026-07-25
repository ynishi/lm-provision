//! mlua-free execution layer for the `ProfileNode` DSL (backlog D).
//!
//! Replaces the `dsl_poc` mock `OpRegistry` (which only pushed the op
//! name onto a log) with a real bridge: [`capgate`] enforces the
//! declared-capability contract, [`payload`] recovers each node's
//! payload from the AST (dsl-kit does not pass leaf payloads into
//! [`dsl_kit::Op::apply`]), [`effects`] carries the pure-Rust effect
//! implementations (ported from the old `src/bridge/*` mlua bridges with
//! the Lua layer stripped), and [`registry`] wires all 22 catalog ops
//! onto the engine.
//!
//! The old mlua stack (`src/bridge/`, `src/sandbox/`, ...) is left
//! untouched — it is scheduled for removal in a later backlog item, and
//! its `mlua::Table` in/out shape makes a pure-Rust re-port cheaper than
//! an adapter.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dsl_kit::NodeId;

use crate::dsl_poc::ProfileNode;

pub mod capgate;
pub mod effects;
pub mod lifecycle;
pub mod payload;
pub mod policy;
pub mod registry;

/// Whether effects run for real or only render a dry-run trace.
///
/// `DryRun` skips the effect itself but still enforces the capability
/// contract (a dry run is "do not execute", not "do not validate"), so
/// an op whose required capability is undeclared fails in `DryRun` too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Do not run effects; push a per-op trace line onto the log.
    DryRun,
    /// Run the real effect and push a result summary onto the log.
    Real,
}

/// Errors raised while building an [`ExecContext`] or executing an op.
///
/// These surface out of an op handler as
/// [`dsl_kit::EngineError::EvalFailed`] (see [`registry`]), so the
/// engine reports the node at which the failure happened.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// A declared capability is not in [`capgate::KNOWN_CAPABILITIES`] —
    /// fail-fast at context-build time, before any op runs.
    #[error("capability '{0}' declared but not implemented by host")]
    CapabilityUnknown(String),

    /// An op required a capability the profile never declared — the
    /// physical "declared ⊆ used" enforcement point.
    #[error("capability '{0}' not declared in profile.capabilities")]
    CapabilityDenied(String),

    /// An op targeted a filesystem path outside every declared root in
    /// `profile.paths` (or a non-absolute / `..`-containing path) —
    /// the physical L3 path-policy enforcement point (spec 05 §L3).
    #[error("'{path}' is not absolute, contains '..', or lies outside profile.paths")]
    PathDenied {
        /// The rejected path.
        path: String,
    },

    /// An op targeted an HTTP URL that matches no pattern in
    /// `profile.http_allowlist` — the physical L3 HTTP-policy
    /// enforcement point (spec 05 §L3).
    #[error("'{url}' matches no pattern in profile.http_allowlist")]
    HttpDenied {
        /// The rejected URL.
        url: String,
    },

    /// No payload node was recorded for the op's `NodeId` (an AST/host
    /// wiring bug, not a profile-author error).
    #[error("no payload recorded for node n{0}")]
    PayloadMissing(u64),

    /// The payload node for an op was not the variant the op expects.
    #[error("payload for node n{node} is not a {expected} node")]
    PayloadVariant {
        /// The offending node id.
        node: u64,
        /// The variant the op expected.
        expected: &'static str,
    },

    /// An effect ran but failed (non-zero exit, transport error, I/O
    /// error, ...). `op` is the registry op name.
    #[error("{op}: {message}")]
    EffectFailed {
        /// Registry op name (e.g. `"sh_exec"`).
        op: String,
        /// Human-readable failure description.
        message: String,
    },

    /// The requested effect is not supported here (non-Linux mount, an
    /// env-routed transfer scheme pending an AST `env` field, ...).
    #[error("{0}")]
    Unsupported(String),
}

/// Per-evaluation execution context shared by every op handler.
///
/// Built once from the profile root by [`ExecContext::from_root`] and
/// handed (behind an `Arc`) to [`registry::profile_op_registry`].
pub struct ExecContext {
    /// Real vs dry-run.
    pub mode: ExecMode,
    /// The declared-capability gate.
    pub gate: capgate::CapabilityGate,
    /// The declared-path allowlist. Direct ops that write to /
    /// mount / unmount a filesystem path consult this in both
    /// [`ExecMode::DryRun`] and [`ExecMode::Real`] (spec 07 "dry-run
    /// does policy").
    pub path_policy: policy::PathPolicy,
    /// The declared-URL allowlist. Direct ops that reach an HTTP URL
    /// consult this in both modes, matching `path_policy`.
    pub http_policy: policy::HttpPolicy,
    /// `NodeId -> ProfileNode` payload lookup (dsl-kit does not pass leaf
    /// payloads into [`dsl_kit::Op::apply`]).
    pub payloads: Arc<HashMap<NodeId, ProfileNode>>,
    /// Shared execution log (trace lines / result summaries).
    pub log: Arc<Mutex<Vec<String>>>,
}

impl ExecContext {
    /// Build a context from the profile `root`.
    ///
    /// The declared `capabilities` / `paths` / `http_allowlist` come
    /// from a [`ProfileNode::Spec`] root; any other root is treated as
    /// declaring nothing (a pure-computation profile with empty
    /// policies that deny every path / URL). The capability gate is
    /// validated against [`capgate::KNOWN_CAPABILITIES`] here, so an
    /// unknown declared capability fails before any op runs.
    pub fn from_root(
        root: &ProfileNode,
        mode: ExecMode,
        log: Arc<Mutex<Vec<String>>>,
    ) -> Result<Self, ExecError> {
        let (declared, paths, http_allowlist): (Vec<String>, Vec<String>, Vec<String>) = match root
        {
            ProfileNode::Spec {
                capabilities,
                paths,
                http_allowlist,
                ..
            } => (capabilities.clone(), paths.clone(), http_allowlist.clone()),
            _ => (Vec::new(), Vec::new(), Vec::new()),
        };
        let gate = capgate::CapabilityGate::build(&declared)?;
        let path_policy = policy::PathPolicy::new(&paths);
        let http_policy = policy::HttpPolicy::new(&http_allowlist);
        let payloads = Arc::new(payload::build_payload_map(root));
        Ok(Self {
            mode,
            gate,
            path_policy,
            http_policy,
            payloads,
            log,
        })
    }
}
