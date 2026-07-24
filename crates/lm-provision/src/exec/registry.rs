//! The 22-op [`OpRegistry`] wired onto the engine.
//!
//! Every catalog op is one [`ProfileOp`] handler sharing the same
//! [`ExecContext`]. On each `apply` the handler recovers its payload
//! node ([`payload`](super::payload)), enforces the required capability
//! ([`capgate`](super::capgate)), then branches on [`ExecMode`]:
//!
//! - **direct 7 ops** (`sh_exec` / `fs_write` / `net_http_get` /
//!   `net_http_post` / `net_transfer` / `mount_bind` / `mount_umount`)
//!   render a trace line in `DryRun` and call [`effects`](super::effects)
//!   in `Real`.
//! - **lifecycle 15 ops** delegate to [`lifecycle::expand`](super::lifecycle::expand)
//!   for step composition, then render each step in `DryRun` and execute
//!   each step (via [`lifecycle::execute_step`](super::lifecycle::execute_step))
//!   in `Real`. A single per-op log line joins the per-step summaries
//!   with `; `, preserving the direct-op shape (`"<op> ..."`).
//!
//! An [`ExecError`] from any step surfaces as
//! [`EngineError::EvalFailed`], carrying the node at which it happened.

use std::sync::Arc;

use dsl_kit::{EngineError, NodeContext, NodeId, Op, OpRegistry, Path};

use super::{effects, lifecycle, ExecContext, ExecError, ExecMode};
use crate::dsl_poc::{ProfileNode, ProfileValue};

/// The seven direct ops with real effect wiring.
const DIRECT_OPS: [&str; 7] = [
    "sh_exec",
    "fs_write",
    "net_http_get",
    "net_http_post",
    "net_transfer",
    "mount_bind",
    "mount_umount",
];

/// The fifteen lifecycle ops handled through [`lifecycle::expand`].
const LIFECYCLE_OPS: [&str; 15] = [
    "system_apt",
    "comfyui_install",
    "python_version_check",
    "python_deps",
    "custom_nodes",
    "sync_pull",
    "sync_push",
    "staging_push",
    "models",
    "llm_models",
    "post_install",
    "comfyui_restart",
    "comfyui_health",
    "service_start",
    "service_ready",
];

/// Capability an op requires, or `None` for a marker op (`sync_push`).
///
/// The mapping is frozen against plan.md §Capability mapping (spec 02
/// §Catalog kinds).
fn required_capability(op: &str) -> Option<&'static str> {
    match op {
        "sh_exec" => Some("sh.exec"),
        "fs_write" => Some("fs.write"),
        "net_http_get" => Some("net.http_get"),
        "net_http_post" => Some("net.http_post"),
        "net_transfer" => Some("net.transfer"),
        "mount_bind" => Some("mount.bind"),
        "mount_umount" => Some("mount.umount"),
        "system_apt"
        | "comfyui_install"
        | "python_version_check"
        | "python_deps"
        | "custom_nodes"
        | "llm_models"
        | "post_install"
        | "comfyui_restart"
        | "comfyui_health"
        | "service_start"
        | "service_ready" => Some("sh.exec"),
        "sync_pull" | "staging_push" | "models" => Some("net.transfer"),
        "sync_push" => None,
        _ => None,
    }
}

/// Build the 22-op registry over a shared [`ExecContext`].
pub fn profile_op_registry(ctx: Arc<ExecContext>) -> Arc<OpRegistry<ProfileValue>> {
    let mut registry = OpRegistry::new();
    for &name in DIRECT_OPS.iter().chain(LIFECYCLE_OPS.iter()) {
        registry.register(
            name,
            Arc::new(ProfileOp {
                name,
                ctx: Arc::clone(&ctx),
            }),
        );
    }
    Arc::new(registry)
}

/// One op handler, bound to its registry name and the shared context.
struct ProfileOp {
    name: &'static str,
    ctx: Arc<ExecContext>,
}

impl Op<ProfileValue> for ProfileOp {
    fn apply(&self, node: NodeId, _args: &[ProfileValue]) -> Result<ProfileValue, EngineError> {
        self.dispatch(node)
            .map_err(|err| to_engine_error(node, err))
    }
}

impl ProfileOp {
    /// Common flow: payload lookup → capability check → mode branch.
    fn dispatch(&self, node: NodeId) -> Result<ProfileValue, ExecError> {
        let payload = self
            .ctx
            .payloads
            .get(&node)
            .ok_or(ExecError::PayloadMissing(node.0))?;

        if let Some(capability) = required_capability(self.name) {
            self.ctx.gate.require(capability)?;
        }

        if LIFECYCLE_OPS.contains(&self.name) {
            return self.run_lifecycle(payload);
        }

        match self.name {
            "sh_exec" => self.run_sh_exec(node, payload),
            "fs_write" => self.run_fs_write(node, payload),
            "net_http_get" => self.run_http_get(node, payload),
            "net_http_post" => self.run_http_post(node, payload),
            "net_transfer" => self.run_transfer(node, payload),
            "mount_bind" => self.run_mount_bind(node, payload),
            "mount_umount" => self.run_mount_umount(node, payload),
            other => Err(ExecError::EffectFailed {
                op: other.to_string(),
                message: "op is not registered as direct or lifecycle".to_string(),
            }),
        }
    }

    /// Push `line` onto the shared log and return it as the op's value.
    fn record(&self, line: String) -> ProfileValue {
        self.ctx.log.lock().unwrap().push(line.clone());
        ProfileValue::Success(line)
    }

    /// Compose a lifecycle op's steps, then render (dry-run) or execute
    /// (real) each one and collapse the results into the single per-op
    /// log line.
    fn run_lifecycle(&self, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let steps = lifecycle::expand(payload)?;
        let renders: Vec<String> = match self.ctx.mode {
            ExecMode::DryRun => steps.iter().map(lifecycle::render_dry).collect(),
            ExecMode::Real => steps
                .iter()
                .map(|step| lifecycle::execute_step(step, self.name))
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(self.record(format!("{} {}", self.name, renders.join("; "))))
    }

    fn variant_err(&self, node: NodeId, expected: &'static str) -> ExecError {
        ExecError::PayloadVariant {
            node: node.0,
            expected,
        }
    }

    fn run_sh_exec(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::ShExec { argv, .. } = payload else {
            return Err(self.variant_err(node, "ShExec"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => Ok(self.record(format!("sh_exec argv={argv:?}"))),
            ExecMode::Real => {
                let outcome = effects::sh_exec(argv, &effects::ShOpts)?;
                if outcome.exit_code != 0 {
                    return Err(ExecError::EffectFailed {
                        op: "sh_exec".to_string(),
                        message: format!(
                            "exit {} stderr={:?}",
                            outcome.exit_code, outcome.stderr_tail
                        ),
                    });
                }
                Ok(self.record(format!(
                    "sh_exec exit={} stdout={:?}",
                    outcome.exit_code, outcome.stdout_tail
                )))
            }
        }
    }

    fn run_fs_write(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::FsWrite { path, content, .. } = payload else {
            return Err(self.variant_err(node, "FsWrite"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => {
                Ok(self.record(format!("fs_write path={path} bytes={}", content.len())))
            }
            ExecMode::Real => {
                let bytes = effects::fs_write(path, content.as_bytes())?;
                Ok(self.record(format!("fs_write path={path} bytes={bytes}")))
            }
        }
    }

    fn run_http_get(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetHttpGet { url, .. } = payload else {
            return Err(self.variant_err(node, "NetHttpGet"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => Ok(self.record(format!("net_http_get url={url}"))),
            ExecMode::Real => {
                let outcome = effects::http_get(url)?;
                Ok(self.record(format!("net_http_get url={url} status={}", outcome.status)))
            }
        }
    }

    fn run_http_post(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetHttpPost { url, .. } = payload else {
            return Err(self.variant_err(node, "NetHttpPost"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => Ok(self.record(format!("net_http_post url={url}"))),
            ExecMode::Real => {
                let outcome = effects::http_post(url, &[], "application/octet-stream")?;
                Ok(self.record(format!("net_http_post url={url} status={}", outcome.status)))
            }
        }
    }

    fn run_transfer(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetTransfer { src, dst, .. } = payload else {
            return Err(self.variant_err(node, "NetTransfer"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => Ok(self.record(format!("net_transfer src={src} dst={dst}"))),
            ExecMode::Real => {
                let outcome = effects::transfer(src, dst)?;
                Ok(self.record(format!(
                    "net_transfer src={src} dst={} bytes={}",
                    outcome.dst, outcome.bytes
                )))
            }
        }
    }

    fn run_mount_bind(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::MountBind { src, dst, .. } = payload else {
            return Err(self.variant_err(node, "MountBind"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => Ok(self.record(format!("mount_bind src={src} dst={dst}"))),
            ExecMode::Real => {
                effects::mount_bind(src, dst)?;
                Ok(self.record(format!("mount_bind src={src} dst={dst}")))
            }
        }
    }

    fn run_mount_umount(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::MountUmount { path, .. } = payload else {
            return Err(self.variant_err(node, "MountUmount"));
        };
        match self.ctx.mode {
            ExecMode::DryRun => Ok(self.record(format!("mount_umount path={path}"))),
            ExecMode::Real => {
                effects::umount(path)?;
                Ok(self.record(format!("mount_umount path={path}")))
            }
        }
    }
}

/// Wrap an [`ExecError`] as the engine's node-located failure, matching
/// the dsl-kit-cli refdsl convention.
fn to_engine_error(node: NodeId, err: ExecError) -> EngineError {
    EngineError::EvalFailed {
        at: NodeContext::at(node, Path::root().push(node)),
        source: Box::new(err),
    }
}
