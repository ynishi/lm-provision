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
//!   in `Real`. Path- and URL-carrying ops (all six except `sh_exec`)
//!   additionally consult [`policy`](super::policy) in both modes
//!   (spec 07 "dry-run does policy"), rejecting targets that fall
//!   outside the profile's declared `paths` / `http_allowlist`.
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

use super::{audit, effects, lifecycle, report::StepReport, ExecContext, ExecError, ExecMode};
use crate::profile_ast::{ProfileNode, ProfileValue};

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
    ///
    /// Every path that returns `Err` first appends a failing
    /// [`StepReport`] for the node (via a runner or
    /// [`record_phase_failure`](Self::record_phase_failure)), so the last
    /// entry in [`ExecContext::reports`] is always the failing step —
    /// the AST apply entry point reads it to build the fail-fast
    /// envelope `error` line without re-deriving it from the engine's
    /// error type.
    fn dispatch(&self, node: NodeId) -> Result<ProfileValue, ExecError> {
        let payload = match self.ctx.payloads.get(&node) {
            Some(payload) => payload,
            None => {
                let err = ExecError::PayloadMissing(node.0);
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        };

        if let Some(capability) = required_capability(self.name) {
            if let Err(err) = self.ctx.gate.require(capability) {
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        }

        if LIFECYCLE_OPS.contains(&self.name) {
            return self.run_lifecycle(node, payload);
        }

        match self.name {
            "sh_exec" => self.run_sh_exec(node, payload),
            "fs_write" => self.run_fs_write(node, payload),
            "net_http_get" => self.run_http_get(node, payload),
            "net_http_post" => self.run_http_post(node, payload),
            "net_transfer" => self.run_transfer(node, payload),
            "mount_bind" => self.run_mount_bind(node, payload),
            "mount_umount" => self.run_mount_umount(node, payload),
            other => {
                let err = ExecError::EffectFailed {
                    op: other.to_string(),
                    message: "op is not registered as direct or lifecycle".to_string(),
                };
                self.record_phase_failure(node, &err);
                Err(err)
            }
        }
    }

    /// Push `line` onto the shared log and return it as the op's value.
    fn record(&self, line: String) -> ProfileValue {
        self.ctx.log.lock().unwrap().push(line.clone());
        ProfileValue::Success(line)
    }

    /// Whether this run is a dry run.
    fn dry(&self) -> bool {
        self.ctx.mode == ExecMode::DryRun
    }

    /// Append a structured step report entry.
    fn push(&self, entry: StepReport) {
        self.ctx.reports.lock().unwrap().push(entry);
    }

    /// The `(<phase_index>_<kind>, kind)` base for `node`'s report entry.
    /// Falls back to a `n<node-id>` id for a node the phase map does not
    /// know (never expected for a registered op).
    fn base(&self, node: NodeId) -> (String, String) {
        let (index, kind) = self.ctx.phase_meta_of(node);
        if index == 0 {
            (format!("n{}", node.0), kind)
        } else {
            (format!("{index}_{kind}"), kind)
        }
    }

    /// Flip a report entry to the failed state, stamping the reason and
    /// (under dry-run) the `dry_run` marker. `status` stays at its
    /// default `-1` unless the caller already set a more specific code
    /// (e.g. a non-zero process exit).
    fn mark_fail(&self, entry: &mut StepReport, err: &ExecError) {
        entry.ok = false;
        if entry.status == 0 {
            entry.status = -1;
        }
        entry.reason = Some(err.to_string());
        if self.dry() {
            entry.dry_run = Some(true);
        }
    }

    /// Record a phase-level failure that happened before (or instead of)
    /// any effect ran — a payload lookup miss, a capability denial, or an
    /// unrouted op. The report entry carries the phase kind as its `op`
    /// (no effect was reached to name a more specific one).
    fn record_phase_failure(&self, node: NodeId, err: &ExecError) {
        let (id, kind) = self.base(node);
        let mut entry = StepReport::new(id, kind.clone(), kind);
        self.mark_fail(&mut entry, err);
        self.push(entry);
    }

    /// Build a failing report for a direct-op payload-variant mismatch,
    /// pushing it and returning the error (an AST/host wiring bug, not a
    /// profile-author error).
    fn variant_fail(&self, node: NodeId, op: &str, expected: &'static str) -> ExecError {
        let err = ExecError::PayloadVariant {
            node: node.0,
            expected,
        };
        let (id, kind) = self.base(node);
        let mut entry = StepReport::new(id, kind, op);
        self.mark_fail(&mut entry, &err);
        self.push(entry);
        err
    }

    /// Compose a lifecycle op's steps, then render (dry-run) or execute
    /// (real) each one. Each sub-step becomes its own report entry
    /// (`<phase_index>_<kind>_<n>`, labelled with the effect it runs);
    /// the per-op trace log line is still the joined summary, unchanged.
    ///
    /// The phase's `env` keyed slot (present on `sync.pull` /
    /// `staging.push`) is resolved once through the
    /// [`EnvPolicy`](super::policy::EnvPolicy) — in **both** modes
    /// (spec 06 §Resolution "dry-run resolves too"), so an undeclared or
    /// missing secret fails a dry run identically — and injected into the
    /// composed [`lifecycle::Step::Sh`] steps. Fail-fast: a failing
    /// sub-step is recorded and stops the phase, so its predecessors
    /// remain in the report but no later sub-step is reached.
    fn run_lifecycle(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let (base_id, kind) = self.base(node);
        let env = match self.resolve_phase_env(payload) {
            Ok(env) => env,
            Err(err) => {
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        };
        let steps = match lifecycle::expand(payload) {
            Ok(steps) => steps,
            Err(err) => {
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        };

        let mut renders = Vec::with_capacity(steps.len());
        for (index, step) in steps.iter().enumerate() {
            let sub_id = format!("{base_id}_{}", index + 1);
            let op = step_effect_op(step);
            // Audit before the sub-step runs. Env keys go through the
            // redaction helper (spec 09 §Audit log); the resolved
            // values from the phase's `env` map never reach the event.
            audit_lifecycle_step(self.ctx.mode, &kind, step, &env);
            match self.ctx.mode {
                ExecMode::DryRun => {
                    renders.push(lifecycle::render_dry(step, &env));
                    let mut entry = StepReport::new(sub_id, kind.clone(), op);
                    apply_step_input_fields(&mut entry, step);
                    // A `note` sub-step is inert in either mode, matching
                    // the legacy `dispatch_pending` skip's lack of a
                    // `dry_run` marker; effect-bearing sub-steps carry it.
                    if !matches!(step, lifecycle::Step::Note(_)) {
                        entry.dry_run = Some(true);
                    }
                    self.push(entry);
                }
                ExecMode::Real => match lifecycle::execute_step(step, self.name, &env) {
                    Ok(result) => {
                        let mut entry = StepReport::new(sub_id, kind.clone(), op);
                        apply_step_input_fields(&mut entry, step);
                        apply_step_result_fields(&mut entry, &result);
                        self.push(entry);
                        renders.push(result.summary);
                    }
                    Err(failure) => {
                        let mut entry = StepReport::new(sub_id, kind.clone(), op);
                        apply_step_input_fields(&mut entry, step);
                        // The partial observation lands *before*
                        // `mark_fail`, which only substitutes `-1` when
                        // no more specific status is already there — so
                        // a non-zero exit code survives.
                        apply_step_result_fields(&mut entry, &failure.observed);
                        self.mark_fail(&mut entry, &failure.error);
                        self.push(entry);
                        return Err(failure.error);
                    }
                },
            }
        }
        Ok(self.record(format!("{} {}", self.name, renders.join("; "))))
    }

    /// Resolve the phase's `env` keyed slot into a concrete `name →
    /// value` map (empty for phases without an `env` field). Fail-fast on
    /// an undeclared or missing secret.
    fn resolve_phase_env(
        &self,
        payload: &ProfileNode,
    ) -> Result<std::collections::BTreeMap<String, String>, ExecError> {
        match payload {
            ProfileNode::SyncPull { env, .. } | ProfileNode::StagingPush { env, .. } => {
                self.ctx.env_policy.resolve(env)
            }
            _ => Ok(std::collections::BTreeMap::new()),
        }
    }

    fn run_sh_exec(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::ShExec { argv, env, .. } = payload else {
            return Err(self.variant_fail(node, "sh.exec", "ShExec"));
        };
        let (id, kind) = self.base(node);
        // Resolve the env-injection map in both modes (spec 06
        // §Resolution "dry-run resolves too"): an undeclared or missing
        // secret fails a dry run identically to a real run.
        let resolved_env = match self.ctx.env_policy.resolve(env) {
            Ok(resolved_env) => resolved_env,
            Err(err) => {
                let mut entry = StepReport::new(id, kind, "sh.exec");
                entry.argv = Some(argv.clone());
                self.mark_fail(&mut entry, &err);
                self.push(entry);
                return Err(err);
            }
        };
        // Audit before the effect (spec 09 §Audit log). Env keys go
        // through the redaction helper; the resolved values never enter
        // the event.
        audit::sh_exec(self.ctx.mode, &kind, argv, &resolved_env);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let line = if resolved_env.is_empty() {
                    format!("sh_exec argv={argv:?}")
                } else {
                    format!(
                        "sh_exec argv={argv:?} env_keys={:?}",
                        resolved_env.keys().collect::<Vec<_>>()
                    )
                };
                let value = self.record(line);
                let mut entry = StepReport::new(id, kind, "sh.exec");
                entry.argv = Some(argv.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let outcome = match effects::sh_exec(argv, &effects::ShOpts::new(resolved_env)) {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        let mut entry = StepReport::new(id, kind, "sh.exec");
                        entry.argv = Some(argv.clone());
                        self.mark_fail(&mut entry, &err);
                        self.push(entry);
                        return Err(err);
                    }
                };
                if outcome.exit_code != 0 {
                    let err = ExecError::EffectFailed {
                        op: "sh_exec".to_string(),
                        message: format!(
                            "exit {} stderr={:?}",
                            outcome.exit_code, outcome.stderr_tail
                        ),
                    };
                    let mut entry = StepReport::new(id, kind, "sh.exec");
                    entry.argv = Some(argv.clone());
                    entry.status = i64::from(outcome.exit_code);
                    entry.stdout = Some(outcome.stdout_tail.clone());
                    entry.stderr = Some(outcome.stderr_tail.clone());
                    entry.ok = false;
                    entry.reason = Some(err.to_string());
                    self.push(entry);
                    return Err(err);
                }
                let value = self.record(format!(
                    "sh_exec exit={} stdout={:?}",
                    outcome.exit_code, outcome.stdout_tail
                ));
                let mut entry = StepReport::new(id, kind, "sh.exec");
                entry.argv = Some(argv.clone());
                entry.status = i64::from(outcome.exit_code);
                entry.stdout = Some(outcome.stdout_tail.clone());
                entry.stderr = Some(outcome.stderr_tail.clone());
                self.push(entry);
                Ok(value)
            }
        }
    }

    fn run_fs_write(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::FsWrite { path, content, .. } = payload else {
            return Err(self.variant_fail(node, "fs.write", "FsWrite"));
        };
        let (id, kind) = self.base(node);
        // Path policy runs in both modes (spec 07 "dry-run does policy").
        if let Err(err) = self.ctx.path_policy.check(path) {
            let mut entry = StepReport::new(id, kind, "fs.write");
            entry.path = Some(path.clone());
            self.mark_fail(&mut entry, &err);
            self.push(entry);
            return Err(err);
        }
        // `content_source = "string"` while `content` is a literal
        // `String`; the `"secret:<name>"` form lands once the AST
        // carries a `SecretRef` value (spec 04 §`fs.write`, spec 06
        // consumption point 3, currently blocked on dsl-kit #14).
        audit::fs_write(self.ctx.mode, &kind, path, content.len() as u64, "string");
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("fs_write path={path} bytes={}", content.len()));
                let mut entry = StepReport::new(id, kind, "fs.write");
                entry.path = Some(path.clone());
                entry.bytes = Some(content.len() as u64);
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let bytes = match effects::fs_write(path, content.as_bytes()) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        let mut entry = StepReport::new(id, kind, "fs.write");
                        entry.path = Some(path.clone());
                        self.mark_fail(&mut entry, &err);
                        self.push(entry);
                        return Err(err);
                    }
                };
                let value = self.record(format!("fs_write path={path} bytes={bytes}"));
                let mut entry = StepReport::new(id, kind, "fs.write");
                entry.path = Some(path.clone());
                entry.bytes = Some(bytes as u64);
                self.push(entry);
                Ok(value)
            }
        }
    }

    fn run_http_get(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetHttpGet { url, .. } = payload else {
            return Err(self.variant_fail(node, "net.http_get", "NetHttpGet"));
        };
        let (id, kind) = self.base(node);
        if let Err(err) = self.ctx.http_policy.check(url) {
            let mut entry = StepReport::new(id, kind, "net.http_get");
            entry.url = Some(url.clone());
            self.mark_fail(&mut entry, &err);
            self.push(entry);
            return Err(err);
        }
        audit::http_get(self.ctx.mode, &kind, url);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("net_http_get url={url}"));
                let mut entry = StepReport::new(id, kind, "net.http_get");
                entry.url = Some(url.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let outcome = match effects::http_get(url) {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        let mut entry = StepReport::new(id, kind, "net.http_get");
                        entry.url = Some(url.clone());
                        self.mark_fail(&mut entry, &err);
                        self.push(entry);
                        return Err(err);
                    }
                };
                let value =
                    self.record(format!("net_http_get url={url} status={}", outcome.status));
                let mut entry = StepReport::new(id, kind, "net.http_get");
                entry.url = Some(url.clone());
                entry.status = i64::from(outcome.status);
                self.push(entry);
                Ok(value)
            }
        }
    }

    fn run_http_post(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetHttpPost { url, .. } = payload else {
            return Err(self.variant_fail(node, "net.http_post", "NetHttpPost"));
        };
        let (id, kind) = self.base(node);
        if let Err(err) = self.ctx.http_policy.check(url) {
            let mut entry = StepReport::new(id, kind, "net.http_post");
            entry.url = Some(url.clone());
            self.mark_fail(&mut entry, &err);
            self.push(entry);
            return Err(err);
        }
        audit::http_post(self.ctx.mode, &kind, url);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("net_http_post url={url}"));
                let mut entry = StepReport::new(id, kind, "net.http_post");
                entry.url = Some(url.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let outcome = match effects::http_post(url, &[], "application/octet-stream") {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        let mut entry = StepReport::new(id, kind, "net.http_post");
                        entry.url = Some(url.clone());
                        self.mark_fail(&mut entry, &err);
                        self.push(entry);
                        return Err(err);
                    }
                };
                let value =
                    self.record(format!("net_http_post url={url} status={}", outcome.status));
                let mut entry = StepReport::new(id, kind, "net.http_post");
                entry.url = Some(url.clone());
                entry.status = i64::from(outcome.status);
                self.push(entry);
                Ok(value)
            }
        }
    }

    fn run_transfer(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetTransfer { src, dst, .. } = payload else {
            return Err(self.variant_fail(node, "net.transfer", "NetTransfer"));
        };
        let (id, kind) = self.base(node);
        // Destination is always a local path; source is HTTP-checked
        // when it carries an `http(s)://` scheme (a download). Local
        // sources are left to the effect layer's own routing.
        if let Err(err) = self.ctx.path_policy.check(dst) {
            self.push_transfer_failure(&id, &kind, src, dst, &err);
            return Err(err);
        }
        if src.starts_with("http://") || src.starts_with("https://") {
            if let Err(err) = self.ctx.http_policy.check(src) {
                self.push_transfer_failure(&id, &kind, src, dst, &err);
                return Err(err);
            }
        }
        audit::transfer(self.ctx.mode, &kind, src, dst);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("net_transfer src={src} dst={dst}"));
                let mut entry = StepReport::new(id, kind, "net.transfer");
                entry.src = Some(src.clone());
                entry.dst = Some(dst.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let outcome = match effects::transfer(src, dst) {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        self.push_transfer_failure(&id, &kind, src, dst, &err);
                        return Err(err);
                    }
                };
                let value = self.record(format!(
                    "net_transfer src={src} dst={} bytes={}",
                    outcome.dst, outcome.bytes
                ));
                let mut entry = StepReport::new(id, kind, "net.transfer");
                entry.src = Some(src.clone());
                entry.dst = Some(outcome.dst.clone());
                entry.bytes = Some(outcome.bytes);
                self.push(entry);
                Ok(value)
            }
        }
    }

    /// Push a failed `net.transfer` report carrying the declared src/dst.
    fn push_transfer_failure(&self, id: &str, kind: &str, src: &str, dst: &str, err: &ExecError) {
        let mut entry = StepReport::new(id.to_string(), kind.to_string(), "net.transfer");
        entry.src = Some(src.to_string());
        entry.dst = Some(dst.to_string());
        self.mark_fail(&mut entry, err);
        self.push(entry);
    }

    fn run_mount_bind(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::MountBind { src, dst, .. } = payload else {
            return Err(self.variant_fail(node, "mount.bind", "MountBind"));
        };
        let (id, kind) = self.base(node);
        for target in [src, dst] {
            if let Err(err) = self.ctx.path_policy.check(target) {
                let mut entry = StepReport::new(id, kind, "mount.bind");
                entry.src = Some(src.clone());
                entry.dst = Some(dst.clone());
                self.mark_fail(&mut entry, &err);
                self.push(entry);
                return Err(err);
            }
        }
        audit::mount_bind(self.ctx.mode, &kind, src, dst);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("mount_bind src={src} dst={dst}"));
                let mut entry = StepReport::new(id, kind, "mount.bind");
                entry.src = Some(src.clone());
                entry.dst = Some(dst.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                if let Err(err) = effects::mount_bind(src, dst) {
                    let mut entry = StepReport::new(id, kind, "mount.bind");
                    entry.src = Some(src.clone());
                    entry.dst = Some(dst.clone());
                    self.mark_fail(&mut entry, &err);
                    self.push(entry);
                    return Err(err);
                }
                let value = self.record(format!("mount_bind src={src} dst={dst}"));
                let mut entry = StepReport::new(id, kind, "mount.bind");
                entry.src = Some(src.clone());
                entry.dst = Some(dst.clone());
                self.push(entry);
                Ok(value)
            }
        }
    }

    fn run_mount_umount(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::MountUmount { path, .. } = payload else {
            return Err(self.variant_fail(node, "mount.umount", "MountUmount"));
        };
        let (id, kind) = self.base(node);
        if let Err(err) = self.ctx.path_policy.check(path) {
            let mut entry = StepReport::new(id, kind, "mount.umount");
            entry.path = Some(path.clone());
            self.mark_fail(&mut entry, &err);
            self.push(entry);
            return Err(err);
        }
        audit::mount_umount(self.ctx.mode, &kind, path);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("mount_umount path={path}"));
                let mut entry = StepReport::new(id, kind, "mount.umount");
                entry.path = Some(path.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                if let Err(err) = effects::umount(path) {
                    let mut entry = StepReport::new(id, kind, "mount.umount");
                    entry.path = Some(path.clone());
                    self.mark_fail(&mut entry, &err);
                    self.push(entry);
                    return Err(err);
                }
                let value = self.record(format!("mount_umount path={path}"));
                let mut entry = StepReport::new(id, kind, "mount.umount");
                entry.path = Some(path.clone());
                self.push(entry);
                Ok(value)
            }
        }
    }
}

/// Emit one audit event for a lifecycle sub-step, dispatched by its
/// [`lifecycle::Step`] variant. Placed here (not in `audit`) because
/// it depends on `lifecycle`'s step type, which `audit` deliberately
/// does not import — audit's helpers stay effect-shaped, not
/// lifecycle-shaped, so a caller from `registry`'s direct-op branches
/// pays the same shape.
fn audit_lifecycle_step(
    mode: ExecMode,
    kind: &str,
    step: &lifecycle::Step,
    env: &std::collections::BTreeMap<String, String>,
) {
    match step {
        lifecycle::Step::Sh(argv) => audit::sh_exec(mode, kind, argv, env),
        lifecycle::Step::Transfer { src, dst } => audit::transfer(mode, kind, src, dst),
        lifecycle::Step::HttpPoll { url, timeout_sec } => {
            audit::http_poll(mode, kind, url, *timeout_sec)
        }
        lifecycle::Step::Note(message) => audit::note(mode, kind, message),
    }
}

/// The effect op name a lifecycle sub-step runs (the report entry's `op`).
/// A [`lifecycle::Step::Note`] has no effect, so it is reported honestly
/// as `note` rather than the legacy `dispatch_pending` skip.
fn step_effect_op(step: &lifecycle::Step) -> &'static str {
    match step {
        lifecycle::Step::Sh(_) => "sh.exec",
        lifecycle::Step::Transfer { .. } => "net.transfer",
        lifecycle::Step::HttpPoll { .. } => "net.http_get",
        lifecycle::Step::Note(_) => "note",
    }
}

/// Copy a lifecycle sub-step's *declared inputs* onto its report entry.
/// The observations from actually running it are applied separately by
/// [`apply_step_result_fields`] (dry-run has inputs but no
/// observations).
fn apply_step_input_fields(entry: &mut StepReport, step: &lifecycle::Step) {
    match step {
        lifecycle::Step::Sh(argv) => entry.argv = Some(argv.clone()),
        lifecycle::Step::Transfer { src, dst } => {
            entry.src = Some(src.clone());
            entry.dst = Some(dst.clone());
        }
        lifecycle::Step::HttpPoll { url, .. } => entry.url = Some(url.clone()),
        lifecycle::Step::Note(message) => entry.note = Some(message.clone()),
    }
}

/// Copy what a lifecycle sub-step observed while running onto its
/// report entry (real mode only).
///
/// This is what makes a lifecycle sub-step's entry as informative as a
/// direct op's: before [`lifecycle::StepResult`] existed the exec layer
/// kept only the trace summary, so a real-mode `system.apt` step
/// reported its argv but never its exit status or output. `dst` is
/// overwritten with the destination actually written, which can differ
/// from the declared one.
///
/// A *failing* sub-step goes through here too, with the partial
/// observation from [`lifecycle::StepFailure::observed`] — so a
/// non-zero exit reports its real code rather than the generic `-1`
/// [`mark_fail`](ProfileOp::mark_fail) substitutes when nothing was
/// observed.
fn apply_step_result_fields(entry: &mut StepReport, result: &lifecycle::StepResult) {
    entry.status = result.status;
    if result.stdout.is_some() {
        entry.stdout = result.stdout.clone();
    }
    if result.stderr.is_some() {
        entry.stderr = result.stderr.clone();
    }
    if result.bytes.is_some() {
        entry.bytes = result.bytes;
    }
    if result.dst.is_some() {
        entry.dst = result.dst.clone();
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
