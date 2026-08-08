//! The 22-op [`OpRegistry`] wired onto the engine.
//!
//! Every catalog op is one `ProfileOp` handler sharing the same
//! [`ExecContext`]. On each `apply` the handler recovers its payload
//! node ([`payload`](super::payload)), enforces the required capability
//! ([`capgate`](super::capgate)), then branches on [`ExecMode`]:
//!
//! - **direct 7 ops** (`sh_exec` / `fs_write` / `net_http_get` /
//!   `net_http_post` / `net_transfer` / `mount_bind` / `mount_umount`)
//!   render a trace line in `DryRun` and call [`effects`]
//!   in `Real`. Path- and URL-carrying ops (all six except `sh_exec`)
//!   additionally consult [`policy`](super::policy) in both modes
//!   (spec 07 "dry-run does policy"), rejecting targets that fall
//!   outside the profile's declared `paths` / `http_allowlist`.
//! - **lifecycle 15 ops** delegate to [`lifecycle::expand`]
//!   for step composition, enforce the capability each expanded step
//!   resolves to ([`step_capability`]) before running any of them, then
//!   render each step in `DryRun` and execute each step (via
//!   [`lifecycle::execute_step`]) in `Real`. A single per-op log line
//!   joins the per-step summaries with `; `, preserving the direct-op
//!   shape (`"<op> ..."`).
//!
//! An [`ExecError`] from any step surfaces as
//! [`EngineError::EvalFailed`], carrying the node at which it happened.
//!
//! ## Two routes for `net.transfer`
//!
//! [`Op::apply`] is a `fn`, so an op handler cannot await — and dsl-kit
//! says so itself: "Ops never suspend: effects belong in `Call`
//! children" (`dsl_kit::Op`'s doc). [`TransferRoute`] is the host-side
//! switch between the two shapes a `net.transfer` phase can take:
//!
//! - [`TransferRoute::Op`] — the node stays an `Apply` over the
//!   `net_transfer` op, which drives the async effect from the
//!   synchronous seam ([`effects::block_on_effect`]). This is the route
//!   every other async-effect-bearing op still takes.
//! - [`TransferRoute::Call`] — [`ProfileCallAst`] reclassifies the node
//!   as a dsl-kit `Call`, so the engine suspends on it and the host's
//!   `AsyncEffectResolver` ([`crate::apply`]) awaits
//!   [`effects::transfer`] directly. No `block_on` is involved.
//!
//! Both routes run the same gate (L4) and the same `paths` /
//! `http_allowlist` policies (L3) **before** the effect, and write the
//! same [`StepReport`] fields, so the same profile can be run through
//! both and the two reports compared.

use std::collections::HashMap;
use std::sync::Arc;

use dsl_kit::{
    Ast, EngineError, LoopDecision, NodeContext, NodeId, NodeKind, Op, OpRegistry, OwnedDerivedAst,
    Path, SuspendReason,
};

use super::{
    audit, demand, effects, lifecycle, report::StepReport, ExecContext, ExecError, ExecMode,
};
use crate::profile_ast::{ProfileAst, ProfileNode, ProfileSemantics, ProfileValue};

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

        // Dereferencing a `Spec.env` entry is its own effect, and the
        // one thing that makes `env.ref` a reachable capability rather
        // than a reserved key (spec 02 §Catalog kinds,
        // §Shared vocabulary). The demand follows the `EnvRef` value
        // node wherever it sits — `fs.write` content, an `env` keyed
        // slot, a header, a POST body — rather than being spelled out
        // per kind, which would leave the same hole in every slot the
        // catalog's capability column does not mention.
        if let Some(capability) = demand::env_ref(payload) {
            if let Err(err) = self.ctx.gate.require(capability) {
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        }

        if LIFECYCLE_OPS.contains(&self.name) {
            return self.run_lifecycle(node, payload);
        }

        // A direct op's demand is fixed by its payload, so both gates
        // run here rather than inside each handler: the capability the
        // L4 entry check requires and the allowlist targets the L3
        // policies check, all before the handler sees the node
        // (spec 05 §L3 / §L4). The same [`demand`] mapping is what
        // [`crate::derive`] collects to assert `declared ⊇ derived` at
        // validate time — one definition, two readers.
        let demanded = match demand::direct(payload) {
            Ok(demanded) => demanded,
            Err(err) => {
                self.push_policy_failure(node, payload, &err);
                return Err(err);
            }
        };
        if let Some(capability) = demanded.capability {
            if let Err(err) = self.ctx.gate.require(capability) {
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        }
        // Policy runs in both modes (spec 07 "dry-run does policy").
        for path in &demanded.paths {
            if let Err(err) = self.ctx.path_policy.check(path) {
                self.push_policy_failure(node, payload, &err);
                return Err(err);
            }
        }
        for url in &demanded.urls {
            if let Err(err) = self.ctx.http_policy.check(url) {
                self.push_policy_failure(node, payload, &err);
                return Err(err);
            }
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
        record_line(&self.ctx, line)
    }

    /// Append a structured step report entry.
    fn push(&self, entry: StepReport) {
        push_report(&self.ctx, entry);
    }

    /// The `(<phase_index>_<kind>, kind)` base for `node`'s report entry.
    fn base(&self, node: NodeId) -> (String, String) {
        report_base(&self.ctx, node)
    }

    /// Flip a report entry to the failed state (see
    /// [`mark_report_failed`]).
    fn mark_fail(&self, entry: &mut StepReport, err: &ExecError) {
        mark_report_failed(&self.ctx, entry, err);
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

    /// Push the failing [`StepReport`] for a direct op denied by policy
    /// (or by a route that does not resolve), carrying the same input
    /// fields the op's own report would have shown.
    ///
    /// A direct op's report `op` label and its `kind` are the same
    /// string (`self.base` reads both from the phase map), so the entry
    /// is built once here instead of at each denial site.
    fn push_policy_failure(&self, node: NodeId, payload: &ProfileNode, err: &ExecError) {
        let (id, kind) = self.base(node);
        let mut entry = StepReport::new(id, kind.clone(), kind);
        match payload {
            ProfileNode::FsWrite { path, .. } | ProfileNode::MountUmount { path, .. } => {
                entry.path = Some(path.clone());
            }
            ProfileNode::NetHttpGet { url, .. } | ProfileNode::NetHttpPost { url, .. } => {
                entry.url = Some(url.clone());
            }
            ProfileNode::NetTransfer { src, dst, .. } | ProfileNode::MountBind { src, dst, .. } => {
                entry.src = Some(src.clone());
                entry.dst = Some(dst.clone());
            }
            _ => {}
        }
        self.mark_fail(&mut entry, err);
        self.push(entry);
    }

    /// Apply the path / http policy to one expanded lifecycle step.
    ///
    /// A lifecycle phase reaches the same bridges a direct op does, so
    /// it answers to the same allowlists (spec 05 §L3): a `sync.pull`
    /// writing outside `paths` or a `comfyui.health` polling a host
    /// outside `http_allowlist` is denied exactly as the direct
    /// `net.transfer` / `net.http_get` spelling of it would be. The
    /// targets are read off the resolved step, mirroring
    /// [`step_capability`]'s treatment of the demand.
    ///
    /// `Sh` steps carry no policy target — `sh.exec` is outside the
    /// path layer by design (spec 04 §`sh.exec`) — and a `Note` runs no
    /// effect at all. The pid file an `HttpPoll` re-reads is likewise
    /// exempt: it is a provisioner-internal read, not a bridge op
    /// (spec 02 §Poll deadlines).
    fn check_step_policy(&self, step: &lifecycle::Step) -> Result<(), ExecError> {
        let demanded = demand::step(step)?;
        for path in &demanded.paths {
            self.ctx.path_policy.check(path)?;
        }
        for url in &demanded.urls {
            self.ctx.http_policy.check(url)?;
        }
        Ok(())
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

        // Both gates see the *resolved* steps: expansion is pure, so the
        // route is known before anything runs, and the whole phase is
        // checked up front — a phase whose second step would be denied
        // never executes its first (spec 02 §Dispatch routing "What the
        // L4 gate sees", spec 05 §L3 / §L4).
        for step in &steps {
            let capability = match demand::step(step) {
                Ok(demanded) => demanded.capability,
                Err(err) => {
                    self.record_phase_failure(node, &err);
                    return Err(err);
                }
            };
            if let Some(capability) = capability {
                if let Err(err) = self.ctx.gate.require(capability) {
                    self.record_phase_failure(node, &err);
                    return Err(err);
                }
            }
            if let Err(err) = self.check_step_policy(step) {
                self.record_phase_failure(node, &err);
                return Err(err);
            }
        }

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
        // Resolve the content value node in both modes (spec 06
        // §Resolution "dry-run resolves too"): an undeclared or missing
        // secret fails a dry run identically to a real run. The label
        // names the source (spec 09 names-not-values) — the resolved
        // value itself never reaches the event or the report.
        let content_source = value_source(content);
        let resolved = match self.ctx.env_policy.resolve_one(content) {
            Ok(resolved) => resolved,
            Err(err) => {
                let mut entry = StepReport::new(id, kind, "fs.write");
                entry.path = Some(path.clone());
                self.mark_fail(&mut entry, &err);
                self.push(entry);
                return Err(err);
            }
        };
        audit::fs_write(
            self.ctx.mode,
            &kind,
            path,
            resolved.len() as u64,
            &content_source,
        );
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!("fs_write path={path} bytes={}", resolved.len()));
                let mut entry = StepReport::new(id, kind, "fs.write");
                entry.path = Some(path.clone());
                entry.bytes = Some(resolved.len() as u64);
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let bytes = match effects::fs_write(path, resolved.as_bytes()) {
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

    /// `net.http_get`: URL policy → header resolution → effect.
    ///
    /// The `headers` keyed slot is resolved through the
    /// [`EnvPolicy`](super::policy::EnvPolicy) in **both** modes
    /// (spec 06 §Resolution "dry-run resolves too"), so an undeclared or
    /// host-absent header secret fails a dry run identically. Neither
    /// the trace line nor the report carries a resolved value — only the
    /// header names reach the transcript.
    fn run_http_get(&self, node: NodeId, payload: &ProfileNode) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetHttpGet {
            url,
            headers,
            timeout_sec,
            ..
        } = payload
        else {
            return Err(self.variant_fail(node, "net.http_get", "NetHttpGet"));
        };
        let (id, kind) = self.base(node);
        let resolved_headers = match self.ctx.env_policy.resolve(headers) {
            Ok(resolved) => resolved,
            Err(err) => {
                let mut entry = StepReport::new(id, kind, "net.http_get");
                entry.url = Some(url.clone());
                self.mark_fail(&mut entry, &err);
                self.push(entry);
                return Err(err);
            }
        };
        audit::http_get(self.ctx.mode, &kind, url, &resolved_headers);
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!(
                    "net_http_get url={url}{}",
                    render_http_request(&resolved_headers, *timeout_sec)
                ));
                let mut entry = StepReport::new(id, kind, "net.http_get");
                entry.url = Some(url.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let opts = effects::HttpOpts::new(resolved_headers, *timeout_sec);
                let outcome =
                    match effects::block_on_effect("net_http_get", effects::http_get(url, &opts)) {
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

    /// `net.http_post`: URL policy → header + body resolution → effect.
    ///
    /// Headers resolve exactly as in [`run_http_get`](Self::run_http_get).
    /// The body is whichever of the two mutually exclusive forms the
    /// profile declared — declaring both is rejected here as well as at
    /// validate, since `apply` does not run validate first: a `body`
    /// value node resolves through the same secret pipe as `fs.write`'s
    /// `content`, a `body_json` string is sent verbatim. The content
    /// type follows from the form (`application/json` for `body_json`,
    /// `application/octet-stream` otherwise) unless `headers` declares
    /// one, which wins.
    fn run_http_post(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let ProfileNode::NetHttpPost {
            url,
            headers,
            body,
            body_json,
            timeout_sec,
            ..
        } = payload
        else {
            return Err(self.variant_fail(node, "net.http_post", "NetHttpPost"));
        };
        let (id, kind) = self.base(node);
        let resolved_headers = match self.ctx.env_policy.resolve(headers) {
            Ok(resolved) => resolved,
            Err(err) => {
                self.push_http_post_failure(&id, &kind, url, &err);
                return Err(err);
            }
        };
        // Resolve the body in both modes, like `fs.write`'s content:
        // a dry run that passes proves the secret plumbing.
        let (body_bytes, content_type, body_source) = match (body, body_json) {
            // Both forms declared. Validate rejects this, but `apply`
            // does not run validate first (spec 07 §Invocation), so the
            // rule is re-checked here rather than silently resolved by
            // an invented precedence — the two name different bodies
            // *and* different content types.
            (Some(_), Some(_)) => {
                let err = ExecError::EffectFailed {
                    op: "net_http_post".to_string(),
                    message: "body and body_json are mutually exclusive".to_string(),
                };
                self.push_http_post_failure(&id, &kind, url, &err);
                return Err(err);
            }
            (Some(body), None) => {
                let source = format!("body:{}", value_source(body));
                let resolved = match self.ctx.env_policy.resolve_one(body) {
                    Ok(resolved) => resolved,
                    Err(err) => {
                        self.push_http_post_failure(&id, &kind, url, &err);
                        return Err(err);
                    }
                };
                (
                    resolved.into_bytes(),
                    "application/octet-stream".to_string(),
                    source,
                )
            }
            (None, Some(body_json)) => (
                body_json.clone().into_bytes(),
                "application/json".to_string(),
                "body_json".to_string(),
            ),
            // Neither form declared: the pre-field behaviour, an empty
            // octet-stream body.
            (None, None) => (
                Vec::new(),
                "application/octet-stream".to_string(),
                "none".to_string(),
            ),
        };
        audit::http_post(
            self.ctx.mode,
            &kind,
            url,
            &resolved_headers,
            &body_source,
            body_bytes.len() as u64,
        );
        match self.ctx.mode {
            ExecMode::DryRun => {
                let value = self.record(format!(
                    "net_http_post url={url}{} body={body_source} body_bytes={}",
                    render_http_request(&resolved_headers, *timeout_sec),
                    body_bytes.len(),
                ));
                let mut entry = StepReport::new(id, kind, "net.http_post");
                entry.url = Some(url.clone());
                entry.dry_run = Some(true);
                self.push(entry);
                Ok(value)
            }
            ExecMode::Real => {
                let opts = effects::HttpOpts::new(resolved_headers, *timeout_sec);
                let outcome = match effects::block_on_effect(
                    "net_http_post",
                    effects::http_post(url, &body_bytes, &content_type, &opts),
                ) {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        self.push_http_post_failure(&id, &kind, url, &err);
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
                let outcome =
                    match effects::block_on_effect("net_transfer", effects::transfer(src, dst)) {
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

    /// Push a failed `net.http_post` report carrying the declared URL. The
    /// handler has four pre-effect / effect failure points (URL policy,
    /// header resolution, body resolution, the request itself), so the
    /// entry is built here once rather than at each of them — the
    /// sibling of [`push_transfer_failure`](Self::push_transfer_failure).
    fn push_http_post_failure(&self, id: &str, kind: &str, url: &str, err: &ExecError) {
        let mut entry = StepReport::new(id.to_string(), kind.to_string(), "net.http_post");
        entry.url = Some(url.to_string());
        self.mark_fail(&mut entry, err);
        self.push(entry);
    }

    /// Push a failed `net.transfer` report carrying the declared src/dst.
    fn push_transfer_failure(&self, id: &str, kind: &str, src: &str, dst: &str, err: &ExecError) {
        push_transfer_failure_report(&self.ctx, id, kind, src, dst, err);
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

/// Name where a resolved value node's content came from without
/// carrying it (spec 09 names-not-values): `"string"` for a literal,
/// `"secret:<name>"` for an [`ProfileNode::EnvSecret`],
/// `"env_ref:<name>"` for an [`ProfileNode::EnvRef`]. Shared by the
/// `fs.write` `content` and `net.http_post` `body` positions so the two
/// transcripts label the same shape the same way.
fn value_source(node: &ProfileNode) -> String {
    match node {
        ProfileNode::EnvSecret { name, .. } => format!("secret:{name}"),
        ProfileNode::EnvRef { name, .. } => format!("env_ref:{name}"),
        _ => "string".to_string(),
    }
}

/// The dry-run trace suffix common to both HTTP ops: the resolved
/// header *names* and the declared deadline, each omitted when the
/// profile declared none. Header values never reach the trace (spec 09),
/// so this renders keys only — the same shape `sh_exec`'s `env_keys=`
/// suffix uses.
fn render_http_request(
    headers: &std::collections::BTreeMap<String, String>,
    timeout_sec: Option<u16>,
) -> String {
    let mut out = String::new();
    if !headers.is_empty() {
        out.push_str(&format!(
            " header_names={:?}",
            headers.keys().collect::<Vec<_>>()
        ));
    }
    if let Some(timeout_sec) = timeout_sec {
        out.push_str(&format!(" timeout_sec={timeout_sec}"));
    }
    out
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
        lifecycle::Step::HttpPoll {
            url, timeout_sec, ..
        } => audit::http_poll(mode, kind, url, *timeout_sec),
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

// ---------------------------------------------------------------------
// Report plumbing shared by both routes
//
// The `Op` route reaches these through [`ProfileOp`]'s methods, the
// `Call` route through [`resolve_call`]. One definition each, so the
// two routes cannot drift into writing differently shaped entries.
// ---------------------------------------------------------------------

/// Push `line` onto the shared trace log and return it as the value the
/// phase produces.
fn record_line(ctx: &ExecContext, line: String) -> ProfileValue {
    ctx.log.lock().unwrap().push(line.clone());
    ProfileValue::Success(line)
}

/// Append a structured step report entry.
fn push_report(ctx: &ExecContext, entry: StepReport) {
    ctx.reports.lock().unwrap().push(entry);
}

/// The `(<phase_index>_<kind>, kind)` base for `node`'s report entry.
/// Falls back to a `n<node-id>` id for a node the phase map does not
/// know (never expected for a registered op or a routed phase).
fn report_base(ctx: &ExecContext, node: NodeId) -> (String, String) {
    let (index, kind) = ctx.phase_meta_of(node);
    if index == 0 {
        (format!("n{}", node.0), kind)
    } else {
        (format!("{index}_{kind}"), kind)
    }
}

/// Flip a report entry to the failed state, stamping the reason and
/// (under dry-run) the `dry_run` marker. `status` stays at its default
/// `-1` unless the caller already set a more specific code (e.g. a
/// non-zero process exit).
fn mark_report_failed(ctx: &ExecContext, entry: &mut StepReport, err: &ExecError) {
    entry.ok = false;
    if entry.status == 0 {
        entry.status = -1;
    }
    entry.reason = Some(err.to_string());
    if ctx.mode == ExecMode::DryRun {
        entry.dry_run = Some(true);
    }
}

/// Push a failed `net.transfer` report carrying the declared src/dst.
fn push_transfer_failure_report(
    ctx: &ExecContext,
    id: &str,
    kind: &str,
    src: &str,
    dst: &str,
    err: &ExecError,
) {
    let mut entry = StepReport::new(id.to_string(), kind.to_string(), "net.transfer");
    entry.src = Some(src.to_string());
    entry.dst = Some(dst.to_string());
    mark_report_failed(ctx, &mut entry, err);
    push_report(ctx, entry);
}

// ---------------------------------------------------------------------
// The `Call` route
// ---------------------------------------------------------------------

/// The `CallSpec::label` a suspended `net.transfer` carries.
pub const TRANSFER_CALL_LABEL: &str = "net.transfer";

/// Which shape a `net.transfer` phase takes in the engine (module doc
/// §Two routes for `net.transfer`).
///
/// A host-side switch, deliberately not a profile field: the profile's
/// bytes — and therefore its hash — say nothing about how the host
/// chooses to drive the effect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransferRoute {
    /// `Apply` over the `net_transfer` op; the op runs the effect.
    #[default]
    Op,
    /// dsl-kit `Call`; the host's async resolver runs the effect.
    Call,
}

/// The effect-side failure a host resolver reports back through
/// `Stepper::resolve` (dsl-kit requires `Clone + Error + Send + Sync`,
/// which [`ExecError`] is not — it is carried as its rendered text, and
/// the machine-readable detail is already in the step's report entry).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct CallError(String);

impl From<&ExecError> for CallError {
    fn from(err: &ExecError) -> Self {
        CallError(err.to_string())
    }
}

/// The [`ProfileNode`] AST projected for the engine, with the nodes the
/// host has chosen to route through a `Call` reclassified.
///
/// It wraps [`ProfileAst`] rather than replacing it: every other node
/// keeps the classification `#[derive(DslExec)]` gave it, and the
/// profile's own bytes are untouched, so `hash` / `canonical` are
/// unaffected by which route the host picked.
pub struct ProfileCallAst {
    /// The unmodified derived projection.
    inner: ProfileAst,
    /// `NodeId -> Call` overrides applied on top of `inner`.
    calls: HashMap<NodeId, NodeKind>,
}

impl ProfileCallAst {
    /// Project `root`, reclassifying every `net.transfer` phase as a
    /// `Call` when `route` is [`TransferRoute::Call`].
    ///
    /// The node declares `label = "net.transfer"` and
    /// `payload = { "src": …, "dst": … }`.
    ///
    /// **Only the label reaches the host.** dsl-kit-core 0.8.0 spawns a
    /// `Call` leaf with `serde_json::Value::Null` in place of the
    /// declared payload [`dsl-kit-core-0.8.0/src/engine.rs:1385-1387`],
    /// so a resolver cannot read `src` / `dst` off the suspension. The
    /// payload is declared here anyway — it is what the node *means*,
    /// and it is what the resolver will read once the engine carries it
    /// — while [`resolve_call`] recovers the two fields the way every
    /// other leaf payload in this crate is recovered, through
    /// [`super::payload`]'s `NodeId -> ProfileNode` map (see that
    /// module's doc: dsl-kit does not hand leaf payloads to
    /// [`Op::apply`] either).
    pub fn new(root: &ProfileNode, route: TransferRoute) -> Self {
        let inner = OwnedDerivedAst::new(root, ProfileSemantics);
        let mut calls = HashMap::new();
        if route == TransferRoute::Call {
            for (id, node) in super::payload::build_payload_map(root) {
                if let ProfileNode::NetTransfer { src, dst, .. } = node {
                    calls.insert(
                        id,
                        NodeKind::Call {
                            label: TRANSFER_CALL_LABEL.to_string(),
                            payload: serde_json::json!({ "src": src, "dst": dst }),
                        },
                    );
                }
            }
        }
        Self { inner, calls }
    }
}

impl Ast for ProfileCallAst {
    type Value = ProfileValue;
    type Delta = ();
    type EffectError = CallError;
    type Cursor = ();

    fn root(&self) -> NodeId {
        self.inner.root()
    }

    fn node_kind(&self, id: NodeId) -> NodeKind {
        match self.calls.get(&id) {
            Some(kind) => kind.clone(),
            None => self.inner.node_kind(id),
        }
    }

    fn unit_value(&self) -> ProfileValue {
        self.inner.unit_value()
    }

    fn truthy(&self, value: &ProfileValue) -> Option<bool> {
        self.inner.truthy(value)
    }

    fn continue_loop(&self, node: NodeId, last: &ProfileValue, iteration: usize) -> LoopDecision {
        self.inner.continue_loop(node, last, iteration)
    }

    fn bind_delta(&self, name: &str, value: &ProfileValue) -> Option<()> {
        self.inner.bind_delta(name, value)
    }

    fn lookup(&self, delta: &(), name: &str) -> Option<ProfileValue> {
        self.inner.lookup(delta, name)
    }

    fn literal(&self, node: NodeId) -> Option<ProfileValue> {
        self.inner.literal(node)
    }
}

/// Resolve one suspended `Call` for the host.
///
/// `node` is the AST node that suspended (`Pending::at.node`), which is
/// what labels the step's report entry — a routed phase keeps the id and
/// kind it would have had on the `Op` route.
///
/// The gate and both policies run **here, before the effect**, in the
/// same order [`ProfileOp::dispatch`] runs them: a `Call` bypasses
/// `Op::apply` entirely, so a resolver that skipped them would be a hole
/// in the L3 / L4 enforcement (spec 05) that only the new route has.
pub async fn resolve_call(
    ctx: &ExecContext,
    node: NodeId,
    reason: &SuspendReason,
) -> Result<ProfileValue, CallError> {
    let SuspendReason::Call { spec } = reason else {
        return Err(CallError(format!(
            "the suspension at n{} is not a Call ({reason}); the host resolves Call effects only",
            node.0
        )));
    };
    if spec.label != TRANSFER_CALL_LABEL {
        return Err(CallError(format!(
            "no host resolver is registered for the call '{}'",
            spec.label
        )));
    }
    // `spec.payload` is `Null` on dsl-kit-core 0.8.0 regardless of what
    // the node declared (see [`ProfileCallAst::new`]), so the effect's
    // inputs come from the payload map — the same recovery `Op::apply`
    // does, which is also what keeps the two routes reading one source
    // of truth.
    let Some(ProfileNode::NetTransfer { src, dst, .. }) = ctx.payloads.get(&node) else {
        let err = ExecError::PayloadVariant {
            node: node.0,
            expected: "NetTransfer",
        };
        let (id, kind) = report_base(ctx, node);
        let mut entry = StepReport::new(id, kind, TRANSFER_CALL_LABEL);
        mark_report_failed(ctx, &mut entry, &err);
        push_report(ctx, entry);
        return Err(CallError::from(&err));
    };
    resolve_transfer(ctx, node, src, dst).await
}

/// The `Call`-route twin of [`ProfileOp::run_transfer`]: gate → policy →
/// audit → effect, writing the same report entry either branch of the
/// `Op` route would.
async fn resolve_transfer(
    ctx: &ExecContext,
    node: NodeId,
    src: &str,
    dst: &str,
) -> Result<ProfileValue, CallError> {
    let (id, kind) = report_base(ctx, node);

    if let Err(err) = check_transfer_demand(ctx, node, src, dst) {
        push_transfer_failure_report(ctx, &id, &kind, src, dst, &err);
        return Err(CallError::from(&err));
    }

    audit::transfer(ctx.mode, &kind, src, dst);
    match ctx.mode {
        ExecMode::DryRun => {
            let value = record_line(ctx, format!("net_transfer src={src} dst={dst}"));
            let mut entry = StepReport::new(id, kind, "net.transfer");
            entry.src = Some(src.to_string());
            entry.dst = Some(dst.to_string());
            entry.dry_run = Some(true);
            push_report(ctx, entry);
            Ok(value)
        }
        ExecMode::Real => {
            // No lock is held across this await: `record_line` /
            // `push_report` take the report and log mutexes for the
            // duration of one push, after the transfer has finished.
            let outcome = match effects::transfer(src, dst).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    push_transfer_failure_report(ctx, &id, &kind, src, dst, &err);
                    return Err(CallError::from(&err));
                }
            };
            let value = record_line(
                ctx,
                format!(
                    "net_transfer src={src} dst={} bytes={}",
                    outcome.dst, outcome.bytes
                ),
            );
            let mut entry = StepReport::new(id, kind, "net.transfer");
            entry.src = Some(src.to_string());
            entry.dst = Some(outcome.dst.clone());
            entry.bytes = Some(outcome.bytes);
            push_report(ctx, entry);
            Ok(value)
        }
    }
}

/// The L4 capability check and both L3 allowlists for a routed
/// `net.transfer`, derived through the same [`demand::direct`] the `Op`
/// route uses — one mapping, so both routes answer to exactly the same
/// declarations.
fn check_transfer_demand(
    ctx: &ExecContext,
    node: NodeId,
    src: &str,
    dst: &str,
) -> Result<(), ExecError> {
    let payload = ProfileNode::NetTransfer {
        id: node,
        src: src.to_string(),
        dst: dst.to_string(),
    };
    let demanded = demand::direct(&payload)?;
    if let Some(capability) = demanded.capability {
        ctx.gate.require(capability)?;
    }
    // Policy runs in both modes (spec 07 "dry-run does policy").
    for path in &demanded.paths {
        ctx.path_policy.check(path)?;
    }
    for url in &demanded.urls {
        ctx.http_policy.check(url)?;
    }
    Ok(())
}
