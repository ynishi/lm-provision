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
//! - **lifecycle 15 ops** no longer run here. Their steps are composed
//!   before the engine starts and projected onto engine nodes — one
//!   `Call` per step ([`super::steps`]) — so the phase is a `Seq` and
//!   each step suspends on its own, resolved by
//!   [`resolve_lifecycle_step`]. A lifecycle phase reaches its op only
//!   when the projection left it there: its expansion failed, or it
//!   composed no steps at all.
//!
//! An [`ExecError`] from any step surfaces as
//! [`EngineError::EvalFailed`], carrying the node at which it happened.
//!
//! ## Two routes for the single-effect ops
//!
//! [`Op::apply`] is a `fn`, so an op handler cannot await — and dsl-kit
//! says so itself: "Ops never suspend: effects belong in `Call`
//! children" (`dsl_kit::Op`'s doc). [`EffectRoute`] is the host-side
//! switch between the two shapes the three single-effect network phases
//! (`net.transfer` / `net.http_get` / `net.http_post`) can take:
//!
//! - [`EffectRoute::Op`] — the node stays an `Apply` over the
//!   `net_transfer` / `net_http_get` / `net_http_post` op, which drives
//!   the async effect from the synchronous seam
//!   ([`effects::block_on_effect`]).
//! - [`EffectRoute::Call`] — [`ProfileCallAst`] reclassifies the node as
//!   a dsl-kit `Call`, so the engine suspends on it and the host's
//!   `AsyncEffectResolver` ([`crate::apply`]) awaits the effect
//!   ([`effects::transfer`] / [`effects::http_get`] /
//!   [`effects::http_post`]) directly. No `block_on` is involved.
//!
//! Both routes run the same gate (L4) and the same `paths` /
//! `http_allowlist` policies (L3) **before** the effect — one
//! [`check_routed_demand`] mirroring the pre-handler block of
//! [`ProfileOp::dispatch`] — and write the same [`StepReport`] fields,
//! so the same profile can be run through both and the two reports
//! compared.
//!
//! A **lifecycle** phase has no such switch. It was not routable while
//! one `Op::apply` ran a whole composed step list; now that the list is
//! engine nodes, every lifecycle step is a `Call` and there is no second
//! shape to choose between. [`EffectRoute`] stays what it always was —
//! the switch for the three single-effect network phases — and the two
//! seams the lifecycle step kinds used to need are gone with them.

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
///
/// `pub(crate)` so [`super::steps`] can pin its variant → op-name map
/// against this list; the two are written out separately and nothing
/// else would stop them drifting.
pub(crate) const LIFECYCLE_OPS: [&str; 15] = [
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
        record_phase_failure_report(&self.ctx, node, err);
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
        push_policy_failure_report(&self.ctx, node, payload, err);
    }

    /// Compose a lifecycle op's steps and run each one, on the
    /// **synchronous** engine driver.
    ///
    /// This is not the route `apply` takes. There a lifecycle phase is a
    /// `Seq` of per-step `Call` nodes ([`super::steps`]) and
    /// [`resolve_lifecycle_step`] awaits each one. But
    /// [`crate::profile_ast::create_profile_engine`] builds an engine
    /// straight over the derived AST and drives it with a synchronous
    /// `Stepper` — the MCP debugger host and the exec integration tests
    /// — and a synchronous stepper cannot resolve a `Call`. On that
    /// driver a lifecycle phase is still an `Apply`, and this is what
    /// runs it.
    ///
    /// So the seam stays here, for the same reason the three network
    /// phases keep theirs: **it belongs to the synchronous driver, not
    /// to lifecycle**. One [`effects::block_on_effect`] per step, over
    /// the whole of [`lifecycle::run_step`] — the same function the
    /// resolver awaits, in the same mode — so the two drivers cannot
    /// answer a step differently. It goes when that driver does.
    ///
    /// The order is the one this function has always had: the phase's
    /// `env` keyed slot resolves through the
    /// [`EnvPolicy`](super::policy::EnvPolicy) first — in **both** modes
    /// (spec 06 §Resolution "dry-run resolves too") — then the
    /// expansion, then both gates over *every* composed step, so a phase
    /// whose second step would be denied never executes its first
    /// (spec 02 §Dispatch routing, spec 05 §L3 / §L4). Fail-fast: a
    /// failing sub-step is recorded and stops the phase.
    fn run_lifecycle(
        &self,
        node: NodeId,
        payload: &ProfileNode,
    ) -> Result<ProfileValue, ExecError> {
        let (base_id, kind) = self.base(node);
        let env = match resolve_phase_env(&self.ctx, payload) {
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
        check_lifecycle_steps(&self.ctx, node, &steps)?;

        let mut renders = Vec::with_capacity(steps.len());
        for (index, step) in steps.iter().enumerate() {
            let sub_id = format!("{base_id}_{}", index + 1);
            // Audit before the sub-step runs. Env keys go through the
            // redaction helper (spec 09 §Audit log); the resolved values
            // from the phase's `env` map never reach the event.
            audit_lifecycle_step(self.ctx.mode, &kind, step, &env);
            let run = effects::block_on_effect(
                self.name,
                lifecycle::run_step(step, self.name, &env, self.ctx.mode),
            );
            renders.push(record_lifecycle_step(
                &self.ctx,
                sub_id,
                kind.clone(),
                step,
                run,
            )?);
        }
        Ok(self.record(format!("{} {}", self.name, renders.join("; "))))
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
                push_http_failure_report(&self.ctx, &id, &kind, "net.http_get", url, &err);
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
                            push_http_failure_report(
                                &self.ctx,
                                &id,
                                &kind,
                                "net.http_get",
                                url,
                                &err,
                            );
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
        let (body_bytes, content_type, body_source) =
            match resolve_post_body(&self.ctx, body.as_deref(), body_json.as_ref()) {
                Ok(resolved) => resolved,
                Err(err) => {
                    self.push_http_post_failure(&id, &kind, url, &err);
                    return Err(err);
                }
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
        push_http_failure_report(&self.ctx, id, kind, "net.http_post", url, err);
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
        lifecycle::Step::Transfer { src, dst, .. } => audit::transfer(mode, kind, src, dst),
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
        lifecycle::Step::Transfer { src, dst, .. } => {
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
    if result.note.is_some() {
        entry.note = result.note.clone();
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

/// Push a failed `net.http_get` / `net.http_post` report (named by `op`)
/// carrying the declared URL — the HTTP sibling of
/// [`push_transfer_failure_report`]. Both ops have several pre-effect
/// failure points (header resolution, body resolution, the request
/// itself), and both routes reach all of them.
fn push_http_failure_report(
    ctx: &ExecContext,
    id: &str,
    kind: &str,
    op: &str,
    url: &str,
    err: &ExecError,
) {
    let mut entry = StepReport::new(id.to_string(), kind.to_string(), op);
    entry.url = Some(url.to_string());
    mark_report_failed(ctx, &mut entry, err);
    push_report(ctx, entry);
}

/// Record a phase-level failure that happened before (or instead of) any
/// effect ran — a payload lookup miss or a capability denial. The report
/// entry carries the phase kind as its `op` (no effect was reached to
/// name a more specific one).
fn record_phase_failure_report(ctx: &ExecContext, node: NodeId, err: &ExecError) {
    let (id, kind) = report_base(ctx, node);
    let mut entry = StepReport::new(id, kind.clone(), kind);
    mark_report_failed(ctx, &mut entry, err);
    push_report(ctx, entry);
}

/// Push the failing [`StepReport`] for a direct phase denied by policy,
/// carrying the same input fields the phase's own report would show.
///
/// A direct phase's report `op` label and its `kind` are the same string
/// ([`report_base`] reads both from the phase map), so the entry is built
/// once here instead of at each denial site.
fn push_policy_failure_report(
    ctx: &ExecContext,
    node: NodeId,
    payload: &ProfileNode,
    err: &ExecError,
) {
    let (id, kind) = report_base(ctx, node);
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
    mark_report_failed(ctx, &mut entry, err);
    push_report(ctx, entry);
}

/// Resolve a phase's `env` keyed slot into a concrete `name → value`
/// map (empty for phases without an `env` field). Fail-fast on an
/// undeclared or missing secret, in **both** modes (spec 06 §Resolution
/// "dry-run resolves too").
fn resolve_phase_env(
    ctx: &ExecContext,
    payload: &ProfileNode,
) -> Result<std::collections::BTreeMap<String, String>, ExecError> {
    match payload {
        ProfileNode::SyncPull { env, .. } | ProfileNode::StagingPush { env, .. } => {
            ctx.env_policy.resolve(env)
        }
        _ => Ok(std::collections::BTreeMap::new()),
    }
}

/// Apply the path / http policy to one expanded lifecycle step.
///
/// A lifecycle phase reaches the same bridges a direct op does, so it
/// answers to the same allowlists (spec 05 §L3): a `sync.pull` writing
/// outside `paths` or a `comfyui.health` polling a host outside
/// `http_allowlist` is denied exactly as the direct `net.transfer` /
/// `net.http_get` spelling of it would be. The targets are read off the
/// resolved step.
///
/// `Sh` steps carry no policy target — `sh.exec` is outside the path
/// layer by design (spec 04 §`sh.exec`) — and a `Note` runs no effect at
/// all. The pid file an `HttpPoll` re-reads is likewise exempt: it is a
/// provisioner-internal read, not a bridge op (spec 02 §Poll deadlines).
fn check_step_policy(ctx: &ExecContext, step: &lifecycle::Step) -> Result<(), ExecError> {
    let demanded = demand::step(step)?;
    for path in &demanded.paths {
        ctx.path_policy.check(path)?;
    }
    for url in &demanded.urls {
        ctx.http_policy.check(url)?;
    }
    Ok(())
}

/// The L4 capability and both L3 allowlists of **every** composed step
/// of a phase, run before any of them executes.
///
/// A phase whose second step would be denied never executes its first
/// (spec 02 §Dispatch routing "What the L4 gate sees", spec 05
/// §L3 / §L4). On the synchronous driver that falls out of checking the
/// list up front. On the `Call` route the engine hands the steps over
/// one at a time, so checking only the arriving step would let step 1
/// run and deny step 2 afterwards — the property would be quietly lost.
/// [`resolve_lifecycle_step`] therefore runs this whole check at *each*
/// step, which restores it: step 1 is refused for step 2's denial. The
/// check is pure and reads a handful of declarations, so repeating it
/// costs nothing and cannot answer differently between steps.
///
/// A denial reports itself at the *phase* node, so callers have nothing
/// to push.
fn check_lifecycle_steps(
    ctx: &ExecContext,
    phase: NodeId,
    steps: &[lifecycle::Step],
) -> Result<(), ExecError> {
    for step in steps {
        let capability = match demand::step(step) {
            Ok(demanded) => demanded.capability,
            Err(err) => {
                record_phase_failure_report(ctx, phase, &err);
                return Err(err);
            }
        };
        if let Some(capability) = capability {
            if let Err(err) = ctx.gate.require(capability) {
                record_phase_failure_report(ctx, phase, &err);
                return Err(err);
            }
        }
        if let Err(err) = check_step_policy(ctx, step) {
            record_phase_failure_report(ctx, phase, &err);
            return Err(err);
        }
    }
    Ok(())
}

/// Everything a lifecycle phase has to answer for before any of its
/// steps runs, for the `Call` route: the `env.ref` capability, the phase
/// `env` resolution, and [`check_lifecycle_steps`].
///
/// The synchronous driver reaches the same three in the same order —
/// `env.ref` in [`ProfileOp::dispatch`], then the two inside
/// [`ProfileOp::run_lifecycle`] — so the two drivers deny the same
/// profiles with the same report entry.
fn lifecycle_preflight(
    ctx: &ExecContext,
    phase: NodeId,
    payload: &ProfileNode,
    steps: &[lifecycle::Step],
) -> Result<std::collections::BTreeMap<String, String>, ExecError> {
    if let Some(capability) = demand::env_ref(payload) {
        if let Err(err) = ctx.gate.require(capability) {
            record_phase_failure_report(ctx, phase, &err);
            return Err(err);
        }
    }
    let env = match resolve_phase_env(ctx, payload) {
        Ok(env) => env,
        Err(err) => {
            record_phase_failure_report(ctx, phase, &err);
            return Err(err);
        }
    };
    check_lifecycle_steps(ctx, phase, steps)?;
    Ok(env)
}

/// Write one lifecycle step's report entry from what running it
/// produced, and return its trace-log summary.
///
/// **Both drivers land here**, which is what keeps a step's report entry
/// independent of which one ran it: the same id, the same `op` label,
/// the same declared-input fields, the same observations, the same
/// `dry_run` marker rule, the same note.
fn record_lifecycle_step(
    ctx: &ExecContext,
    sub_id: String,
    kind: String,
    step: &lifecycle::Step,
    run: Result<lifecycle::StepRun, lifecycle::StepFailure>,
) -> Result<String, ExecError> {
    let mut entry = StepReport::new(sub_id, kind, step_effect_op(step));
    apply_step_input_fields(&mut entry, step);
    match run {
        Ok(lifecycle::StepRun::Dry(decided)) => {
            if let Some(note) = decided.note {
                entry.note = Some(note);
            }
            // A `note` sub-step is inert in either mode, matching the
            // legacy `dispatch_pending` skip's lack of a `dry_run`
            // marker; effect-bearing sub-steps carry it.
            if !matches!(step, lifecycle::Step::Note(_)) {
                entry.dry_run = Some(true);
            }
            push_report(ctx, entry);
            Ok(decided.summary)
        }
        Ok(lifecycle::StepRun::Real(result)) => {
            apply_step_result_fields(&mut entry, &result);
            push_report(ctx, entry);
            Ok(result.summary)
        }
        Err(failure) => {
            // The partial observation lands *before* the failure mark,
            // which only substitutes `-1` when no more specific status
            // is already there — so a non-zero exit code survives.
            apply_step_result_fields(&mut entry, &failure.observed);
            mark_report_failed(ctx, &mut entry, &failure.error);
            push_report(ctx, entry);
            Err(failure.error)
        }
    }
}

/// Resolve a `net.http_post`'s request body into `(bytes, content type,
/// the audit's name for its form)`.
///
/// Shared by both routes, and run in **both** modes — like `fs.write`'s
/// content, a dry run that passes proves the secret plumbing (spec 06
/// §Resolution "dry-run resolves too").
///
/// Declaring both forms is rejected here. Validate rejects it too, but
/// `apply` does not run validate first (spec 07 §Invocation), so the rule
/// is re-checked rather than silently resolved by an invented precedence
/// — the two name different bodies *and* different content types.
/// Declaring neither is the pre-field behaviour, an empty octet-stream
/// body.
fn resolve_post_body(
    ctx: &ExecContext,
    body: Option<&ProfileNode>,
    body_json: Option<&String>,
) -> Result<(Vec<u8>, String, String), ExecError> {
    match (body, body_json) {
        (Some(_), Some(_)) => Err(ExecError::EffectFailed {
            op: "net_http_post".to_string(),
            message: "body and body_json are mutually exclusive".to_string(),
        }),
        (Some(body), None) => {
            let source = format!("body:{}", value_source(body));
            let resolved = ctx.env_policy.resolve_one(body)?;
            Ok((
                resolved.into_bytes(),
                "application/octet-stream".to_string(),
                source,
            ))
        }
        (None, Some(body_json)) => Ok((
            body_json.clone().into_bytes(),
            "application/json".to_string(),
            "body_json".to_string(),
        )),
        (None, None) => Ok((
            Vec::new(),
            "application/octet-stream".to_string(),
            "none".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------
// The `Call` route
// ---------------------------------------------------------------------

/// The `CallSpec::label` a suspended `net.transfer` carries.
pub const TRANSFER_CALL_LABEL: &str = "net.transfer";

/// The `CallSpec::label` a suspended `net.http_get` carries.
pub const HTTP_GET_CALL_LABEL: &str = "net.http_get";

/// The `CallSpec::label` a suspended `net.http_post` carries.
pub const HTTP_POST_CALL_LABEL: &str = "net.http_post";

/// The `CallSpec::label` a suspended **lifecycle step** carries.
///
/// One label for all fifteen ops and all four step shapes: what the
/// resolver needs in order to run the step is the step itself, which it
/// reaches through [`super::steps::StepPlan`], not through the label. A
/// label per op would name the phase twice (the payload already does)
/// and a label per step shape would name the effect twice.
pub const LIFECYCLE_STEP_CALL_LABEL: &str = "lifecycle.step";

/// Which shape the single-effect network phases take in the engine
/// (module doc §Two routes for the single-effect ops).
///
/// A host-side switch, deliberately not a profile field: the profile's
/// bytes — and therefore its hash — say nothing about how the host
/// chooses to drive the effect.
///
/// One switch for the three ops rather than one per op: they are the
/// same shape, and a per-op knob would describe nothing but a
/// half-migrated host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EffectRoute {
    /// `Apply` over the phase's own op; the op runs the effect from the
    /// synchronous seam.
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

/// The [`ProfileNode`] AST projected for the engine, with two kinds of
/// node reclassified on top of the derived one.
///
/// It wraps [`ProfileAst`] rather than replacing it: every other node
/// keeps the classification `#[derive(DslExec)]` gave it, and the
/// profile's own bytes are untouched, so `hash` / `canonical` are
/// unaffected by any of this.
///
/// - a **routable network phase**, when `route` is
///   [`EffectRoute::Call`] — an `Apply` becomes a `Call` ([`call_kind`]);
/// - a **lifecycle phase**, always — an `Apply` becomes a `Seq` over one
///   synthetic `Call` node per composed step ([`super::steps`]). The
///   step nodes exist only here and in the [`StepPlan`](super::steps::StepPlan)
///   both sides read, so they carry no payload of their own; the
///   resolver reaches everything through the phase they name.
pub struct ProfileCallAst {
    /// The unmodified derived projection.
    inner: ProfileAst,
    /// `NodeId -> NodeKind` overrides applied on top of `inner`.
    overrides: HashMap<NodeId, NodeKind>,
}

impl ProfileCallAst {
    /// Project `root`, reclassifying every routable phase
    /// ([`call_kind`]) as a `Call` when `route` is
    /// [`EffectRoute::Call`], and every projected lifecycle phase
    /// (`plan`) as a `Seq` of per-step `Call`s.
    ///
    /// `plan` has to be the same [`StepPlan`](super::steps::StepPlan) the
    /// [`ExecContext`] holds: it is where the synthetic node ids come
    /// from, and a resolver handed one of them looks it up there.
    /// Building a second plan would hand out the same ids by
    /// construction, but nothing would keep it doing so — one plan, two
    /// readers.
    ///
    /// **The children are a `Seq`, not a `Par`.** A phase's steps are
    /// still run in written order, which is the whole basis on which a
    /// partial apply is readable (design §2). What changed is that the
    /// order is now the *engine's*, over independent child nodes, rather
    /// than a loop inside one op — so a later stage swaps this one
    /// constructor call for a `Par` and changes nothing else.
    pub fn new(root: &ProfileNode, route: EffectRoute, plan: &super::steps::StepPlan) -> Self {
        let inner = OwnedDerivedAst::new(root, ProfileSemantics);
        let mut overrides = HashMap::new();
        if route == EffectRoute::Call {
            for (id, node) in super::payload::build_payload_map(root) {
                if let Some(kind) = call_kind(&node) {
                    overrides.insert(id, kind);
                }
            }
        }
        for (phase_id, phase) in plan.projected_phases() {
            let total = phase.steps.len();
            let Some(payload) = plan_phase_payload(root, phase_id) else {
                continue;
            };
            for (offset, step) in phase.steps.iter().enumerate() {
                overrides.insert(
                    phase.nodes[offset],
                    NodeKind::Call {
                        label: LIFECYCLE_STEP_CALL_LABEL.to_string(),
                        payload: lifecycle_step_payload(payload, step, offset + 1, total),
                    },
                );
            }
            overrides.insert(
                phase_id,
                NodeKind::Seq {
                    children: phase.nodes.clone(),
                },
            );
        }
        Self { inner, overrides }
    }
}

/// The declared phase node `phase_id` names, looked up under `root`.
fn plan_phase_payload(root: &ProfileNode, phase_id: NodeId) -> Option<&ProfileNode> {
    let ProfileNode::Spec { phases, .. } = root else {
        return None;
    };
    use dsl_kit::DslNode as _;
    phases.iter().find(|phase| phase.node_id() == phase_id)
}

/// What a suspended lifecycle step declares to an observer.
///
/// The same rule the two HTTP calls follow, applied to a step: **names,
/// addresses and shapes — never a value that must not be observed.**
/// Since dsl-kit-core 0.11.0 a `CallSpec::payload` travels verbatim to
/// the host and surfaces as `PendingProjection.payload`, readable by any
/// MCP client watching the suspension, so what a step may put here is
/// decided by spec 09 §Audit log rather than by convenience.
///
/// For a lifecycle step that means:
///
/// - a [`lifecycle::Step::Sh`] declares its **composed argv** and, when
///   the phase has an `env` keyed slot, the **names** of the variables
///   injected into it — never a resolved value. The argv is composed
///   from payload fields that are already in the profile's own bytes and
///   in the `plan` artifact (`apt-get install …`, a `git clone` URL, a
///   `hooks.post_install` script), so it discloses nothing the profile
///   did not already say; the resolved secrets reach the child process's
///   environment and nothing else;
/// - a [`lifecycle::Step::Transfer`] declares `src` / `dst`, exactly as
///   the direct `net.transfer` call does;
/// - a [`lifecycle::Step::HttpPoll`] declares the URL it polls and its
///   deadline. It carries no headers at all — a poll sends none — so the
///   header-value question the HTTP calls have to answer does not arise;
/// - a [`lifecycle::Step::Note`] declares its message, which is
///   host-composed text about what was *not* run.
///
/// The step's `done` is deliberately absent: it is derived from the
/// destination, which is already here, and printing the condition twice
/// would only widen the surface.
fn lifecycle_step_payload(
    phase: &ProfileNode,
    step: &lifecycle::Step,
    index: usize,
    total: usize,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "phase".to_string(),
        serde_json::Value::from(crate::plan::kind_of(phase)),
    );
    map.insert("step".to_string(), serde_json::Value::from(index));
    map.insert("of".to_string(), serde_json::Value::from(total));
    map.insert(
        "effect".to_string(),
        serde_json::Value::from(step_effect_op(step)),
    );
    match step {
        lifecycle::Step::Sh(argv) => {
            map.insert("argv".to_string(), serde_json::json!(argv));
            let names = phase_env_names(phase);
            if !names.is_empty() {
                map.insert("env_names".to_string(), serde_json::json!(names));
            }
        }
        lifecycle::Step::Transfer { src, dst, .. } => {
            map.insert("src".to_string(), serde_json::Value::from(src.clone()));
            map.insert("dst".to_string(), serde_json::Value::from(dst.clone()));
        }
        lifecycle::Step::HttpPoll {
            url, timeout_sec, ..
        } => {
            map.insert("url".to_string(), serde_json::Value::from(url.clone()));
            map.insert(
                "timeout_sec".to_string(),
                serde_json::Value::from(*timeout_sec),
            );
        }
        lifecycle::Step::Note(message) => {
            map.insert(
                "message".to_string(),
                serde_json::Value::from(message.clone()),
            );
        }
    }
    serde_json::Value::Object(map)
}

/// The **names** in a phase's `env` keyed slot (spec 09
/// names-not-values). Empty for the thirteen lifecycle kinds that have
/// no such slot.
fn phase_env_names(phase: &ProfileNode) -> Vec<&String> {
    match phase {
        ProfileNode::SyncPull { env, .. } | ProfileNode::StagingPush { env, .. } => {
            env.keys().collect()
        }
        _ => Vec::new(),
    }
}

/// The `Call` a routable phase declares, or `None` for a node that stays
/// on its op.
///
/// **The payload is what may be observed, not the channel the resolver
/// reads.** Since dsl-kit-core 0.11.0 the engine carries it verbatim to
/// the host, where it surfaces as `PendingProjection.payload` — visible
/// to any MCP client watching the suspension. That is the reason a
/// header value and a request body are deliberately **not** declared
/// here: spec 09 §Audit log says header values are logged "never
/// (headers may carry tokens); bodies never", and a channel an observer
/// can read is a channel those values must not enter. The two HTTP calls
/// declare header *names* and the body's *form*, matching the
/// names-not-values rule the audit transcript follows; the values
/// themselves resolve through the [`EnvPolicy`](super::policy::EnvPolicy)
/// and reach the request and nothing else.
///
/// [`resolve_call`] therefore recovers every field from
/// [`super::payload`]'s `NodeId -> ProfileNode` map rather than from the
/// suspension — one path for the safe fields and the sensitive ones
/// alike, which is also how every other leaf payload in this crate is
/// recovered (see that module's doc: dsl-kit hands leaf payloads to
/// neither [`Op::apply`] nor, for values that must stay unobserved, the
/// resolver).
fn call_kind(node: &ProfileNode) -> Option<NodeKind> {
    match node {
        ProfileNode::NetTransfer { src, dst, .. } => Some(NodeKind::Call {
            label: TRANSFER_CALL_LABEL.to_string(),
            payload: serde_json::json!({ "src": src, "dst": dst }),
        }),
        ProfileNode::NetHttpGet {
            url,
            headers,
            timeout_sec,
            ..
        } => Some(NodeKind::Call {
            label: HTTP_GET_CALL_LABEL.to_string(),
            payload: serde_json::json!({
                "url": url,
                "header_names": headers.keys().collect::<Vec<_>>(),
                "timeout_sec": timeout_sec,
            }),
        }),
        ProfileNode::NetHttpPost {
            url,
            headers,
            body,
            body_json,
            timeout_sec,
            ..
        } => Some(NodeKind::Call {
            label: HTTP_POST_CALL_LABEL.to_string(),
            payload: serde_json::json!({
                "url": url,
                "header_names": headers.keys().collect::<Vec<_>>(),
                "body": declared_body_form(body.as_deref(), body_json.as_ref()),
                "timeout_sec": timeout_sec,
            }),
        }),
        _ => None,
    }
}

/// Which body form a `net.http_post` declared, named as the audit names
/// it. `"body+body_json"` is the mutually exclusive pair
/// [`resolve_post_body`] rejects — declared honestly rather than
/// silently resolved to one of the two.
fn declared_body_form(body: Option<&ProfileNode>, body_json: Option<&String>) -> &'static str {
    match (body, body_json) {
        (Some(_), Some(_)) => "body+body_json",
        (Some(_), None) => "body",
        (None, Some(_)) => "body_json",
        (None, None) => "none",
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
        match self.overrides.get(&id) {
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
        // A synthetic step node exists only in the override table, so
        // the inner projection has nothing under that id. The engine
        // only asks a `Lit` for its literal and never asks a `Call`, but
        // an override is the one id where "ask the inner AST" is not a
        // question it can answer, so it is answered here.
        if self.overrides.contains_key(&node) {
            return None;
        }
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
    // A lifecycle step is answered before the payload lookup below: its
    // node is synthetic, so there is no `ProfileNode` under that id. Its
    // inputs are the phase's, reached through the step plan.
    if spec.label == LIFECYCLE_STEP_CALL_LABEL {
        return resolve_lifecycle_step(ctx, node).await;
    }
    // `spec.payload` is `Null` on dsl-kit-core 0.8.0 regardless of what
    // the node declared (see [`call_kind`]), so the effect's inputs come
    // from the payload map — the same recovery `Op::apply` does, which
    // is also what keeps the two routes reading one source of truth.
    let Some(payload) = ctx.payloads.get(&node) else {
        let err = ExecError::PayloadMissing(node.0);
        record_phase_failure_report(ctx, node, &err);
        return Err(CallError::from(&err));
    };
    match spec.label.as_str() {
        TRANSFER_CALL_LABEL => resolve_transfer(ctx, node, payload).await,
        HTTP_GET_CALL_LABEL => resolve_http_get(ctx, node, payload).await,
        HTTP_POST_CALL_LABEL => resolve_http_post(ctx, node, payload).await,
        other => Err(CallError(format!(
            "no host resolver is registered for the call '{other}'"
        ))),
    }
}

/// Resolve one suspended **lifecycle step**.
///
/// This is where a lifecycle op runs now. The phase composed its steps
/// before the engine started ([`super::steps`]); the engine walks them
/// as a `Seq` and suspends on each, and this awaits the one it is given.
///
/// What it writes is what the `Op` route wrote, deliberately: the same
/// `<phase_index>_<kind>_<n>` report id (taken from the *phase*, not
/// from the synthetic node), the same `op` label, the same input and
/// observation fields. Fail-fast still holds — a failing step's entry is
/// the last one in the report and the engine stops — because the engine
/// stops on the first `Err` a resolver returns.
///
/// The difference from [`ProfileOp::run_lifecycle`] is **only how the
/// step is reached**: there a synchronous `Op::apply` hands
/// [`lifecycle::run_step`] to [`effects::block_on_effect`], here it is
/// awaited. Same function, same mode, same report writer
/// ([`record_lifecycle_step`]) — so the answer a step gives does not
/// depend on which driver is turning the engine.
async fn resolve_lifecycle_step(
    ctx: &ExecContext,
    node: NodeId,
) -> Result<ProfileValue, CallError> {
    let Some((phase_steps, step_ref, step)) = ctx.step_plan.locate(node) else {
        return Err(CallError(format!(
            "n{} is labelled '{LIFECYCLE_STEP_CALL_LABEL}' but the step plan does not \
             project it; the AST and the plan disagree",
            node.0
        )));
    };
    let phase = step_ref.phase;
    let Some(payload) = ctx.payloads.get(&phase) else {
        let err = ExecError::PayloadMissing(phase.0);
        record_phase_failure_report(ctx, phase, &err);
        return Err(CallError::from(&err));
    };

    // The gate and both policies run here, before the effect, over the
    // *whole* phase — see [`lifecycle_preflight`] for why every step
    // pays for every other step's denial. They report their own failure
    // at the phase node, so there is nothing to push here.
    let env = lifecycle_preflight(ctx, phase, payload, &phase_steps.steps)
        .map_err(|err| CallError::from(&err))?;

    let (base_id, kind) = report_base(ctx, phase);
    let sub_id = format!("{base_id}_{}", step_ref.index);
    let op = phase_steps.op;
    // Audit before the step runs (spec 09 §Audit log). Env keys go
    // through the redaction helper; the resolved values never reach the
    // event.
    audit_lifecycle_step(ctx.mode, &kind, step, &env);
    // No lock is held across this await: `record_line` / `push_report`
    // take their mutexes for the duration of one push, after the step
    // has finished.
    let run = lifecycle::run_step(step, op, &env, ctx.mode).await;
    let summary =
        record_lifecycle_step(ctx, sub_id, kind, step, run).map_err(|err| CallError::from(&err))?;
    Ok(record_line(ctx, format!("{op} {summary}")))
}

/// Report and render a routed phase whose payload is not the variant its
/// label names — an AST/host wiring bug rather than a profile-author
/// error, and the `Call`-route twin of [`ProfileOp::variant_fail`].
fn payload_variant_failure(
    ctx: &ExecContext,
    node: NodeId,
    op: &str,
    expected: &'static str,
) -> CallError {
    let err = ExecError::PayloadVariant {
        node: node.0,
        expected,
    };
    let (id, kind) = report_base(ctx, node);
    let mut entry = StepReport::new(id, kind, op);
    mark_report_failed(ctx, &mut entry, &err);
    push_report(ctx, entry);
    CallError::from(&err)
}

/// The `Call`-route twin of [`ProfileOp::run_transfer`]: gate → policy →
/// audit → effect, writing the same report entry either branch of the
/// `Op` route would.
async fn resolve_transfer(
    ctx: &ExecContext,
    node: NodeId,
    payload: &ProfileNode,
) -> Result<ProfileValue, CallError> {
    let ProfileNode::NetTransfer { src, dst, .. } = payload else {
        return Err(payload_variant_failure(
            ctx,
            node,
            TRANSFER_CALL_LABEL,
            "NetTransfer",
        ));
    };
    let (id, kind) = report_base(ctx, node);

    // The gate and both policies report their own denial (the entry the
    // `Op` route's `dispatch` would have written), so there is nothing
    // to push here.
    check_routed_demand(ctx, node, payload).map_err(|err| CallError::from(&err))?;

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

/// The `Call`-route twin of [`ProfileOp::run_http_get`]: gate → policy →
/// header resolution → audit → effect, writing the same report entry
/// either branch of the `Op` route would.
async fn resolve_http_get(
    ctx: &ExecContext,
    node: NodeId,
    payload: &ProfileNode,
) -> Result<ProfileValue, CallError> {
    let ProfileNode::NetHttpGet {
        url,
        headers,
        timeout_sec,
        ..
    } = payload
    else {
        return Err(payload_variant_failure(
            ctx,
            node,
            HTTP_GET_CALL_LABEL,
            "NetHttpGet",
        ));
    };
    let (id, kind) = report_base(ctx, node);

    check_routed_demand(ctx, node, payload).map_err(|err| CallError::from(&err))?;

    // Resolved in both modes, exactly as the op resolves it: a dry run
    // that passes proves the header plumbing (spec 06 §Resolution).
    let resolved_headers = match ctx.env_policy.resolve(headers) {
        Ok(resolved) => resolved,
        Err(err) => {
            push_http_failure_report(ctx, &id, &kind, "net.http_get", url, &err);
            return Err(CallError::from(&err));
        }
    };
    audit::http_get(ctx.mode, &kind, url, &resolved_headers);
    match ctx.mode {
        ExecMode::DryRun => {
            let value = record_line(
                ctx,
                format!(
                    "net_http_get url={url}{}",
                    render_http_request(&resolved_headers, *timeout_sec)
                ),
            );
            let mut entry = StepReport::new(id, kind, "net.http_get");
            entry.url = Some(url.clone());
            entry.dry_run = Some(true);
            push_report(ctx, entry);
            Ok(value)
        }
        ExecMode::Real => {
            let opts = effects::HttpOpts::new(resolved_headers, *timeout_sec);
            // No lock is held across this await (see
            // [`resolve_transfer`]'s note).
            let outcome = match effects::http_get(url, &opts).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    push_http_failure_report(ctx, &id, &kind, "net.http_get", url, &err);
                    return Err(CallError::from(&err));
                }
            };
            let value = record_line(
                ctx,
                format!("net_http_get url={url} status={}", outcome.status),
            );
            let mut entry = StepReport::new(id, kind, "net.http_get");
            entry.url = Some(url.clone());
            entry.status = i64::from(outcome.status);
            push_report(ctx, entry);
            Ok(value)
        }
    }
}

/// The `Call`-route twin of [`ProfileOp::run_http_post`]: gate → policy →
/// header + body resolution → audit → effect, writing the same report
/// entry either branch of the `Op` route would.
async fn resolve_http_post(
    ctx: &ExecContext,
    node: NodeId,
    payload: &ProfileNode,
) -> Result<ProfileValue, CallError> {
    let ProfileNode::NetHttpPost {
        url,
        headers,
        body,
        body_json,
        timeout_sec,
        ..
    } = payload
    else {
        return Err(payload_variant_failure(
            ctx,
            node,
            HTTP_POST_CALL_LABEL,
            "NetHttpPost",
        ));
    };
    let (id, kind) = report_base(ctx, node);

    check_routed_demand(ctx, node, payload).map_err(|err| CallError::from(&err))?;

    let resolved_headers = match ctx.env_policy.resolve(headers) {
        Ok(resolved) => resolved,
        Err(err) => {
            push_http_failure_report(ctx, &id, &kind, "net.http_post", url, &err);
            return Err(CallError::from(&err));
        }
    };
    let (body_bytes, content_type, body_source) =
        match resolve_post_body(ctx, body.as_deref(), body_json.as_ref()) {
            Ok(resolved) => resolved,
            Err(err) => {
                push_http_failure_report(ctx, &id, &kind, "net.http_post", url, &err);
                return Err(CallError::from(&err));
            }
        };
    audit::http_post(
        ctx.mode,
        &kind,
        url,
        &resolved_headers,
        &body_source,
        body_bytes.len() as u64,
    );
    match ctx.mode {
        ExecMode::DryRun => {
            let value = record_line(
                ctx,
                format!(
                    "net_http_post url={url}{} body={body_source} body_bytes={}",
                    render_http_request(&resolved_headers, *timeout_sec),
                    body_bytes.len(),
                ),
            );
            let mut entry = StepReport::new(id, kind, "net.http_post");
            entry.url = Some(url.clone());
            entry.dry_run = Some(true);
            push_report(ctx, entry);
            Ok(value)
        }
        ExecMode::Real => {
            let opts = effects::HttpOpts::new(resolved_headers, *timeout_sec);
            // No lock is held across this await (see
            // [`resolve_transfer`]'s note).
            let outcome = match effects::http_post(url, &body_bytes, &content_type, &opts).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    push_http_failure_report(ctx, &id, &kind, "net.http_post", url, &err);
                    return Err(CallError::from(&err));
                }
            };
            let value = record_line(
                ctx,
                format!("net_http_post url={url} status={}", outcome.status),
            );
            let mut entry = StepReport::new(id, kind, "net.http_post");
            entry.url = Some(url.clone());
            entry.status = i64::from(outcome.status);
            push_report(ctx, entry);
            Ok(value)
        }
    }
}

/// The `env.ref` gate, the L4 capability check and both L3 allowlists for
/// a routed phase — the same [`demand`] mapping, in the same order, and
/// writing the same failing report entry as the pre-handler block of
/// [`ProfileOp::dispatch`].
///
/// A `Call` bypasses `Op::apply` entirely, so a resolver that skipped
/// this would be a hole in the L3 / L4 enforcement (spec 05) that only
/// the new route has. One definition, so the two routes answer to
/// exactly the same declarations.
fn check_routed_demand(
    ctx: &ExecContext,
    node: NodeId,
    payload: &ProfileNode,
) -> Result<(), ExecError> {
    if let Some(capability) = demand::env_ref(payload) {
        if let Err(err) = ctx.gate.require(capability) {
            record_phase_failure_report(ctx, node, &err);
            return Err(err);
        }
    }
    let demanded = match demand::direct(payload) {
        Ok(demanded) => demanded,
        Err(err) => {
            push_policy_failure_report(ctx, node, payload, &err);
            return Err(err);
        }
    };
    if let Some(capability) = demanded.capability {
        if let Err(err) = ctx.gate.require(capability) {
            record_phase_failure_report(ctx, node, &err);
            return Err(err);
        }
    }
    // Policy runs in both modes (spec 07 "dry-run does policy").
    for path in &demanded.paths {
        if let Err(err) = ctx.path_policy.check(path) {
            push_policy_failure_report(ctx, node, payload, &err);
            return Err(err);
        }
    }
    for url in &demanded.urls {
        if let Err(err) = ctx.http_policy.check(url) {
            push_policy_failure_report(ctx, node, payload, &err);
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    /// Which phases the host can route, pinned directly.
    ///
    /// The end-to-end "both routes agree" regressions
    /// (`tests/ast_apply.rs`) compare two reports, and two reports agree
    /// vacuously when the `Call` route was never taken — a phase this
    /// function forgot would make them green while proving nothing. So
    /// the reclassification itself is asserted here, at the one place
    /// that decides it.
    #[test]
    fn the_three_single_effect_phases_are_the_routable_ones() {
        let ids = IdGen::new();
        let label = |node: &ProfileNode| match call_kind(node) {
            Some(NodeKind::Call { label, .. }) => Some(label),
            _ => None,
        };

        assert_eq!(
            label(&ProfileNode::NetTransfer {
                id: ids.node(),
                src: "https://example.com/a.bin".into(),
                dst: "/workspace/a.bin".into(),
            })
            .as_deref(),
            Some(TRANSFER_CALL_LABEL)
        );
        assert_eq!(
            label(&ProfileNode::NetHttpGet {
                id: ids.node(),
                url: "https://example.com/ping".into(),
                headers: Default::default(),
                timeout_sec: None,
            })
            .as_deref(),
            Some(HTTP_GET_CALL_LABEL)
        );
        assert_eq!(
            label(&ProfileNode::NetHttpPost {
                id: ids.node(),
                url: "https://example.com/echo".into(),
                headers: Default::default(),
                body: None,
                body_json: None,
                timeout_sec: None,
            })
            .as_deref(),
            Some(HTTP_POST_CALL_LABEL)
        );

        // A lifecycle phase and a non-network direct op stay on their op.
        assert!(call_kind(&ProfileNode::SystemApt {
            id: ids.node(),
            packages: vec!["git".into()],
        })
        .is_none());
        assert!(call_kind(&ProfileNode::ShExec {
            id: ids.node(),
            argv: vec!["true".into()],
            env: Default::default(),
        })
        .is_none());
    }

    /// …and the reclassification reaches the AST the engine reads: the
    /// same node is an `Apply` on the `Op` route and a `Call` on the
    /// `Call` route.
    #[test]
    fn the_route_decides_the_node_kind_the_engine_sees() {
        let ids = IdGen::new();
        let phase_ids = [ids.node(), ids.node(), ids.node()];
        let root = ProfileNode::Spec {
            id: ids.node(),
            name: "routing".into(),
            version: None,
            description: None,
            capabilities: vec![
                "net.transfer".into(),
                "net.http_get".into(),
                "net.http_post".into(),
            ],
            env: Default::default(),
            env_secrets: Vec::new(),
            paths: vec!["/workspace".into()],
            http_allowlist: vec!["https://example.com".into()],
            phases: vec![
                ProfileNode::NetTransfer {
                    id: phase_ids[0],
                    src: "https://example.com/a.bin".into(),
                    dst: "/workspace/a.bin".into(),
                },
                ProfileNode::NetHttpGet {
                    id: phase_ids[1],
                    url: "https://example.com/ping".into(),
                    headers: Default::default(),
                    timeout_sec: None,
                },
                ProfileNode::NetHttpPost {
                    id: phase_ids[2],
                    url: "https://example.com/echo".into(),
                    headers: Default::default(),
                    body: None,
                    body_json: None,
                    timeout_sec: None,
                },
            ],
        };

        // No lifecycle phase here, so the plan projects nothing and the
        // routing under test is the network phases' alone.
        let plan = crate::exec::steps::StepPlan::build(&root);
        let on_op = ProfileCallAst::new(&root, EffectRoute::Op, &plan);
        let on_call = ProfileCallAst::new(&root, EffectRoute::Call, &plan);
        let expected = [
            TRANSFER_CALL_LABEL,
            HTTP_GET_CALL_LABEL,
            HTTP_POST_CALL_LABEL,
        ];
        for (id, expected) in phase_ids.into_iter().zip(expected) {
            assert!(
                !matches!(on_op.node_kind(id), NodeKind::Call { .. }),
                "n{}: the op route leaves the derived classification alone",
                id.0
            );
            match on_call.node_kind(id) {
                NodeKind::Call { label, .. } => assert_eq!(label, expected, "n{}", id.0),
                other => panic!("n{}: expected a Call, got {other:?}", id.0),
            }
        }
    }
}
