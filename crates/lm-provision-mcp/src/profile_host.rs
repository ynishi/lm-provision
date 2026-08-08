//! `DslHost` adapter for `lm-provision`'s `ProfileNode` DSL.

use dsl_kit::{BreakpointSet, DslNode, Engine, IdGen, Pending, StepOutcome, Stepper};
use dsl_kit_mcp::host::{
    DslHost, EventCounts, HostLocation, HostOutcome, HostSnapshot, PendingProjection,
};
use dsl_kit_mcp::resources::ResourceEntry;
use lm_provision::exec::ExecMode;
use lm_provision::profile_ast::{create_profile_engine, ProfileAst, ProfileNode, ProfileValue};
use std::sync::Arc;

/// `DslHost` adapter for profile AST execution and MCP debugging.
///
/// The engine runs over [`ProfileAst`] (`OwnedDerivedAst`), so the host
/// owns program and engine together without `Box::leak`.
pub struct ProfileHost {
    program: ProfileNode,
    executed_log: Arc<std::sync::Mutex<Vec<String>>>,
    engine: Engine<ProfileAst>,
}

impl ProfileHost {
    /// Builds a host around a given `ProfileNode` AST.
    ///
    /// The program is normalized first, so stepping through it in the
    /// debugger walks the same phases, in the same order, that `apply`
    /// runs and the plan artifact renders
    /// (`lm_provision::normalize`).
    pub fn new(program: ProfileNode) -> Self {
        let program = lm_provision::normalize::normalize(&program);
        let executed_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&executed_log))
            .expect("profile engine construction should succeed");
        Self {
            program,
            executed_log,
            engine,
        }
    }

    /// Creates a host loaded with a default demo profile.
    pub fn new_demo() -> Self {
        let id_gen = IdGen::new();
        let program = ProfileNode::Spec {
            id: id_gen.node(),
            name: "demo-comfyui-vllm-pod".to_string(),
            version: Some("0.0.0".to_string()),
            description: None,
            capabilities: vec!["sh.exec".to_string(), "net.transfer".to_string()],
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            // The demo profile only wires lifecycle ops (SystemApt /
            // PythonDeps / PostInstall). Lifecycle ops do not run
            // through the direct-op path / URL policy check, so leaving
            // both allowlists empty preserves the dry-run trace shape.
            paths: Vec::new(),
            http_allowlist: Vec::new(),
            phases: vec![
                ProfileNode::SystemApt {
                    id: id_gen.node(),
                    packages: vec!["git".to_string(), "curl".to_string()],
                },
                ProfileNode::PythonDeps {
                    id: id_gen.node(),
                    deps: vec!["torch".to_string(), "vllm".to_string()],
                    in_comfy_venv: false,
                },
                ProfileNode::PostInstall {
                    id: id_gen.node(),
                    script: "echo 'Provisioning complete'".to_string(),
                },
            ],
        };
        Self::new(program)
    }
}

fn pending_to_location(ctx: &dsl_kit::NodeContext) -> HostLocation {
    HostLocation {
        node: ctx.node.0,
        path: ctx.path.0.iter().map(|n| n.0).collect(),
        depth: ctx.depth,
        frame: ctx.frame.map(|f| f.0),
        iteration: ctx.iteration.map(|i| i.0),
    }
}

fn step_outcome_to_host(outcome: StepOutcome<ProfileValue>, pending: &[Pending]) -> HostOutcome {
    match outcome {
        StepOutcome::Done(_) => HostOutcome::Done,
        StepOutcome::Ready => HostOutcome::Advanced,
        StepOutcome::Blocked { newly_pending } => {
            let reference = newly_pending.first().or_else(|| pending.first());
            match reference {
                Some(p) => HostOutcome::Suspended {
                    reason: p.reason.to_string(),
                    at: pending_to_location(&p.at),
                },
                None => HostOutcome::Suspended {
                    reason: "waiting".into(),
                    at: HostLocation {
                        node: 0,
                        path: Vec::new(),
                        depth: 0,
                        frame: None,
                        iteration: None,
                    },
                },
            }
        }
    }
}

use async_trait::async_trait;

#[async_trait]
impl DslHost for ProfileHost {
    fn dsl_name(&self) -> &str {
        "lm-provision"
    }

    fn root_node_id(&self) -> u64 {
        self.program.node_id().0
    }

    fn supports_calls(&self) -> bool {
        false
    }

    fn root_summary(&self) -> String {
        match &self.program {
            ProfileNode::Spec { name, .. } => format!("Profile Spec ({name})"),
            _ => "Profile Node".to_string(),
        }
    }

    fn ast_size(&self) -> usize {
        1 + match &self.program {
            ProfileNode::Spec { phases, .. } => phases.len(),
            _ => 0,
        }
    }

    fn ast_pretty(&self) -> String {
        format!("{:#?}", self.program)
    }

    fn snapshot(&self) -> HostSnapshot {
        let counts = self.engine.events();
        let executed = self.executed_log.lock().unwrap();
        let results = executed
            .iter()
            .enumerate()
            .map(|(idx, name)| (idx as u64, name.clone()))
            .collect();

        // `PendingProjection::of` rather than a hand-rolled match: the
        // reason vocabulary and the payload pass-through then stay
        // identical across every DSL
        // (`dsl-kit-mcp-0.11.0/src/host.rs:132-137`). Building the
        // struct by hand is what let this host answer `"unknown"` to a
        // `SuspendReason::User { tag }` the upstream projection names,
        // and what dropped the effect payload the engine now carries.
        let pending: Vec<PendingProjection> = self
            .engine
            .pending()
            .iter()
            .map(PendingProjection::of)
            .collect();

        HostSnapshot {
            depth: self.engine.depth(),
            current_path: self
                .engine
                .current_path()
                .map(|p| p.0.iter().map(|n| n.0).collect()),
            suspended_call: None,
            pending,
            results,
            events: EventCounts {
                visit_pre: counts.visit_pre,
                visit_post: counts.visit_post,
                frame_enter: counts.frame_enter,
                frame_leave: counts.frame_leave,
                iteration_tick: counts.iteration_tick,
                suspend: counts.suspend,
                resume: counts.resume,
            },
        }
    }

    async fn step_one(&mut self, breakpoints: &BreakpointSet) -> Result<HostOutcome, String> {
        let outcome = self
            .engine
            .step_with_breakpoints(breakpoints)
            .map_err(|e| e.to_string())?;
        Ok(step_outcome_to_host(outcome, self.engine.pending()))
    }

    async fn step_to_yield(&mut self, breakpoints: &BreakpointSet) -> Result<HostOutcome, String> {
        let outcome = self
            .engine
            .run_to_yield_with_breakpoints(breakpoints)
            .map_err(|e| e.to_string())?;
        Ok(step_outcome_to_host(outcome, self.engine.pending()))
    }

    fn reset(&mut self) {
        self.executed_log.lock().unwrap().clear();
        self.engine = create_profile_engine(
            &self.program,
            ExecMode::DryRun,
            Arc::clone(&self.executed_log),
        )
        .expect("profile engine reconstruction should succeed");
    }

    fn resources(&self) -> Vec<ResourceEntry> {
        vec![ResourceEntry::static_markdown(
            "dsl-kit://dsl/lm-provision/profile",
            "lm-provision Profile DSL",
            "Universal GPU/LLM infrastructure profile DSL based on dsl-kit.",
            "# lm-provision Profile DSL\nDefined via dsl-kit AST ProfileNode.",
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit_mcp::DslMcpHandler;

    #[tokio::test]
    async fn test_profile_host_mcp_handler_integration() {
        let host = ProfileHost::new_demo();
        let _handler = DslMcpHandler::new(Box::new(host));
    }
}
