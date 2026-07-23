//! `DslHost` adapter for `lm-provision`'s `ProfileNode` DSL.

use std::sync::Arc;
use dsl_kit::{BreakpointSet, DslNode, Engine, IdGen, Pending, StepOutcome, Stepper};
use dsl_kit_mcp::host::{
    DslHost, EventCounts, HostLocation, HostOutcome, HostSnapshot, PendingProjection, ResolvedCall,
};
use dsl_kit_mcp::resources::ResourceEntry;
use lm_provision::dsl_poc::{
    ProfileNode, ProfileSemantics, ProfileValue, create_profile_engine,
};

/// `DslHost` adapter for profile AST execution and MCP debugging.
///
/// KNOWN LIMITATION: the AST is leaked exactly once per host (`Box::leak`)
/// to satisfy the engine's `'static` borrow; `reset` reuses the same leaked
/// reference, so repeated resets do not accumulate memory.
pub struct ProfileHost {
    program: &'static ProfileNode,
    executed_log: Arc<std::sync::Mutex<Vec<String>>>,
    engine: Engine<dsl_kit::DerivedAst<'static, ProfileNode, ProfileSemantics>>,
}

impl ProfileHost {
    /// Builds a host around a given `ProfileNode` AST.
    pub fn new(program: ProfileNode) -> Self {
        let executed_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        // Leak once to provide the 'static reference the Engine requires.
        let program: &'static ProfileNode = Box::leak(Box::new(program));
        let engine = create_profile_engine(program, Arc::clone(&executed_log));
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
            env: Vec::new(),
            env_secrets: Vec::new(),
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

fn step_outcome_to_host(
    outcome: StepOutcome<ProfileValue>,
    pending: &[Pending],
) -> HostOutcome {
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

    fn root_summary(&self) -> String {
        match self.program {
            ProfileNode::Spec { name, .. } => format!("Profile Spec ({name})"),
            _ => "Profile Node".to_string(),
        }
    }

    fn ast_size(&self) -> usize {
        1 + match self.program {
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

        let pending: Vec<PendingProjection> = self
            .engine
            .pending()
            .iter()
            .map(|p| {
                let (reason, label) = match &p.reason {
                    dsl_kit::SuspendReason::Call { spec } => {
                        ("call".to_string(), spec.label.clone())
                    }
                    dsl_kit::SuspendReason::Breakpoint => ("breakpoint".into(), String::new()),
                    dsl_kit::SuspendReason::Cooperative => ("cooperative".into(), String::new()),
                    _ => ("unknown".into(), String::new()),
                };
                PendingProjection {
                    id: p.id.0,
                    reason,
                    label,
                    at: pending_to_location(&p.at),
                }
            })
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

    async fn step_to_done(&mut self, breakpoints: &BreakpointSet) -> Result<HostOutcome, String> {
        let mut steps = 0;
        loop {
            let outcome = self
                .engine
                .run_to_yield_with_breakpoints(breakpoints)
                .map_err(|e| e.to_string())?;
            if matches!(outcome, StepOutcome::Done(_)) {
                return Ok(HostOutcome::Done);
            }
            steps += 1;
            if steps > 1000 {
                return Err("exceeded step limit".to_string());
            }
        }
    }

    async fn resolve(&mut self, _result: Option<String>) -> Result<ResolvedCall, String> {
        Err("resolve not implemented for static provision host".to_string())
    }

    fn reset(&mut self) {
        self.executed_log.lock().unwrap().clear();
        self.engine = create_profile_engine(self.program, Arc::clone(&self.executed_log));
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
