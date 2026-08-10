//! The step-level projection of a lifecycle phase.
//!
//! A lifecycle phase is one AST node that stands for a *list* of things
//! to do ([`lifecycle::expand`]). Until this module existed that list
//! lived entirely inside one `Op::apply` call: the engine saw a single
//! `Apply`, and the loop over the steps ran below it, on the synchronous
//! seam. This module turns the list into engine nodes instead — one
//! `Call` per step — so the engine stops **at every step** and the host
//! resolves each one by `await`.
//!
//! ## Why per step, and not per phase
//!
//! A whole phase behind one `Call` would move the `block_on` into the
//! resolver and leave the engine's granularity exactly where it was. Per
//! step, the engine's own report / resume / breakpoint surface becomes
//! step-shaped, and a later stage can hand the same child list to a
//! `Par` instead of a `Seq` without touching anything here (the children
//! are already independent node ids; only the parent kind would change).
//!
//! ## When the expansion happens — and where its failure lands
//!
//! [`StepPlan::build`] runs every lifecycle phase's expansion **once, at
//! engine-construction time**, before the engine takes a step. That is a
//! move forward in time: the expansion used to run inside `Op::apply`.
//!
//! Expansion is a pure function of the payload — a malformed
//! `models_json`, a `models` entry naming neither `dst` nor `name`, an
//! `hf://` URI with no file path. It cannot fail for a reason the host
//! supplies, so there is nothing to be gained by asking later, and two
//! things to be lost:
//!
//! - **Deferring to suspend time is strictly worse.** The node list has
//!   to exist before the first step can suspend, so a per-step decode
//!   would only discover the third item's error after the first two had
//!   already transferred — a payload that was never valid would have
//!   half-run.
//! - **Validate cannot be the only place.** `apply` deliberately does
//!   not run validate first (spec 07 §Invocation), so a check that lives
//!   only there does not protect a run.
//!
//! So the decision is taken here, and the **report** stays exactly where
//! it was: a phase whose expansion failed is *not* projected, keeps its
//! `Apply` node, and reaches
//! [`ProfileOp::run_lifecycle`](super::registry) — which resolves the
//! phase env and re-runs the expansion, writing the same phase-level
//! failure entry, in the same position, with the same message it wrote
//! before this module existed. Nothing about that surface moved; only
//! the moment the answer is known did.

use std::collections::HashMap;

use dsl_kit::{DslNode, NodeId, Walk};

use super::lifecycle::{self, PlannedStep};
use crate::profile_ast::ProfileNode;
use crate::resource::ResourceEnv;

/// The registry op name a lifecycle phase dispatches to, or `None` for
/// any other node.
///
/// This is the crate's one answer to "is this node one of the fifteen",
/// and it is spelled as the *op name* rather than a boolean because the
/// name is also what a step's failure is labelled with
/// ([`lifecycle::execute_step`]'s `op` argument). Deriving it from
/// [`crate::plan::kind_of`] would not work: `hooks.post_install` is the
/// catalog kind of the op registered as `post_install`.
///
/// A test in this module pins the image of this function against
/// [`super::registry`]'s `LIFECYCLE_OPS`, so the two lists cannot drift.
pub(crate) fn lifecycle_op_name(node: &ProfileNode) -> Option<&'static str> {
    let name = match node {
        ProfileNode::SystemApt { .. } => "system_apt",
        ProfileNode::ComfyUiInstall { .. } => "comfyui_install",
        ProfileNode::PythonVersionCheck { .. } => "python_version_check",
        ProfileNode::PythonDeps { .. } => "python_deps",
        ProfileNode::CustomNodes { .. } => "custom_nodes",
        ProfileNode::SyncPull { .. } => "sync_pull",
        ProfileNode::SyncPush { .. } => "sync_push",
        ProfileNode::StagingPush { .. } => "staging_push",
        ProfileNode::Models { .. } => "models",
        ProfileNode::LlmModels { .. } => "llm_models",
        ProfileNode::PostInstall { .. } => "post_install",
        ProfileNode::ComfyUiRestart { .. } => "comfyui_restart",
        ProfileNode::ComfyUiHealth { .. } => "comfyui_health",
        ProfileNode::ServiceStart { .. } => "service_start",
        ProfileNode::ServiceReady { .. } => "service_ready",
        _ => return None,
    };
    Some(name)
}

/// One lifecycle phase's expansion, with an engine node id per step.
#[derive(Debug)]
pub struct PhaseSteps {
    /// The registry op name the phase dispatches to.
    pub op: &'static str,
    /// The expanded steps, in the order [`lifecycle::expand`] composed
    /// them. **Never reordered**: the report id of a step is its
    /// position here, and the phase is still executed in sequence.
    pub steps: Vec<PlannedStep>,
    /// The synthetic node ids, one per entry of [`steps`](Self::steps)
    /// and in the same order.
    pub nodes: Vec<NodeId>,
}

/// Where a projected step sits: which phase composed it, and its
/// position within that phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepRef {
    /// The phase node that composed the step. Everything a resolver
    /// needs beyond the step itself — the payload, the report id, the
    /// declared `env` — is reached through this, not through the
    /// synthetic node.
    pub phase: NodeId,
    /// 1-based position within the phase, which is exactly how the
    /// report id spells it (`<phase_index>_<kind>_<n>`).
    pub index: usize,
}

/// Every lifecycle phase's steps, projected onto engine node ids.
///
/// Built once per run and shared (behind an `Arc`) by the two readers
/// that must agree on the *same* synthetic ids: the AST projection,
/// which declares the nodes, and the effect resolver, which is handed
/// one of them back and has to find the step it stands for.
#[derive(Debug, Default)]
pub struct StepPlan {
    phases: HashMap<NodeId, PhaseSteps>,
    steps: HashMap<NodeId, StepRef>,
    /// The resources in scope at each phase, recorded by the same walk
    /// that expanded it.
    ///
    /// Kept so that the op handler can re-expand a phase against the
    /// environment it was *composed* against. Re-deriving it there would
    /// mean a second fold over the phase list, and two folds are two
    /// chances to disagree about what "earlier" means.
    envs: HashMap<NodeId, ResourceEnv>,
}

impl StepPlan {
    /// Expand every lifecycle phase under `root` and allocate a node id
    /// per composed step.
    ///
    /// Two shapes are deliberately **left unprojected**, and both keep
    /// the phase on its own op (see the module doc):
    ///
    /// - an expansion that failed — the phase's op re-runs it and
    ///   reports the failure exactly where it always did;
    /// - an expansion that composed **no** steps (an empty `models` /
    ///   `custom_nodes` list) — an empty `Seq` is a node shape with
    ///   nothing to say, and the op's existing "ran nothing" line is
    ///   already the honest report.
    ///
    /// Synthetic ids start above every id in the tree, so they collide
    /// with no real node, and are handed out in declaration order, so a
    /// given profile always projects onto the same ids.
    pub fn build(root: &ProfileNode) -> Self {
        let mut plan = StepPlan::default();
        let ProfileNode::Spec {
            phases, assumes, ..
        } = root
        else {
            return plan;
        };
        let mut next = max_node_id(root) + 1;
        // The scope fold (design §3.6). This walk *is* the scope check's
        // walk: phases in canonical order, each composing against what
        // earlier phases produced, then folding in its own `produces`.
        // A phase whose `requires` nothing bound fails to expand and so
        // stays on its own op, where the error is reported — the same
        // route an unparseable payload takes.
        let mut env = ResourceEnv::from_assumes(assumes);
        for phase in phases {
            let expanded = lifecycle::expand(phase, &env);
            plan.envs.insert(phase.node_id(), env.clone());
            env.bind(phase);
            let Some(op) = lifecycle_op_name(phase) else {
                continue;
            };
            let Ok(steps) = expanded else {
                continue;
            };
            if steps.is_empty() {
                continue;
            }
            let phase_id = phase.node_id();
            let mut nodes = Vec::with_capacity(steps.len());
            for offset in 0..steps.len() {
                let id = NodeId(next);
                next += 1;
                nodes.push(id);
                plan.steps.insert(
                    id,
                    StepRef {
                        phase: phase_id,
                        index: offset + 1,
                    },
                );
            }
            plan.phases
                .insert(phase_id, PhaseSteps { op, steps, nodes });
        }
        plan
    }

    /// The steps a phase was projected into, or `None` for a phase that
    /// stayed on its op.
    pub fn phase(&self, phase: NodeId) -> Option<&PhaseSteps> {
        self.phases.get(&phase)
    }

    /// The resources in scope at `phase`, as the build walk saw them.
    ///
    /// An empty environment for a phase the walk never reached, which is
    /// the honest answer: nothing was bound, so a phase requiring
    /// anything fails to expand and says which resource was missing.
    pub fn env_at(&self, phase: NodeId) -> ResourceEnv {
        self.envs.get(&phase).cloned().unwrap_or_default()
    }

    /// Every projected phase, for the AST projection to declare.
    pub fn projected_phases(&self) -> impl Iterator<Item = (NodeId, &PhaseSteps)> {
        self.phases.iter().map(|(id, steps)| (*id, steps))
    }

    /// Resolve a synthetic node id back to the phase it belongs to, its
    /// position, and the step itself.
    ///
    /// `None` for any node that is not one of the ids
    /// [`build`](Self::build) handed out — which is what lets a resolver
    /// fail loudly on a suspension it was not meant to answer rather
    /// than guessing at a step.
    pub fn locate(&self, node: NodeId) -> Option<(&PhaseSteps, StepRef, &PlannedStep)> {
        let step_ref = *self.steps.get(&node)?;
        let phase = self.phases.get(&step_ref.phase)?;
        let step = phase.steps.get(step_ref.index - 1)?;
        Some((phase, step_ref, step))
    }
}

/// The largest node id in the tree, so synthetic ids can start above it.
fn max_node_id(node: &ProfileNode) -> u64 {
    let mut max = node.node_id().0;
    for child in node.children() {
        max = max.max(max_node_id(child));
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    /// Every fixture here declares the ComfyUI root as already present.
    /// These tests are about projection — how many nodes a phase becomes
    /// and where their ids start — so a `models` phase has to be able to
    /// compose steps at all, and an install phase would add its own.
    fn spec(phases: Vec<ProfileNode>, ids: &IdGen) -> ProfileNode {
        ProfileNode::Spec {
            assumes: std::collections::BTreeMap::from([(
                crate::resource::Resource::ComfyUiRoot.as_str().to_string(),
                crate::resource::COMFYUI_ROOT_DEFAULT.to_string(),
            )]),
            id: ids.node(),
            name: "step-plan".to_string(),
            version: None,
            description: None,
            capabilities: vec!["net.transfer".to_string(), "sh.exec".to_string()],
            env: Default::default(),
            env_secrets: Vec::new(),
            paths: Vec::new(),
            http_allowlist: Vec::new(),
            phases,
        }
    }

    /// The 15 op names this module answers with are exactly the 15 the
    /// registry registers. The two lists are written out separately —
    /// one maps a variant to a name, the other names what is wired onto
    /// the engine — so nothing but a test stops them drifting.
    #[test]
    fn the_projected_op_names_are_the_registrys_lifecycle_ops() {
        let ids = IdGen::new();
        let phases = vec![
            ProfileNode::SystemApt {
                id: ids.node(),
                packages: vec!["git".into()],
            },
            ProfileNode::Models {
                id: ids.node(),
                models_json: "[]".into(),
            },
            ProfileNode::PostInstall {
                id: ids.node(),
                script: "true".into(),
            },
        ];
        for phase in &phases {
            let name = lifecycle_op_name(phase).expect("a lifecycle phase names its op");
            assert!(
                super::super::registry::LIFECYCLE_OPS.contains(&name),
                "{name} is not registered as a lifecycle op",
            );
        }
        // …and a direct op is not one of them.
        assert_eq!(
            lifecycle_op_name(&ProfileNode::ShExec {
                id: ids.node(),
                argv: vec!["true".into()],
                env: Default::default(),
            }),
            None
        );
    }

    /// A `models` phase with two entries projects onto two nodes, in
    /// order, above every real id — the shape the engine walks.
    #[test]
    fn a_phase_projects_one_node_per_step_above_every_real_id() {
        let ids = IdGen::new();
        let models = ProfileNode::Models {
            id: ids.node(),
            models_json: r#"[{"src":"https://e/a.bin","dst":"a.bin"},
                             {"src":"https://e/b.bin","dst":"b.bin"}]"#
                .into(),
        };
        let phase_id = models.node_id();
        let root = spec(vec![models], &ids);
        let ceiling = max_node_id(&root);

        let plan = StepPlan::build(&root);
        let phase = plan.phase(phase_id).expect("the phase is projected");
        assert_eq!(phase.op, "models");
        assert_eq!(phase.steps.len(), 2);
        assert_eq!(phase.nodes.len(), 2);
        for (offset, node) in phase.nodes.iter().enumerate() {
            assert!(node.0 > ceiling, "n{} collides with the tree", node.0);
            let (_, step_ref, step) = plan.locate(*node).expect("the node resolves to its step");
            assert_eq!(step_ref.phase, phase_id);
            assert_eq!(step_ref.index, offset + 1);
            assert_eq!(step, &phase.steps[offset]);
        }
    }

    /// A payload the expansion rejects is left on its op, which is what
    /// keeps the failure landing where it always did.
    #[test]
    fn an_expansion_failure_leaves_the_phase_on_its_op() {
        let ids = IdGen::new();
        let models = ProfileNode::Models {
            id: ids.node(),
            models_json: "not json at all".into(),
        };
        let phase_id = models.node_id();
        let plan = StepPlan::build(&spec(vec![models], &ids));
        assert!(plan.phase(phase_id).is_none());
        assert_eq!(plan.projected_phases().count(), 0);
    }

    /// So is an expansion that composed nothing: an empty `Seq` would be
    /// a node that says nothing, and the op already reports "ran
    /// nothing" honestly.
    #[test]
    fn an_empty_expansion_leaves_the_phase_on_its_op() {
        let ids = IdGen::new();
        let models = ProfileNode::Models {
            id: ids.node(),
            models_json: "[]".into(),
        };
        let phase_id = models.node_id();
        let plan = StepPlan::build(&spec(vec![models], &ids));
        assert!(plan.phase(phase_id).is_none());
    }

    /// A node the plan never handed out does not resolve — a resolver
    /// handed a foreign suspension has to be able to say so rather than
    /// pick a step.
    #[test]
    fn a_foreign_node_does_not_resolve_to_a_step() {
        let ids = IdGen::new();
        let apt = ProfileNode::SystemApt {
            id: ids.node(),
            packages: vec!["git".into()],
        };
        let phase_id = apt.node_id();
        let plan = StepPlan::build(&spec(vec![apt], &ids));
        assert!(plan.locate(phase_id).is_none());
        assert!(plan.locate(NodeId(u64::MAX)).is_none());
    }
}
