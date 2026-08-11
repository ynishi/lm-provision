//! Derive what a profile will demand of its declared lists, so validate
//! can assert `declared ⊇ derived` (spec 00 §Capability derivation).
//!
//! The declared `capabilities` / `paths` / `http_allowlist` fields are
//! assertions, not free-form declarations: the profile states what it
//! will need, and the compiler checks that statement against what the
//! run actually reaches. Without the check the fields only bite at the
//! L4 entry gate during apply — on the pod, half-provisioned — where a
//! missing entry reads as a mid-run failure rather than as the
//! precondition error it is.
//!
//! **The walk runs over the normalized AST**, not the phases as
//! written. Implicit insertion happens before execution
//! ([`crate::normalize`]): a `comfyui.install` gains a restart and a
//! health poll, and deriving from the authored list would miss the
//! poll's `net.http_get` and the paths those steps touch — exactly the
//! entries an author is least likely to have declared, because they
//! never wrote the step.
//!
//! What each unit demands comes from [`crate::exec::demand`], the same
//! mapping the execution gates read. That sharing is the point: a
//! derivation with its own copy of the catalog would assert something
//! about a run other than the one that will happen, and the drift would
//! surface only as a profile that passed validate and then failed the
//! entry check.
//!
//! Not derived here: `env` / `env_secrets`. A phase's references into
//! them are cross-checked by name in [`crate::validate`] check 4b / 6,
//! which is the same assertion in the shape that slot takes.

use std::collections::BTreeSet;

use crate::exec::{demand, lifecycle};
use crate::profile_ast::ProfileNode;

/// What a profile's phases will demand of its declared lists.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Derived {
    /// Capabilities the L4 entry check will require, deduplicated and
    /// ordered for a deterministic first violation.
    pub capabilities: BTreeSet<&'static str>,
    /// Local paths the L3 path policy will check, in walk order.
    pub paths: Vec<String>,
    /// Remote URLs the L3 http allowlist will check, already resolved,
    /// in walk order.
    pub urls: Vec<String>,
}

/// Derive the demand of `root`, which must already be normalized
/// ([`crate::normalize::normalize`]).
///
/// A phase whose expansion fails contributes nothing: it cannot run at
/// all, so it has no demand to assert, and the expansion error is the
/// apply-stage failure that names it. Reporting it here as a missing
/// capability would name the wrong problem.
pub fn derive(root: &ProfileNode) -> Derived {
    let ProfileNode::Spec {
        phases, assumes, ..
    } = root
    else {
        return Derived::default();
    };

    let mut derived = Derived::default();
    // The same scope fold `crate::exec::steps` runs, for the same
    // reason: what paths a phase touches depends on the root bound at
    // it, so a profile that installs ComfyUI somewhere else derives
    // paths under *that* root and must declare it.
    let mut env = crate::resource::ResourceEnv::from_assumes(assumes);
    for phase in phases {
        if let Some(capability) = demand::env_ref(phase) {
            derived.capabilities.insert(capability);
        }
        let expanded = lifecycle::expand(phase, &env);
        env.bind(phase);
        match expanded {
            // A lifecycle phase: its demand is the union of its
            // expanded steps' (the routes are decided by the payload,
            // so they are known statically).
            Ok(steps) => {
                for planned in &steps {
                    // The demand is the *effect's*; a step's condition
                    // adds none (see `demand::step`).
                    if let Ok(demanded) = demand::step(&planned.step) {
                        derived.absorb(demanded);
                    }
                }
            }
            // Not a lifecycle payload — a direct op, whose demand is
            // fixed by its own payload.
            Err(_) => {
                if let Ok(demanded) = demand::direct(phase) {
                    derived.absorb(demanded);
                }
            }
        }
    }
    derived
}

impl Derived {
    fn absorb(&mut self, demanded: demand::Demand) {
        if let Some(capability) = demanded.capability {
            self.capabilities.insert(capability);
        }
        self.paths.extend(demanded.paths);
        self.urls.extend(demanded.urls);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::normalize;
    use dsl_kit::IdGen;

    fn spec(phases: Vec<ProfileNode>) -> ProfileNode {
        let ids = IdGen::new();
        ProfileNode::Spec {
            assumes: Default::default(),
            id: ids.node(),
            name: "demo".into(),
            version: None,
            description: None,
            capabilities: Vec::new(),
            env: Default::default(),
            env_secrets: Vec::new(),
            paths: Vec::new(),
            http_allowlist: Vec::new(),
            phases,
        }
    }

    fn derive_normalized(phases: Vec<ProfileNode>) -> Derived {
        derive(&normalize(&spec(phases)))
    }

    /// The same, for phases that consume ComfyUI without the fixture
    /// carrying a `comfyui.install`. Declaring the root as already
    /// present is what a profile provisioning into a prepared pod
    /// writes; adding an install phase instead would drag its own
    /// derived paths — and the implicitly inserted restart and health
    /// poll — into assertions that are about one phase.
    fn derive_normalized_assuming_comfyui(phases: Vec<ProfileNode>) -> Derived {
        let mut root = spec(phases);
        if let ProfileNode::Spec { assumes, .. } = &mut root {
            assumes.insert(
                crate::resource::Resource::ComfyUiRoot.as_str().to_string(),
                crate::resource::COMFYUI_ROOT_DEFAULT.to_string(),
            );
        }
        derive(&normalize(&root))
    }

    /// The inserted health poll is the case the walk exists for: an
    /// author who wrote only `comfyui.install` never wrote the GET, so
    /// deriving from the authored list would miss `net.http_get`.
    #[test]
    fn an_implicit_health_poll_contributes_its_capability() {
        let ids = IdGen::new();
        let derived = derive_normalized(vec![ProfileNode::ComfyUiInstall {
            install_dir: None,
            id: ids.node(),
            ref_name: "master".into(),
            repo: None,
        }]);
        assert!(derived.capabilities.contains("sh.exec"), "{derived:?}");
        assert!(derived.capabilities.contains("net.http_get"), "{derived:?}");
        assert!(
            derived
                .urls
                .iter()
                .any(|url| url.contains("/object_info") && url.contains("8188")),
            "the inserted poll's URL must be derived: {derived:?}"
        );
    }

    #[test]
    fn a_public_pull_derives_its_destination_and_resolved_host() {
        let ids = IdGen::new();
        let derived = derive_normalized(vec![ProfileNode::SyncPull {
            id: ids.node(),
            src: "hf://owner/repo/model.bin".into(),
            dst: "/workspace/model.bin".into(),
            env: Default::default(),
            revision: None,
        }]);
        assert!(derived.capabilities.contains("net.transfer"));
        assert_eq!(derived.paths, vec!["/workspace/model.bin".to_string()]);
        assert_eq!(
            derived.urls,
            vec!["https://huggingface.co/owner/repo/resolve/main/model.bin".to_string()]
        );
    }

    /// A credential `env` moves the same phase onto the CLI route, and
    /// the derived capability moves with it.
    #[test]
    fn a_credential_pull_derives_sh_exec_instead() {
        let ids = IdGen::new();
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "HF_TOKEN".to_string(),
            ProfileNode::EnvLiteral {
                id: ids.node(),
                value: "t".into(),
            },
        );
        let derived = derive_normalized(vec![ProfileNode::SyncPull {
            id: ids.node(),
            src: "hf://owner/repo/model.bin".into(),
            dst: "/workspace".into(),
            env,
            revision: None,
        }]);
        assert!(derived.capabilities.contains("sh.exec"), "{derived:?}");
        assert!(
            !derived.capabilities.contains("net.transfer"),
            "{derived:?}"
        );
    }

    #[test]
    fn a_models_phase_derives_the_built_in_models_root() {
        let ids = IdGen::new();
        let derived = derive_normalized_assuming_comfyui(vec![ProfileNode::Models {
            id: ids.node(),
            models_json: r#"[{"src":"https://example.com/a.bin","dst":"a.bin"}]"#.into(),
        }]);
        assert_eq!(
            derived.paths,
            vec!["/workspace/ComfyUI/models/checkpoints/a.bin".to_string()],
            "the destination an author never spelled out must still be derived"
        );
    }

    #[test]
    fn a_direct_op_derives_its_own_payload_targets() {
        let ids = IdGen::new();
        let derived = derive_normalized(vec![ProfileNode::FsWrite {
            id: ids.node(),
            path: "/etc/conf".into(),
            content: Box::new(ProfileNode::EnvRef {
                id: ids.node(),
                name: "SHARED".into(),
            }),
        }]);
        assert!(derived.capabilities.contains("fs.write"));
        assert!(
            derived.capabilities.contains("env.ref"),
            "the value node's own demand counts too: {derived:?}"
        );
        assert_eq!(derived.paths, vec!["/etc/conf".to_string()]);
    }

    /// A suppressed phase demands nothing — it is not in the run.
    #[test]
    fn a_suppressed_version_check_contributes_nothing() {
        let ids = IdGen::new();
        let derived = derive_normalized(vec![ProfileNode::PythonVersionCheck {
            id: ids.node(),
            want: "3.12".into(),
        }]);
        assert_eq!(derived, Derived::default());
    }
}
