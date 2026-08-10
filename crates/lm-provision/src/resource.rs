//! Resources: the static half of the model (design §3.6).
//!
//! A phase can only reach a path some earlier phase created. Until this
//! module existed that fact lived nowhere: the ComfyUI install dir, its
//! models root, its custom-nodes root, its venv interpreter and its
//! entry point were five separate `const &str` in
//! [`crate::exec::lifecycle`], invisible to the profile and therefore to
//! anyone reading one.
//!
//! ```text
//! step が宣言する       produces : Resource*   requires : Resource*
//! profile が宣言する    assumes  : Resource*
//!
//! well-formed = すべての requires が、より前の produces か assumes で束縛されている
//! ```
//!
//! **This is a scope check, not graph analysis.** Nothing is reordered,
//! so it is not the per-kind `depends_on` + topological sort that
//! `02-phase-catalog.md` §Stability rules out. It is one forward fold
//! over the phase list.
//!
//! ## What the author writes, and what they do not
//!
//! | | who declares it | where it lives |
//! |---|---|---|
//! | `produces` | the author, per phase | [`ProfileNode::ComfyUiInstall::install_dir`] |
//! | `assumes` | the author, per profile | [`ProfileNode::Spec::assumes`] |
//! | `requires` | **nobody** — fixed per kind | [`requires`], below |
//!
//! `requires` is not in the AST because it is not a choice: that
//! `models` needs somewhere to put a model is a property of the kind,
//! not of the profile. Writing it down per profile would be the same
//! fact recorded twice, which design §3.6 rules out for the `requires` /
//! `assumes` pair for the same reason.
//!
//! ## "Earlier" means canonical order, not written order
//!
//! Phases run in the fixed order `02-phase-catalog.md` §Canonical phase
//! ordering assigns, which [`crate::normalize`] imposes — a profile that
//! writes `models` above `comfyui.install` still runs the install first.
//! So the fold is over **normalized** phases. Walking the as-written
//! order would reject profiles that run fine.

use std::collections::BTreeMap;

use crate::profile_ast::ProfileNode;

/// Where `comfyui.install` puts the checkout when the phase declares no
/// `install_dir` — the value every profile written before the slot
/// existed means (`02-phase-catalog.md` §Resource-derived paths).
pub const COMFYUI_ROOT_DEFAULT: &str = "/workspace/ComfyUI";

/// A named thing a phase can create and a later phase can consume.
///
/// One variant today. The type exists rather than a bare `&str` so that
/// adding `Venv` (design §4.3's other half — the venv nothing creates)
/// is a variant plus two match arms, and so that a resource name that
/// matches nothing is a parse failure rather than a silent miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resource {
    /// The ComfyUI checkout root. Produced by `comfyui.install`; every
    /// ComfyUI-relative path is derived from it (see
    /// [`ComfyUiPaths`]).
    ComfyUiRoot,
}

impl Resource {
    /// The name an author writes in `Spec.assumes`.
    pub fn as_str(self) -> &'static str {
        match self {
            Resource::ComfyUiRoot => "comfyui_root",
        }
    }

    /// Parse an `assumes` key. `None` for an unknown name, which
    /// validate reports rather than ignoring.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "comfyui_root" => Some(Resource::ComfyUiRoot),
            _ => None,
        }
    }
}

/// Every ComfyUI path, derived from one root.
///
/// The five constants this replaced could drift from each other; here
/// they cannot, because there is one input. The venv spelling is the
/// one place where the derivation is known to disagree with the
/// predecessor implementation, which uses `.venv` — recorded rather
/// than silently reconciled, because nothing in lm-provision creates
/// either directory yet (design §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyUiPaths {
    root: String,
}

impl ComfyUiPaths {
    /// Derive every path from a checkout root.
    pub fn new(root: impl Into<String>) -> Self {
        Self { root: root.into() }
    }

    /// The checkout root itself.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Where `models` entries land, before the per-entry subdir.
    pub fn models_root(&self) -> String {
        format!("{}/models", self.root)
    }

    /// Where `custom_nodes` clones land.
    pub fn custom_nodes_root(&self) -> String {
        format!("{}/custom_nodes", self.root)
    }

    /// The venv `pip` used by `python.deps` (`in_comfy_venv`) and by
    /// each custom node's requirements install.
    pub fn venv_pip(&self) -> String {
        format!("{}/venv/bin/pip", self.root)
    }

    /// The venv interpreter `comfyui.restart` launches with.
    pub fn venv_python(&self) -> String {
        format!("{}/venv/bin/python", self.root)
    }

    /// The ComfyUI entry point.
    pub fn main_py(&self) -> String {
        format!("{}/main.py", self.root)
    }
}

/// What `phase` creates, if anything.
pub fn produces(phase: &ProfileNode) -> Option<(Resource, String)> {
    match phase {
        ProfileNode::ComfyUiInstall { install_dir, .. } => Some((
            Resource::ComfyUiRoot,
            install_dir
                .clone()
                .unwrap_or_else(|| COMFYUI_ROOT_DEFAULT.to_string()),
        )),
        _ => None,
    }
}

/// What `phase` needs already bound.
///
/// Fixed per kind — see the module header on why this is not authored.
/// `python.deps` is the one conditional entry: it only reaches the venv
/// when `in_comfy_venv` is set, and a plain `pip install` needs nothing
/// from ComfyUI.
pub fn requires(phase: &ProfileNode) -> &'static [Resource] {
    const ROOT: &[Resource] = &[Resource::ComfyUiRoot];
    const NONE: &[Resource] = &[];
    match phase {
        ProfileNode::Models { .. }
        | ProfileNode::CustomNodes { .. }
        | ProfileNode::ComfyUiRestart { .. } => ROOT,
        ProfileNode::PythonDeps { in_comfy_venv, .. } => {
            if *in_comfy_venv {
                ROOT
            } else {
                NONE
            }
        }
        _ => NONE,
    }
}

/// The resources in scope at a point in the phase list.
///
/// Drive it with the fold both consumers write out:
///
/// ```text
/// let mut env = ResourceEnv::from_assumes(assumes);
/// for phase in phases {          // normalized order — see module header
///     ... read env at this phase ...
///     env.bind(phase);           // after, never before
/// }
/// ```
///
/// `bind` comes **after** the phase is read because a phase does not see
/// what it itself produces: `comfyui.install` composes its own steps
/// from its payload, not from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceEnv {
    bound: BTreeMap<Resource, String>,
}

impl ResourceEnv {
    /// Seed the environment from a profile's `assumes`. Keys naming no
    /// resource are skipped here and reported by validate — this type
    /// stays total so that exec can run without validate having.
    pub fn from_assumes(assumes: &BTreeMap<String, String>) -> Self {
        let mut bound = BTreeMap::new();
        for (name, path) in assumes {
            if let Some(resource) = Resource::parse(name) {
                bound.insert(resource, path.clone());
            }
        }
        Self { bound }
    }

    /// Fold `phase`'s `produces` in. Call after reading the environment
    /// at that phase, not before.
    pub fn bind(&mut self, phase: &ProfileNode) {
        if let Some((resource, path)) = produces(phase) {
            self.bound.insert(resource, path);
        }
    }

    /// The path bound to `resource`, if any.
    pub fn resolve(&self, resource: Resource) -> Option<&str> {
        self.bound.get(&resource).map(String::as_str)
    }

    /// The first resource `phase` requires that nothing has bound, if
    /// the phase is not well-formed here.
    pub fn unbound(&self, phase: &ProfileNode) -> Option<Resource> {
        requires(phase)
            .iter()
            .copied()
            .find(|resource| !self.bound.contains_key(resource))
    }

    /// The ComfyUI paths in scope, or `None` when nothing has bound the
    /// root. Callers that require the root treat `None` as an error
    /// rather than substituting the default: a profile that consumes
    /// ComfyUI without installing it or assuming it is exactly the shape
    /// design §4.2 says fails today without being named.
    pub fn comfyui(&self) -> Option<ComfyUiPaths> {
        self.resolve(Resource::ComfyUiRoot).map(ComfyUiPaths::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    fn install(dir: Option<&str>) -> ProfileNode {
        ProfileNode::ComfyUiInstall {
            id: IdGen::new().node(),
            ref_name: "master".into(),
            repo: None,
            install_dir: dir.map(str::to_string),
        }
    }

    fn models() -> ProfileNode {
        ProfileNode::Models {
            id: IdGen::new().node(),
            models_json: "[]".into(),
        }
    }

    #[test]
    fn an_undeclared_install_dir_produces_the_built_in_root() {
        assert_eq!(
            produces(&install(None)),
            Some((Resource::ComfyUiRoot, COMFYUI_ROOT_DEFAULT.to_string()))
        );
    }

    #[test]
    fn a_declared_install_dir_is_what_gets_bound() {
        let mut env = ResourceEnv::default();
        env.bind(&install(Some("/opt/comfy")));
        assert_eq!(env.resolve(Resource::ComfyUiRoot), Some("/opt/comfy"));
        assert_eq!(
            env.comfyui().map(|p| p.models_root()),
            Some("/opt/comfy/models".to_string())
        );
    }

    #[test]
    fn models_is_unbound_until_something_binds_the_root() {
        let mut env = ResourceEnv::default();
        assert_eq!(env.unbound(&models()), Some(Resource::ComfyUiRoot));
        env.bind(&install(None));
        assert_eq!(env.unbound(&models()), None);
    }

    #[test]
    fn assumes_binds_the_root_with_no_install_phase() {
        let assumes = BTreeMap::from([("comfyui_root".to_string(), "/pre/installed".to_string())]);
        let env = ResourceEnv::from_assumes(&assumes);
        assert_eq!(env.unbound(&models()), None);
        assert_eq!(env.resolve(Resource::ComfyUiRoot), Some("/pre/installed"));
    }

    #[test]
    fn an_assumes_key_naming_no_resource_binds_nothing() {
        let assumes = BTreeMap::from([("comfy_root".to_string(), "/typo".to_string())]);
        let env = ResourceEnv::from_assumes(&assumes);
        assert_eq!(env.resolve(Resource::ComfyUiRoot), None);
    }

    #[test]
    fn python_deps_requires_the_root_only_inside_the_venv() {
        let outside = ProfileNode::PythonDeps {
            id: IdGen::new().node(),
            deps: vec!["numpy".into()],
            in_comfy_venv: false,
        };
        let inside = ProfileNode::PythonDeps {
            id: IdGen::new().node(),
            deps: vec!["numpy".into()],
            in_comfy_venv: true,
        };
        assert_eq!(requires(&outside), &[] as &[Resource]);
        assert_eq!(requires(&inside), &[Resource::ComfyUiRoot]);
    }

    #[test]
    fn every_comfyui_path_moves_with_the_root() {
        let paths = ComfyUiPaths::new("/srv/ui");
        assert_eq!(paths.models_root(), "/srv/ui/models");
        assert_eq!(paths.custom_nodes_root(), "/srv/ui/custom_nodes");
        assert_eq!(paths.venv_pip(), "/srv/ui/venv/bin/pip");
        assert_eq!(paths.venv_python(), "/srv/ui/venv/bin/python");
        assert_eq!(paths.main_py(), "/srv/ui/main.py");
    }
}
