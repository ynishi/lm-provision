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
/// The type exists rather than a bare `&str` so that a resource name
/// matching nothing is a parse failure rather than a silent miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resource {
    /// The ComfyUI checkout root. Produced by `comfyui.install`; the
    /// models root, the custom-nodes root and the entry point are all
    /// derived from it (see [`ComfyUiPaths`]).
    ComfyUiRoot,
    /// The Python virtual environment ComfyUI runs in. Produced by
    /// `toolchain.python`, which places it under the root it requires.
    ///
    /// **Its identity is weak, and design §3.6 says so up front**: a
    /// venv has no digest, so "there is one" is the strongest thing
    /// that can be observed about it. Changing what a profile declares
    /// should be inside it does not make an existing one disagree.
    Venv,
}

impl Resource {
    /// The name an author writes in `Spec.assumes`.
    pub fn as_str(self) -> &'static str {
        match self {
            Resource::ComfyUiRoot => "comfyui_root",
            Resource::Venv => "venv",
        }
    }

    /// Parse an `assumes` key. `None` for an unknown name, which
    /// validate reports rather than ignoring.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "comfyui_root" => Some(Resource::ComfyUiRoot),
            "venv" => Some(Resource::Venv),
            _ => None,
        }
    }
}

/// A virtual environment, by the directory it lives in.
///
/// Separate from [`ComfyUiPaths`] because a venv is a *bound resource*
/// with a location of its own, not a path derived from the checkout.
/// Deriving `pip` from the root would mean every consumer computing
/// where the venv "should" be; reading it off the binding means they
/// use the one that was actually produced or assumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VenvPaths {
    dir: String,
}

impl VenvPaths {
    /// Wrap a venv directory.
    pub fn new(dir: impl Into<String>) -> Self {
        Self { dir: dir.into() }
    }

    /// The venv directory itself.
    pub fn dir(&self) -> &str {
        &self.dir
    }

    /// The venv's `pip`, used by `python.deps` (`in_comfy_venv`), by
    /// each custom node's requirements install, and by
    /// `toolchain.python`'s own requirements install.
    pub fn pip(&self) -> String {
        format!("{}/bin/pip", self.dir)
    }

    /// The venv's interpreter, which `comfyui.restart` launches with.
    pub fn python(&self) -> String {
        format!("{}/bin/python", self.dir)
    }
}

/// Every ComfyUI path, derived from one root.
///
/// The constants this replaced could drift from each other; here they
/// cannot, because there is one input.
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

    /// Where `toolchain.python` puts the venv it creates.
    ///
    /// **`.venv`, not `venv`** — the spelling the predecessor
    /// implementation uses [実測: `profile_service.rs:1067`]. The
    /// earlier `venv` spelling pointed at a directory nothing has ever
    /// created, so correcting it breaks no installed base.
    pub fn venv_dir(&self) -> String {
        format!("{}/.venv", self.root)
    }

    /// The ComfyUI entry point.
    pub fn main_py(&self) -> String {
        format!("{}/main.py", self.root)
    }

    /// ComfyUI's own dependency list, which `toolchain.python` installs
    /// when a profile points at it.
    pub fn requirements_txt(&self) -> String {
        format!("{}/requirements.txt", self.root)
    }
}

/// What `phase` creates, if anything, in the scope it runs in.
///
/// **`env` is a parameter because a producer can place its output
/// relative to something it requires.** `comfyui.install` does not need
/// it — its root comes off its own payload — but `toolchain.python`
/// puts the venv under the root in scope, so what it produces is not a
/// function of the phase alone. That was not visible with one resource.
pub fn produces(phase: &ProfileNode, env: &ResourceEnv) -> Option<(Resource, String)> {
    match phase {
        ProfileNode::ComfyUiInstall { install_dir, .. } => Some((
            Resource::ComfyUiRoot,
            install_dir
                .clone()
                .unwrap_or_else(|| COMFYUI_ROOT_DEFAULT.to_string()),
        )),
        // `None` when the root is unbound: the phase requires it, so it
        // fails to expand and says so. Producing a venv under a root
        // nothing bound would be inventing a location.
        ProfileNode::ToolchainPython { .. } => env
            .comfyui()
            .map(|paths| (Resource::Venv, paths.venv_dir())),
        _ => None,
    }
}

/// What `phase` needs already bound.
///
/// Fixed per kind — see the module header on why this is not authored.
/// Two entries are conditional on the payload rather than on the kind
/// alone, and both conditions are the author's own words about whether
/// the phase reaches the venv:
///
/// - `python.deps` reaches it only under `in_comfy_venv`; a plain
///   `pip install` needs nothing from ComfyUI at all.
/// - `custom_nodes` reaches it only when some node asks for its
///   requirements to be installed. A payload that does not parse
///   answers the root alone: the expansion fails on the parse error,
///   which is the message worth reporting, and demanding a venv on top
///   of it would name the wrong problem.
pub fn requires(phase: &ProfileNode) -> &'static [Resource] {
    const NONE: &[Resource] = &[];
    const ROOT: &[Resource] = &[Resource::ComfyUiRoot];
    const VENV: &[Resource] = &[Resource::Venv];
    const ROOT_AND_VENV: &[Resource] = &[Resource::ComfyUiRoot, Resource::Venv];
    match phase {
        ProfileNode::Models { .. } => ROOT,
        ProfileNode::ToolchainPython { .. } => ROOT,
        ProfileNode::ComfyUiRestart { .. } => ROOT_AND_VENV,
        ProfileNode::PythonDeps { in_comfy_venv, .. } => {
            if *in_comfy_venv {
                VENV
            } else {
                NONE
            }
        }
        ProfileNode::CustomNodes { nodes_json, .. } => {
            if custom_nodes_install_requirements(nodes_json) {
                ROOT_AND_VENV
            } else {
                ROOT
            }
        }
        _ => NONE,
    }
}

/// Whether any entry of a `custom_nodes` payload asks for its
/// `requirements.txt` to be installed, which is what takes the phase
/// into the venv.
fn custom_nodes_install_requirements(nodes_json: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct PipFlag {
        #[serde(default)]
        pip: bool,
    }
    serde_json::from_str::<Vec<PipFlag>>(nodes_json)
        .map(|nodes| nodes.iter().any(|node| node.pip))
        .unwrap_or(false)
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
    ///
    /// The environment is read as well as written: a producer may place
    /// what it makes relative to something already bound (see
    /// [`produces`]).
    pub fn bind(&mut self, phase: &ProfileNode) {
        if let Some((resource, path)) = produces(phase, self) {
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

    /// The venv in scope, or `None` when nothing has produced or assumed
    /// one. Read off the binding rather than derived from the root, so a
    /// consumer uses the venv that exists rather than the one that would
    /// exist if something had made it.
    pub fn venv(&self) -> Option<VenvPaths> {
        self.resolve(Resource::Venv).map(VenvPaths::new)
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

    fn toolchain_python() -> ProfileNode {
        ProfileNode::ToolchainPython {
            id: IdGen::new().node(),
            requirements: None,
            isolated: false,
        }
    }

    #[test]
    fn an_undeclared_install_dir_produces_the_built_in_root() {
        assert_eq!(
            produces(&install(None), &ResourceEnv::default()),
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
    fn python_deps_requires_the_venv_only_inside_it() {
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
        assert_eq!(requires(&inside), &[Resource::Venv]);
    }

    #[test]
    fn every_comfyui_path_moves_with_the_root() {
        let paths = ComfyUiPaths::new("/srv/ui");
        assert_eq!(paths.models_root(), "/srv/ui/models");
        assert_eq!(paths.custom_nodes_root(), "/srv/ui/custom_nodes");
        assert_eq!(paths.venv_dir(), "/srv/ui/.venv");
        assert_eq!(paths.main_py(), "/srv/ui/main.py");
        assert_eq!(paths.requirements_txt(), "/srv/ui/requirements.txt");
    }

    #[test]
    fn a_venv_carries_its_own_paths() {
        let venv = VenvPaths::new("/srv/ui/.venv");
        assert_eq!(venv.pip(), "/srv/ui/.venv/bin/pip");
        assert_eq!(venv.python(), "/srv/ui/.venv/bin/python");
    }

    /// **What one resource could not show.** `comfyui.install` reads its
    /// root off its own payload, so `produces` looked like a function of
    /// the phase; `toolchain.python` puts the venv under the root in
    /// scope, so it is not.
    #[test]
    fn the_venv_is_produced_under_whatever_root_is_bound() {
        let mut env = ResourceEnv::default();
        assert_eq!(
            produces(&toolchain_python(), &env),
            None,
            "with no root bound there is no location to produce"
        );

        env.bind(&install(Some("/opt/comfy")));
        assert_eq!(
            produces(&toolchain_python(), &env),
            Some((Resource::Venv, "/opt/comfy/.venv".to_string()))
        );

        env.bind(&toolchain_python());
        assert_eq!(
            env.venv().map(|v| v.pip()),
            Some("/opt/comfy/.venv/bin/pip".to_string())
        );
    }

    /// A venv nothing produced is named, and the phases that need one
    /// are exactly the phases that reach into it.
    #[test]
    fn the_venv_consumers_are_unbound_until_toolchain_python_runs() {
        let restart = ProfileNode::ComfyUiRestart {
            id: IdGen::new().node(),
            port: 8188,
            extra_args: Vec::new(),
        };
        let mut env = ResourceEnv::default();
        env.bind(&install(None));

        assert_eq!(env.unbound(&restart), Some(Resource::Venv));
        assert_eq!(
            env.unbound(&models()),
            None,
            "a models phase never touches the venv"
        );

        env.bind(&toolchain_python());
        assert_eq!(env.unbound(&restart), None);
    }

    /// `custom_nodes` reaches the venv only for entries that ask for
    /// their requirements to be installed — a clone-only phase runs
    /// without one.
    #[test]
    fn custom_nodes_requires_the_venv_only_when_an_entry_installs_requirements() {
        let with_pip = ProfileNode::CustomNodes {
            id: IdGen::new().node(),
            nodes_json: r#"[{"name":"a","repo":"o/r","pip":true}]"#.into(),
        };
        let clone_only = ProfileNode::CustomNodes {
            id: IdGen::new().node(),
            nodes_json: r#"[{"name":"a","repo":"o/r"}]"#.into(),
        };
        let malformed = ProfileNode::CustomNodes {
            id: IdGen::new().node(),
            nodes_json: "not json".into(),
        };
        assert_eq!(
            requires(&with_pip),
            &[Resource::ComfyUiRoot, Resource::Venv]
        );
        assert_eq!(requires(&clone_only), &[Resource::ComfyUiRoot]);
        assert_eq!(
            requires(&malformed),
            &[Resource::ComfyUiRoot],
            "a payload that does not parse is reported by the expansion, \
             not as a demand for a venv"
        );
    }
}
