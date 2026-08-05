//! Canonical-order normalization: the one AST→AST pass that both the
//! plan stage and apply run before they consume a profile.
//!
//! Three of the rules in `02-phase-catalog.md` §Canonical phase ordering
//! are content-sensitive — they change *which* phases exist and in
//! *what order*, not how one phase executes:
//!
//! - bucketing / ordering: phases are emitted in the fixed canonical
//!   order, each bucket keeping its relative declaration order;
//! - implicit insertion: a `comfyui.install` without one of
//!   `comfyui.restart` / `comfyui.health` gets the missing one, carrying
//!   the other's port when that was declared and the default otherwise;
//! - suppression: a `python.version_check` asserting the default
//!   version is dropped.
//!
//! They used to live inside [`crate::plan`], which meant they applied to
//! the plan artifact and nothing else: apply drives the AST directly, so
//! it ran phases in declaration order, without the inserted lifecycle
//! steps, and executed the version check the plan had suppressed. The
//! plan then described a run that never happened — the one thing a plan
//! stage exists to prevent.
//!
//! Normalizing here fixes the direction of the dependency: the rules
//! rewrite the AST once, and both consumers walk the same phases. The
//! plan artifact is a rendering of the normalized AST (plus the
//! `sync.routes` bundling, which is plan-internal by spec), and apply
//! executes exactly what the plan rendered.
//!
//! What normalization deliberately does **not** touch: the authored AST
//! that `hash` / `canonical` see. Those run on the profile as written
//! (`02` §Stability — an inserted step must not change a profile's
//! hash), so normalization happens at the plan / apply entry points,
//! never inside the frontend.

use dsl_kit::{DslNode as _, NodeId};

use crate::profile_ast::ProfileNode;

/// Default port used when [`ProfileNode::ComfyUiRestart`] or
/// [`ProfileNode::ComfyUiHealth`] is implicitly inserted
/// (`02-phase-catalog.md` §Canonical phase ordering).
pub(crate) const DEFAULT_COMFYUI_PORT: u16 = 8188;

/// Default `want` value that suppresses the
/// [`ProfileNode::PythonVersionCheck`] step
/// (`02-phase-catalog.md` §Catalog kinds `python.version_check`).
pub(crate) const DEFAULT_PYTHON_VERSION_WANT: &str = "3.12";

/// Rewrite `root`'s phase list into canonical execution order, applying
/// implicit insertion and suppression.
///
/// A non-[`ProfileNode::Spec`] root is returned unchanged: the frontend
/// only ever hands a `Spec` here, so the fallback keeps the function
/// total rather than describing a reachable case.
///
/// Node ids of the author's phases are preserved. Inserted phases mint
/// fresh ids above every id already in the tree, so the
/// `NodeId -> payload` map the exec context builds stays injective.
pub fn normalize(root: &ProfileNode) -> ProfileNode {
    let ProfileNode::Spec {
        id,
        name,
        version,
        description,
        capabilities,
        env,
        env_secrets,
        paths,
        http_allowlist,
        phases,
    } = root
    else {
        return root.clone();
    };

    ProfileNode::Spec {
        id: *id,
        name: name.clone(),
        version: version.clone(),
        description: description.clone(),
        capabilities: capabilities.clone(),
        env: env.clone(),
        env_secrets: env_secrets.clone(),
        paths: paths.clone(),
        http_allowlist: http_allowlist.clone(),
        phases: normalize_phases(phases, IdMinter::above(root)),
    }
}

/// The canonical-order phase list for `phases`.
fn normalize_phases(phases: &[ProfileNode], mut ids: IdMinter) -> Vec<ProfileNode> {
    let mut buckets = Buckets::default();

    for phase in phases {
        match phase {
            ProfileNode::SystemApt { .. } => buckets.system_apt.push(phase.clone()),
            ProfileNode::ComfyUiInstall { .. } => buckets.comfyui_install.push(phase.clone()),
            // Suppressed: asserting the default version against itself
            // cannot fail. The test is a literal equality against the
            // default, not an analysis of which wants are vacuous
            // (`02` §Canonical phase ordering).
            ProfileNode::PythonVersionCheck { want, .. } => {
                if want != DEFAULT_PYTHON_VERSION_WANT {
                    buckets.python_version_check.push(phase.clone());
                }
            }
            ProfileNode::PythonDeps { .. } => buckets.python_deps.push(phase.clone()),
            ProfileNode::CustomNodes { .. } => buckets.custom_nodes.push(phase.clone()),
            ProfileNode::SyncPull { .. } => buckets.sync_pull.push(phase.clone()),
            ProfileNode::SyncPush { .. } => buckets.sync_push.push(phase.clone()),
            ProfileNode::StagingPush { .. } => buckets.staging_push.push(phase.clone()),
            ProfileNode::Models { .. } => buckets.models.push(phase.clone()),
            ProfileNode::LlmModels { .. } => buckets.llm_models.push(phase.clone()),
            ProfileNode::PostInstall { .. } => buckets.post_install.push(phase.clone()),
            ProfileNode::ComfyUiRestart { .. } => buckets.comfyui_restart.push(phase.clone()),
            ProfileNode::ComfyUiHealth { .. } => buckets.comfyui_health.push(phase.clone()),
            ProfileNode::ServiceStart { .. } | ProfileNode::ServiceReady { .. } => {
                buckets.services.push(phase.clone())
            }
            // Direct-operation kinds land in the trailing bucket in
            // declaration order. Sharing that bucket is an ordering
            // statement only — each one still dispatches to its bridge
            // primitive (`02` §Unknown kinds).
            ProfileNode::ShExec { .. }
            | ProfileNode::FsWrite { .. }
            | ProfileNode::NetHttpGet { .. }
            | ProfileNode::NetHttpPost { .. }
            | ProfileNode::NetTransfer { .. }
            | ProfileNode::MountBind { .. }
            | ProfileNode::MountUmount { .. } => buckets.trailing.push(phase.clone()),
            // A `Spec` nested inside `phases`, or an `Env*` value node
            // outside its slot, is a malformed AST the frontend does not
            // produce; drop rather than panic to keep this total.
            ProfileNode::Spec { .. }
            | ProfileNode::EnvLiteral { .. }
            | ProfileNode::EnvSecret { .. }
            | ProfileNode::EnvRef { .. } => {}
        }
    }

    insert_comfyui_lifecycle(&mut buckets, &mut ids);

    let mut out = Vec::with_capacity(phases.len() + 2);
    out.append(&mut buckets.system_apt);
    out.append(&mut buckets.comfyui_install);
    out.append(&mut buckets.python_version_check);
    out.append(&mut buckets.python_deps);
    out.append(&mut buckets.custom_nodes);
    out.append(&mut buckets.sync_pull);
    out.append(&mut buckets.sync_push);
    out.append(&mut buckets.staging_push);
    out.append(&mut buckets.models);
    out.append(&mut buckets.llm_models);
    out.append(&mut buckets.post_install);
    out.append(&mut buckets.comfyui_restart);
    out.append(&mut buckets.comfyui_health);
    out.append(&mut buckets.services);
    out.append(&mut buckets.trailing);
    out
}

/// Apply the implicit-insertion rule to the restart / health buckets.
///
/// The guard is per phase, not "neither was declared": a profile that
/// declares only the restart still gets its health poll. The inserted
/// step carries the port of the other one when that was declared, and
/// the default port when neither was (`02` §Canonical phase ordering).
fn insert_comfyui_lifecycle(buckets: &mut Buckets, ids: &mut IdMinter) {
    if buckets.comfyui_install.is_empty() {
        return;
    }

    if buckets.comfyui_restart.is_empty() {
        let port = buckets
            .comfyui_health
            .first()
            .and_then(port_of)
            .unwrap_or(DEFAULT_COMFYUI_PORT);
        buckets.comfyui_restart.push(ProfileNode::ComfyUiRestart {
            id: ids.next(),
            port,
            extra_args: Vec::new(),
        });
    }

    if buckets.comfyui_health.is_empty() {
        let port = buckets
            .comfyui_restart
            .first()
            .and_then(port_of)
            .unwrap_or(DEFAULT_COMFYUI_PORT);
        buckets.comfyui_health.push(ProfileNode::ComfyUiHealth {
            id: ids.next(),
            port,
            timeout_sec: None,
        });
    }
}

/// The port a `comfyui.restart` / `comfyui.health` phase carries.
fn port_of(phase: &ProfileNode) -> Option<u16> {
    match phase {
        ProfileNode::ComfyUiRestart { port, .. } | ProfileNode::ComfyUiHealth { port, .. } => {
            Some(*port)
        }
        _ => None,
    }
}

/// Mints [`NodeId`]s above every id already present in the tree, so an
/// inserted phase cannot collide with an existing node.
///
/// The ceiling is taken over the **whole** tree — the `Spec` root and
/// the nested value nodes included, not just the top-level phases. The
/// frontend hands the root the last id it allocates, so minting above
/// the phases alone produced an id equal to the root's: the derived AST
/// keys its program on `NodeId`, and the collision made the engine run
/// the colliding phase in place of the whole profile [実測: 2026-08-05、
/// apply が 5 phase 中 1 phase だけを実行して ok=true を返した].
struct IdMinter(u64);

impl IdMinter {
    fn above(root: &ProfileNode) -> Self {
        Self(max_node_id(root))
    }

    fn next(&mut self) -> NodeId {
        self.0 += 1;
        NodeId(self.0)
    }
}

/// The largest [`NodeId`] anywhere in `node`'s subtree, itself included.
fn max_node_id(node: &ProfileNode) -> u64 {
    let own = node.node_id().0;
    let nested: u64 = match node {
        ProfileNode::Spec { env, phases, .. } => env
            .values()
            .chain(phases.iter())
            .map(max_node_id)
            .max()
            .unwrap_or(0),
        ProfileNode::FsWrite { content, .. } => max_node_id(content),
        ProfileNode::SyncPull { env, .. }
        | ProfileNode::StagingPush { env, .. }
        | ProfileNode::ShExec { env, .. } => env.values().map(max_node_id).max().unwrap_or(0),
        ProfileNode::NetHttpGet { headers, .. } => {
            headers.values().map(max_node_id).max().unwrap_or(0)
        }
        ProfileNode::NetHttpPost { headers, body, .. } => headers
            .values()
            .chain(body.as_deref())
            .map(max_node_id)
            .max()
            .unwrap_or(0),
        _ => 0,
    };
    own.max(nested)
}

/// Per-kind phase buckets, in canonical order.
#[derive(Default)]
struct Buckets {
    system_apt: Vec<ProfileNode>,
    comfyui_install: Vec<ProfileNode>,
    python_version_check: Vec<ProfileNode>,
    python_deps: Vec<ProfileNode>,
    custom_nodes: Vec<ProfileNode>,
    sync_pull: Vec<ProfileNode>,
    sync_push: Vec<ProfileNode>,
    staging_push: Vec<ProfileNode>,
    models: Vec<ProfileNode>,
    llm_models: Vec<ProfileNode>,
    post_install: Vec<ProfileNode>,
    comfyui_restart: Vec<ProfileNode>,
    comfyui_health: Vec<ProfileNode>,
    /// `service.start` / `service.ready`, interleaved in declaration
    /// order — the pairing rule reads that order.
    services: Vec<ProfileNode>,
    /// Direct-operation kinds, in declaration order.
    trailing: Vec<ProfileNode>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    fn ids() -> IdGen {
        IdGen::new()
    }

    fn spec(phases: Vec<ProfileNode>) -> ProfileNode {
        let g = IdGen::new();
        ProfileNode::Spec {
            id: g.node(),
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

    fn kinds(root: &ProfileNode) -> Vec<&'static str> {
        match root {
            ProfileNode::Spec { phases, .. } => phases.iter().map(crate::plan::kind_of).collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn phases_are_reordered_into_the_canonical_order() {
        let g = ids();
        let root = spec(vec![
            ProfileNode::ShExec {
                id: g.node(),
                argv: vec!["true".into()],
                env: Default::default(),
            },
            ProfileNode::PythonDeps {
                id: g.node(),
                deps: vec!["torch".into()],
                in_comfy_venv: true,
            },
            ProfileNode::SystemApt {
                id: g.node(),
                packages: vec!["git".into()],
            },
        ]);
        assert_eq!(
            kinds(&normalize(&root)),
            vec!["system.apt", "python.deps", "sh.exec"],
        );
    }

    #[test]
    fn the_default_python_version_check_is_suppressed() {
        let g = ids();
        let root = spec(vec![ProfileNode::PythonVersionCheck {
            id: g.node(),
            want: "3.12".into(),
        }]);
        assert!(kinds(&normalize(&root)).is_empty());
    }

    #[test]
    fn a_non_default_python_version_check_survives() {
        let g = ids();
        let root = spec(vec![ProfileNode::PythonVersionCheck {
            id: g.node(),
            want: "3.11".into(),
        }]);
        assert_eq!(kinds(&normalize(&root)), vec!["python.version_check"]);
    }

    #[test]
    fn an_install_alone_gains_both_lifecycle_phases_at_the_default_port() {
        let g = ids();
        let root = spec(vec![ProfileNode::ComfyUiInstall {
            id: g.node(),
            ref_name: "master".into(),
            repo: None,
        }]);
        let normalized = normalize(&root);
        assert_eq!(
            kinds(&normalized),
            vec!["comfyui.install", "comfyui.restart", "comfyui.health"],
        );
        let ProfileNode::Spec { phases, .. } = &normalized else {
            unreachable!()
        };
        assert_eq!(port_of(&phases[1]), Some(DEFAULT_COMFYUI_PORT));
        assert_eq!(port_of(&phases[2]), Some(DEFAULT_COMFYUI_PORT));
    }

    /// The guard is per phase: declaring only the restart still gets a
    /// health poll, and the inserted one carries the declared port.
    #[test]
    fn the_missing_lifecycle_phase_inherits_the_declared_port() {
        let g = ids();
        let root = spec(vec![
            ProfileNode::ComfyUiInstall {
                id: g.node(),
                ref_name: "master".into(),
                repo: None,
            },
            ProfileNode::ComfyUiRestart {
                id: g.node(),
                port: 9999,
                extra_args: Vec::new(),
            },
        ]);
        let normalized = normalize(&root);
        let ProfileNode::Spec { phases, .. } = &normalized else {
            unreachable!()
        };
        assert_eq!(kinds(&normalized).len(), 3);
        assert_eq!(port_of(&phases[2]), Some(9999));
    }

    #[test]
    fn no_install_means_no_insertion() {
        let g = ids();
        let root = spec(vec![ProfileNode::ComfyUiRestart {
            id: g.node(),
            port: 8188,
            extra_args: Vec::new(),
        }]);
        assert_eq!(kinds(&normalize(&root)), vec!["comfyui.restart"]);
    }

    /// An inserted phase must not reuse **any** id in the tree — the
    /// derived AST keys its program on `NodeId`, and the exec context
    /// keys its payload map on it too.
    ///
    /// Taking the ceiling over the phases alone is not enough: the
    /// frontend allocates the `Spec` root's id last, so a phase minted
    /// at `max(phases) + 1` lands exactly on the root. That collision
    /// made the engine execute the inserted phase in place of the whole
    /// profile — one step, `ok = true`, four phases silently unrun
    /// [実測: 2026-08-05 apply report].
    #[test]
    fn inserted_phases_get_ids_above_every_id_in_the_tree() {
        let g = ids();
        let install = ProfileNode::ComfyUiInstall {
            id: g.node(),
            ref_name: "master".into(),
            repo: None,
        };
        // Mirror the frontend's allocation order: the root's id comes
        // after its children's.
        let root = ProfileNode::Spec {
            id: g.node(),
            name: "demo".into(),
            version: None,
            description: None,
            capabilities: Vec::new(),
            env: Default::default(),
            env_secrets: Vec::new(),
            paths: Vec::new(),
            http_allowlist: Vec::new(),
            phases: vec![install],
        };
        let root_id = root.node_id();

        let normalized = normalize(&root);
        let ProfileNode::Spec { phases, .. } = &normalized else {
            unreachable!()
        };
        let mut seen = std::collections::HashSet::new();
        seen.insert(root_id);
        for phase in phases {
            assert!(
                seen.insert(phase.node_id()),
                "phase id {} collides with another node in the tree",
                phase.node_id()
            );
        }
    }

    #[test]
    fn service_phases_keep_their_declaration_order() {
        let g = ids();
        let root = spec(vec![
            ProfileNode::ServiceReady {
                id: g.node(),
                name: "resumed".into(),
                check_url: "http://x/health".into(),
                timeout_sec: None,
            },
            ProfileNode::ServiceStart {
                id: g.node(),
                name: "svc".into(),
                platform_kind: "vllm".into(),
                model: None,
                port: None,
                dtype: None,
                tensor_parallel_size: None,
                extra_args: Vec::new(),
            },
        ]);
        assert_eq!(
            kinds(&normalize(&root)),
            vec!["service.ready", "service.start"],
        );
    }
}
