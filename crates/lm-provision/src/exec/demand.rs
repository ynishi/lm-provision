//! What one unit of work demands: its capability and the allowlist
//! targets it will be checked against.
//!
//! Two consumers read this, and that is the point. [`super::registry`]
//! enforces the demand at execution time (the L4 entry check and the L3
//! policies), and [`crate::derive`] collects it at validate time to
//! assert `declared ⊇ derived` (spec 00 §Capability derivation). If the
//! two derived the mapping separately, the assertion would be a second
//! reading of the catalog rather than a statement about the run that
//! will actually happen — and the drift between them would be invisible
//! until a profile passed validate and then failed the entry check.
//!
//! Two granularities, because the pipeline has two:
//!
//! - [`direct`] answers for a direct-operation phase, whose payload maps
//!   1:1 onto a bridge primitive (spec 02 §Catalog kinds);
//! - [`step`] answers for one **expanded** lifecycle step, because a
//!   lifecycle phase's demand depends on the route its payload resolves
//!   to (spec 02 §Dispatch routing "What the L4 gate sees").

use super::{lifecycle, scheme, ExecError};
use crate::profile_ast::ProfileNode;

/// The capability and allowlist targets one unit of work carries.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Demand {
    /// Capability the L4 entry check requires, or `None` for a unit that
    /// runs no effect (`sync.push` markers, note steps).
    pub(crate) capability: Option<&'static str>,
    /// Local paths the L3 path policy checks.
    pub(crate) paths: Vec<String>,
    /// Remote URLs the L3 http allowlist checks, already resolved — an
    /// `hf://` source appears here as the `https://huggingface.co` URL
    /// the transfer will actually reach.
    pub(crate) urls: Vec<String>,
}

/// The demand of a direct-operation phase.
///
/// Fails only where resolution itself fails: a `net.transfer` whose
/// direction the schemes do not determine has no route, and therefore
/// no targets to name.
pub(crate) fn direct(payload: &ProfileNode) -> Result<Demand, ExecError> {
    let demand = match payload {
        ProfileNode::ShExec { .. } => Demand {
            capability: Some("sh.exec"),
            ..Demand::default()
        },
        ProfileNode::FsWrite { path, .. } => Demand {
            capability: Some("fs.write"),
            paths: vec![path.clone()],
            ..Demand::default()
        },
        ProfileNode::NetHttpGet { url, .. } => Demand {
            capability: Some("net.http_get"),
            urls: vec![url.clone()],
            ..Demand::default()
        },
        ProfileNode::NetHttpPost { url, .. } => Demand {
            capability: Some("net.http_post"),
            urls: vec![url.clone()],
            ..Demand::default()
        },
        ProfileNode::NetTransfer { src, dst, .. } => {
            let (local, remote) = transfer_targets("net_transfer", src, dst)?;
            Demand {
                capability: Some("net.transfer"),
                paths: vec![local],
                urls: vec![remote],
            }
        }
        ProfileNode::MountBind { src, dst, .. } => Demand {
            capability: Some("mount.bind"),
            paths: vec![src.clone(), dst.clone()],
            ..Demand::default()
        },
        ProfileNode::MountUmount { path, .. } => Demand {
            capability: Some("mount.umount"),
            paths: vec![path.clone()],
            ..Demand::default()
        },
        _ => Demand::default(),
    };
    Ok(demand)
}

/// The demand of one expanded lifecycle step.
///
/// A `Sh` step demands `sh.exec` and nothing else: subprocess writes are
/// outside the path layer by design (spec 04 §`sh.exec`). The pid file a
/// poll re-reads is likewise absent — a provisioner-internal read, not a
/// bridge op (spec 02 §Poll deadlines).
///
/// A step's `done` adds no demand either, for the same reason as the
/// pid file: evaluating it reads the provisioner's own filesystem
/// rather than calling a bridge op, and it reads only the destination
/// the transfer is already gated on. A condition that could widen what
/// a phase touches would have to be gated; this one cannot, because it
/// is derived from the step's own destination rather than authored.
pub(crate) fn step(step: &lifecycle::Step) -> Result<Demand, ExecError> {
    let demand = match step {
        lifecycle::Step::Sh(_) => Demand {
            capability: Some("sh.exec"),
            ..Demand::default()
        },
        lifecycle::Step::Transfer { src, dst, .. } => {
            let (local, remote) = transfer_targets("net_transfer", src, dst)?;
            Demand {
                capability: Some("net.transfer"),
                paths: vec![local],
                urls: vec![remote],
            }
        }
        lifecycle::Step::HttpPoll { url, .. } => Demand {
            capability: Some("net.http_get"),
            urls: vec![url.clone()],
            ..Demand::default()
        },
        lifecycle::Step::Note(_) => Demand::default(),
    };
    Ok(demand)
}

/// The extra capability a phase carrying an [`ProfileNode::EnvRef`]
/// value node demands, wherever that node sits (spec 02
/// §Shared vocabulary).
pub(crate) fn env_ref(payload: &ProfileNode) -> Option<&'static str> {
    fn is_ref(node: &ProfileNode) -> bool {
        matches!(node, ProfileNode::EnvRef { .. })
    }
    fn any_ref<'a>(nodes: impl IntoIterator<Item = &'a ProfileNode>) -> bool {
        nodes.into_iter().any(is_ref)
    }

    let carries = match payload {
        ProfileNode::FsWrite { content, .. } => is_ref(content),
        ProfileNode::SyncPull { env, .. }
        | ProfileNode::StagingPush { env, .. }
        | ProfileNode::ShExec { env, .. } => any_ref(env.values()),
        ProfileNode::NetHttpGet { headers, .. } => any_ref(headers.values()),
        ProfileNode::NetHttpPost { headers, body, .. } => {
            any_ref(headers.values()) || body.as_deref().is_some_and(is_ref)
        }
        _ => false,
    };
    carries.then_some("env.ref")
}

/// The `(local path, remote URL)` a transfer is checked against, read
/// off its resolved route rather than its field names: on a download
/// the local side is `dst`, on an upload it is `src`.
fn transfer_targets(op: &str, src: &str, dst: &str) -> Result<(String, String), ExecError> {
    Ok(match scheme::resolve(op, src, dst)? {
        scheme::Transfer::Download { url } => (dst.to_string(), url),
        scheme::Transfer::Upload { url } => (src.to_string(), url),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    #[test]
    fn a_download_gates_its_destination_path_and_its_source_url() {
        let ids = IdGen::new();
        let demand = direct(&ProfileNode::NetTransfer {
            id: ids.node(),
            src: "https://example.com/a.bin".into(),
            dst: "/workspace/a.bin".into(),
        })
        .expect("a download resolves");
        assert_eq!(demand.capability, Some("net.transfer"));
        assert_eq!(demand.paths, vec!["/workspace/a.bin".to_string()]);
        assert_eq!(demand.urls, vec!["https://example.com/a.bin".to_string()]);
    }

    #[test]
    fn an_upload_gates_its_source_path_and_its_destination_url() {
        let ids = IdGen::new();
        let demand = direct(&ProfileNode::NetTransfer {
            id: ids.node(),
            src: "/workspace/a.bin".into(),
            dst: "https://example.com/a.bin".into(),
        })
        .expect("an upload resolves");
        assert_eq!(demand.paths, vec!["/workspace/a.bin".to_string()]);
        assert_eq!(demand.urls, vec!["https://example.com/a.bin".to_string()]);
    }

    #[test]
    fn an_hf_step_gates_the_resolved_host() {
        let demand = step(&lifecycle::Step::Transfer {
            src: "https://huggingface.co/o/r/resolve/main/a.bin".into(),
            dst: "/workspace/a.bin".into(),
            done: None,
        })
        .expect("resolves");
        assert_eq!(
            demand.urls,
            vec!["https://huggingface.co/o/r/resolve/main/a.bin".to_string()]
        );
    }

    #[test]
    fn a_note_step_demands_nothing() {
        assert_eq!(
            step(&lifecycle::Step::Note("nothing to run".into())).unwrap(),
            Demand::default()
        );
    }

    #[test]
    fn an_env_ref_in_any_slot_demands_the_capability() {
        let ids = IdGen::new();
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "MODE".to_string(),
            ProfileNode::EnvRef {
                id: ids.node(),
                name: "SHARED".into(),
            },
        );
        assert_eq!(
            env_ref(&ProfileNode::ShExec {
                id: ids.node(),
                argv: vec!["true".into()],
                env,
            }),
            Some("env.ref")
        );
        assert_eq!(
            env_ref(&ProfileNode::ShExec {
                id: ids.node(),
                argv: vec!["true".into()],
                env: Default::default(),
            }),
            None
        );
    }
}
