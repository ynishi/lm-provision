//! `NodeId -> ProfileNode` payload recovery.
//!
//! dsl-kit's `#[dsl_exec(apply = "op")]` does not pass a leaf variant's
//! payload fields (argv / url / packages / ...) into
//! [`dsl_kit::Op::apply`] — the `args` slice there only carries the
//! folded values of recursive children, which for our leaf ops is empty.
//! So the only way an op can reach its own payload is to look the node up
//! by id in a map built from the AST. [`build_payload_map`] walks the
//! tree once (via [`dsl_kit::Walk::children`]) and clones every node,
//! including the root, into that map.

use std::collections::HashMap;

use dsl_kit::{DslNode, NodeId, Walk};

use crate::profile_ast::ProfileNode;

/// Walk `root` depth-first and return a `NodeId -> ProfileNode` map
/// containing every node (root included), each cloned by value.
pub fn build_payload_map(root: &ProfileNode) -> HashMap<NodeId, ProfileNode> {
    fn collect(node: &ProfileNode, map: &mut HashMap<NodeId, ProfileNode>) {
        map.insert(node.node_id(), node.clone());
        for child in node.children() {
            collect(child, map);
        }
    }
    let mut map = HashMap::new();
    collect(root, &mut map);
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    #[test]
    fn map_contains_the_root_and_every_phase_node() {
        let ids = IdGen::new();
        let root_id = ids.node();
        let apt_id = ids.node();
        let sh_id = ids.node();

        let root = ProfileNode::Spec {
            assumes: Default::default(),
            requires_ports: Default::default(),
            requires_gpu: Default::default(),
            provider: Default::default(),
            id: root_id,
            name: "demo".to_string(),
            version: None,
            description: None,
            capabilities: vec!["sh.exec".to_string()],
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            paths: Vec::new(),
            http_allowlist: Vec::new(),
            phases: vec![
                ProfileNode::SystemApt {
                    id: apt_id,
                    packages: vec!["git".to_string()],
                },
                ProfileNode::ShExec {
                    id: sh_id,
                    argv: vec!["ls".to_string()],
                    env: Default::default(),
                },
            ],
        };

        let map = build_payload_map(&root);
        assert_eq!(map.len(), 3);
        assert!(matches!(map.get(&root_id), Some(ProfileNode::Spec { .. })));
        assert!(matches!(
            map.get(&apt_id),
            Some(ProfileNode::SystemApt { .. })
        ));
        assert!(matches!(map.get(&sh_id), Some(ProfileNode::ShExec { .. })));
    }
}
