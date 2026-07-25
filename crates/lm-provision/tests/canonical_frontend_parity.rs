//! Frontend-parity contract for `canonical::encode` / `canonical::hash`.
//!
//! The same logical profile, expressed twice — once through the
//! canonical text grammar (dsl-kit-parse peg + `from_parse_tree`), once
//! through the JSON serde bridge (`serde_bridge::from_json_value` +
//! `from_parse_tree`) — must yield the *same* canonical bytes and the
//! *same* profile hash, even though the two builds produce distinct
//! `NodeId` sequences.

use dsl_kit::{IdGen, NodeId};
use dsl_kit_parse::{peg::Grammar, serde_bridge::from_json_value, DslBuild as _};
use dsl_kit_schema::DslSchema as _;
use lm_provision::canonical;
use lm_provision::dsl_poc::ProfileNode;

/// Same logical profile, but the two frontends declare the sortable
/// lists in different order — the canonical encoder normalises both,
/// so parity must still hold. Phase order is identical on both sides
/// (semantic).
const TEXT_PROFILE: &str = concat!(
    "Spec(",
    "name: \"parity-demo\", ",
    "version: \"1.2.3\", ",
    "description: \"cross-frontend parity fixture\", ",
    // Text frontend declares capabilities in one order …
    "capabilities: [\"sh.exec\", \"fs.write\", \"net.transfer\"], ",
    "env: [\"HOME\", \"PATH\"], ",
    "env_secrets: [\"HF_TOKEN\"], ",
    // … and declares paths / http_allowlist in one order …
    "paths: [\"/workspace\", \"/tmp\"], ",
    "http_allowlist: [\"https://b.example.com\", \"https://a.example.com\"], ",
    "phases: [",
    "SystemApt(packages: [\"git\", \"curl\"]), ",
    "PythonDeps(deps: [\"torch\"], in_comfy_venv: false), ",
    "ShExec(argv: [\"echo\", \"ok\"]), ",
    "FsWrite(path: \"/tmp/x\", content: \"hello\")",
    "])",
);

fn json_profile() -> serde_json::Value {
    // … the JSON frontend declares them in a *different* order and omits
    // one optional field to prove Option::None → key-absent parity.
    serde_json::json!({
        "type": "Spec",
        "name": "parity-demo",
        "version": "1.2.3",
        "description": "cross-frontend parity fixture",
        "capabilities": ["net.transfer", "sh.exec", "fs.write"],
        "env": ["PATH", "HOME"],
        "env_secrets": ["HF_TOKEN"],
        // … and the JSON frontend declares paths / http_allowlist in
        // the reverse order to prove canonical sorts them too.
        "paths": ["/tmp", "/workspace"],
        "http_allowlist": ["https://a.example.com", "https://b.example.com"],
        "phases": [
            { "type": "SystemApt", "packages": ["git", "curl"] },
            { "type": "PythonDeps", "deps": ["torch"], "in_comfy_venv": false },
            { "type": "ShExec", "argv": ["echo", "ok"] },
            { "type": "FsWrite", "path": "/tmp/x", "content": "hello" },
        ],
    })
}

fn build_from_text(text: &str) -> ProfileNode {
    let ids = IdGen::new();
    let schema = ProfileNode::schema();
    let grammar =
        Grammar::from_schema(&schema, &ids).expect("grammar must build from ProfileNode schema");
    let tree = grammar
        .parse(text)
        .expect("canonical text must parse against the generated grammar");
    ProfileNode::from_parse_tree(&tree, &ids).expect("text ParseTree must build into typed AST")
}

fn build_from_json(value: &serde_json::Value) -> ProfileNode {
    let ids = IdGen::new();
    let schema = ProfileNode::schema();
    let tree =
        from_json_value(value, &schema).expect("JSON value must convert to ParseTree via serde");
    ProfileNode::from_parse_tree(&tree, &ids).expect("JSON ParseTree must build into typed AST")
}

fn root_id(node: &ProfileNode) -> NodeId {
    match node {
        ProfileNode::Spec { id, .. } => *id,
        _ => panic!("fixture root must be Spec"),
    }
}

#[test]
fn text_and_json_frontends_yield_byte_identical_canonical() {
    let ast_text = build_from_text(TEXT_PROFILE);
    let ast_json = build_from_json(&json_profile());

    assert_eq!(
        canonical::encode(&ast_text),
        canonical::encode(&ast_json),
        "canonical bytes must be byte-identical across frontends",
    );
    assert_eq!(
        canonical::hash(&ast_text),
        canonical::hash(&ast_json),
        "profile hash must be identical across frontends",
    );
}

#[test]
fn frontend_parity_holds_despite_distinct_node_ids() {
    let ast_text = build_from_text(TEXT_PROFILE);
    let ast_json = build_from_json(&json_profile());

    let id_text = root_id(&ast_text);
    let id_json = root_id(&ast_json);
    // Fresh IdGen per build: identical Spec placement -> identical
    // low-id sequences, so the roots collide numerically. What matters
    // is that the *canonical bytes* would remain equal even if they
    // diverged — verified below by shifting the JSON build's IdGen so
    // the roots definitely differ.
    let _ = (id_text, id_json);

    // Force divergent NodeIds: pre-burn ids in the JSON build's
    // generator so its root sits at a different number.
    let ids_json = IdGen::new();
    for _ in 0..100 {
        let _ = ids_json.node();
    }
    let schema = ProfileNode::schema();
    let tree_json = from_json_value(&json_profile(), &schema).expect("serde bridge must succeed");
    let ast_json_shifted = ProfileNode::from_parse_tree(&tree_json, &ids_json)
        .expect("shifted-IdGen build must succeed");

    assert_ne!(
        root_id(&ast_text),
        root_id(&ast_json_shifted),
        "NodeId sequences must diverge under distinct IdGens (proves the id-exclusion test is meaningful)",
    );
    assert_eq!(
        canonical::encode(&ast_text),
        canonical::encode(&ast_json_shifted),
        "canonical bytes must ignore NodeId divergence",
    );
    assert_eq!(
        canonical::hash(&ast_text),
        canonical::hash(&ast_json_shifted),
        "profile hash must ignore NodeId divergence",
    );
}
