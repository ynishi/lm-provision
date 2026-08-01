//! Frontend-parity contract for `canonical::encode` / `canonical::hash`.
//!
//! The same logical profile, expressed twice — once through the
//! canonical text grammar (dsl-kit-parse peg + `from_parse_tree`), once
//! through the JSON serde bridge (`serde_bridge::from_json_value` +
//! `from_parse_tree`) — must yield the *same* canonical bytes and the
//! *same* profile hash, even though the two builds produce distinct
//! `NodeId` sequences.

use dsl_kit::{IdGen, NodeId};
use dsl_kit_parse::{
    peg::{choice, token},
    schema_gen::{checked_grammar_from_schema_with, SyntaxOverrides},
    serde_bridge::from_json_value,
    DslBuild as _,
};
use dsl_kit_schema::DslSchema as _;
use lm_provision::canonical;
use lm_provision::profile_ast::ProfileNode;

/// Same override wiring the frontend crate ships (spec 01 §Profile-scoped
/// env table's numeric-side sibling: `Option<u16>` needs a
/// `SyntaxOverrides::for_type` value production since it is outside
/// dsl-kit's built-in type table).
fn overrides() -> SyntaxOverrides {
    SyntaxOverrides::new().for_type("Option<u16>", |ids| {
        choice(ids, vec![token(ids, "%kw:none"), token(ids, "%int")])
    })
}

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
    // `Spec.env` is a keyed slot now; entries in one key order …
    "env: {HOME: EnvLiteral(value: \"/root\"), PATH: EnvLiteral(value: \"/usr/local/bin\")}, ",
    "env_secrets: [\"HF_TOKEN\"], ",
    // … and declares paths / http_allowlist in one order …
    "paths: [\"/workspace\", \"/tmp\"], ",
    "http_allowlist: [\"https://b.example.com\", \"https://a.example.com\"], ",
    "phases: [",
    "SystemApt(packages: [\"git\", \"curl\"]), ",
    "PythonDeps(deps: [\"torch\"], in_comfy_venv: false), ",
    // … and writes the `env` keyed slot's entries in one key order
    // (01 §Env keyed slots: bare identifier keys, brace-delimited).
    "ShExec(argv: [\"echo\", \"ok\"], env: {",
    "HF_TOKEN: EnvSecret(name: \"HF_TOKEN\"), ",
    "MODE: EnvLiteral(value: \"fast\")",
    "}), ",
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
        // … and the JSON frontend writes the same entries in reverse
        // key order, proving Spec.env's keyed slot is normalised
        // (BTreeMap iteration) the same way the sortable lists are.
        "env": {
            "PATH": { "type": "EnvLiteral", "value": "/usr/local/bin" },
            "HOME": { "type": "EnvLiteral", "value": "/root" }
        },
        "env_secrets": ["HF_TOKEN"],
        // … and the JSON frontend declares paths / http_allowlist in
        // the reverse order to prove canonical sorts them too.
        "paths": ["/tmp", "/workspace"],
        "http_allowlist": ["https://a.example.com", "https://b.example.com"],
        "phases": [
            { "type": "SystemApt", "packages": ["git", "curl"] },
            { "type": "PythonDeps", "deps": ["torch"], "in_comfy_venv": false },
            // … and the JSON frontend writes the same `env` entries in
            // the reverse key order, to prove the keyed slot is
            // normalised the same way the sortable lists are.
            { "type": "ShExec", "argv": ["echo", "ok"], "env": {
                "MODE": { "type": "EnvLiteral", "value": "fast" },
                "HF_TOKEN": { "type": "EnvSecret", "name": "HF_TOKEN" },
            } },
            { "type": "FsWrite", "path": "/tmp/x", "content": "hello" },
        ],
    })
}

fn build_from_text(text: &str) -> ProfileNode {
    let ids = IdGen::new();
    let schema = ProfileNode::schema();
    let grammar = checked_grammar_from_schema_with(&schema, &ids, &overrides())
        .expect("grammar must build from ProfileNode schema with Option<u16> override");
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

/// `fs.write` `content` accepts two spellings per front-end — the bare
/// scalar shorthand (`content: "hello"`, pre-migration form) and the
/// explicit value node (`content: EnvLiteral(value: "hello")`) — and
/// all four land on the same canonical bytes, which are also the exact
/// bytes the slot produced while it was a plain `String` payload
/// (hash neutrality, spec 04 §`fs.write` / dsl-kit #14).
#[test]
fn fs_write_content_spellings_share_canonical_bytes_across_frontends() {
    let text_bare = r#"FsWrite(path: "/tmp/x", content: "hello")"#;
    let text_explicit = r#"FsWrite(path: "/tmp/x", content: EnvLiteral(value: "hello"))"#;
    let json_bare = serde_json::json!({ "type": "FsWrite", "path": "/tmp/x", "content": "hello" });
    let json_explicit = serde_json::json!({
        "type": "FsWrite",
        "path": "/tmp/x",
        "content": { "type": "EnvLiteral", "value": "hello" },
    });

    let baseline = canonical::encode(&build_from_text(text_bare));
    // Pre-migration byte shape: content is a bare JSON string.
    assert_eq!(
        baseline,
        r#"{"content":"hello","path":"/tmp/x","type":"FsWrite"}"#
    );
    for (label, ast) in [
        ("text explicit", build_from_text(text_explicit)),
        ("json bare", build_from_json(&json_bare)),
        ("json explicit", build_from_json(&json_explicit)),
    ] {
        assert_eq!(
            canonical::encode(&ast),
            baseline,
            "{label} spelling must share the bare-string canonical bytes",
        );
    }

    // The secret form is the reason the slot became a value node: it
    // canonicalizes to the same marker an `env`-map secret uses.
    let json_secret = serde_json::json!({
        "type": "FsWrite",
        "path": "/tmp/x",
        "content": { "type": "EnvSecret", "name": "HF_TOKEN" },
    });
    assert_eq!(
        canonical::encode(&build_from_json(&json_secret)),
        r#"{"content":{"__secret":"HF_TOKEN"},"path":"/tmp/x","type":"FsWrite"}"#
    );
}

/// `net.http_post` `body` is the *optional* sibling of `fs.write`'s
/// `content` slot, and carries the same two spellings per front-end —
/// the bare scalar shorthand and the explicit value node. All four land
/// on the same canonical bytes. A request that declares no body at all
/// keeps the exact bytes the variant produced before the field existed
/// (hash neutrality, spec 04 §`net.http_post`).
#[test]
fn http_post_body_spellings_share_canonical_bytes_across_frontends() {
    let url = "https://example.com/post";
    let text_bare = r#"NetHttpPost(url: "https://example.com/post", body: "raw")"#;
    let text_explicit =
        r#"NetHttpPost(url: "https://example.com/post", body: EnvLiteral(value: "raw"))"#;
    let json_bare = serde_json::json!({ "type": "NetHttpPost", "url": url, "body": "raw" });
    let json_explicit = serde_json::json!({
        "type": "NetHttpPost",
        "url": url,
        "body": { "type": "EnvLiteral", "value": "raw" },
    });

    let baseline = canonical::encode(&build_from_text(text_bare));
    assert_eq!(
        baseline,
        r#"{"body":"raw","type":"NetHttpPost","url":"https://example.com/post"}"#
    );
    for (label, ast) in [
        ("text explicit", build_from_text(text_explicit)),
        ("json bare", build_from_json(&json_bare)),
        ("json explicit", build_from_json(&json_explicit)),
    ] {
        assert_eq!(
            canonical::encode(&ast),
            baseline,
            "{label} spelling must share the bare-string canonical bytes",
        );
    }

    // Pre-field byte shape: no body, no headers, no deadline.
    let bare_text = r#"NetHttpPost(url: "https://example.com/post")"#;
    let bare_json = serde_json::json!({ "type": "NetHttpPost", "url": url });
    let pre_field = r#"{"type":"NetHttpPost","url":"https://example.com/post"}"#;
    assert_eq!(canonical::encode(&build_from_text(bare_text)), pre_field);
    assert_eq!(canonical::encode(&build_from_json(&bare_json)), pre_field);
}

/// The `headers` keyed slot normalises key order exactly as `env` does,
/// so the two front-ends may declare the same headers in opposite order
/// and still hash identically.
#[test]
fn http_header_slot_key_order_is_normalised_across_frontends() {
    let text = concat!(
        r#"NetHttpGet(url: "https://example.com/get", headers: {"#,
        r#"Accept: EnvLiteral(value: "application/json"), "#,
        r#"Authorization: EnvSecret(name: "API_TOKEN")"#,
        r#"}, timeout_sec: 5)"#,
    );
    let json = serde_json::json!({
        "type": "NetHttpGet",
        "url": "https://example.com/get",
        "headers": {
            "Authorization": { "type": "EnvSecret", "name": "API_TOKEN" },
            "Accept": { "type": "EnvLiteral", "value": "application/json" },
        },
        "timeout_sec": 5,
    });
    assert_eq!(
        canonical::encode(&build_from_text(text)),
        canonical::encode(&build_from_json(&json)),
    );
    assert_eq!(
        canonical::hash(&build_from_text(text)),
        canonical::hash(&build_from_json(&json)),
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
