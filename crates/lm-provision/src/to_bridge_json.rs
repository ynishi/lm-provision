//! Expanded [`ProfileNode`] AST → [`serde_json::Value`] serializer whose
//! output the JSON serde bridge accepts.
//!
//! # Why this is not `canonical::encode`
//!
//! [`crate::canonical`] is deliberately *not* re-parseable: it uses the
//! `{"__secret":"NAME"}` marker for [`ProfileNode::EnvSecret`] and the
//! `{"__env_ref":"NAME"}` marker for [`ProfileNode::EnvRef`], and it
//! writes an [`ProfileNode::EnvLiteral`] as a plain string in the
//! keyed-slot position. Those markers exist so the profile hash covers
//! *which secret* / *which entry* without carrying the resolved value —
//! a hash concern, not a shape the parser accepts.
//!
//! The JSON serde bridge parses env value nodes back into
//! [`ProfileNode`] variants through the schema's `"type"`-discriminated
//! object form: an env map value spells as
//! `{"type": "EnvLiteral", "value": "..."}`,
//! `{"type": "EnvSecret", "name": "..."}`, or
//! `{"type": "EnvRef", "name": "..."}`. This module emits that shape so
//! its output round-trips.
//!
//! # The invariant
//!
//! Every caller rests on one property (spec 11 §Cache last paragraph):
//!
//! ```text
//! canonical::hash(parse(to_bridge_json(ast))) == canonical::hash(ast)
//! ```
//!
//! In other words: serialize an expanded AST → parse the JSON back →
//! canonically encode both — the two hashes are equal. That is what
//! lets the cache store an expanded fragment as bridge JSON, read it
//! back, and use the recomputed hash to verify it against the pin (spec
//! 11 §Cache), and — later — what lets the driver upload an expanded
//! payload for the pod to re-parse and re-hash (chapter 08 steps 1-2).
//!
//! # Field-omission rules
//!
//! Optional fields (`Option<T>`) that are `None` omit the key.
//! Empty keyed maps (`env` / `headers`) also omit the key.
//! Vec<String> declared lists (`capabilities`, `paths`, etc.) always
//! emit — including as `[]` when empty — so the shape is unambiguous.
//! These rules mirror the JSON front-end's own "absent = default"
//! acceptance (see [`crate::frontend`] tests) and match what the
//! canonical byte encoder already treats as identity-preserving.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::profile_ast::ProfileNode;

/// Serialize `node` into a [`serde_json::Value`] the JSON serde bridge
/// re-parses to a canonically-equivalent AST.
///
/// The output's `"type"` discriminator, field names and nesting shape
/// are the JSON front-end's own: this is what a hand-authored profile
/// JSON looks like, just machine-generated.
pub fn to_bridge_json(node: &ProfileNode) -> Value {
    match node {
        ProfileNode::Spec {
            id: _,
            name,
            version,
            description,
            capabilities,
            env,
            env_secrets,
            paths,
            http_allowlist,
            sh_egress,
            assumes,
            requires_ports,
            requires_gpu,
            requires_disk,
            provider,
            artifacts,
            phases,
        } => {
            let mut obj = variant_object("Spec");
            obj.insert("name".into(), Value::String(name.clone()));
            insert_optional_str(&mut obj, "version", version);
            insert_optional_str(&mut obj, "description", description);
            obj.insert("capabilities".into(), string_array(capabilities));
            insert_value_map(&mut obj, "env", env);
            obj.insert("env_secrets".into(), string_array(env_secrets));
            obj.insert("paths".into(), string_array(paths));
            obj.insert("http_allowlist".into(), string_array(http_allowlist));
            insert_string_array_when_nonempty(&mut obj, "sh_egress", sh_egress);
            insert_str_map(&mut obj, "assumes", assumes);
            insert_str_map(&mut obj, "requires_ports", requires_ports);
            insert_str_map(&mut obj, "requires_gpu", requires_gpu);
            insert_str_map(&mut obj, "requires_disk", requires_disk);
            insert_str_map(&mut obj, "provider", provider);
            insert_string_array_when_nonempty(&mut obj, "artifacts", artifacts);
            obj.insert("phases".into(), phase_array(phases));
            Value::Object(obj)
        }
        ProfileNode::Fragment {
            id: _,
            name,
            version,
            description,
            capabilities,
            env,
            env_secrets,
            paths,
            http_allowlist,
            sh_egress,
            assumes,
            phases,
        } => {
            let mut obj = variant_object("Fragment");
            obj.insert("name".into(), Value::String(name.clone()));
            insert_optional_str(&mut obj, "version", version);
            insert_optional_str(&mut obj, "description", description);
            obj.insert("capabilities".into(), string_array(capabilities));
            insert_value_map(&mut obj, "env", env);
            obj.insert("env_secrets".into(), string_array(env_secrets));
            obj.insert("paths".into(), string_array(paths));
            obj.insert("http_allowlist".into(), string_array(http_allowlist));
            insert_string_array_when_nonempty(&mut obj, "sh_egress", sh_egress);
            insert_str_map(&mut obj, "assumes", assumes);
            obj.insert("phases".into(), phase_array(phases));
            Value::Object(obj)
        }
        ProfileNode::Import { id: _, src, hash } => {
            let mut obj = variant_object("Import");
            obj.insert("src".into(), Value::String(src.clone()));
            insert_optional_str(&mut obj, "hash", hash);
            Value::Object(obj)
        }
        ProfileNode::SystemApt { id: _, packages } => {
            let mut obj = variant_object("SystemApt");
            obj.insert("packages".into(), string_array(packages));
            Value::Object(obj)
        }
        ProfileNode::ComfyUiInstall {
            id: _,
            ref_name,
            repo,
            install_dir,
        } => {
            let mut obj = variant_object("ComfyUiInstall");
            obj.insert("ref_name".into(), Value::String(ref_name.clone()));
            insert_optional_str(&mut obj, "repo", repo);
            insert_optional_str(&mut obj, "install_dir", install_dir);
            Value::Object(obj)
        }
        ProfileNode::ToolchainPython {
            id: _,
            requirements,
            isolated,
        } => {
            let mut obj = variant_object("ToolchainPython");
            insert_optional_str(&mut obj, "requirements", requirements);
            obj.insert("isolated".into(), Value::Bool(*isolated));
            Value::Object(obj)
        }
        ProfileNode::PythonVersionCheck { id: _, want } => {
            let mut obj = variant_object("PythonVersionCheck");
            obj.insert("want".into(), Value::String(want.clone()));
            Value::Object(obj)
        }
        ProfileNode::PythonDeps {
            id: _,
            deps,
            in_comfy_venv,
        } => {
            let mut obj = variant_object("PythonDeps");
            obj.insert("deps".into(), string_array(deps));
            obj.insert("in_comfy_venv".into(), Value::Bool(*in_comfy_venv));
            Value::Object(obj)
        }
        ProfileNode::CustomNodes { id: _, nodes_json } => {
            let mut obj = variant_object("CustomNodes");
            obj.insert("nodes_json".into(), Value::String(nodes_json.clone()));
            Value::Object(obj)
        }
        ProfileNode::SyncPull {
            id: _,
            src,
            dst,
            env,
            revision,
        } => {
            let mut obj = variant_object("SyncPull");
            obj.insert("src".into(), Value::String(src.clone()));
            obj.insert("dst".into(), Value::String(dst.clone()));
            insert_value_map(&mut obj, "env", env);
            insert_optional_str(&mut obj, "revision", revision);
            Value::Object(obj)
        }
        ProfileNode::SyncPush { id: _, src, dst } => {
            let mut obj = variant_object("SyncPush");
            obj.insert("src".into(), Value::String(src.clone()));
            obj.insert("dst".into(), Value::String(dst.clone()));
            Value::Object(obj)
        }
        ProfileNode::StagingPush {
            id: _,
            src,
            dst,
            env,
            revision,
        } => {
            let mut obj = variant_object("StagingPush");
            obj.insert("src".into(), Value::String(src.clone()));
            obj.insert("dst".into(), Value::String(dst.clone()));
            insert_value_map(&mut obj, "env", env);
            insert_optional_str(&mut obj, "revision", revision);
            Value::Object(obj)
        }
        ProfileNode::Models { id: _, models_json } => {
            let mut obj = variant_object("Models");
            obj.insert("models_json".into(), Value::String(models_json.clone()));
            Value::Object(obj)
        }
        ProfileNode::LlmModels { id: _, models_json } => {
            let mut obj = variant_object("LlmModels");
            obj.insert("models_json".into(), Value::String(models_json.clone()));
            Value::Object(obj)
        }
        ProfileNode::PostInstall { id: _, script } => {
            let mut obj = variant_object("PostInstall");
            obj.insert("script".into(), Value::String(script.clone()));
            Value::Object(obj)
        }
        ProfileNode::ComfyUiRestart {
            id: _,
            port,
            extra_args,
        } => {
            let mut obj = variant_object("ComfyUiRestart");
            obj.insert("port".into(), json!(*port));
            insert_string_array_when_nonempty(&mut obj, "extra_args", extra_args);
            Value::Object(obj)
        }
        ProfileNode::ComfyUiHealth {
            id: _,
            port,
            timeout_sec,
        } => {
            let mut obj = variant_object("ComfyUiHealth");
            obj.insert("port".into(), json!(*port));
            insert_optional_u16(&mut obj, "timeout_sec", timeout_sec);
            Value::Object(obj)
        }
        ProfileNode::ServiceStart {
            id: _,
            name,
            platform_kind,
            model,
            port,
            dtype,
            tensor_parallel_size,
            extra_args,
        } => {
            let mut obj = variant_object("ServiceStart");
            obj.insert("name".into(), Value::String(name.clone()));
            obj.insert("platform_kind".into(), Value::String(platform_kind.clone()));
            insert_optional_str(&mut obj, "model", model);
            insert_optional_u16(&mut obj, "port", port);
            insert_optional_str(&mut obj, "dtype", dtype);
            insert_optional_u16(&mut obj, "tensor_parallel_size", tensor_parallel_size);
            insert_string_array_when_nonempty(&mut obj, "extra_args", extra_args);
            Value::Object(obj)
        }
        ProfileNode::ServiceReady {
            id: _,
            name,
            check_url,
            timeout_sec,
        } => {
            let mut obj = variant_object("ServiceReady");
            obj.insert("name".into(), Value::String(name.clone()));
            obj.insert("check_url".into(), Value::String(check_url.clone()));
            insert_optional_u16(&mut obj, "timeout_sec", timeout_sec);
            Value::Object(obj)
        }
        ProfileNode::ShExec { id: _, argv, env } => {
            let mut obj = variant_object("ShExec");
            obj.insert("argv".into(), string_array(argv));
            insert_value_map(&mut obj, "env", env);
            Value::Object(obj)
        }
        ProfileNode::FsWrite {
            id: _,
            path,
            content,
        } => {
            let mut obj = variant_object("FsWrite");
            obj.insert("path".into(), Value::String(path.clone()));
            // `content` is a value node — [`FsWrite::content`] is
            // `Box<ProfileNode>` — so it round-trips through the same
            // discriminated-object shape env-map values use, rather than
            // the bare-string shorthand the JSON frontend also accepts.
            obj.insert("content".into(), to_bridge_json(content));
            Value::Object(obj)
        }
        ProfileNode::NetHttpGet {
            id: _,
            url,
            headers,
            timeout_sec,
        } => {
            let mut obj = variant_object("NetHttpGet");
            obj.insert("url".into(), Value::String(url.clone()));
            insert_value_map(&mut obj, "headers", headers);
            insert_optional_u16(&mut obj, "timeout_sec", timeout_sec);
            Value::Object(obj)
        }
        ProfileNode::NetHttpPost {
            id: _,
            url,
            headers,
            body,
            body_json,
            timeout_sec,
        } => {
            let mut obj = variant_object("NetHttpPost");
            obj.insert("url".into(), Value::String(url.clone()));
            insert_value_map(&mut obj, "headers", headers);
            if let Some(body) = body {
                obj.insert("body".into(), to_bridge_json(body));
            }
            insert_optional_str(&mut obj, "body_json", body_json);
            insert_optional_u16(&mut obj, "timeout_sec", timeout_sec);
            Value::Object(obj)
        }
        ProfileNode::NetTransfer { id: _, src, dst } => {
            let mut obj = variant_object("NetTransfer");
            obj.insert("src".into(), Value::String(src.clone()));
            obj.insert("dst".into(), Value::String(dst.clone()));
            Value::Object(obj)
        }
        ProfileNode::MountBind { id: _, src, dst } => {
            let mut obj = variant_object("MountBind");
            obj.insert("src".into(), Value::String(src.clone()));
            obj.insert("dst".into(), Value::String(dst.clone()));
            Value::Object(obj)
        }
        ProfileNode::MountUmount { id: _, path } => {
            let mut obj = variant_object("MountUmount");
            obj.insert("path".into(), Value::String(path.clone()));
            Value::Object(obj)
        }
        ProfileNode::EnvLiteral { id: _, value } => json!({
            "type": "EnvLiteral",
            "value": value,
        }),
        ProfileNode::EnvSecret { id: _, name } => json!({
            "type": "EnvSecret",
            "name": name,
        }),
        ProfileNode::EnvRef { id: _, name } => json!({
            "type": "EnvRef",
            "name": name,
        }),
    }
}

fn variant_object(name: &str) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String(name.into()));
    obj
}

fn string_array(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
}

fn phase_array(phases: &[ProfileNode]) -> Value {
    Value::Array(phases.iter().map(to_bridge_json).collect())
}

fn insert_optional_str(obj: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        obj.insert(key.into(), Value::String(v.clone()));
    }
}

fn insert_optional_u16(obj: &mut Map<String, Value>, key: &str, value: &Option<u16>) {
    if let Some(v) = value {
        obj.insert(key.into(), json!(*v));
    }
}

fn insert_string_array_when_nonempty(obj: &mut Map<String, Value>, key: &str, items: &[String]) {
    if !items.is_empty() {
        obj.insert(key.into(), string_array(items));
    }
}

fn insert_str_map(obj: &mut Map<String, Value>, key: &str, map: &BTreeMap<String, String>) {
    if map.is_empty() {
        return;
    }
    let mut inner = Map::new();
    for (k, v) in map {
        inner.insert(k.clone(), Value::String(v.clone()));
    }
    obj.insert(key.into(), Value::Object(inner));
}

fn insert_value_map(obj: &mut Map<String, Value>, key: &str, map: &BTreeMap<String, ProfileNode>) {
    if map.is_empty() {
        return;
    }
    let mut inner = Map::new();
    for (k, v) in map {
        inner.insert(k.clone(), to_bridge_json(v));
    }
    obj.insert(key.into(), Value::Object(inner));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical;
    use crate::frontend;
    use crate::profile_ast::ProfileNode;
    use dsl_kit::IdGen;
    use dsl_kit_parse::{example_gen, schema_gen, DslBuild as _};
    use dsl_kit_schema::DslSchema as _;
    use serde_json::json;

    /// Parse `text` through the canonical text grammar into a
    /// [`ProfileNode`]. Small helper because the schema + overrides
    /// wiring is verbose and every invariant test needs it.
    fn parse_text(text: &str, ids: &IdGen) -> ProfileNode {
        let schema = ProfileNode::schema();
        let overrides = frontend::profile_syntax_overrides_for_test();
        let grammar = schema_gen::checked_grammar_from_schema_with(&schema, ids, &overrides)
            .expect("grammar generation must succeed");
        let tree = grammar
            .parse(text)
            .expect("example must parse against the generated grammar");
        ProfileNode::from_parse_tree(&tree, ids).expect("parse tree must build")
    }

    /// Parse `value` through the JSON serde bridge into a [`ProfileNode`].
    fn parse_json(value: &serde_json::Value, ids: &IdGen) -> ProfileNode {
        let schema = ProfileNode::schema();
        let tree = dsl_kit_parse::serde_bridge::from_json_value(value, &schema)
            .expect("bridge JSON must parse");
        ProfileNode::from_parse_tree(&tree, ids).expect("parse tree must build")
    }

    /// The core invariant: for every AST reachable via example_gen's
    /// grammar walk, serialize → reparse → canonically-encode yields the
    /// same bytes (and therefore the same hash). If example_gen extends
    /// to cover a new variant, this test picks it up automatically; if
    /// a variant is deliberately unreachable via example_gen (`Import` /
    /// `Fragment` — the depth-2 rich composite emits them via
    /// `Fragment`-inside-`Spec`, but the per-rule minimal examples for
    /// `Import` / `Fragment` are also covered) the fallbacks below add
    /// explicit fixtures.
    #[test]
    fn every_variant_round_trips_through_the_bridge_serializer() {
        let ids = IdGen::new();
        let schema = ProfileNode::schema();
        let overrides = frontend::profile_syntax_overrides_for_test();
        let grammar = schema_gen::checked_grammar_from_schema_with(&schema, &ids, &overrides)
            .expect("grammar generation must succeed for the ProfileNode schema");
        let examples =
            example_gen::examples_from_grammar(&grammar).expect("example synthesis must succeed");

        assert!(
            !examples.per_rule.is_empty(),
            "example_gen must yield at least one variant example"
        );

        for example in &examples.per_rule {
            // Per-rule examples enter at their variant's own rule and
            // may be minimal enough that required fields are absent —
            // that is a shape of the grammar, not of this serializer.
            // Skip a per-rule example whose parse tree cannot build
            // into a typed AST; the composite path below exercises the
            // recursive full-profile shape either way, and the explicit
            // fixtures cover the omitted variants.
            let ids_a = IdGen::new();
            let overrides = frontend::profile_syntax_overrides_for_test();
            let grammar = schema_gen::checked_grammar_from_schema_with(&schema, &ids_a, &overrides)
                .expect("grammar generation must succeed for the ProfileNode schema");
            let Ok(tree) = grammar.parse(&example.text) else {
                continue;
            };
            let Ok(ast_a) = ProfileNode::from_parse_tree(&tree, &ids_a) else {
                continue;
            };

            let bridge = to_bridge_json(&ast_a);
            let ast_b = parse_json(&bridge, &IdGen::new());

            assert_eq!(
                canonical::encode(&ast_a),
                canonical::encode(&ast_b),
                "variant {} did not round-trip",
                example.rule,
            );
        }

        // The rich composite covers the recursive shape (a Spec whose
        // phases include most other variants at depth). Round-trip that
        // too so the top-level shape is exercised even if per-rule
        // examples cannot enter at the start rule.
        let ast_a = parse_text(&examples.composite, &IdGen::new());
        let bridge = to_bridge_json(&ast_a);
        let ast_b = parse_json(&bridge, &IdGen::new());
        assert_eq!(canonical::encode(&ast_a), canonical::encode(&ast_b));
    }

    /// Explicit coverage for the variants example_gen may not surface
    /// standalone (`Import` and `Fragment` — every phase list they
    /// synthesize embeds them inside a `Spec`, so the per-rule pass
    /// above only reaches them by chance). The invariant is the same:
    /// serialize + reparse + canonical → equal bytes.
    #[test]
    fn fragment_and_import_variants_round_trip_explicitly() {
        for value in [
            json!({
                "type": "Fragment",
                "name": "explicit-frag",
                "version": "0.1.0",
                "description": "explicit fragment fixture",
                "capabilities": ["sh.exec"],
                "env": {
                    "TOKEN": { "type": "EnvSecret", "name": "TOKEN" },
                    "SEEN": { "type": "EnvLiteral", "value": "yes" }
                },
                "env_secrets": ["TOKEN"],
                "paths": ["/workspace"],
                "http_allowlist": ["https://example.com/"],
                "sh_egress": ["*.hf.co"],
                "assumes": { "comfyui_root": "/workspace/ComfyUI" },
                "phases": [
                    { "type": "ShExec", "argv": ["echo", "ok"] },
                    { "type": "Import", "src": "./inner.json",
                      "hash": "0000000000000000000000000000000000000000000000000000000000000000" }
                ]
            }),
            json!({
                "type": "Import",
                "src": "https://example.com/frag.json",
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ] {
            let ast_a = parse_json(&value, &IdGen::new());
            let bridge = to_bridge_json(&ast_a);
            let ast_b = parse_json(&bridge, &IdGen::new());
            assert_eq!(canonical::encode(&ast_a), canonical::encode(&ast_b));
        }
    }

    /// `EnvRef` never lowers as its own top-level example (it is only
    /// legal as a value in a keyed slot), so it needs its own fixture —
    /// a Spec whose `env` includes an EnvRef, whose phase's `env`
    /// references it.
    #[test]
    fn env_ref_value_nodes_round_trip() {
        let value = json!({
            "type": "Spec",
            "name": "envref-fixture",
            "capabilities": ["sh.exec"],
            "env_secrets": ["HF_TOKEN"],
            "env": {
                "TOKEN": { "type": "EnvSecret", "name": "HF_TOKEN" }
            },
            "phases": [
                {
                    "type": "ShExec",
                    "argv": ["echo", "ok"],
                    "env": {
                        "PASSED": { "type": "EnvRef", "name": "TOKEN" }
                    }
                }
            ]
        });
        let ast_a = parse_json(&value, &IdGen::new());
        let bridge = to_bridge_json(&ast_a);
        let ast_b = parse_json(&bridge, &IdGen::new());
        assert_eq!(canonical::encode(&ast_a), canonical::encode(&ast_b));
    }
}
