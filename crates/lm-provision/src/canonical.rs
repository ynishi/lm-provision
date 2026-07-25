//! Canonical byte encoding + profile hash over the `ProfileNode` AST.
//!
//! Respecified from the legacy Lua IR encoding onto the typed AST
//! (spec `03-pipeline-stage-artifacts.md` §canonical / §hash). The
//! contract: two frontends (text grammar / JSON serde) that represent
//! the same logical profile yield the same [`ProfileNode`] AST, and
//! therefore the same canonical bytes and the same hash.
//!
//! The encoding is derived from the AST *structure* alone (not from
//! the wire text): whitespace, key order, and optional-field spelling
//! never enter the byte stream.
//!
//! Rules (respec highlights vs the Lua IR encoding):
//!
//! - `NodeId` is excluded from every variant. IdGen mints fresh ids
//!   per parse-run; keeping them in canonical would break the
//!   frontend-parity guarantee that is the point of this module.
//! - the `Spec` fields `capabilities`, `env`, `env_secrets`, `paths`,
//!   and `http_allowlist` are declaration-order independent
//!   (set-shaped) — canonical sorts them lexicographically before
//!   encoding (the AST itself is not mutated).
//! - `Spec.phases` is order-preserving (phase order is semantic).
//! - `Option::None` omits the key; `Option::Some(x)` emits it.
//! - Empty `Vec` encodes as `[]` (the typed AST removes the
//!   array/object ambiguity that motivated the legacy
//!   empty-table-as-`{}` rule).
//! - No secret-marker rule: the current AST has no secret *value*
//!   type; `env_secrets` carries only *names* (bare strings).
//! - Object keys are the Rust field identifiers; variant tag is the
//!   Rust variant name emitted under the `"type"` key (matching the
//!   JSON serde bridge's `"type"` discriminator).
//! - String escape (`"` `\` named control + `<0x20` as `\u00xx`
//!   lowercase hex), object-key lexicographic order, array order,
//!   and 64-char lowercase-hex SHA-256 output match the legacy
//!   contract byte-for-byte.
//!
//! Decode is out of scope: the current ledger persists JSON Lines and
//! does not require canonical→AST reconstruction.

use crate::dsl_poc::ProfileNode;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Intermediate canonical value.
///
/// `BTreeMap` fixes object key order to lexicographic by
/// construction; `Array` preserves insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CanonValue {
    Object(BTreeMap<String, CanonValue>),
    Array(Vec<CanonValue>),
    Str(String),
    Int(i64),
    Bool(bool),
}

/// Canonically encode `node` to deterministic JSON bytes.
///
/// Byte-identical for AST-equal inputs regardless of the frontend
/// that produced them: `NodeId` is excluded, declared lists are
/// sorted, phase order is preserved.
pub fn encode(node: &ProfileNode) -> String {
    let canon = to_canon(node);
    let mut out = String::new();
    write_canon(&canon, &mut out);
    out
}

/// SHA-256 of [`encode(node)`], lowercase hex, no prefix (64 chars).
pub fn hash(node: &ProfileNode) -> String {
    let bytes = encode(node);
    let digest = Sha256::digest(bytes.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        // `format!("{byte:02x}")` guarantees two lowercase hex chars.
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// ---------------------------------------------------------------------
// to_canon: ProfileNode -> CanonValue
// ---------------------------------------------------------------------

fn to_canon(node: &ProfileNode) -> CanonValue {
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
            phases,
        } => {
            let mut fields = variant_object("Spec");
            fields.insert("name".into(), CanonValue::Str(name.clone()));
            insert_optional_str(&mut fields, "version", version);
            insert_optional_str(&mut fields, "description", description);
            fields.insert("capabilities".into(), sorted_string_array(capabilities));
            fields.insert("env".into(), sorted_string_array(env));
            fields.insert("env_secrets".into(), sorted_string_array(env_secrets));
            fields.insert("http_allowlist".into(), sorted_string_array(http_allowlist));
            fields.insert("paths".into(), sorted_string_array(paths));
            fields.insert(
                "phases".into(),
                CanonValue::Array(phases.iter().map(to_canon).collect()),
            );
            CanonValue::Object(fields)
        }

        ProfileNode::SystemApt { id: _, packages } => {
            let mut fields = variant_object("SystemApt");
            fields.insert("packages".into(), string_array(packages));
            CanonValue::Object(fields)
        }

        ProfileNode::ComfyUiInstall {
            id: _,
            ref_name,
            repo,
        } => {
            let mut fields = variant_object("ComfyUiInstall");
            fields.insert("ref_name".into(), CanonValue::Str(ref_name.clone()));
            insert_optional_str(&mut fields, "repo", repo);
            CanonValue::Object(fields)
        }

        ProfileNode::PythonVersionCheck { id: _, want } => {
            let mut fields = variant_object("PythonVersionCheck");
            fields.insert("want".into(), CanonValue::Str(want.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::PythonDeps {
            id: _,
            deps,
            in_comfy_venv,
        } => {
            let mut fields = variant_object("PythonDeps");
            fields.insert("deps".into(), string_array(deps));
            fields.insert("in_comfy_venv".into(), CanonValue::Bool(*in_comfy_venv));
            CanonValue::Object(fields)
        }

        ProfileNode::CustomNodes { id: _, nodes_json } => {
            let mut fields = variant_object("CustomNodes");
            fields.insert("nodes_json".into(), CanonValue::Str(nodes_json.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::SyncPull { id: _, src, dst } => {
            let mut fields = variant_object("SyncPull");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::SyncPush { id: _, src, dst } => {
            let mut fields = variant_object("SyncPush");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::StagingPush { id: _, src, dst } => {
            let mut fields = variant_object("StagingPush");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::Models { id: _, models_json } => {
            let mut fields = variant_object("Models");
            fields.insert("models_json".into(), CanonValue::Str(models_json.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::LlmModels { id: _, models_json } => {
            let mut fields = variant_object("LlmModels");
            fields.insert("models_json".into(), CanonValue::Str(models_json.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::PostInstall { id: _, script } => {
            let mut fields = variant_object("PostInstall");
            fields.insert("script".into(), CanonValue::Str(script.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::ComfyUiRestart { id: _, port } => {
            let mut fields = variant_object("ComfyUiRestart");
            fields.insert("port".into(), CanonValue::Int(i64::from(*port)));
            CanonValue::Object(fields)
        }

        ProfileNode::ComfyUiHealth { id: _, port } => {
            let mut fields = variant_object("ComfyUiHealth");
            fields.insert("port".into(), CanonValue::Int(i64::from(*port)));
            CanonValue::Object(fields)
        }

        ProfileNode::ServiceStart {
            id: _,
            name,
            platform_kind,
        } => {
            let mut fields = variant_object("ServiceStart");
            fields.insert("name".into(), CanonValue::Str(name.clone()));
            fields.insert(
                "platform_kind".into(),
                CanonValue::Str(platform_kind.clone()),
            );
            CanonValue::Object(fields)
        }

        ProfileNode::ServiceReady {
            id: _,
            name,
            check_url,
        } => {
            let mut fields = variant_object("ServiceReady");
            fields.insert("name".into(), CanonValue::Str(name.clone()));
            fields.insert("check_url".into(), CanonValue::Str(check_url.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::ShExec { id: _, argv } => {
            let mut fields = variant_object("ShExec");
            fields.insert("argv".into(), string_array(argv));
            CanonValue::Object(fields)
        }

        ProfileNode::FsWrite {
            id: _,
            path,
            content,
        } => {
            let mut fields = variant_object("FsWrite");
            fields.insert("path".into(), CanonValue::Str(path.clone()));
            fields.insert("content".into(), CanonValue::Str(content.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::NetHttpGet { id: _, url } => {
            let mut fields = variant_object("NetHttpGet");
            fields.insert("url".into(), CanonValue::Str(url.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::NetHttpPost { id: _, url } => {
            let mut fields = variant_object("NetHttpPost");
            fields.insert("url".into(), CanonValue::Str(url.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::NetTransfer { id: _, src, dst } => {
            let mut fields = variant_object("NetTransfer");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::MountBind { id: _, src, dst } => {
            let mut fields = variant_object("MountBind");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::MountUmount { id: _, path } => {
            let mut fields = variant_object("MountUmount");
            fields.insert("path".into(), CanonValue::Str(path.clone()));
            CanonValue::Object(fields)
        }
    }
}

fn variant_object(name: &str) -> BTreeMap<String, CanonValue> {
    let mut map = BTreeMap::new();
    map.insert("type".into(), CanonValue::Str(name.into()));
    map
}

fn insert_optional_str(
    fields: &mut BTreeMap<String, CanonValue>,
    key: &str,
    value: &Option<String>,
) {
    if let Some(v) = value {
        fields.insert(key.into(), CanonValue::Str(v.clone()));
    }
}

fn string_array(items: &[String]) -> CanonValue {
    CanonValue::Array(items.iter().map(|s| CanonValue::Str(s.clone())).collect())
}

fn sorted_string_array(items: &[String]) -> CanonValue {
    let mut sorted: Vec<String> = items.to_vec();
    sorted.sort();
    string_array(&sorted)
}

// ---------------------------------------------------------------------
// write_canon: CanonValue -> deterministic JSON bytes
// ---------------------------------------------------------------------

fn write_canon(value: &CanonValue, out: &mut String) {
    match value {
        CanonValue::Object(map) => {
            out.push('{');
            let mut first = true;
            for (k, v) in map {
                if !first {
                    out.push(',');
                }
                first = false;
                write_string(k, out);
                out.push(':');
                write_canon(v, out);
            }
            out.push('}');
        }
        CanonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canon(item, out);
            }
            out.push(']');
        }
        CanonValue::Str(s) => write_string(s, out),
        CanonValue::Int(n) => out.push_str(&format!("{n}")),
        CanonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
    }
}

/// Writes `s` as a JSON string literal (surrounding quotes included),
/// matching the legacy Lua encode byte-for-byte:
///
/// - `"` `\` and the named control escapes (`\n` `\r` `\t` `\b` `\f`);
/// - any other codepoint `< 0x20` as `\u00xx` (lowercase hex);
/// - every other character passes through raw (its UTF-8 byte
///   sequence).
///
/// Iterating by `char` is equivalent to the Lua byte-level pass-through
/// on UTF-8 input: every byte the Lua encoder would escape (`"`, `\`,
/// or a control byte `< 0x20`) is a single-byte UTF-8 codepoint, and
/// every other char re-encodes to its original UTF-8 bytes when pushed
/// back into a `String`.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::{IdGen, NodeId};

    fn new_id(gen: &IdGen) -> NodeId {
        gen.node()
    }

    fn empty_spec(gen: &IdGen, name: &str) -> ProfileNode {
        ProfileNode::Spec {
            id: new_id(gen),
            name: name.into(),
            version: None,
            description: None,
            capabilities: vec![],
            env: vec![],
            env_secrets: vec![],
            paths: vec![],
            http_allowlist: vec![],
            phases: vec![],
        }
    }

    #[test]
    fn nodeid_is_excluded_from_canonical() {
        let gen = IdGen::new();
        let a = ProfileNode::ShExec {
            id: new_id(&gen),
            argv: vec!["ls".into(), "-la".into()],
        };
        let b = ProfileNode::ShExec {
            id: new_id(&gen),
            argv: vec!["ls".into(), "-la".into()],
        };
        assert_eq!(encode(&a), encode(&b));
    }

    #[test]
    fn declared_lists_are_sorted_lexicographically() {
        let gen = IdGen::new();

        let a = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec!["net.transfer".into(), "sh.exec".into()],
            env: vec!["FOO".into(), "BAR".into()],
            env_secrets: vec!["S2".into(), "S1".into()],
            paths: vec!["/workspace".into(), "/tmp".into()],
            http_allowlist: vec!["https://b.example/".into(), "https://a.example/".into()],
            phases: vec![],
        };
        let b = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec!["sh.exec".into(), "net.transfer".into()],
            env: vec!["BAR".into(), "FOO".into()],
            env_secrets: vec!["S1".into(), "S2".into()],
            paths: vec!["/tmp".into(), "/workspace".into()],
            http_allowlist: vec!["https://a.example/".into(), "https://b.example/".into()],
            phases: vec![],
        };
        assert_eq!(encode(&a), encode(&b));
    }

    #[test]
    fn phase_order_is_significant() {
        let gen = IdGen::new();
        let apt = || ProfileNode::SystemApt {
            id: new_id(&gen),
            packages: vec!["git".into()],
        };
        let sh = || ProfileNode::ShExec {
            id: new_id(&gen),
            argv: vec!["ls".into()],
        };

        let a = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec![],
            env: vec![],
            env_secrets: vec![],
            paths: vec![],
            http_allowlist: vec![],
            phases: vec![apt(), sh()],
        };
        let b = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec![],
            env: vec![],
            env_secrets: vec![],
            paths: vec![],
            http_allowlist: vec![],
            phases: vec![sh(), apt()],
        };
        assert_ne!(encode(&a), encode(&b));
    }

    #[test]
    fn option_none_omits_key_some_emits_it() {
        let gen = IdGen::new();

        // version: None / description: None -> keys absent
        let none = empty_spec(&gen, "p");
        let bytes = encode(&none);
        assert!(!bytes.contains("\"version\""), "bytes: {bytes}");
        assert!(!bytes.contains("\"description\""), "bytes: {bytes}");

        // Some -> keys present with value
        let some = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: Some("1.0.0".into()),
            description: Some("d".into()),
            capabilities: vec![],
            env: vec![],
            env_secrets: vec![],
            paths: vec![],
            http_allowlist: vec![],
            phases: vec![],
        };
        let bytes = encode(&some);
        assert!(bytes.contains("\"version\":\"1.0.0\""), "bytes: {bytes}");
        assert!(bytes.contains("\"description\":\"d\""), "bytes: {bytes}");
    }

    #[test]
    fn empty_vec_encodes_as_bracket_pair() {
        let gen = IdGen::new();
        let bytes = encode(&empty_spec(&gen, "p"));
        assert!(bytes.contains("\"capabilities\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"env\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"env_secrets\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"http_allowlist\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"paths\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"phases\":[]"), "bytes: {bytes}");
    }

    #[test]
    fn string_escape_matches_legacy_byte_rules() {
        let gen = IdGen::new();
        // Mix: quote, backslash, LF, tab, control byte 0x01, non-ASCII UTF-8.
        let content = "a\"b\\c\nd\te\x01\u{3042}";
        let node = ProfileNode::FsWrite {
            id: new_id(&gen),
            path: "/tmp/x".into(),
            content: content.into(),
        };
        let bytes = encode(&node);
        // Expected canonical form:
        // {"content":"a\"b\\c\nd\te<UTF-8 bytes of あ>","path":"/tmp/x","type":"FsWrite"}
        let mut expected = String::new();
        expected.push_str("{\"content\":\"a\\\"b\\\\c\\nd\\te\\u0001");
        // 3 UTF-8 bytes of U+3042 「あ」 pass through raw.
        expected.push('\u{3042}');
        expected.push_str("\",\"path\":\"/tmp/x\",\"type\":\"FsWrite\"}");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn nested_spec_full_literal_encoding() {
        let gen = IdGen::new();
        let node = ProfileNode::Spec {
            id: new_id(&gen),
            name: "demo".into(),
            version: None,
            description: None,
            capabilities: vec!["sh.exec".into()],
            env: vec![],
            env_secrets: vec![],
            paths: vec![],
            http_allowlist: vec![],
            phases: vec![
                ProfileNode::SystemApt {
                    id: new_id(&gen),
                    packages: vec!["git".into(), "curl".into()],
                },
                ProfileNode::ShExec {
                    id: new_id(&gen),
                    argv: vec!["ls".into(), "-la".into()],
                },
            ],
        };
        let bytes = encode(&node);
        // Keys within each object are lexicographic; NodeId absent;
        // packages / argv order preserved; capabilities sorted (already
        // singleton); phases order preserved.
        let expected = concat!(
            "{",
            "\"capabilities\":[\"sh.exec\"],",
            "\"env\":[],",
            "\"env_secrets\":[],",
            "\"http_allowlist\":[],",
            "\"name\":\"demo\",",
            "\"paths\":[],",
            "\"phases\":[",
            "{\"packages\":[\"git\",\"curl\"],\"type\":\"SystemApt\"},",
            "{\"argv\":[\"ls\",\"-la\"],\"type\":\"ShExec\"}",
            "],",
            "\"type\":\"Spec\"",
            "}",
        );
        assert_eq!(bytes, expected);
        // NodeId marker never appears.
        assert!(!bytes.contains("\"id\""), "bytes: {bytes}");
    }

    #[test]
    fn hash_is_64_char_lowercase_hex() {
        let gen = IdGen::new();
        let h = hash(&empty_spec(&gen, "p"));
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')),
            "hash: {h}"
        );
    }

    #[test]
    fn hash_regression_fixed_input() {
        // Deterministic regression pin: empty Spec named "p" hashes to
        // a fixed value derived from the canonical bytes above.
        let gen = IdGen::new();
        let h = hash(&empty_spec(&gen, "p"));
        let expected_bytes = concat!(
            "{",
            "\"capabilities\":[],",
            "\"env\":[],",
            "\"env_secrets\":[],",
            "\"http_allowlist\":[],",
            "\"name\":\"p\",",
            "\"paths\":[],",
            "\"phases\":[],",
            "\"type\":\"Spec\"",
            "}",
        );
        assert_eq!(encode(&empty_spec(&gen, "p")), expected_bytes);
        // sha256("{...}") — computed from expected_bytes.
        let computed = {
            let d = Sha256::digest(expected_bytes.as_bytes());
            let mut s = String::with_capacity(64);
            for b in d {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        assert_eq!(h, computed);
    }

    #[test]
    fn paths_and_http_allowlist_are_sorted_lexicographically() {
        let gen = IdGen::new();
        let node = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec![],
            env: vec![],
            env_secrets: vec![],
            paths: vec!["/workspace".into(), "/tmp".into()],
            http_allowlist: vec![
                "https://b.example.com/".into(),
                "https://a.example.com/".into(),
            ],
            phases: vec![],
        };
        let bytes = encode(&node);
        assert!(
            bytes.contains("\"paths\":[\"/tmp\",\"/workspace\"]"),
            "paths must be sorted: {bytes}"
        );
        assert!(
            bytes.contains(
                "\"http_allowlist\":[\"https://a.example.com/\",\"https://b.example.com/\"]"
            ),
            "http_allowlist must be sorted: {bytes}"
        );
    }

    #[test]
    fn port_encodes_as_integer() {
        let gen = IdGen::new();
        let node = ProfileNode::ComfyUiRestart {
            id: new_id(&gen),
            port: 8188,
        };
        let bytes = encode(&node);
        assert_eq!(bytes, "{\"port\":8188,\"type\":\"ComfyUiRestart\"}");
    }
}
