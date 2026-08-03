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
//! - Secret-marker rule: an [`ProfileNode::EnvSecret`] `env`-map value
//!   encodes as the `{"__secret":"NAME"}` marker (spec 03 / spec 06
//!   §SecretRef); an [`ProfileNode::EnvLiteral`] value encodes as its
//!   plain string. The `env_secrets` *declaration* list is unaffected —
//!   it still carries only bare names.
//! - The `env` keyed slot on `sync.pull` / `staging.push` / `sh.exec`
//!   encodes as an object mapping each key to its (marker or string)
//!   value; an empty `env` omits the key entirely, so a profile that
//!   declares no env hashes byte-for-byte as it did before the field
//!   was introduced. `revision` follows the `Option` omit rule above.
//!   The `headers` keyed slot on `net.http_get` / `net.http_post`
//!   follows the identical rule, as do those kinds' `body` (a value
//!   node, encoded like an `env` value), `body_json` (an opaque JSON
//!   string), and `timeout_sec` (`Option`).
//! - `comfyui.restart`'s `extra_args` follows the same omit-when-empty
//!   rule for the same reason: it is a payload field added after
//!   profiles were already being hashed, and the overwhelmingly common
//!   case (no extra args) must keep its existing hash. When non-empty
//!   it encodes as a declaration-ordered array — the entries are
//!   argv positions, so unlike the `Spec` declared lists they are not
//!   sorted.
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

use crate::profile_ast::ProfileNode;
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

/// SHA-256 of the [`encode`] bytes, lowercase hex, no prefix (64 chars).
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
            // Spec.env: keyed slot of `EnvLiteral` / `EnvSecret` value
            // nodes. Empty maps are omitted so a profile that declares
            // no entries here hashes exactly as it did while `env` was
            // a bare allowlist `Vec<String>` — the old declaration form
            // hashed as `"env":[]` which the omit-when-empty rule
            // matches for empty maps too (a profile that carried names
            // in the old `Vec` will re-hash under this shape, which is
            // the intended shape change; the field had no consumer).
            insert_env(&mut fields, env);
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

        ProfileNode::SyncPull {
            id: _,
            src,
            dst,
            env,
            revision,
        } => {
            let mut fields = variant_object("SyncPull");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            insert_env(&mut fields, env);
            insert_optional_str(&mut fields, "revision", revision);
            CanonValue::Object(fields)
        }

        ProfileNode::SyncPush { id: _, src, dst } => {
            let mut fields = variant_object("SyncPush");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            CanonValue::Object(fields)
        }

        ProfileNode::StagingPush {
            id: _,
            src,
            dst,
            env,
            revision,
        } => {
            let mut fields = variant_object("StagingPush");
            fields.insert("src".into(), CanonValue::Str(src.clone()));
            fields.insert("dst".into(), CanonValue::Str(dst.clone()));
            insert_env(&mut fields, env);
            insert_optional_str(&mut fields, "revision", revision);
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

        ProfileNode::ComfyUiRestart {
            id: _,
            port,
            extra_args,
        } => {
            let mut fields = variant_object("ComfyUiRestart");
            fields.insert("port".into(), CanonValue::Int(i64::from(*port)));
            insert_when_non_empty(&mut fields, "extra_args", extra_args);
            CanonValue::Object(fields)
        }

        ProfileNode::ComfyUiHealth {
            id: _,
            port,
            timeout_sec,
        } => {
            let mut fields = variant_object("ComfyUiHealth");
            fields.insert("port".into(), CanonValue::Int(i64::from(*port)));
            // Omitted when unset, so a profile that leaves the deadline
            // to the kind default keeps the bytes — and therefore the
            // hash — it had before the field existed.
            insert_optional_u16(&mut fields, "timeout_sec", timeout_sec);
            CanonValue::Object(fields)
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
            let mut fields = variant_object("ServiceStart");
            fields.insert("name".into(), CanonValue::Str(name.clone()));
            fields.insert(
                "platform_kind".into(),
                CanonValue::Str(platform_kind.clone()),
            );
            // Every platform-detail field is omitted when unset, so a
            // profile that declares only `kind` keeps the bytes (and
            // therefore the hash) it had before the fields existed.
            insert_optional_str(&mut fields, "model", model);
            insert_optional_u16(&mut fields, "port", port);
            insert_optional_str(&mut fields, "dtype", dtype);
            insert_optional_u16(&mut fields, "tensor_parallel_size", tensor_parallel_size);
            insert_when_non_empty(&mut fields, "extra_args", extra_args);
            CanonValue::Object(fields)
        }

        ProfileNode::ServiceReady {
            id: _,
            name,
            check_url,
            timeout_sec,
        } => {
            let mut fields = variant_object("ServiceReady");
            fields.insert("name".into(), CanonValue::Str(name.clone()));
            fields.insert("check_url".into(), CanonValue::Str(check_url.clone()));
            // Omitted when unset, same rule as `ComfyUiHealth`'s.
            insert_optional_u16(&mut fields, "timeout_sec", timeout_sec);
            CanonValue::Object(fields)
        }

        ProfileNode::ShExec { id: _, argv, env } => {
            let mut fields = variant_object("ShExec");
            fields.insert("argv".into(), string_array(argv));
            insert_env(&mut fields, env);
            CanonValue::Object(fields)
        }

        ProfileNode::FsWrite {
            id: _,
            path,
            content,
        } => {
            let mut fields = variant_object("FsWrite");
            fields.insert("path".into(), CanonValue::Str(path.clone()));
            // The content value node canonicalizes exactly like an
            // `env`-map value: an `EnvLiteral` is its bare string —
            // byte-identical to the pre-node `content: String` encoding,
            // so literal-content profiles keep their hash — a secret /
            // ref is its marker object.
            fields.insert("content".into(), to_canon(content));
            CanonValue::Object(fields)
        }

        ProfileNode::NetHttpGet {
            id: _,
            url,
            headers,
            timeout_sec,
        } => {
            let mut fields = variant_object("NetHttpGet");
            fields.insert("url".into(), CanonValue::Str(url.clone()));
            // Both follow the omit-when-unset rule: they are payload
            // fields added after profiles were already being hashed, so
            // a request that declares neither keeps its pre-field bytes.
            insert_value_map(&mut fields, "headers", headers);
            insert_optional_u16(&mut fields, "timeout_sec", timeout_sec);
            CanonValue::Object(fields)
        }

        ProfileNode::NetHttpPost {
            id: _,
            url,
            headers,
            body,
            body_json,
            timeout_sec,
        } => {
            let mut fields = variant_object("NetHttpPost");
            fields.insert("url".into(), CanonValue::Str(url.clone()));
            insert_value_map(&mut fields, "headers", headers);
            // `body` is a value node encoded by the same rules as an
            // `env`-map value (a literal is its bare string, a secret /
            // ref its marker object); `body_json` is an opaque JSON
            // string like `models_json`. Both omitted when unset — and
            // validate rejects declaring the two together, so at most
            // one of these keys is ever present.
            if let Some(body) = body {
                fields.insert("body".into(), to_canon(body));
            }
            insert_optional_str(&mut fields, "body_json", body_json);
            insert_optional_u16(&mut fields, "timeout_sec", timeout_sec);
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

        // Env value nodes: an `EnvLiteral` is its bare string; an
        // `EnvSecret` is the `{"__secret":"NAME"}` marker; an
        // `EnvRef` is the `{"__env_ref":"NAME"}` marker (symmetric
        // with `__secret` so a consumer can spot references without
        // resolving them). These arms are reached through
        // [`insert_env`] and the [`Spec::env`] slot — they never
        // occur as top-level phases.
        ProfileNode::EnvLiteral { id: _, value } => CanonValue::Str(value.clone()),
        ProfileNode::EnvSecret { id: _, name } => {
            let mut marker = BTreeMap::new();
            marker.insert("__secret".into(), CanonValue::Str(name.clone()));
            CanonValue::Object(marker)
        }
        ProfileNode::EnvRef { id: _, name } => {
            let mut marker = BTreeMap::new();
            marker.insert("__env_ref".into(), CanonValue::Str(name.clone()));
            CanonValue::Object(marker)
        }
    }
}

/// Insert the `env` key when `env` is non-empty, mapping each entry's
/// key to its canonical value (a plain string for
/// [`ProfileNode::EnvLiteral`], the `{"__secret":"NAME"}` marker for
/// [`ProfileNode::EnvSecret`]). An empty `env` omits the key so a
/// profile that declares no env hashes exactly as it did before the
/// field existed. `BTreeMap` iteration is already lexicographic by key.
fn insert_env(fields: &mut BTreeMap<String, CanonValue>, env: &BTreeMap<String, ProfileNode>) {
    insert_value_map(fields, "env", env);
}

/// The keyed-slot counterpart of [`insert_when_non_empty`]: insert
/// `key` as an object mapping each entry to its value node's canonical
/// form, or omit it entirely when `map` is empty. [`insert_env`] is the
/// `env`-slot spelling; `net.http_*`'s `headers` slot uses the same
/// rule for the same reason (a keyed slot added after profiles were
/// already being hashed must not move an undeclaring profile's bytes).
/// `BTreeMap` iteration is already lexicographic by key.
fn insert_value_map(
    fields: &mut BTreeMap<String, CanonValue>,
    key: &str,
    map: &BTreeMap<String, ProfileNode>,
) {
    if map.is_empty() {
        return;
    }
    let mut obj = BTreeMap::new();
    for (entry_key, value) in map {
        obj.insert(entry_key.clone(), to_canon(value));
    }
    fields.insert(key.into(), CanonValue::Object(obj));
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

/// The `Option<u16>` counterpart to [`insert_optional_str`]: emit an
/// `Int` when set, omit the key entirely otherwise. Matches the same
/// omit-when-`None` rule so a `service.start` that declares no
/// `port` / `tensor_parallel_size` keeps its pre-migration hash.
fn insert_optional_u16(fields: &mut BTreeMap<String, CanonValue>, key: &str, value: &Option<u16>) {
    if let Some(v) = value {
        fields.insert(key.into(), CanonValue::Int(i64::from(*v)));
    }
}

/// Insert `key` only when `items` is non-empty, preserving declaration
/// order.
///
/// Used for payload list fields introduced *after* profiles were already
/// being hashed (`comfyui.restart` `extra_args`): omitting the key when
/// empty keeps the canonical bytes — and therefore the profile hash —
/// unchanged for every profile that does not use the field. The sibling
/// rule for keyed slots is [`insert_env`].
fn insert_when_non_empty(fields: &mut BTreeMap<String, CanonValue>, key: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    fields.insert(key.into(), string_array(items));
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
            env: BTreeMap::new(),
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
            env: BTreeMap::new(),
        };
        let b = ProfileNode::ShExec {
            id: new_id(&gen),
            argv: vec!["ls".into(), "-la".into()],
            env: BTreeMap::new(),
        };
        assert_eq!(encode(&a), encode(&b));
    }

    #[test]
    fn declared_lists_are_sorted_lexicographically() {
        let gen = IdGen::new();

        // `Spec.env` is now a keyed map (BTreeMap iteration is already
        // lexicographic by key), so its ordering guarantee is inherent
        // rather than sort-on-encode. The other four declared lists
        // are still Vec<String> and the encoder sorts them before
        // emission, so the parity check runs over those.
        let a = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec!["net.transfer".into(), "sh.exec".into()],
            env: BTreeMap::new(),
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
            env: BTreeMap::new(),
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
            env: BTreeMap::new(),
        };

        let a = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec![],
            env: BTreeMap::new(),
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
            env: BTreeMap::new(),
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
            env: BTreeMap::new(),
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
        assert!(bytes.contains("\"env_secrets\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"http_allowlist\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"paths\":[]"), "bytes: {bytes}");
        assert!(bytes.contains("\"phases\":[]"), "bytes: {bytes}");
        // `Spec.env` is a keyed map now, not a Vec — empty maps are
        // omitted from the canonical so a profile that declares no
        // env-table entries keeps the pre-migration hash.
        assert!(
            !bytes.contains("\"env\":"),
            "empty Spec.env must be omitted from canonical: {bytes}"
        );
    }

    /// A populated `Spec.env` encodes as a keyed object whose values
    /// follow the same `EnvLiteral` / `EnvSecret` / `EnvRef` shape as
    /// the per-phase env slots (marker for the reference / secret
    /// nodes, bare string for the literal).
    #[test]
    fn populated_spec_env_encodes_as_a_keyed_object() {
        let gen = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert(
            "LOG_LEVEL".to_string(),
            ProfileNode::EnvLiteral {
                id: new_id(&gen),
                value: "info".into(),
            },
        );
        env.insert(
            "HF_TOKEN".to_string(),
            ProfileNode::EnvSecret {
                id: new_id(&gen),
                name: "HF_TOKEN".into(),
            },
        );
        let node = ProfileNode::Spec {
            id: new_id(&gen),
            name: "p".into(),
            version: None,
            description: None,
            capabilities: vec![],
            env,
            env_secrets: vec!["HF_TOKEN".into()],
            paths: vec![],
            http_allowlist: vec![],
            phases: vec![],
        };
        let bytes = encode(&node);
        // BTreeMap key iteration is lexicographic; HF_TOKEN < LOG_LEVEL.
        assert!(
            bytes.contains(
                "\"env\":{\"HF_TOKEN\":{\"__secret\":\"HF_TOKEN\"},\"LOG_LEVEL\":\"info\"}"
            ),
            "bytes: {bytes}"
        );
    }

    #[test]
    fn string_escape_matches_legacy_byte_rules() {
        let gen = IdGen::new();
        // Mix: quote, backslash, LF, tab, control byte 0x01, non-ASCII UTF-8.
        let content = "a\"b\\c\nd\te\x01\u{3042}";
        // A literal content node encodes as its bare string — the
        // byte-identical shape `content: String` produced before the
        // slot became a value node (hash neutrality for pre-migration
        // profiles).
        let node = ProfileNode::FsWrite {
            id: new_id(&gen),
            path: "/tmp/x".into(),
            content: Box::new(ProfileNode::EnvLiteral {
                id: new_id(&gen),
                value: content.into(),
            }),
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
            env: BTreeMap::new(),
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
                    env: BTreeMap::new(),
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
            // `Spec.env` omitted: empty keyed map, so no key emitted.
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
            // `Spec.env` omitted (empty keyed map).
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
            env: BTreeMap::new(),
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
            extra_args: Vec::new(),
        };
        let bytes = encode(&node);
        assert_eq!(bytes, "{\"port\":8188,\"type\":\"ComfyUiRestart\"}");
    }

    /// An empty `extra_args` must leave the canonical bytes — and so the
    /// profile hash — exactly as they were before the field existed
    /// (the expected string above is the pre-field encoding, verbatim).
    #[test]
    fn empty_extra_args_is_omitted_so_the_hash_is_unchanged() {
        let gen = IdGen::new();
        let without = ProfileNode::ComfyUiRestart {
            id: new_id(&gen),
            port: 8188,
            extra_args: Vec::new(),
        };
        assert_eq!(
            encode(&without),
            "{\"port\":8188,\"type\":\"ComfyUiRestart\"}"
        );
    }

    /// A non-empty `extra_args` encodes in declaration order — the
    /// entries are argv positions, so (unlike the `Spec` declared lists)
    /// they must not be sorted.
    #[test]
    fn extra_args_encodes_in_declaration_order() {
        let gen = IdGen::new();
        let node = ProfileNode::ComfyUiRestart {
            id: new_id(&gen),
            port: 8188,
            // Deliberately not lexicographic: sorting would reorder
            // these to ["--listen", "--port=9000"].
            extra_args: vec!["--port=9000".to_string(), "--listen".to_string()],
        };
        assert_eq!(
            encode(&node),
            "{\"extra_args\":[\"--port=9000\",\"--listen\"],\"port\":8188,\"type\":\"ComfyUiRestart\"}"
        );
    }

    /// A `service.start` that declares no platform detail must encode
    /// exactly as it did before the five optional platform fields
    /// existed (the expected string is the pre-field encoding,
    /// verbatim), so adding them left every existing profile's hash
    /// alone.
    #[test]
    fn service_start_without_platform_detail_keeps_its_pre_field_bytes() {
        let gen = IdGen::new();
        let node = ProfileNode::ServiceStart {
            id: new_id(&gen),
            name: "llm".to_string(),
            platform_kind: "vllm".to_string(),
            model: None,
            port: None,
            dtype: None,
            tensor_parallel_size: None,
            extra_args: Vec::new(),
        };
        assert_eq!(
            encode(&node),
            "{\"name\":\"llm\",\"platform_kind\":\"vllm\",\"type\":\"ServiceStart\"}"
        );
    }

    /// Declared platform detail encodes, and changes the hash: two
    /// services differing in a numeric knob are not the same service.
    #[test]
    fn service_start_platform_detail_encodes_and_changes_the_hash() {
        let gen = IdGen::new();
        let bare = ProfileNode::ServiceStart {
            id: new_id(&gen),
            name: "llm".to_string(),
            platform_kind: "vllm".to_string(),
            model: None,
            port: None,
            dtype: None,
            tensor_parallel_size: None,
            extra_args: Vec::new(),
        };
        let detailed = ProfileNode::ServiceStart {
            id: new_id(&gen),
            name: "llm".to_string(),
            platform_kind: "vllm".to_string(),
            model: Some("meta-llama/Llama-3-8B".to_string()),
            port: Some(9000),
            dtype: Some("bfloat16".to_string()),
            tensor_parallel_size: Some(4),
            extra_args: Vec::new(),
        };
        assert_eq!(
            encode(&detailed),
            "{\"dtype\":\"bfloat16\",\"model\":\"meta-llama/Llama-3-8B\",\
             \"name\":\"llm\",\"platform_kind\":\"vllm\",\"port\":9000,\
             \"tensor_parallel_size\":4,\"type\":\"ServiceStart\"}"
        );
        assert_ne!(hash(&bare), hash(&detailed));
    }

    /// A poll kind that leaves its deadline to the kind default must
    /// encode exactly as it did before `timeout_sec` existed (both
    /// expected strings are the pre-field encodings, verbatim), so
    /// adding the field left every existing profile's hash alone.
    #[test]
    fn undeclared_poll_timeouts_keep_their_pre_field_bytes() {
        let gen = IdGen::new();
        let health = ProfileNode::ComfyUiHealth {
            id: new_id(&gen),
            port: 8188,
            timeout_sec: None,
        };
        assert_eq!(
            encode(&health),
            "{\"port\":8188,\"type\":\"ComfyUiHealth\"}"
        );

        let ready = ProfileNode::ServiceReady {
            id: new_id(&gen),
            name: "llm".to_string(),
            check_url: "http://127.0.0.1:9000/health".to_string(),
            timeout_sec: None,
        };
        assert_eq!(
            encode(&ready),
            "{\"check_url\":\"http://127.0.0.1:9000/health\",\
             \"name\":\"llm\",\"type\":\"ServiceReady\"}"
        );
    }

    /// A declared deadline encodes as an `Int` and changes the hash:
    /// two polls that wait for different lengths are not the same poll.
    #[test]
    fn declared_poll_timeouts_encode_and_change_the_hash() {
        let gen = IdGen::new();
        let health_bare = ProfileNode::ComfyUiHealth {
            id: new_id(&gen),
            port: 8188,
            timeout_sec: None,
        };
        let health_declared = ProfileNode::ComfyUiHealth {
            id: new_id(&gen),
            port: 8188,
            timeout_sec: Some(240),
        };
        assert_eq!(
            encode(&health_declared),
            "{\"port\":8188,\"timeout_sec\":240,\"type\":\"ComfyUiHealth\"}"
        );
        assert_ne!(hash(&health_bare), hash(&health_declared));

        let ready_bare = ProfileNode::ServiceReady {
            id: new_id(&gen),
            name: "llm".to_string(),
            check_url: "http://127.0.0.1:9000/health".to_string(),
            timeout_sec: None,
        };
        let ready_declared = ProfileNode::ServiceReady {
            id: new_id(&gen),
            name: "llm".to_string(),
            check_url: "http://127.0.0.1:9000/health".to_string(),
            timeout_sec: Some(600),
        };
        assert_eq!(
            encode(&ready_declared),
            "{\"check_url\":\"http://127.0.0.1:9000/health\",\
             \"name\":\"llm\",\"timeout_sec\":600,\"type\":\"ServiceReady\"}"
        );
        assert_ne!(hash(&ready_bare), hash(&ready_declared));
    }

    /// Declaring extra args must change the hash — the field is part of
    /// the invocation, so two profiles differing in it are not the same
    /// profile.
    #[test]
    fn extra_args_participates_in_the_hash() {
        let gen = IdGen::new();
        let bare = ProfileNode::ComfyUiRestart {
            id: new_id(&gen),
            port: 8188,
            extra_args: Vec::new(),
        };
        let with_args = ProfileNode::ComfyUiRestart {
            id: new_id(&gen),
            port: 8188,
            extra_args: vec!["--listen".to_string()],
        };
        assert_ne!(hash(&bare), hash(&with_args));
    }

    // -----------------------------------------------------------------
    // env value nodes + revision.
    // -----------------------------------------------------------------

    fn env_map(entries: &[(&str, ProfileNode)]) -> BTreeMap<String, ProfileNode> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn env_map_encodes_literals_and_secret_markers() {
        let gen = IdGen::new();
        let env = env_map(&[
            (
                "LOG_LEVEL",
                ProfileNode::EnvLiteral {
                    id: new_id(&gen),
                    value: "debug".into(),
                },
            ),
            (
                "HF_TOKEN",
                ProfileNode::EnvSecret {
                    id: new_id(&gen),
                    name: "HF_TOKEN".into(),
                },
            ),
        ]);
        let node = ProfileNode::SyncPull {
            id: new_id(&gen),
            src: "hf://owner/repo/model.bin".into(),
            dst: "/workspace/model.bin".into(),
            env,
            revision: Some("abc123".into()),
        };
        let bytes = encode(&node);
        // env object: keys lexicographic, EnvLiteral -> string,
        // EnvSecret -> {"__secret":"NAME"}; revision emitted.
        assert!(
            bytes.contains(
                "\"env\":{\"HF_TOKEN\":{\"__secret\":\"HF_TOKEN\"},\"LOG_LEVEL\":\"debug\"}"
            ),
            "bytes: {bytes}"
        );
        assert!(bytes.contains("\"revision\":\"abc123\""), "bytes: {bytes}");
    }

    #[test]
    fn empty_env_and_none_revision_omit_their_keys_and_match_the_legacy_bytes() {
        let gen = IdGen::new();
        let node = ProfileNode::SyncPull {
            id: new_id(&gen),
            src: "b2://bucket/model.bin".into(),
            dst: "/workspace/model.bin".into(),
            env: BTreeMap::new(),
            revision: None,
        };
        let bytes = encode(&node);
        // Byte-for-byte the pre-field shape: only dst / src / type.
        assert_eq!(
            bytes,
            "{\"dst\":\"/workspace/model.bin\",\"src\":\"b2://bucket/model.bin\",\"type\":\"SyncPull\"}"
        );
    }

    #[test]
    fn env_bearing_profiles_hash_deterministically() {
        let gen = IdGen::new();
        let make = || ProfileNode::ShExec {
            id: new_id(&gen),
            argv: vec!["echo".into()],
            env: env_map(&[(
                "TOKEN",
                ProfileNode::EnvSecret {
                    id: new_id(&gen),
                    name: "TOKEN".into(),
                },
            )]),
        };
        assert_eq!(hash(&make()), hash(&make()));
    }

    // -----------------------------------------------------------------
    // net.http_get / net.http_post request fields.
    // -----------------------------------------------------------------

    /// An HTTP op that declares none of the request fields must encode
    /// exactly as it did before they existed (both expected strings are
    /// the pre-field encodings, verbatim), so adding `headers` / `body`
    /// / `body_json` / `timeout_sec` left every existing profile's hash
    /// alone.
    #[test]
    fn undeclared_http_request_fields_keep_their_pre_field_bytes() {
        let gen = IdGen::new();
        let get = ProfileNode::NetHttpGet {
            id: new_id(&gen),
            url: "https://example.com/get".into(),
            headers: BTreeMap::new(),
            timeout_sec: None,
        };
        assert_eq!(
            encode(&get),
            "{\"type\":\"NetHttpGet\",\"url\":\"https://example.com/get\"}"
        );

        let post = ProfileNode::NetHttpPost {
            id: new_id(&gen),
            url: "https://example.com/post".into(),
            headers: BTreeMap::new(),
            body: None,
            body_json: None,
            timeout_sec: None,
        };
        assert_eq!(
            encode(&post),
            "{\"type\":\"NetHttpPost\",\"url\":\"https://example.com/post\"}"
        );
    }

    /// Declared request fields encode — headers as a keyed object whose
    /// values follow the `env`-value rules, `body` as one such value,
    /// `body_json` as its opaque string, `timeout_sec` as an `Int` — and
    /// each changes the hash: two requests that differ in what they send
    /// are not the same request.
    #[test]
    fn declared_http_request_fields_encode_and_change_the_hash() {
        let gen = IdGen::new();
        let headers = env_map(&[
            (
                "Accept",
                ProfileNode::EnvLiteral {
                    id: new_id(&gen),
                    value: "application/json".into(),
                },
            ),
            (
                "Authorization",
                ProfileNode::EnvSecret {
                    id: new_id(&gen),
                    name: "API_TOKEN".into(),
                },
            ),
        ]);

        let get_bare = ProfileNode::NetHttpGet {
            id: new_id(&gen),
            url: "https://example.com/get".into(),
            headers: BTreeMap::new(),
            timeout_sec: None,
        };
        let get = ProfileNode::NetHttpGet {
            id: new_id(&gen),
            url: "https://example.com/get".into(),
            headers: headers.clone(),
            timeout_sec: Some(5),
        };
        assert_eq!(
            encode(&get),
            "{\"headers\":{\"Accept\":\"application/json\",\
             \"Authorization\":{\"__secret\":\"API_TOKEN\"}},\
             \"timeout_sec\":5,\"type\":\"NetHttpGet\",\
             \"url\":\"https://example.com/get\"}"
        );
        assert_ne!(hash(&get_bare), hash(&get));

        let post_bare = ProfileNode::NetHttpPost {
            id: new_id(&gen),
            url: "https://example.com/post".into(),
            headers: BTreeMap::new(),
            body: None,
            body_json: None,
            timeout_sec: None,
        };
        let post_body = ProfileNode::NetHttpPost {
            id: new_id(&gen),
            url: "https://example.com/post".into(),
            headers,
            body: Some(Box::new(ProfileNode::EnvSecret {
                id: new_id(&gen),
                name: "API_TOKEN".into(),
            })),
            body_json: None,
            timeout_sec: None,
        };
        assert_eq!(
            encode(&post_body),
            "{\"body\":{\"__secret\":\"API_TOKEN\"},\
             \"headers\":{\"Accept\":\"application/json\",\
             \"Authorization\":{\"__secret\":\"API_TOKEN\"}},\
             \"type\":\"NetHttpPost\",\"url\":\"https://example.com/post\"}"
        );
        assert_ne!(hash(&post_bare), hash(&post_body));

        // The two body forms are distinct statements even when they
        // carry the same characters, so they must not collide.
        let post_literal_body = ProfileNode::NetHttpPost {
            id: new_id(&gen),
            url: "https://example.com/post".into(),
            headers: BTreeMap::new(),
            body: Some(Box::new(ProfileNode::EnvLiteral {
                id: new_id(&gen),
                value: "{\"k\":1}".into(),
            })),
            body_json: None,
            timeout_sec: None,
        };
        let post_json_body = ProfileNode::NetHttpPost {
            id: new_id(&gen),
            url: "https://example.com/post".into(),
            headers: BTreeMap::new(),
            body: None,
            body_json: Some("{\"k\":1}".into()),
            timeout_sec: None,
        };
        assert_eq!(
            encode(&post_json_body),
            "{\"body_json\":\"{\\\"k\\\":1}\",\
             \"type\":\"NetHttpPost\",\"url\":\"https://example.com/post\"}"
        );
        assert_ne!(hash(&post_literal_body), hash(&post_json_body));
    }

    #[test]
    fn env_secret_marker_standalone_encoding() {
        let gen = IdGen::new();
        let node = ProfileNode::EnvSecret {
            id: new_id(&gen),
            name: "B2_KEY".into(),
        };
        assert_eq!(encode(&node), "{\"__secret\":\"B2_KEY\"}");
    }
}
