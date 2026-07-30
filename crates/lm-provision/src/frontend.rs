//! Profile file frontend: parse a profile file into a [`ProfileNode`]
//! AST.
//!
//! Two input formats are supported and picked purely by file
//! extension (07-cli.md §File-format routing, plan §形式判定):
//!
//! - `.json` (case-insensitive) → JSON serde bridge
//!   ([`dsl_kit_parse::serde_bridge::from_json_value`])
//! - anything else → canonical text grammar
//!   ([`dsl_kit_parse::peg::Grammar::from_schema`])
//!
//! `.lua` is the one extension that is explicitly rejected (see
//! [`FrontendError::LuaUnsupported`]): the legacy embedded-Lua authoring
//! frontend has been removed, so a `.lua` file must fail loudly rather
//! than fall through to the text grammar and be silently misparsed.
//!
//! Both parse paths converge on [`ProfileNode::from_parse_tree`] so the
//! resulting AST is byte-identical to the one the JSON path would
//! produce for the same logical profile, which is what makes
//! [`crate::canonical::hash`] frontend-parity hold (see
//! `tests/canonical_frontend_parity.rs`).

use std::path::Path;

use dsl_kit::IdGen;
use dsl_kit_parse::{peg::Grammar, serde_bridge::from_json_value, DslBuild as _};
use dsl_kit_schema::DslSchema as _;

use crate::profile_ast::ProfileNode;

/// Errors returned by [`load_profile`].
///
/// Kept as a small three-variant enum so callers (currently the `hash`
/// / `plan` CLI subcommands, see [`crate::cli`]) can convert straight
/// into their own rendered-message error type via a `From` impl
/// without depending on `dsl-kit-parse`'s error surface.
#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    /// The profile file could not be read from disk.
    #[error("failed to read profile '{path}': {source}")]
    Io {
        /// The path we tried to read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The profile file could not be parsed (text grammar or JSON
    /// serde bridge).
    #[error("failed to parse profile: {0}")]
    Parse(String),
    /// The parse tree could not be built into a typed [`ProfileNode`].
    #[error("failed to build AST: {0}")]
    Build(String),
    /// The profile file has a `.lua` extension. Lua profiles are no
    /// longer supported; the input must be JSON or the canonical text
    /// form.
    #[error("Lua profiles are no longer supported; use JSON or the canonical text form")]
    LuaUnsupported,
}

/// Read `path` and parse it into a [`ProfileNode`] AST.
///
/// Files whose extension is `json` (case-insensitive) go through the
/// JSON serde bridge; every other extension goes through the canonical
/// text grammar. Both paths use a fresh [`IdGen`] per call — `NodeId`s
/// therefore vary across invocations, but [`crate::canonical::hash`]
/// excludes them and remains stable.
pub fn load_profile(path: &Path) -> Result<ProfileNode, FrontendError> {
    // Reject `.lua` up front, before any I/O: the embedded-Lua authoring
    // frontend is gone, so a `.lua` file must fail loudly rather than be
    // read and misparsed as canonical text.
    if has_extension(path, "lua") {
        return Err(FrontendError::LuaUnsupported);
    }

    let text = std::fs::read_to_string(path).map_err(|source| FrontendError::Io {
        path: path.display().to_string(),
        source,
    })?;

    if has_extension(path, "json") {
        parse_json(&text)
    } else {
        parse_text(&text)
    }
}

/// True when `path`'s extension equals `ext` (case-insensitive).
fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

fn parse_json(text: &str) -> Result<ProfileNode, FrontendError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|err| FrontendError::Parse(err.to_string()))?;
    let ids = IdGen::new();
    let schema = ProfileNode::schema();
    let tree =
        from_json_value(&value, &schema).map_err(|err| FrontendError::Parse(err.to_string()))?;
    ProfileNode::from_parse_tree(&tree, &ids).map_err(|err| FrontendError::Build(err.to_string()))
}

fn parse_text(text: &str) -> Result<ProfileNode, FrontendError> {
    let ids = IdGen::new();
    let schema = ProfileNode::schema();
    let grammar =
        Grammar::from_schema(&schema, &ids).map_err(|err| FrontendError::Parse(err.to_string()))?;
    let tree = grammar
        .parse(text)
        .map_err(|err| FrontendError::Parse(err.to_string()))?;
    ProfileNode::from_parse_tree(&tree, &ids).map_err(|err| FrontendError::Build(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical;
    use std::path::PathBuf;

    /// Convenience accessor: pull the recorded path back out of a
    /// [`FrontendError::Io`] so tests can distinguish the failure kind
    /// without regex-matching the rendered message.
    fn io_error_path(err: &FrontendError) -> Option<PathBuf> {
        match err {
            FrontendError::Io { path, .. } => Some(PathBuf::from(path)),
            _ => None,
        }
    }

    const TEXT_PROFILE: &str = concat!(
        "Spec(",
        "name: \"demo-frontend\", ",
        "version: \"1.0.0\", ",
        "description: none, ",
        "capabilities: [\"sh.exec\"], ",
        // `Spec.env` is a keyed slot: `{name: value_node}`.
        "env: {HOME: EnvLiteral(value: \"/root\")}, ",
        "env_secrets: [], ",
        "phases: [",
        "SystemApt(packages: [\"git\", \"curl\"]), ",
        "ShExec(argv: [\"echo\", \"ok\"])",
        "])",
    );

    fn json_profile_value() -> serde_json::Value {
        serde_json::json!({
            "type": "Spec",
            "name": "demo-frontend",
            "version": "1.0.0",
            "capabilities": ["sh.exec"],
            "env": { "HOME": { "type": "EnvLiteral", "value": "/root" } },
            "phases": [
                { "type": "SystemApt", "packages": ["git", "curl"] },
                { "type": "ShExec", "argv": ["echo", "ok"] },
            ],
        })
    }

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-frontend-{}-{}",
            std::process::id(),
            name,
        ));
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("temp file must be writable");
        path
    }

    #[test]
    fn json_extension_routes_through_the_serde_bridge() {
        let path = write_temp("profile.json", &json_profile_value().to_string());
        let ast = load_profile(&path).expect("valid JSON profile must load");
        match ast {
            ProfileNode::Spec { name, phases, .. } => {
                assert_eq!(name, "demo-frontend");
                assert_eq!(phases.len(), 2);
            }
            other => panic!("expected Spec root, got {other:?}"),
        }
    }

    #[test]
    fn text_extension_routes_through_the_canonical_grammar() {
        let path = write_temp("profile.txt", TEXT_PROFILE);
        let ast = load_profile(&path).expect("valid text profile must load");
        match ast {
            ProfileNode::Spec { name, phases, .. } => {
                assert_eq!(name, "demo-frontend");
                assert_eq!(phases.len(), 2);
            }
            other => panic!("expected Spec root, got {other:?}"),
        }
    }

    #[test]
    fn unknown_extension_still_falls_through_to_the_text_grammar() {
        // `.profile` is not `.json`, so the text grammar path applies.
        let path = write_temp("profile.profile", TEXT_PROFILE);
        let ast = load_profile(&path).expect("unknown extension must parse as text");
        assert!(matches!(ast, ProfileNode::Spec { .. }));
    }

    #[test]
    fn json_and_text_frontends_produce_the_same_canonical_hash() {
        let json_path = write_temp("parity.json", &json_profile_value().to_string());
        let text_path = write_temp("parity.txt", TEXT_PROFILE);
        let ast_json = load_profile(&json_path).expect("JSON parity fixture must load");
        let ast_text = load_profile(&text_path).expect("text parity fixture must load");
        assert_eq!(canonical::hash(&ast_json), canonical::hash(&ast_text));
    }

    #[test]
    fn json_env_keyed_slot_round_trips_into_env_value_nodes() {
        // The serde bridge routes an `env` object (Multiplicity::Map)
        // into keyed children, and DslBuild rebuilds each value as an
        // EnvLiteral / EnvSecret node. Exercises the keyed-slot path
        // end-to-end (JSON front-end → typed AST).
        let value = serde_json::json!({
            "type": "Spec",
            "name": "env-demo",
            "env_secrets": ["HF_TOKEN"],
            "phases": [
                {
                    "type": "SyncPull",
                    "src": "hf://owner/repo/m.bin",
                    "dst": "/workspace/m.bin",
                    "env": {
                        "LOG_LEVEL": { "type": "EnvLiteral", "value": "debug" },
                        "TOKEN": { "type": "EnvSecret", "name": "HF_TOKEN" }
                    },
                    "revision": "main"
                }
            ]
        });
        let path = write_temp("env.json", &value.to_string());
        let ast = load_profile(&path).expect("env profile must load");

        let ProfileNode::Spec { phases, .. } = &ast else {
            panic!("expected Spec root");
        };
        let ProfileNode::SyncPull { env, revision, .. } = &phases[0] else {
            panic!("expected SyncPull phase, got {:?}", phases[0]);
        };
        assert_eq!(revision.as_deref(), Some("main"));
        assert_eq!(env.len(), 2);
        match env.get("LOG_LEVEL") {
            Some(ProfileNode::EnvLiteral { value, .. }) => assert_eq!(value, "debug"),
            other => panic!("expected EnvLiteral for LOG_LEVEL, got {other:?}"),
        }
        match env.get("TOKEN") {
            Some(ProfileNode::EnvSecret { name, .. }) => assert_eq!(name, "HF_TOKEN"),
            other => panic!("expected EnvSecret for TOKEN, got {other:?}"),
        }

        // The rebuilt AST validates (HF_TOKEN is declared) and hashes
        // deterministically.
        assert!(crate::validate::validate(&ast).is_ok());
        assert_eq!(canonical::hash(&ast), canonical::hash(&ast));
    }

    #[test]
    fn malformed_json_surfaces_as_parse_error() {
        let path = write_temp("bad.json", "{not: valid json,");
        let err = load_profile(&path).expect_err("malformed JSON must fail");
        assert!(matches!(err, FrontendError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn malformed_text_surfaces_as_parse_error() {
        let path = write_temp("bad.txt", "This is not a Spec(...) expression");
        let err = load_profile(&path).expect_err("malformed text must fail");
        assert!(matches!(err, FrontendError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn lua_extension_is_rejected_before_any_io() {
        // A `.lua` path is rejected purely on its extension — the file
        // need not (and here does not) exist, proving the check precedes
        // the read.
        let path = std::env::temp_dir().join(format!(
            "lm-provision-frontend-{}-never-read.lua",
            std::process::id(),
        ));
        let _ = std::fs::remove_file(&path);
        let err = load_profile(&path).expect_err("a .lua profile must be rejected");
        assert!(matches!(err, FrontendError::LuaUnsupported), "got {err:?}");
        assert!(err
            .to_string()
            .contains("Lua profiles are no longer supported"));
    }

    #[test]
    fn lua_extension_rejection_is_case_insensitive() {
        let path = write_temp("Profile.LUA", "anything");
        let err = load_profile(&path).expect_err("a .LUA profile must be rejected");
        assert!(matches!(err, FrontendError::LuaUnsupported), "got {err:?}");
    }

    #[test]
    fn missing_file_surfaces_as_io_error() {
        let missing = std::env::temp_dir().join(format!(
            "lm-provision-frontend-missing-{}.txt",
            std::process::id(),
        ));
        // Ensure it really is absent.
        let _ = std::fs::remove_file(&missing);
        let err = load_profile(&missing).expect_err("missing path must fail");
        let recovered = io_error_path(&err).expect("error must expose the missing path");
        assert_eq!(recovered, missing);
    }
}
