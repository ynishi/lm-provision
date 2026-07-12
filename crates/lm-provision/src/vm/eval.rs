//! Profile evaluation loop: registration order steps 1-5
//! (04-bridge.md §Registration order).
//!
//! ```text
//! 1. L1 stdlib strip + custom require (embedded lm.*)   [boot_vm, M0]
//! 2. print redirect                                      [boot_vm, M0]
//! 3. env.ref factory                                     [bridge::env_ref, M1-3]
//! 4. profile file evaluation  → _LM_PROFILE global       [this module, M1-3]
//! 5. declaration extraction (name / capabilities / env /
//!    env_secrets / paths / http_allowlist)                [this module, M1-3]
//! ```
//!
//! Steps 6-9 (batteries `std.*` registration, capability gate build,
//! cap-gated bridge registration, pipeline execution) are out of M1-3
//! scope and land in milestone M3. The security consequence of stopping
//! here is the point: "during steps 4–5 no batteries primitive and no
//! bridge exists — a profile that reaches for one dies with `attempt to
//! call a nil value` before any effect can run. This is a physical
//! guarantee, not a lint" (04 §Registration order) — nothing in this
//! module registers `sh` / `net` / `fs` / `mount` / `std.*`, so that
//! guarantee holds simply by omission.

use std::path::{Path, PathBuf};

use mlua::{Lua, Table, Value};
use thiserror::Error;

use crate::bridge::env_ref;
use crate::vm::{boot_vm, VmError};

/// Errors raised while evaluating a profile file (steps 1-5).
#[derive(Debug, Error)]
pub enum EvalError {
    /// The profile file could not be read from disk
    /// ([`evaluate_profile_file`] only).
    #[error("failed to read profile file {path:?}: {source}")]
    Io {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The sandboxed VM failed to boot (registration order steps 1-2).
    #[error("failed to boot the sandboxed VM: {0}")]
    Vm(#[from] VmError),

    /// A Lua error surfaced while installing `env.ref`, evaluating the
    /// profile chunk, or extracting a declared field
    /// (01-profile-dsl-surface.md §Error surface).
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),

    /// The profile file did not `return` a table
    /// (01-profile-dsl-surface.md §Inputs "Entry-point convention").
    #[error("profile.lua must return a table from lm.profile {{...}}")]
    ProfileMustReturnTable,
}

/// Declarations extracted from the IR at registration order step 5
/// (04-bridge.md §Registration order): the six policy-relevant fields the
/// host needs before batteries / capability gate / bridge registration
/// (milestone M3).
///
/// `phases` is intentionally excluded — step 5 names exactly these six
/// fields; `phases` is the pipeline stages' input
/// (03-pipeline-stage-artifacts.md §Inputs), reached through
/// [`ExtractedProfile::ir`] instead.
#[derive(Debug, Clone)]
pub struct Declarations {
    /// `lm.profile { name = ... }` (01-profile-dsl-surface.md §Inputs).
    pub name: String,
    /// Declared `version`; defaults to `"0.0.0"` (01 §Inputs).
    pub version: String,
    /// Declared `description`, if any (01 §Inputs).
    pub description: Option<String>,
    /// Stable-sorted `capabilities` allowlist (01 §List-shape rule).
    pub capabilities: Vec<String>,
    /// Stable-sorted non-secret `env` allowlist (01 §List-shape rule).
    pub env: Vec<String>,
    /// Stable-sorted `env_secrets` allowlist (01 §List-shape rule).
    pub env_secrets: Vec<String>,
    /// Stable-sorted `paths` allowlist (01 §List-shape rule).
    pub paths: Vec<String>,
    /// Stable-sorted `http_allowlist` (01 §List-shape rule).
    pub http_allowlist: Vec<String>,
}

/// The result of evaluating a profile file through registration order
/// steps 1-5.
///
/// Bridges, batteries, and the capability gate (steps 6-9) are never
/// registered on [`ExtractedProfile::lua`] — they land in milestone M3.
pub struct ExtractedProfile {
    /// The sandboxed VM the profile was evaluated in. Kept alive because
    /// [`ExtractedProfile::ir`] borrows from it — an `mlua::Table` holds
    /// only a weak reference to its owning VM, not an owning one.
    pub lua: Lua,
    /// The full IR table (01-profile-dsl-surface.md §Outputs), including
    /// `phases` in user-declared order — the input every downstream
    /// pipeline stage consumes (03-pipeline-stage-artifacts.md §Inputs).
    pub ir: Table,
    /// The six declaration fields registration order step 5 extracts.
    pub declarations: Declarations,
}

/// Evaluate `source` as a profile file (registration order steps 1-5)
/// and extract its declarations.
///
/// `chunk_name` is used only for Lua error attribution (e.g. a file path,
/// or a synthetic name for in-memory sources such as tests); it carries
/// no semantic meaning to the pipeline.
pub fn evaluate_profile_source(
    source: &str,
    chunk_name: &str,
) -> Result<ExtractedProfile, EvalError> {
    let lua = boot_vm()?; // steps 1-2
    env_ref::install(&lua)?; // step 3

    let value: Value = lua
        .load(source)
        .set_name(chunk_name)
        .set_mode(mlua::ChunkMode::Text)
        .eval()?; // step 4

    let ir = match value {
        Value::Table(table) => table,
        _ => return Err(EvalError::ProfileMustReturnTable),
    };

    let declarations = extract_declarations(&ir)?; // step 5

    Ok(ExtractedProfile {
        lua,
        ir,
        declarations,
    })
}

/// Read `path` and evaluate it as a profile file (see
/// [`evaluate_profile_source`]).
pub fn evaluate_profile_file(path: &Path) -> Result<ExtractedProfile, EvalError> {
    let source = std::fs::read_to_string(path).map_err(|source| EvalError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    evaluate_profile_source(&source, &path.display().to_string())
}

fn extract_declarations(ir: &Table) -> mlua::Result<Declarations> {
    Ok(Declarations {
        name: ir.get("name")?,
        version: ir.get("version")?,
        description: ir.get("description")?,
        capabilities: string_list(ir, "capabilities")?,
        env: string_list(ir, "env")?,
        env_secrets: string_list(ir, "env_secrets")?,
        paths: string_list(ir, "paths")?,
        http_allowlist: string_list(ir, "http_allowlist")?,
    })
}

fn string_list(ir: &Table, field: &str) -> mlua::Result<Vec<String>> {
    let list: Table = ir.get(field)?;
    list.sequence_values::<String>().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_PROFILE: &str = r#"
        local profile = require('lm.profile')
        return profile { name = "demo" }
    "#;

    #[test]
    fn evaluate_profile_source_extracts_declarations_from_a_minimal_profile() {
        let extracted = evaluate_profile_source(MINIMAL_PROFILE, "test-profile")
            .expect("minimal profile should evaluate");

        assert_eq!(extracted.declarations.name, "demo");
        assert_eq!(extracted.declarations.version, "0.0.0");
        assert_eq!(extracted.declarations.description, None);
        assert!(extracted.declarations.capabilities.is_empty());
        assert!(extracted.declarations.env.is_empty());
        assert!(extracted.declarations.env_secrets.is_empty());
        assert!(extracted.declarations.paths.is_empty());
        assert!(extracted.declarations.http_allowlist.is_empty());

        // The IR reference stays usable after evaluation returns (the
        // returned `Lua` keeps the weak `Table` reference alive).
        let schema: String = extracted.ir.get("schema").expect("schema field");
        assert_eq!(schema, "lm.profile/1");
    }

    #[test]
    fn evaluate_profile_source_extracts_declared_lists_sorted_regardless_of_declaration_order() {
        let source = r#"
            local profile = require('lm.profile')
            return profile {
                name = "demo",
                capabilities = { "sh.exec", "fs.write", "env.ref" },
                env = { "ZETA", "ALPHA", "MID" },
                env_secrets = { "HF_TOKEN", "B2_KEY" },
                paths = { "/workspace", "/data" },
                http_allowlist = { "https://z.example.com/", "https://a.example.com/" },
            }
        "#;
        let extracted =
            evaluate_profile_source(source, "test-profile").expect("profile should evaluate");

        assert_eq!(
            extracted.declarations.capabilities,
            vec!["env.ref", "fs.write", "sh.exec"]
        );
        assert_eq!(extracted.declarations.env, vec!["ALPHA", "MID", "ZETA"]);
        assert_eq!(
            extracted.declarations.env_secrets,
            vec!["B2_KEY", "HF_TOKEN"]
        );
        assert_eq!(extracted.declarations.paths, vec!["/data", "/workspace"]);
        assert_eq!(
            extracted.declarations.http_allowlist,
            vec!["https://a.example.com/", "https://z.example.com/"]
        );
    }

    #[test]
    fn env_ref_is_callable_from_the_profile_body_before_declaration_extraction() {
        let source = r#"
            local profile = require('lm.profile')
            local token = env.ref("HF_TOKEN")
            return profile {
                name = "demo",
                env_secrets = { "HF_TOKEN" },
                phases = {
                    { kind = "fs.write", path = "/workspace/secret.txt", content = token },
                },
            }
        "#;
        let extracted = evaluate_profile_source(source, "test-profile")
            .expect("env.ref should be callable ahead of declaration extraction");

        let phases: Table = extracted.ir.get("phases").expect("phases");
        assert_eq!(phases.raw_len(), 1);
    }

    #[test]
    fn profile_that_reaches_for_an_unregistered_bridge_primitive_fails_before_any_effect_runs() {
        let source = r#"
            local profile = require('lm.profile')
            sh.exec({ "echo", "hi" })
            return profile { name = "demo" }
        "#;
        // `ExtractedProfile` (the `Ok` side) does not implement `Debug`
        // (it holds an `mlua::Lua`), so `.err()` — rather than
        // `expect_err` — is used to avoid requiring that bound.
        let err = evaluate_profile_source(source, "test-profile")
            .err()
            .expect("sh is not registered during profile evaluation (defer pattern, 04 §Registration order)");
        let message = err.to_string();
        assert!(
            message.contains('\'')
                && message.to_lowercase().contains("nil value")
                && message.contains("sh"),
            "04 §Registration order: reaching for an unregistered bridge primitive must fail \
             structurally before any effect runs: {message}"
        );
    }

    #[test]
    fn profile_not_returning_a_table_is_rejected_with_the_literal_message() {
        let err = evaluate_profile_source("return 42", "test-profile")
            .err()
            .expect("non-table return must be rejected");
        assert!(matches!(err, EvalError::ProfileMustReturnTable));
        assert_eq!(
            err.to_string(),
            "profile.lua must return a table from lm.profile {...}"
        );
    }

    #[test]
    fn evaluate_profile_file_reads_and_evaluates_a_profile_from_disk() {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-eval-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let profile_path = dir.join("profile.lua");
        std::fs::write(&profile_path, MINIMAL_PROFILE).expect("write profile file");

        let extracted = evaluate_profile_file(&profile_path).expect("profile file should evaluate");
        assert_eq!(extracted.declarations.name, "demo");

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }

    #[test]
    fn evaluate_profile_file_surfaces_an_io_error_for_a_missing_file() {
        let missing = PathBuf::from("/nonexistent/lm-provision-profile.lua");
        let err = evaluate_profile_file(&missing)
            .err()
            .expect("missing file must be an Io error");
        assert!(matches!(err, EvalError::Io { .. }));
    }
}
