//! `codegen <profile>` pipeline (07-cli.md §Invocation: load →
//! declarations → codegen, read-only, no effects).
//!
//! Emits a `.d.lua` EmmyLua annotation file (lua-language-server
//! compatible) describing the *shape* vocabulary shared across every
//! profile — the `lm.profile` IR field list plus the `lm.phase.kind` and
//! `lm.capability` enumerations — not any single profile instance's
//! values. The `lm.phase.kind` / `lm.capability` alias members are read
//! from `lm.catalog_data` at codegen time, every run (Crux #5: the
//! shared-vocabulary catalog is the single source of truth; this module
//! never hardcodes a second copy of either list in Rust).

use std::path::Path;

use mlua::Table;

use crate::cli::{require_module, PipelineResult};
use crate::vm::eval::evaluate_profile_file;

/// `codegen <profile>` pipeline. Evaluates `profile` through the same
/// sandboxed VM path every other read-only subcommand uses
/// ([`evaluate_profile_file`]), then reads `lm.catalog_data`'s
/// `PHASE_KINDS` and `KNOWN_CAPABILITIES` tables to render the `.d.lua`
/// annotation string ([`render_d_lua`]).
///
/// The evaluated profile's own IR is not walked field-by-field — a
/// successful [`evaluate_profile_file`] call is itself the precondition
/// check this subcommand needs (the `.d.lua` output is type annotation,
/// not this profile instance's data).
pub fn codegen_pipeline(profile: &Path) -> PipelineResult<String> {
    let extracted = evaluate_profile_file(profile)?;

    let catalog = require_module(&extracted.lua, "lm.catalog_data")?;

    let phase_kinds_table: Table = catalog.get("PHASE_KINDS")?;
    let phase_kinds: Vec<String> = phase_kinds_table
        .sequence_values::<Table>()
        .map(|entry| entry.and_then(|table| table.get::<String>("kind")))
        .collect::<mlua::Result<Vec<String>>>()?;

    let capabilities_table: Table = catalog.get("KNOWN_CAPABILITIES")?;
    let capabilities: Vec<String> = capabilities_table
        .sequence_values::<String>()
        .collect::<mlua::Result<Vec<String>>>()?;

    Ok(render_d_lua(&phase_kinds, &capabilities))
}

/// Render the `.d.lua` EmmyLua annotation string from an already-read
/// `phase_kinds` / `capabilities` vocabulary (order preserved from the
/// caller — `lm.catalog_data`'s declared table order, not sorted).
///
/// Pure string building (`format!` / `push_str` over compile-time
/// literals): no external template file, no templating crate dependency
/// (Crux #4 — the musl static build must not gain a runtime file
/// dependency).
///
/// The `lm.profile` field list is a fixed literal mirroring `ir.lua`'s
/// `M.build` return shape (`schema` / `name` / `version` / `description`
/// / `capabilities` / `env` / `env_secrets` / `paths` / `http_allowlist`
/// / `phases`) — it changes only when that IR shape changes, unlike
/// `phase_kinds` / `capabilities`, which are read from `lm.catalog_data`
/// fresh on every call.
pub fn render_d_lua(phase_kinds: &[String], capabilities: &[String]) -> String {
    let mut out = String::new();

    out.push_str("---@meta\n\n");

    out.push_str("---@class lm.profile\n");
    out.push_str("---@field schema \"lm.profile/1\"\n");
    out.push_str("---@field name string\n");
    out.push_str("---@field version string\n");
    out.push_str("---@field description string\n");
    out.push_str("---@field capabilities lm.capability[]\n");
    out.push_str("---@field env table<string, string>\n");
    out.push_str("---@field env_secrets string[]\n");
    out.push_str("---@field paths table<string, string>\n");
    out.push_str("---@field http_allowlist string[]\n");
    out.push_str("---@field phases lm.phase[]\n\n");

    out.push_str("---@class lm.phase\n");
    out.push_str("---@field kind lm.phase.kind\n\n");

    out.push_str("---@alias lm.phase.kind\n");
    for kind in phase_kinds {
        out.push_str(&format!("---| \"{kind}\"\n"));
    }
    out.push('\n');

    out.push_str("---@alias lm.capability\n");
    for capability in capabilities {
        out.push_str(&format!("---| \"{capability}\"\n"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_d_lua_emits_meta_and_class_headers() {
        let rendered = render_d_lua(&["system.apt".to_string()], &["sh.exec".to_string()]);
        assert!(rendered.starts_with("---@meta\n\n"));
        assert!(rendered.contains("---@class lm.profile\n"));
        assert!(rendered.contains("---@class lm.phase\n"));
    }

    #[test]
    fn render_d_lua_lists_every_phase_kind_and_capability_in_order() {
        let phase_kinds = vec!["a.one".to_string(), "b.two".to_string()];
        let capabilities = vec!["cap.one".to_string(), "cap.two".to_string()];
        let rendered = render_d_lua(&phase_kinds, &capabilities);

        let phase_kind_pos = rendered.find("---@alias lm.phase.kind\n").unwrap();
        let capability_pos = rendered.find("---@alias lm.capability\n").unwrap();
        assert!(phase_kind_pos < capability_pos);

        assert!(rendered.contains("---| \"a.one\"\n---| \"b.two\"\n"));
        assert!(rendered.contains("---| \"cap.one\"\n---| \"cap.two\"\n"));
    }

    #[test]
    fn render_d_lua_handles_empty_vocabulary() {
        let rendered = render_d_lua(&[], &[]);
        assert!(rendered.contains("---@alias lm.phase.kind\n\n---@alias lm.capability\n"));
    }
}
