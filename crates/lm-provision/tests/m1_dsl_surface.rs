//! M1 (DSL surface + IR + shared vocab) regression tests.
//!
//! Exercises `lm.catalog_data`, `lm.profile`, `lm.ir`, and `lm.env`
//! through the sandboxed VM boot path ([`lm_provision::vm::boot_vm`]),
//! the same entry point the CLI uses, rather than unit-testing the Lua
//! source in isolation.
//!
//! Covers:
//! - 01-profile-dsl-surface.md §List-shape rule (declared-list stable
//!   sort, `phases` user-order preservation).
//! - 01-profile-dsl-surface.md §Outputs (`schema = "lm.profile/1"`,
//!   default-fill).
//! - 01-profile-dsl-surface.md §Error surface (definition-time typed
//!   assert literal message).
//! - 02-phase-catalog.md §Shared vocabulary (22 kinds, 9 capabilities,
//!   8+8 substring sets) via `lm.catalog_data`.

use lm_provision::vm::boot_vm;
use mlua::Table;

fn catalog(lua: &mlua::Lua) -> Table {
    lua.load("return require('lm.catalog_data')")
        .eval()
        .expect("lm.catalog_data should be requireable")
}

// ---------------------------------------------------------------------
// M1-1: lm.catalog_data shared vocabulary counts + representative entries
// ---------------------------------------------------------------------

#[test]
fn catalog_data_has_the_documented_shared_vocabulary_counts() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let catalog = catalog(&lua);

    let phase_kinds: Table = catalog.get("PHASE_KINDS").expect("PHASE_KINDS");
    assert_eq!(
        phase_kinds.raw_len(),
        22,
        "02-phase-catalog.md §Inputs: catalog is exhaustive at 22 user-facing kinds"
    );

    let known_caps: Table = catalog
        .get("KNOWN_CAPABILITIES")
        .expect("KNOWN_CAPABILITIES");
    assert_eq!(
        known_caps.raw_len(),
        9,
        "05 §L4 / 02 §Shared vocabulary: KNOWN_CAPABILITIES has 9 operation-scoped entries"
    );

    let secret_keys: Table = catalog
        .get("SECRET_KEY_SUBSTRINGS")
        .expect("SECRET_KEY_SUBSTRINGS");
    assert_eq!(
        secret_keys.raw_len(),
        8,
        "chapter 06 secret-key substring set"
    );

    let sensitive_keys: Table = catalog
        .get("SENSITIVE_KEY_SUBSTRINGS")
        .expect("SENSITIVE_KEY_SUBSTRINGS");
    assert_eq!(
        sensitive_keys.raw_len(),
        8,
        "chapter 09 sensitive-key substring set"
    );
}

#[test]
fn catalog_data_representative_kind_entries_match_the_spec_table() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let catalog = catalog(&lua);
    let by_kind: Table = catalog
        .get("PHASE_KINDS_BY_KIND")
        .expect("PHASE_KINDS_BY_KIND");

    let system_apt: Table = by_kind.get("system.apt").expect("system.apt entry");
    let caps: Table = system_apt.get("capabilities").expect("capabilities");
    let caps_vec: Vec<String> = caps
        .sequence_values()
        .collect::<mlua::Result<_>>()
        .expect("capabilities values");
    assert_eq!(caps_vec, vec!["sh.exec"]);

    let mount_umount: Table = by_kind.get("mount.umount").expect("mount.umount entry");
    let fields: Table = mount_umount.get("fields").expect("fields");
    assert_eq!(fields.raw_len(), 3, "path, lazy?, force?");

    let net_transfer: Table = by_kind.get("net.transfer").expect("net.transfer entry");
    let net_transfer_caps: Table = net_transfer.get("capabilities").expect("capabilities");
    let net_transfer_caps_vec: Vec<String> = net_transfer_caps
        .sequence_values()
        .collect::<mlua::Result<_>>()
        .expect("capabilities values");
    assert_eq!(
        net_transfer_caps_vec,
        vec!["net.transfer", "sh.exec"],
        "02 §Dispatch routing: net.transfer may route to sh.exec"
    );

    // sync.routes is plan-internal, not user-declarable (02 §Plan-internal
    // kind); it must not appear in the 22-kind catalog.
    let sync_routes: mlua::Value = by_kind.get("sync.routes").expect("lookup for sync.routes");
    assert!(
        matches!(sync_routes, mlua::Value::Nil),
        "sync.routes must be absent from PHASE_KINDS_BY_KIND"
    );
}

#[test]
fn known_capabilities_include_the_reserved_mount_volume_attach_entry() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let catalog = catalog(&lua);

    let known_caps: Table = catalog
        .get("KNOWN_CAPABILITIES")
        .expect("KNOWN_CAPABILITIES");
    let names: Vec<String> = known_caps
        .sequence_values()
        .collect::<mlua::Result<_>>()
        .expect("capability names");
    assert!(names.contains(&"mount.volume_attach".to_string()));

    let reserved: Table = catalog
        .get("RESERVED_CAPABILITIES")
        .expect("RESERVED_CAPABILITIES");
    let is_reserved: bool = reserved.get("mount.volume_attach").expect("reserved flag");
    assert!(
        is_reserved,
        "02 §Shared vocabulary: mount.volume_attach passes the gate build but has no bridge"
    );
}

// ---------------------------------------------------------------------
// M1-2: lm.profile + lm.ir
// ---------------------------------------------------------------------

#[test]
fn lm_profile_attaches_schema_tag_and_fills_defaults() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let ir: Table = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile { name = "demo" }
            "#,
        )
        .eval()
        .expect("lm.profile should normalize a minimal spec");

    let schema: String = ir.get("schema").expect("schema");
    assert_eq!(schema, "lm.profile/1");

    let name: String = ir.get("name").expect("name");
    assert_eq!(name, "demo");

    let version: String = ir.get("version").expect("version");
    assert_eq!(version, "0.0.0", "01 §Inputs: version defaults to 0.0.0");

    let capabilities: Table = ir.get("capabilities").expect("capabilities");
    assert_eq!(
        capabilities.raw_len(),
        0,
        "01 §Inputs: capabilities defaults to {{}}"
    );

    let phases: Table = ir.get("phases").expect("phases");
    assert_eq!(phases.raw_len(), 0, "01 §Inputs: phases defaults to {{}}");
}

#[test]
fn lm_profile_stable_sorts_declared_lists_lexicographically() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let ir: Table = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile {
                name = "demo",
                capabilities = { "sh.exec", "fs.write", "env.ref" },
                env = { "ZETA", "ALPHA", "MID" },
            }
            "#,
        )
        .eval()
        .expect("lm.profile should sort declared lists");

    let capabilities: Table = ir.get("capabilities").expect("capabilities");
    let caps_vec: Vec<String> = capabilities
        .sequence_values()
        .collect::<mlua::Result<_>>()
        .expect("capabilities values");
    assert_eq!(
        caps_vec,
        vec!["env.ref", "fs.write", "sh.exec"],
        "01 §List-shape rule: capabilities is stable-sorted lexicographically"
    );

    let env: Table = ir.get("env").expect("env");
    let env_vec: Vec<String> = env
        .sequence_values()
        .collect::<mlua::Result<_>>()
        .expect("env values");
    assert_eq!(env_vec, vec!["ALPHA", "MID", "ZETA"]);
}

#[test]
fn lm_profile_preserves_phase_declaration_order() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let ir: Table = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile {
                name = "demo",
                phases = {
                    { kind = "system.apt", packages = { "curl" } },
                    { kind = "hooks.post_install", script = "echo hi" },
                    { kind = "comfyui.install", ref = "abc" },
                },
            }
            "#,
        )
        .eval()
        .expect("lm.profile should preserve phase order");

    let phases: Table = ir.get("phases").expect("phases");
    assert_eq!(phases.raw_len(), 3);

    let kinds: Vec<String> = phases
        .sequence_values::<Table>()
        .map(|phase| {
            phase
                .expect("phase table")
                .get::<String>("kind")
                .expect("kind field")
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["system.apt", "hooks.post_install", "comfyui.install"],
        "01 §List-shape rule: phases preserves user-declared order verbatim, not phase-kind bucket order"
    );
}

#[test]
fn lm_profile_rejects_non_string_declared_list_entry_with_the_literal_message() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile { name = "demo", capabilities = { "sh.exec", 42 } }
            "#,
        )
        .exec()
        .expect_err("non-string declared-list entry must raise");
    let message = err.to_string();
    assert!(
        message.contains("lm.profile: capabilities[2] must be a string, got number"),
        "01 §Inputs literal message form: {message}"
    );
}

#[test]
fn lm_profile_rejects_missing_name() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile { version = "1.0.0" }
            "#,
        )
        .exec()
        .expect_err("missing name must raise");
    let message = err.to_string();
    assert!(
        message.contains("lm.profile: name is required"),
        "01 §Error surface: name missing/empty is a definition-time assert: {message}"
    );
}

#[test]
fn lm_profile_rejects_non_table_spec() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile("not-a-table")
            "#,
        )
        .exec()
        .expect_err("non-table spec must raise");
    let message = err.to_string();
    assert!(
        message.contains("lm.profile: spec must be a table"),
        "01 §Error surface: spec not a table is a definition-time assert: {message}"
    );
}

#[test]
fn lm_profile_rejects_non_list_shaped_phases() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load(
            r#"
            local profile = require('lm.profile')
            return profile { name = "demo", phases = "nope" }
            "#,
        )
        .exec()
        .expect_err("non-table phases must raise");
    let message = err.to_string();
    assert!(
        message.contains("lm.profile: phases must be a list-shaped table"),
        "01 §Error surface: phases not a list-shaped table is a definition-time assert: {message}"
    );
}

// ---------------------------------------------------------------------
// M1-2: lm.env (facade skeleton only; env.ref/env.get land in M1-3/M3)
// ---------------------------------------------------------------------

#[test]
fn lm_env_is_requireable_and_is_currently_an_empty_placeholder() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let env_module: Table = lua
        .load("return require('lm.env')")
        .eval()
        .expect("lm.env should be requireable");
    assert_eq!(
        env_module.raw_len(),
        0,
        "lm.env is a stub through M1: env.ref/env.get are host-registered in M1-3/M3"
    );
}
