//! M2-3 (`lm.plan`) regression tests.
//!
//! Exercises `lm.plan.expand(ir)` through the sandboxed VM boot path
//! ([`lm_provision::vm::boot_vm`]).
//!
//! Covers 02-phase-catalog.md §Canonical phase ordering (bucket order,
//! same-kind declaration order, implicit `comfyui.restart` /
//! `comfyui.health` insertion, `service.start` / `service.ready`
//! per-declaration indexing), the `python.version_check` default-value
//! suppression rule, the `sync.routes` plan-internal bundle (02
//! §Plan-internal kind), the trailing `zz_unknown` bucket (02 §Unknown
//! kinds), and the 1-based contiguous `index` counter
//! (03-pipeline-stage-artifacts.md §plan).

use lm_provision::vm::boot_vm;
use mlua::Table;

/// Evaluates `local ir = <ir_expr>; return require('lm.plan').expand(ir)`
/// and returns `(lua, plan)`. `ir_expr` is expected to be a full
/// `require('lm.profile')`-style expression, or a literal IR table.
///
/// The `Lua` VM must be kept alive alongside the returned `Table` (see
/// `m2_validate.rs`'s `validate_source` doc comment for why).
fn expand(ir_expr: &str) -> (mlua::Lua, Table) {
    let lua = boot_vm().expect("boot_vm should succeed");
    let source = format!(
        r#"
        local profile = require('lm.profile')
        local plan = require('lm.plan')
        local ir = {ir_expr}
        return plan.expand(ir)
        "#
    );
    let result = lua
        .load(source)
        .eval::<Table>()
        .expect("plan.expand should evaluate without a Lua error");
    (lua, result)
}

fn steps(plan: &Table) -> Table {
    plan.get("steps").expect("steps field")
}

fn step_ids(plan: &Table) -> Vec<String> {
    steps(plan)
        .sequence_values::<Table>()
        .map(|s| {
            s.expect("step table")
                .get::<String>("id")
                .expect("id field")
        })
        .collect()
}

fn step_kinds(plan: &Table) -> Vec<String> {
    steps(plan)
        .sequence_values::<Table>()
        .map(|s| {
            s.expect("step table")
                .get::<String>("kind")
                .expect("kind field")
        })
        .collect()
}

fn step_indices(plan: &Table) -> Vec<i64> {
    steps(plan)
        .sequence_values::<Table>()
        .map(|s| {
            s.expect("step table")
                .get::<i64>("index")
                .expect("index field")
        })
        .collect()
}

fn step_at(plan: &Table, i: usize) -> Table {
    steps(plan)
        .sequence_values::<Table>()
        .nth(i)
        .expect("step should exist")
        .expect("step table")
}

// ---------------------------------------------------------------------
// Canonical phase ordering (02 §Canonical phase ordering).
// ---------------------------------------------------------------------

#[test]
fn steps_are_emitted_in_the_canonical_bucket_order() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                -- Declared out of canonical order on purpose (service.start
                -- before service.ready, the sane declaration order for a
                -- single service — see the dedicated service-indexing tests
                -- below for the out-of-order / index-0 edge cases).
                { kind = "totally.unknown", whatever = 1 },
                { kind = "service.start", name = "svc", platform = { kind = "vllm" } },
                { kind = "service.ready", name = "svc", check = { http = "http://x/health" } },
                { kind = "comfyui.restart", port = 9000 },
                { kind = "comfyui.health", port = 9000 },
                { kind = "hooks.post_install", script = "echo hi" },
                { kind = "llm_models", models = { { src = "hf://owner/repo" } } },
                { kind = "models", models = { { src = "https://x/y.bin", name = "y.bin" } } },
                {
                    kind = "sync.pull",
                    src = "b2://bucket/path.bin",
                    dst = "/workspace/path.bin",
                },
                { kind = "custom_nodes", nodes = { { name = "n1", repo = "owner/repo1" } } },
                { kind = "python.deps", deps = { "torch" } },
                { kind = "comfyui.install", ref = "abc123" },
                { kind = "system.apt", packages = { "curl" } },
                { kind = "sh.exec", argv = { "echo", "hi" } },
            },
        }
        "#,
    );

    assert_eq!(
        step_ids(&plan),
        vec![
            "1_system_apt",
            "2_comfyui_install",
            "3_python_deps",
            "4_custom_nodes",
            "5_sync_routes",
            "7_models",
            "7b_llm_models",
            "8_post_install",
            "9_comfyui_restart",
            "10_comfyui_health",
            "11_service_0_start",
            "11_service_0_ready",
            "zz_unknown",
            "zz_unknown",
        ]
    );
}

#[test]
fn multiple_phases_of_the_same_kind_keep_their_relative_declaration_order() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "system.apt", packages = { "first" } },
                { kind = "system.apt", packages = { "second" } },
                { kind = "system.apt", packages = { "third" } },
            },
        }
        "#,
    );

    let ids = step_ids(&plan);
    assert_eq!(ids, vec!["1_system_apt", "1_system_apt", "1_system_apt"]);

    let first_pkg: String = step_at(&plan, 0)
        .get::<Table>("payload")
        .unwrap()
        .get::<Table>("packages")
        .unwrap()
        .get(1)
        .unwrap();
    let second_pkg: String = step_at(&plan, 1)
        .get::<Table>("payload")
        .unwrap()
        .get::<Table>("packages")
        .unwrap()
        .get(1)
        .unwrap();
    let third_pkg: String = step_at(&plan, 2)
        .get::<Table>("payload")
        .unwrap()
        .get::<Table>("packages")
        .unwrap()
        .get(1)
        .unwrap();
    assert_eq!(first_pkg, "first");
    assert_eq!(second_pkg, "second");
    assert_eq!(third_pkg, "third");
}

// ---------------------------------------------------------------------
// Implicit comfyui.restart / comfyui.health insertion (02 §Canonical
// phase ordering).
// ---------------------------------------------------------------------

#[test]
fn comfyui_install_with_neither_restart_nor_health_inserts_both_with_the_default_port() {
    let (_lua, plan) = expand(
        r#"
        profile { name = "demo", phases = { { kind = "comfyui.install", ref = "abc" } } }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec![
            "2_comfyui_install",
            "9_comfyui_restart",
            "10_comfyui_health"
        ]
    );

    let restart_port: i64 = step_at(&plan, 1)
        .get::<Table>("payload")
        .unwrap()
        .get("port")
        .unwrap();
    let health_port: i64 = step_at(&plan, 2)
        .get::<Table>("payload")
        .unwrap()
        .get("port")
        .unwrap();
    assert_eq!(restart_port, 8188);
    assert_eq!(health_port, 8188);
}

#[test]
fn comfyui_install_with_only_restart_declared_makes_health_inherit_its_port() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "comfyui.install", ref = "abc" },
                { kind = "comfyui.restart", port = 9001 },
            },
        }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec![
            "2_comfyui_install",
            "9_comfyui_restart",
            "10_comfyui_health"
        ]
    );

    let health_port: i64 = step_at(&plan, 2)
        .get::<Table>("payload")
        .unwrap()
        .get("port")
        .unwrap();
    assert_eq!(
        health_port, 9001,
        "health must inherit the user-declared restart port"
    );
}

#[test]
fn comfyui_install_with_only_health_declared_makes_restart_inherit_its_port() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "comfyui.install", ref = "abc" },
                { kind = "comfyui.health", port = 9002 },
            },
        }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec![
            "2_comfyui_install",
            "9_comfyui_restart",
            "10_comfyui_health"
        ]
    );

    let restart_port: i64 = step_at(&plan, 1)
        .get::<Table>("payload")
        .unwrap()
        .get("port")
        .unwrap();
    assert_eq!(
        restart_port, 9002,
        "restart must inherit the user-declared health port"
    );
}

#[test]
fn comfyui_install_with_both_declared_inserts_neither() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "comfyui.install", ref = "abc" },
                { kind = "comfyui.restart", port = 1111 },
                { kind = "comfyui.health", port = 2222 },
            },
        }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec![
            "2_comfyui_install",
            "9_comfyui_restart",
            "10_comfyui_health"
        ]
    );
    let restart_port: i64 = step_at(&plan, 1)
        .get::<Table>("payload")
        .unwrap()
        .get("port")
        .unwrap();
    let health_port: i64 = step_at(&plan, 2)
        .get::<Table>("payload")
        .unwrap()
        .get("port")
        .unwrap();
    assert_eq!(restart_port, 1111);
    assert_eq!(health_port, 2222);
}

#[test]
fn no_comfyui_install_means_no_implicit_restart_or_health_insertion() {
    let (_lua, plan) = expand(r#"profile { name = "demo", phases = {} }"#);
    assert!(step_ids(&plan).is_empty());
}

// ---------------------------------------------------------------------
// service.start / service.ready per-declaration indexing (02 §Canonical
// phase ordering).
// ---------------------------------------------------------------------

#[test]
fn service_ready_before_any_service_start_gets_index_zero() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "service.ready", name = "svc", check = { http = "http://x/health" } },
            },
        }
        "#,
    );
    assert_eq!(step_ids(&plan), vec!["11_service_0_ready"]);
}

#[test]
fn multiple_services_are_numbered_by_declaration_index() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "service.start", name = "svc-a", platform = { kind = "vllm" } },
                { kind = "service.ready", name = "svc-a", check = { http = "http://a/health" } },
                { kind = "service.start", name = "svc-b", platform = { kind = "ollama" } },
                { kind = "service.ready", name = "svc-b", check = { http = "http://b/health" } },
            },
        }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec![
            "11_service_0_start",
            "11_service_0_ready",
            "11_service_1_start",
            "11_service_1_ready",
        ]
    );
}

#[test]
fn a_ready_step_inherits_the_index_of_the_most_recently_declared_start() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "service.start", name = "svc-a", platform = { kind = "vllm" } },
                { kind = "service.start", name = "svc-b", platform = { kind = "ollama" } },
                { kind = "service.ready", name = "svc-b", check = { http = "http://b/health" } },
            },
        }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec![
            "11_service_0_start",
            "11_service_1_start",
            "11_service_1_ready"
        ]
    );
}

// ---------------------------------------------------------------------
// python.version_check default-value suppression (02 §Catalog kinds).
// ---------------------------------------------------------------------

#[test]
fn python_version_check_is_suppressed_when_want_is_omitted() {
    let (_lua, plan) =
        expand(r#"profile { name = "demo", phases = { { kind = "python.version_check" } } }"#);
    assert!(
        step_ids(&plan).is_empty(),
        "omitted want defaults to 3.12 and is suppressed"
    );
}

#[test]
fn python_version_check_is_suppressed_when_want_equals_the_default() {
    let (_lua, plan) = expand(
        r#"profile { name = "demo", phases = { { kind = "python.version_check", want = "3.12" } } }"#,
    );
    assert!(step_ids(&plan).is_empty());
}

#[test]
fn python_version_check_is_kept_when_want_differs_from_the_default() {
    let (_lua, plan) = expand(
        r#"profile { name = "demo", phases = { { kind = "python.version_check", want = "3.11" } } }"#,
    );
    assert_eq!(step_ids(&plan), vec!["3a_python_version_check"]);
}

// ---------------------------------------------------------------------
// sync.routes plan-internal bundle (02 §Plan-internal kind).
// ---------------------------------------------------------------------

#[test]
fn sync_pull_push_and_staging_push_bundle_into_a_single_sync_routes_step() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "sync.pull", src = "b2://bucket/a.bin", dst = "/workspace/a.bin" },
                { kind = "sync.push", src = "/workspace/out.bin", dst = "b2://bucket/out.bin" },
                {
                    kind = "staging.push",
                    src = "/workspace/stage.bin",
                    dst = "hf://owner/repo/stage.bin",
                },
            },
        }
        "#,
    );
    assert_eq!(step_ids(&plan), vec!["5_sync_routes"]);
    assert_eq!(step_kinds(&plan), vec!["sync.routes"]);

    let payload: Table = step_at(&plan, 0).get("payload").unwrap();
    let pull: Table = payload.get("pull").unwrap();
    let push_markers: Table = payload.get("push_markers").unwrap();
    let staging_push: Table = payload.get("staging_push").unwrap();
    assert_eq!(pull.raw_len(), 1);
    assert_eq!(push_markers.raw_len(), 1);
    assert_eq!(staging_push.raw_len(), 1);
}

#[test]
fn no_sync_related_phases_means_no_sync_routes_step() {
    let (_lua, plan) = expand(
        r#"profile { name = "demo", phases = { { kind = "system.apt", packages = { "curl" } } } }"#,
    );
    assert!(!step_ids(&plan).contains(&"5_sync_routes".to_string()));
}

#[test]
fn a_profile_declaring_the_literal_sync_routes_kind_falls_into_zz_unknown() {
    let (_lua, plan) =
        expand(r#"profile { name = "demo", phases = { { kind = "sync.routes" } } }"#);
    assert_eq!(step_ids(&plan), vec!["zz_unknown"]);
    assert_eq!(step_kinds(&plan), vec!["sync.routes"]);
}

// ---------------------------------------------------------------------
// zz_unknown trailing bucket (02 §Unknown kinds).
// ---------------------------------------------------------------------

#[test]
fn direct_operation_kinds_and_unknown_kinds_share_the_trailing_zz_unknown_bucket_in_declaration_order(
) {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "sh.exec", argv = { "echo", "a" } },
                { kind = "totally.unknown.first" },
                { kind = "fs.write", path = "/workspace/x", content = "y" },
                { kind = "totally.unknown.second" },
            },
        }
        "#,
    );
    assert_eq!(
        step_ids(&plan),
        vec!["zz_unknown", "zz_unknown", "zz_unknown", "zz_unknown"]
    );
    assert_eq!(
        step_kinds(&plan),
        vec![
            "sh.exec",
            "totally.unknown.first",
            "fs.write",
            "totally.unknown.second"
        ],
        "02 §Canonical phase ordering: declaration order must be preserved across mixed \
         direct-operation and unknown kinds"
    );
}

// ---------------------------------------------------------------------
// index: 1-based contiguous counter in emission order (03 §plan).
// ---------------------------------------------------------------------

#[test]
fn index_is_a_1_based_contiguous_counter_in_emission_order() {
    let (_lua, plan) = expand(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "system.apt", packages = { "curl" } },
                { kind = "hooks.post_install", script = "echo hi" },
                { kind = "totally.unknown" },
            },
        }
        "#,
    );
    assert_eq!(step_indices(&plan), vec![1, 2, 3]);
}

// ---------------------------------------------------------------------
// Error surface (03 §Error surface: "plan / dispatch: raise only on
// malformed stage input (non-table)").
// ---------------------------------------------------------------------

#[test]
fn expand_raises_on_a_non_table_ir() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load("return require('lm.plan').expand(42)")
        .eval::<mlua::Value>()
        .expect_err("a non-table ir must raise");
    assert!(err.to_string().contains("ir must be a table"));
}

// ---------------------------------------------------------------------
// profile_name / schema passthrough (03 §plan Outputs).
// ---------------------------------------------------------------------

#[test]
fn plan_carries_the_profile_name_and_schema_through_from_the_ir() {
    let (_lua, plan) = expand(r#"profile { name = "demo-profile" }"#);
    let name: String = plan.get("profile_name").unwrap();
    let schema: String = plan.get("schema").unwrap();
    assert_eq!(name, "demo-profile");
    assert_eq!(schema, "lm.profile/1");
}
