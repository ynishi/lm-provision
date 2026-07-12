//! M2-4 (`lm.dispatch`) regression tests.
//!
//! Exercises `lm.dispatch.dispatch(plan)` through the sandboxed VM boot
//! path ([`lm_provision::vm::boot_vm`]).
//!
//! Most tests feed a literal plan-artifact table directly (dispatch's
//! only documented input is "the plan artifact",
//! 03-pipeline-stage-artifacts.md §Inputs) rather than chaining through
//! `lm.profile` + `lm.plan.expand` — this isolates the routing /
//! fan-out logic under test from `lm.plan`'s own bucket-assignment
//! behaviour (covered by `m2_plan.rs`). A couple of end-to-end tests
//! chain the full `profile → plan → dispatch` path to confirm the two
//! stages compose.
//!
//! Covers: the op enum + direct-operation 1:1 passthrough, the seven
//! literal fan-out suffix patterns, scheme routing for b2:// / hf:// /
//! https:// downloads and uploads (02-phase-catalog.md §Dispatch
//! routing), `@<rev>` precedence and owner-segment rejection, the
//! `sync.push` marker-only mapping, and the `dispatch_pending` shape for
//! kinds this milestone defers (comfyui.restart / comfyui.health /
//! service.start / service.ready / python.version_check / a genuinely
//! unrecognized kind).

use lm_provision::vm::boot_vm;
use mlua::{Lua, Table, Value};

/// Evaluates `local plan = <plan_expr>; return
/// require('lm.dispatch').dispatch(plan)` and returns `(lua, result)`.
fn dispatch_plan(plan_expr: &str) -> (Lua, Table) {
    let lua = boot_vm().expect("boot_vm should succeed");
    let source = format!(
        r#"
        local dispatch = require('lm.dispatch')
        local plan = {plan_expr}
        return dispatch.dispatch(plan)
        "#
    );
    let result = lua
        .load(source)
        .eval::<Table>()
        .expect("dispatch.dispatch should evaluate without a Lua error");
    (lua, result)
}

/// Chains `lm.profile` → `lm.plan.expand` → `lm.dispatch.dispatch` for
/// end-to-end composition tests.
fn dispatch_via_pipeline(ir_expr: &str) -> (Lua, Table) {
    let lua = boot_vm().expect("boot_vm should succeed");
    let source = format!(
        r#"
        local profile = require('lm.profile')
        local plan = require('lm.plan')
        local dispatch = require('lm.dispatch')
        local ir = {ir_expr}
        return dispatch.dispatch(plan.expand(ir))
        "#
    );
    let result = lua
        .load(source)
        .eval::<Table>()
        .expect("pipeline should evaluate without a Lua error");
    (lua, result)
}

fn steps(result: &Table) -> Table {
    result.get("steps").expect("steps field")
}

fn step_at(result: &Table, i: usize) -> Table {
    steps(result)
        .sequence_values::<Table>()
        .nth(i)
        .expect("step should exist")
        .expect("step table")
}

fn step_count(result: &Table) -> usize {
    steps(result).raw_len()
}

fn field<T: mlua::FromLua>(step: &Table, name: &str) -> T {
    step.get(name).unwrap_or_else(|_| panic!("{name} field"))
}

fn argv_strings(step: &Table) -> Vec<String> {
    let argv: Table = step.get("argv").expect("argv field");
    argv.sequence_values::<String>()
        .map(|v| v.expect("argv entry"))
        .collect()
}

// ---------------------------------------------------------------------
// Direct-operation kinds: 1:1 passthrough (02 §Catalog kinds (direct
// operations)).
// ---------------------------------------------------------------------

#[test]
fn sh_exec_passes_through_argv_and_opts_verbatim() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "sh.exec",
                    payload = { kind = "sh.exec", argv = { "echo", "hi" }, opts = { cwd = "/workspace" } },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 1);
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "sh.exec");
    assert_eq!(argv_strings(&step), vec!["echo", "hi"]);
    let opts: Table = field(&step, "opts");
    let cwd: String = opts.get("cwd").unwrap();
    assert_eq!(cwd, "/workspace");
}

#[test]
fn fs_write_forwards_non_core_fields_to_opts() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "fs.write",
                    payload = {
                        kind = "fs.write", path = "/workspace/x", content = "hello",
                        mode = 420, append = true, mkdir_p = true,
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "fs.write");
    let path: String = field(&step, "path");
    let content: String = field(&step, "content");
    assert_eq!(path, "/workspace/x");
    assert_eq!(content, "hello");
    let opts: Table = field(&step, "opts");
    let mode: i64 = opts.get("mode").unwrap();
    let append: bool = opts.get("append").unwrap();
    let mkdir_p: bool = opts.get("mkdir_p").unwrap();
    assert_eq!(mode, 420);
    assert!(append);
    assert!(mkdir_p);
}

#[test]
fn net_http_get_forwards_headers_and_timeout_to_opts() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "net.http_get",
                    payload = {
                        kind = "net.http_get", url = "https://example.com/api",
                        headers = { Accept = "application/json" }, timeout_sec = 5,
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "net.http_get");
    let url: String = field(&step, "url");
    assert_eq!(url, "https://example.com/api");
    let opts: Table = field(&step, "opts");
    let timeout_sec: i64 = opts.get("timeout_sec").unwrap();
    assert_eq!(timeout_sec, 5);
}

#[test]
fn net_http_post_forwards_body_json_to_opts() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "net.http_post",
                    payload = {
                        kind = "net.http_post", url = "https://example.com/api",
                        body_json = { a = 1 },
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "net.http_post");
    let opts: Table = field(&step, "opts");
    let body_json: Table = opts.get("body_json").unwrap();
    let a: i64 = body_json.get("a").unwrap();
    assert_eq!(a, 1);
}

#[test]
fn mount_bind_forwards_recursive_and_read_only_to_opts() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "mount.bind",
                    payload = {
                        kind = "mount.bind", src = "/data", dst = "/workspace/data",
                        recursive = true, read_only = true,
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "mount.bind");
    let src: String = field(&step, "src");
    let dst: String = field(&step, "dst");
    assert_eq!(src, "/data");
    assert_eq!(dst, "/workspace/data");
    let opts: Table = field(&step, "opts");
    let recursive: bool = opts.get("recursive").unwrap();
    let read_only: bool = opts.get("read_only").unwrap();
    assert!(recursive);
    assert!(read_only);
}

#[test]
fn mount_umount_forwards_lazy_and_force_to_opts() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "mount.umount",
                    payload = { kind = "mount.umount", path = "/workspace/data", lazy = true, force = false },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "mount.umount");
    let path: String = field(&step, "path");
    assert_eq!(path, "/workspace/data");
    let opts: Table = field(&step, "opts");
    let lazy: bool = opts.get("lazy").unwrap();
    assert!(lazy);
}

// ---------------------------------------------------------------------
// net.transfer (directly-declared phase): direction inference + scheme
// routing (04-bridge.md §net.transfer).
// ---------------------------------------------------------------------

#[test]
fn net_transfer_direct_https_download_stays_on_the_net_transfer_bridge() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "net.transfer",
                    payload = { kind = "net.transfer", src = "https://example.com/x.bin", dst = "/workspace/x.bin" },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "net.transfer");
    let src: String = field(&step, "src");
    let dst: String = field(&step, "dst");
    assert_eq!(src, "https://example.com/x.bin");
    assert_eq!(dst, "/workspace/x.bin");
}

#[test]
fn net_transfer_direct_b2_download_with_env_routes_to_the_native_cli() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "net.transfer",
                    payload = {
                        kind = "net.transfer", src = "b2://bucket/path/a.bin", dst = "/workspace/a.bin",
                        env = { B2_KEY = "x" },
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "sh.exec");
    assert_eq!(
        argv_strings(&step),
        vec![
            "b2",
            "download-file-by-name",
            "bucket",
            "path/a.bin",
            "/workspace/a.bin"
        ]
    );
}

// ---------------------------------------------------------------------
// custom_nodes fan-out (`/<i>_clone`, `/<i>_ref`, `/<i>_pip`).
// ---------------------------------------------------------------------

#[test]
fn custom_nodes_fans_out_clone_ref_and_pip_when_all_are_declared() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "4_custom_nodes", kind = "custom_nodes",
                    payload = {
                        kind = "custom_nodes",
                        nodes = { { name = "n1", repo = "owner/repo1", ref = "v1.0", pip = true } },
                    },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 3);
    let clone = step_at(&result, 0);
    let ref_step = step_at(&result, 1);
    let pip_step = step_at(&result, 2);

    let clone_id: String = field(&clone, "id");
    let ref_id: String = field(&ref_step, "id");
    let pip_id: String = field(&pip_step, "id");
    assert_eq!(clone_id, "4_custom_nodes/1_clone");
    assert_eq!(ref_id, "4_custom_nodes/1_ref");
    assert_eq!(pip_id, "4_custom_nodes/1_pip");

    assert_eq!(
        argv_strings(&clone),
        vec![
            "git",
            "clone",
            "https://github.com/owner/repo1.git",
            "/workspace/ComfyUI/custom_nodes/n1"
        ]
    );
    assert_eq!(
        argv_strings(&ref_step),
        vec![
            "git",
            "-C",
            "/workspace/ComfyUI/custom_nodes/n1",
            "checkout",
            "v1.0"
        ]
    );
    assert_eq!(
        argv_strings(&pip_step),
        vec![
            "/workspace/ComfyUI/venv/bin/pip",
            "install",
            "-r",
            "/workspace/ComfyUI/custom_nodes/n1/requirements.txt",
        ]
    );
}

#[test]
fn custom_nodes_omits_ref_and_pip_steps_when_not_declared() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "4_custom_nodes", kind = "custom_nodes",
                    payload = { kind = "custom_nodes", nodes = { { name = "n1", repo = "owner/repo1" } } },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 1);
    let clone_id: String = field(&step_at(&result, 0), "id");
    assert_eq!(clone_id, "4_custom_nodes/1_clone");
}

#[test]
fn custom_nodes_numbers_multiple_nodes_by_1_based_position() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "4_custom_nodes", kind = "custom_nodes",
                    payload = {
                        kind = "custom_nodes",
                        nodes = { { name = "n1", repo = "owner/r1" }, { name = "n2", repo = "owner/r2" } },
                    },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 2);
    let first_id: String = field(&step_at(&result, 0), "id");
    let second_id: String = field(&step_at(&result, 1), "id");
    assert_eq!(first_id, "4_custom_nodes/1_clone");
    assert_eq!(second_id, "4_custom_nodes/2_clone");
}

// ---------------------------------------------------------------------
// sync.routes fan-out (`/pull_<i>`, `/marker_<i>`, `/staging_<i>`).
// ---------------------------------------------------------------------

#[test]
fn sync_routes_fans_out_pull_marker_and_staging_with_the_literal_suffixes() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = { { src = "https://example.com/a.bin", dst = "/workspace/a.bin" } },
                        push_markers = { { src = "/workspace/out.bin", dst = "b2://bucket/out.bin" } },
                        staging_push = { { src = "/workspace/stage.bin", dst = "https://example.com/stage.bin" } },
                    },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 3);
    let pull_id: String = field(&step_at(&result, 0), "id");
    let marker_id: String = field(&step_at(&result, 1), "id");
    let staging_id: String = field(&step_at(&result, 2), "id");
    assert_eq!(pull_id, "5_sync_routes/pull_1");
    assert_eq!(marker_id, "5_sync_routes/marker_1");
    assert_eq!(staging_id, "5_sync_routes/staging_1");

    let marker_step = step_at(&result, 1);
    let marker_op: String = field(&marker_step, "op");
    assert_eq!(
        marker_op, "dispatch_pending",
        "02 §Catalog kinds: sync.push is marker only, not executed during apply"
    );
}

#[test]
fn sync_pull_b2_with_non_empty_env_routes_to_the_native_cli() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {
                            {
                                src = "b2://my-bucket/models/model.bin", dst = "/workspace/model.bin",
                                env = { B2_KEY = "x" },
                            },
                        },
                        push_markers = {}, staging_push = {},
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "sh.exec");
    assert_eq!(
        argv_strings(&step),
        vec![
            "b2",
            "download-file-by-name",
            "my-bucket",
            "models/model.bin",
            "/workspace/model.bin"
        ]
    );
}

#[test]
fn sync_pull_b2_without_env_stays_on_net_transfer() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = { { src = "b2://my-bucket/models/model.bin", dst = "/workspace/model.bin" } },
                        push_markers = {}, staging_push = {},
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(
        op, "net.transfer",
        "02 §Dispatch routing: public b2:// (no env) stays on the net.transfer bridge"
    );
}

#[test]
fn sync_pull_hf_with_non_empty_env_degrades_to_dispatch_pending() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {
                            { src = "hf://owner/repo/file.bin", dst = "/workspace/file.bin", env = { HF_TOKEN = "x" } },
                        },
                        push_markers = {}, staging_push = {},
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "dispatch_pending");
    let note: String = field(&step, "note");
    assert!(
        note.contains("directory") && note.contains("unconfirmed"),
        "note: {note}"
    );
}

// ---------------------------------------------------------------------
// staging.push / uploads: always CLI for b2/hf dst regardless of env
// (04-bridge.md §net.transfer).
// ---------------------------------------------------------------------

#[test]
fn staging_push_b2_dst_always_routes_to_the_native_cli() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {}, push_markers = {},
                        staging_push = { { src = "/workspace/out.bin", dst = "b2://bucket/out/out.bin" } },
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "sh.exec");
    assert_eq!(
        argv_strings(&step),
        vec![
            "b2",
            "upload-file",
            "bucket",
            "/workspace/out.bin",
            "out/out.bin"
        ]
    );
}

#[test]
fn staging_push_hf_dst_builds_upload_argv_with_revision_and_path_in_repo() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {}, push_markers = {},
                        staging_push = {
                            {
                                src = "/workspace/out.bin", dst = "hf://owner/repo/artifact.bin",
                                revision = "main",
                            },
                        },
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "sh.exec");
    assert_eq!(
        argv_strings(&step),
        vec![
            "huggingface-cli",
            "upload",
            "owner/repo",
            "/workspace/out.bin",
            "artifact.bin",
            "--revision",
            "main",
        ]
    );
}

#[test]
fn staging_push_https_dst_stays_on_net_transfer() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {}, push_markers = {},
                        staging_push = { { src = "/workspace/out.bin", dst = "https://example.com/upload" } },
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "net.transfer");
}

// ---------------------------------------------------------------------
// hf:// @<rev> precedence + owner-segment rejection (02 §Dispatch
// routing).
// ---------------------------------------------------------------------

#[test]
fn a_url_carried_hf_revision_wins_over_the_payload_revision_field() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {}, push_markers = {},
                        staging_push = {
                            {
                                src = "/workspace/out.bin", dst = "hf://owner/repo@from-url/artifact.bin",
                                revision = "from-payload",
                            },
                        },
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let argv = argv_strings(&step);
    let rev_flag_idx = argv
        .iter()
        .position(|s| s == "--revision")
        .expect("--revision flag present");
    assert_eq!(
        argv[rev_flag_idx + 1],
        "from-url",
        "02 §Dispatch routing: a URL-carried revision wins over opts.revision"
    );
}

#[test]
fn an_at_sign_in_the_hf_owner_segment_is_rejected() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let source = r#"
        local dispatch = require('lm.dispatch')
        local plan = {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "5_sync_routes", kind = "sync.routes",
                    payload = {
                        pull = {}, push_markers = {},
                        staging_push = { { src = "/workspace/out.bin", dst = "hf://bad@owner/repo/artifact.bin" } },
                    },
                },
            },
        }
        return dispatch.dispatch(plan)
    "#;
    let err = lua
        .load(source)
        .eval::<Value>()
        .expect_err("'@' in the owner segment must be rejected");
    assert!(
        err.to_string().contains("'@'") && err.to_string().contains("owner segment"),
        "message: {err}"
    );
}

// ---------------------------------------------------------------------
// models / llm_models fan-out (`/<i>`).
// ---------------------------------------------------------------------

#[test]
fn models_fans_out_per_entry_with_the_1_based_numeric_suffix_and_built_in_path() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "7_models", kind = "models",
                    payload = {
                        kind = "models",
                        models = {
                            { src = "https://example.com/a.safetensors", dst = "a.safetensors" },
                            { src = "https://example.com/b.safetensors", name = "b.safetensors", kind = "loras" },
                        },
                    },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 2);
    let first = step_at(&result, 0);
    let second = step_at(&result, 1);
    let first_id: String = field(&first, "id");
    let second_id: String = field(&second, "id");
    assert_eq!(first_id, "7_models/1");
    assert_eq!(second_id, "7_models/2");

    let first_dst: String = field(&first, "dst");
    assert_eq!(
        first_dst,
        "/workspace/ComfyUI/models/checkpoints/a.safetensors"
    );
    let second_dst: String = field(&second, "dst");
    assert_eq!(second_dst, "/workspace/ComfyUI/models/loras/b.safetensors");
}

#[test]
fn llm_models_fans_out_per_entry_with_download_argv() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "7b_llm_models", kind = "llm_models",
                    payload = {
                        kind = "llm_models",
                        models = { { src = "hf://owner/repo@v1", dst_dir = "/data/models" } },
                    },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 1);
    let step = step_at(&result, 0);
    let id: String = field(&step, "id");
    assert_eq!(id, "7b_llm_models/1");
    let op: String = field(&step, "op");
    assert_eq!(op, "sh.exec");
    assert_eq!(
        argv_strings(&step),
        vec![
            "huggingface-cli",
            "download",
            "owner/repo",
            "--local-dir",
            "/data/models",
            "--revision",
            "v1"
        ]
    );
}

// ---------------------------------------------------------------------
// system.apt / comfyui.install / python.deps / hooks.post_install.
// ---------------------------------------------------------------------

#[test]
fn system_apt_builds_a_non_interactive_install_argv() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "1_system_apt", kind = "system.apt",
                    payload = { kind = "system.apt", packages = { "curl", "git" } },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    assert_eq!(
        argv_strings(&step),
        vec!["apt-get", "install", "-y", "curl", "git"]
    );
}

#[test]
fn hooks_post_install_wraps_the_script_in_sh_dash_c() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "8_post_install", kind = "hooks.post_install",
                    payload = { kind = "hooks.post_install", script = "echo hi && echo bye" },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    assert_eq!(argv_strings(&step), vec!["sh", "-c", "echo hi && echo bye"]);
}

#[test]
fn python_deps_uses_the_venv_pip_and_force_reinstall_flag() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "3_python_deps", kind = "python.deps",
                    payload = {
                        kind = "python.deps", deps = { "torch" }, in_comfy_venv = true, force_reinstall = true,
                    },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    assert_eq!(
        argv_strings(&step),
        vec![
            "/workspace/ComfyUI/venv/bin/pip",
            "install",
            "--force-reinstall",
            "torch"
        ]
    );
}

#[test]
fn python_deps_uses_system_pip_when_in_comfy_venv_is_false() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "3_python_deps", kind = "python.deps",
                    payload = { kind = "python.deps", deps = { "numpy" } },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    assert_eq!(argv_strings(&step), vec!["pip", "install", "numpy"]);
}

#[test]
fn comfyui_install_clones_and_checks_out_the_ref_via_sh_dash_c() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "2_comfyui_install", kind = "comfyui.install",
                    payload = { kind = "comfyui.install", ref = "abc123" },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let argv = argv_strings(&step);
    assert_eq!(argv[0], "sh");
    assert_eq!(argv[1], "-c");
    assert!(argv[2]
        .contains("git clone https://github.com/comfyanonymous/ComfyUI.git /workspace/ComfyUI"));
    assert!(argv[2].contains("git -C /workspace/ComfyUI checkout abc123"));
}

// ---------------------------------------------------------------------
// dispatch_pending shape for kinds this milestone defers, and for
// genuinely unrecognized kinds (02 §Unknown kinds).
// ---------------------------------------------------------------------

#[test]
fn comfyui_restart_and_health_degrade_to_dispatch_pending() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "9_comfyui_restart", kind = "comfyui.restart",
                    payload = { kind = "comfyui.restart", port = 8188 },
                },
                {
                    index = 2, id = "10_comfyui_health", kind = "comfyui.health",
                    payload = { kind = "comfyui.health", port = 8188 },
                },
            },
        }
        "#,
    );
    assert_eq!(step_count(&result), 2);
    let restart_op: String = field(&step_at(&result, 0), "op");
    let health_op: String = field(&step_at(&result, 1), "op");
    assert_eq!(restart_op, "dispatch_pending");
    assert_eq!(health_op, "dispatch_pending");
}

#[test]
fn service_start_and_ready_degrade_to_dispatch_pending() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "11_service_0_start", kind = "service.start",
                    payload = { kind = "service.start", name = "svc", platform = { kind = "vllm" } },
                },
                {
                    index = 2, id = "11_service_0_ready", kind = "service.ready",
                    payload = { kind = "service.ready", name = "svc", check = { http = "http://x/health" } },
                },
            },
        }
        "#,
    );
    let start_op: String = field(&step_at(&result, 0), "op");
    let ready_op: String = field(&step_at(&result, 1), "op");
    assert_eq!(start_op, "dispatch_pending");
    assert_eq!(ready_op, "dispatch_pending");
}

#[test]
fn python_version_check_degrades_to_dispatch_pending() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "3a_python_version_check", kind = "python.version_check",
                    payload = { kind = "python.version_check", want = "3.11" },
                },
            },
        }
        "#,
    );
    let op: String = field(&step_at(&result, 0), "op");
    assert_eq!(op, "dispatch_pending");
}

#[test]
fn a_genuinely_unrecognized_kind_degrades_to_dispatch_pending_with_a_note() {
    let (_lua, result) = dispatch_plan(
        r#"
        {
            profile_name = "demo",
            steps = {
                {
                    index = 1, id = "zz_unknown", kind = "totally.unknown",
                    payload = { kind = "totally.unknown", whatever = 1 },
                },
            },
        }
        "#,
    );
    let step = step_at(&result, 0);
    let op: String = field(&step, "op");
    assert_eq!(op, "dispatch_pending");
    let note: String = field(&step, "note");
    assert!(
        note.contains("totally.unknown") && note.contains("02 §Unknown kinds"),
        "note: {note}"
    );
    let payload: Table = field(&step, "payload");
    let whatever: i64 = payload.get("whatever").unwrap();
    assert_eq!(
        whatever, 1,
        "dispatch_pending must carry the original payload, never dropping it"
    );
}

// ---------------------------------------------------------------------
// End-to-end composition (profile -> plan -> dispatch).
// ---------------------------------------------------------------------

#[test]
fn full_pipeline_dispatches_a_representative_profile_without_error() {
    let (_lua, result) = dispatch_via_pipeline(
        r#"
        profile {
            name = "demo",
            phases = {
                { kind = "system.apt", packages = { "curl" } },
                { kind = "comfyui.install", ref = "abc" },
                { kind = "custom_nodes", nodes = { { name = "n1", repo = "owner/repo1" } } },
                {
                    kind = "sync.pull",
                    src = "https://example.com/a.bin",
                    dst = "/workspace/a.bin",
                },
                { kind = "hooks.post_install", script = "echo hi" },
                {
                    kind = "service.start",
                    name = "vllm-main",
                    platform = { kind = "vllm", model = "foo/bar" },
                },
                {
                    kind = "service.ready",
                    name = "vllm-main",
                    check = { http = "http://localhost:8000/health" },
                },
            },
        }
        "#,
    );
    let profile_name: String = result.get("profile_name").unwrap();
    assert_eq!(profile_name, "demo");
    // system.apt (1) + comfyui.install (1) + implicit comfyui.restart (1,
    // dispatch_pending) + implicit comfyui.health (1, dispatch_pending) +
    // custom_nodes clone (1) + sync.routes pull (1, net.transfer — https,
    // no env) + hooks.post_install (1) + service.start (1,
    // dispatch_pending) + service.ready (1, dispatch_pending) = 9.
    assert_eq!(step_count(&result), 9);
}

// ---------------------------------------------------------------------
// Error surface (03 §Error surface: "plan / dispatch: raise only on
// malformed stage input (non-table)").
// ---------------------------------------------------------------------

#[test]
fn dispatch_raises_on_a_non_table_plan() {
    let lua = boot_vm().expect("boot_vm should succeed");
    let err = lua
        .load("return require('lm.dispatch').dispatch(42)")
        .eval::<Value>()
        .expect_err("a non-table plan must raise");
    assert!(err.to_string().contains("plan must be a table"));
}
