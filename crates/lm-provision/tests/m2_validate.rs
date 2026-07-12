//! M2-1 (`lm.validate`) regression tests.
//!
//! Exercises `lm.validate.validate(ir)` through the sandboxed VM boot path
//! ([`lm_provision::vm::boot_vm`]), the same entry point the CLI uses.
//!
//! Covers 03-pipeline-stage-artifacts.md §validate's 7 checks, in order,
//! first-violation-stops semantics, the shell-safety contract (base +
//! with-spaces variants), the `{pod_id}` placeholder exemption on
//! `sync.push` / `staging.push` `dst`, and the `hooks.post_install.script`
//! escape-policy exemption (01-profile-dsl-surface.md §Escape / fragment
//! policy).

use lm_provision::vm::boot_vm;
use mlua::{Table, Value};

/// Evaluate `source` (expected to `return` the result of a
/// `require('lm.validate').validate(ir)` call) and return `(lua, result)`.
///
/// The `Lua` VM must be kept alive alongside the returned `Table` — an
/// `mlua::Table` holds only a weak reference to its owning VM (see
/// `vm::eval::ExtractedProfile`'s doc comment), so a caller that drops
/// `lua` before reading fields off `result` hits an `mlua::Error` /
/// panic ("Lua instance is destroyed").
fn validate_source(source: &str) -> (mlua::Lua, Table) {
    let lua = boot_vm().expect("boot_vm should succeed");
    let result = lua
        .load(source)
        .eval::<Table>()
        .expect("script should evaluate without a Lua error");
    (lua, result)
}

fn ok_field(result: &Table) -> bool {
    result.get::<bool>("ok").expect("ok field")
}

fn error_field(result: &Table) -> String {
    result.get::<String>("error").expect("error field")
}

// ---------------------------------------------------------------------
// Happy path: a profile touching a broad slice of the 22-kind catalog
// validates ok (03 §MVP scope: "validate rejects for bad-* fixtures;
// ... exercised by the example-profile regression suite").
// ---------------------------------------------------------------------

#[test]
fn happy_profile_validates_ok() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local validate = require('lm.validate')
        local ir = profile {
            name = "demo",
            capabilities = { "sh.exec", "net.transfer", "fs.write", "mount.bind" },
            env = { "LOG_LEVEL" },
            env_secrets = { "HF_TOKEN" },
            paths = { "/workspace", "/data" },
            http_allowlist = { "https://example.com/*" },
            phases = {
                { kind = "system.apt", packages = { "curl", "git" } },
                { kind = "comfyui.install", ref = "abc123" },
                { kind = "python.deps", deps = { "torch" }, in_comfy_venv = true },
                {
                    kind = "custom_nodes",
                    nodes = { { name = "n1", repo = "owner/repo1" } },
                },
                {
                    kind = "sync.pull",
                    src = "b2://my-bucket/models/model.bin",
                    dst = "/workspace/models/model.bin",
                },
                { kind = "hooks.post_install", script = "echo 'hello world' && ls -la" },
                { kind = "comfyui.restart", extra_args = { "--fast" } },
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
                { kind = "fs.write", path = "/workspace/config.json", content = "{\"a\":1}" },
                {
                    kind = "staging.push",
                    src = "/workspace/output",
                    dst = "hf://owner/repo/{pod_id}/artifact.bin",
                    commit_message = "Upload run output (v1)!",
                },
                { kind = "mount.bind", src = "/data", dst = "/workspace/data" },
                { kind = "net.http_get", url = "https://example.com/api?x=1&y=2" },
                { kind = "totally.unknown", whatever = 123 },
            },
        }
        return validate.validate(ir)
        "#,
    );

    assert!(
        ok_field(&result),
        "happy profile should validate ok, got error: {:?}",
        result.get::<Value>("error")
    );
    let name: String = result.get("name").expect("name");
    assert_eq!(name, "demo");
}

// ---------------------------------------------------------------------
// Check 1: ir is a table; ir.schema == "lm.profile/1"; ir.name is a
// non-empty string.
// ---------------------------------------------------------------------

#[test]
fn check1_rejects_a_non_table_ir() {
    let (_lua, result) = validate_source("return require('lm.validate').validate(42)");
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("must be a table"));
}

#[test]
fn check1_rejects_wrong_schema_tag() {
    let (_lua, result) = validate_source(
        r#"
        local ir = {
            schema = "lm.profile/2", name = "demo",
            capabilities = {}, env = {}, env_secrets = {}, paths = {}, http_allowlist = {},
            phases = {},
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("lm.profile/1"));
}

#[test]
fn check1_rejects_missing_name() {
    let (_lua, result) = validate_source(
        r#"
        local ir = {
            schema = "lm.profile/1", name = "",
            capabilities = {}, env = {}, env_secrets = {}, paths = {}, http_allowlist = {},
            phases = {},
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("ir.name must be a non-empty string"));
}

// ---------------------------------------------------------------------
// Check 2: the five declared lists are string lists.
// ---------------------------------------------------------------------

#[test]
fn check2_rejects_a_non_string_entry_in_a_declared_list() {
    let (_lua, result) = validate_source(
        r#"
        local ir = {
            schema = "lm.profile/1", name = "demo",
            capabilities = {}, env = { "OK", 42 }, env_secrets = {}, paths = {}, http_allowlist = {},
            phases = {},
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("ir.env[2]") && message.contains("number"),
        "message: {message}"
    );
}

// ---------------------------------------------------------------------
// Check 3: no `env` key is secret-shaped.
// ---------------------------------------------------------------------

#[test]
fn check3_rejects_a_secret_shaped_env_key() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", env = { "API_TOKEN" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("ir.env[1]") && message.contains("secret-shaped"),
        "message: {message}"
    );
}

#[test]
fn check3_secret_shaped_match_is_case_insensitive() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", env = { "api_key" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("secret-shaped"));
}

// ---------------------------------------------------------------------
// Check 4: every env / env_secrets name is shell-safe.
// ---------------------------------------------------------------------

#[test]
fn check4_rejects_a_non_shell_safe_env_name() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", env = { "BAD NAME" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("ir.env[1]") && message.contains("not shell-safe"),
        "message: {message}"
    );
}

#[test]
fn check4_rejects_a_non_shell_safe_env_secrets_name() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", env_secrets = { "HF$TOKEN" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("ir.env_secrets[1]") && message.contains("not shell-safe"),
        "message: {message}"
    );
}

// ---------------------------------------------------------------------
// Check 5: every paths entry is absolute, free of `..` segments, and
// shell-safe.
// ---------------------------------------------------------------------

#[test]
fn check5_rejects_a_relative_path() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", paths = { "relative/path" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("must be absolute"));
}

#[test]
fn check5_rejects_a_path_with_a_dotdot_segment() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", paths = { "/a/../b" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("'..' segment"));
}

#[test]
fn check5_rejects_a_non_shell_safe_path() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", paths = { "/a b" } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    assert!(error_field(&result).contains("not shell-safe"));
}

// ---------------------------------------------------------------------
// Check 6: per-kind phase shape walk.
// ---------------------------------------------------------------------

#[test]
fn check6_rejects_a_missing_required_field() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile { name = "demo", phases = { { kind = "comfyui.install" } } }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].ref") && message.contains("is required"),
        "message: {message}"
    );
}

#[test]
fn check6_rejects_a_non_shell_safe_payload_string() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = { { kind = "system.apt", packages = { "curl", "bad pkg" } } },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].packages[2]") && message.contains("not shell-safe"),
        "message: {message}"
    );
}

#[test]
fn check6_rejects_a_non_shell_safe_nested_list_table_field() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                { kind = "custom_nodes", nodes = { { name = "n1", repo = "owner/bad repo" } } },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].nodes[1].repo") && message.contains("not shell-safe"),
        "message: {message}"
    );
}

#[test]
fn check6_unknown_kind_is_not_an_error() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = { { kind = "totally.unknown", whatever = "anything at all $$ !!" } },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(
        ok_field(&result),
        "02 §Unknown kinds: unrecognized kind must not be a validate-stage error, got: {:?}",
        result.get::<Value>("error")
    );
}

#[test]
fn check6_hooks_post_install_script_is_exempt_from_the_shell_safety_contract() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                {
                    kind = "hooks.post_install",
                    script = "apt-get update && echo 'hi there' | grep hi; rm -rf /tmp/x*",
                },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(
        ok_field(&result),
        "01 §Escape / fragment policy: hooks.post_install.script is the sanctioned raw-shell \
         field, exempt from shell-safety, got: {:?}",
        result.get::<Value>("error")
    );
}

#[test]
fn check6_enum_field_rejects_an_unlisted_value() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                {
                    kind = "service.start",
                    name = "svc",
                    platform = { kind = "not-a-real-engine" },
                },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].platform.kind") && message.contains("vllm"),
        "message: {message}"
    );
}

// ---------------------------------------------------------------------
// Check 6 (continued): sync.* / staging.* route shape.
// ---------------------------------------------------------------------

#[test]
fn sync_pull_rejects_an_unrecognized_src_scheme() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                { kind = "sync.pull", src = "ftp://bucket/path", dst = "/workspace/x" },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].src") && message.contains("not a recognized"),
        "message: {message}"
    );
}

#[test]
fn sync_pull_rejects_a_route_missing_a_bucket_or_path() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                { kind = "sync.pull", src = "b2://bucket-only", dst = "/workspace/x" },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].src") && message.contains("missing bucket/owner or path"),
        "message: {message}"
    );
}

#[test]
fn sync_pull_rejects_a_non_absolute_dst() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                { kind = "sync.pull", src = "b2://bucket/path", dst = "relative/dst" },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].dst") && message.contains("absolute"),
        "message: {message}"
    );
}

#[test]
fn staging_push_dst_allows_the_pod_id_placeholder() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                {
                    kind = "staging.push",
                    src = "/workspace/output",
                    dst = "hf://owner/repo/{pod_id}/artifact.bin",
                },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(
        ok_field(&result),
        "02 §Catalog kinds: {{pod_id}} is an allowed placeholder in dst, got: {:?}",
        result.get::<Value>("error")
    );
}

#[test]
fn staging_push_dst_still_rejects_other_non_shell_safe_characters() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                {
                    kind = "staging.push",
                    src = "/workspace/output",
                    dst = "hf://owner/repo/{pod_id}/bad file.bin",
                },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[1].dst") && message.contains("not shell-safe"),
        "message: {message}"
    );
}

#[test]
fn staging_push_commit_message_is_not_shell_safety_checked() {
    // commit_message is free-form text (a git commit message), not marked
    // shell_safe in lm.catalog_data — spaces and punctuation must be
    // accepted.
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                {
                    kind = "staging.push",
                    src = "/workspace/output",
                    dst = "b2://bucket/artifact.bin",
                    commit_message = "Fix bug: improve error handling (v2)!",
                },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(
        ok_field(&result),
        "commit_message must not be shell-safety-checked, got: {:?}",
        result.get::<Value>("error")
    );
}

// ---------------------------------------------------------------------
// Check 7: service.start names are unique across the profile.
// ---------------------------------------------------------------------

#[test]
fn check7_rejects_duplicate_service_start_names() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                { kind = "service.start", name = "svc", platform = { kind = "vllm" } },
                { kind = "service.start", name = "svc", platform = { kind = "ollama" } },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("phases[2].name") && message.contains("duplicates"),
        "message: {message}"
    );
}

#[test]
fn check7_allows_distinct_service_start_names() {
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            phases = {
                { kind = "service.start", name = "svc-a", platform = { kind = "vllm" } },
                { kind = "service.start", name = "svc-b", platform = { kind = "ollama" } },
            },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(ok_field(&result), "got: {:?}", result.get::<Value>("error"));
}

// ---------------------------------------------------------------------
// First-violation-stops semantics (03 §validate: "the first violation;
// single-error reporting; validation stops at the first failure").
// ---------------------------------------------------------------------

#[test]
fn first_violation_wins_when_multiple_checks_would_fail() {
    // env[1] is secret-shaped (check 3) *and* paths[1] is not absolute
    // (check 5). Check 3 runs before check 5, so the reported error must
    // be the check-3 violation, not the check-5 one.
    let (_lua, result) = validate_source(
        r#"
        local profile = require('lm.profile')
        local ir = profile {
            name = "demo",
            env = { "API_TOKEN" },
            paths = { "relative/path" },
        }
        return require('lm.validate').validate(ir)
        "#,
    );
    assert!(!ok_field(&result));
    let message = error_field(&result);
    assert!(
        message.contains("secret-shaped") && !message.contains("absolute"),
        "expected the earlier check-3 violation to win, got: {message}"
    );
}

// ---------------------------------------------------------------------
// Shell-safety contract: charset boundary, with-spaces variant.
// ---------------------------------------------------------------------

fn is_shell_safe(s: &str) -> bool {
    let lua = boot_vm().expect("boot_vm should succeed");
    lua.load(format!(
        "return require('lm.validate').is_shell_safe({s:?})"
    ))
    .eval::<bool>()
    .expect("is_shell_safe should evaluate")
}

fn is_shell_safe_with_spaces(s: &str) -> bool {
    let lua = boot_vm().expect("boot_vm should succeed");
    lua.load(format!(
        "return require('lm.validate').is_shell_safe_with_spaces({s:?})"
    ))
    .eval::<bool>()
    .expect("is_shell_safe_with_spaces should evaluate")
}

#[test]
fn shell_safe_accepts_every_charset_character() {
    assert!(is_shell_safe("Aa9._/@:+=~-"));
}

#[test]
fn shell_safe_rejects_the_empty_string() {
    assert!(!is_shell_safe(""));
}

#[test]
fn shell_safe_rejects_a_forbidden_character() {
    for bad in ["a$b", "a b", "a&b", "a;b", "a|b", "a(b)"] {
        assert!(!is_shell_safe(bad), "{bad:?} must not be shell-safe");
    }
}

#[test]
fn shell_safe_with_spaces_allows_a_single_space_but_never_double() {
    assert!(is_shell_safe_with_spaces("a b"));
    assert!(!is_shell_safe_with_spaces("a  b"));
    assert!(!is_shell_safe_with_spaces(""));
}

#[test]
fn shell_safe_with_spaces_still_rejects_a_forbidden_character() {
    assert!(!is_shell_safe_with_spaces("a $b"));
}
