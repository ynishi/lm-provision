//! M3-4 (`fs.write` + `mount.bind` / `mount.umount` bridges) regression
//! tests (04-bridge.md §Outputs `fs.write` / `mount.bind` /
//! `mount.umount`; 06-secret-handling.md §Inputs "Consumption points").
//!
//! Drives the bridges through the same public path a profile author's
//! own `apply`-time code would take:
//! [`lm_provision::vm::eval::evaluate_profile_source`] (registration
//! order steps 1-5) then [`lm_provision::sandbox::wire_sandboxed_profile`]
//! (steps 6-8, which installs the declared `fs.*` / `mount.*`
//! operations) — mirrors `tests/m3_sh_exec.rs` and `tests/m3_net.rs`.
//!
//! `mount.bind` / `mount.umount`'s actual Linux syscall path
//! (`#[cfg(target_os = "linux")]` in `src/bridge/mount.rs`) is not
//! exercised here: this crate's dev machine is not Linux, and 04
//! §Outputs itself only requires the not-supported short-circuit to be
//! observable on other platforms ("registration itself succeeds so
//! profiles remain loadable everywhere"). The real-mount behaviour is a
//! Linux CI / on-pod concern, not a unit-test one.

use lm_provision::sandbox::wire_sandboxed_profile;
use lm_provision::vm::eval::evaluate_profile_source;
use mlua::{Lua, Table, Value};

fn sandboxed_lua(profile_expr: &str) -> Lua {
    let source = format!(
        r#"
        local profile = require('lm.profile')
        return profile {profile_expr}
        "#
    );
    let extracted =
        evaluate_profile_source(&source, "test-profile").expect("profile should evaluate");
    let sandboxed =
        wire_sandboxed_profile(extracted).expect("sandbox wiring (steps 6-8) should succeed");
    sandboxed.extracted.lua
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-fs-mount-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// ---------------------------------------------------------------------
// fs.write: capability gate (register skip)
// ---------------------------------------------------------------------

#[test]
fn fs_is_nil_for_a_profile_that_does_not_declare_fs_write() {
    let lua = sandboxed_lua(r#"{ name = "demo" }"#);
    let value: Value = lua.load("return fs").eval().expect("global lookup");
    assert!(
        matches!(value, Value::Nil),
        "05 §L4 register skip: fs must not exist when fs.write is not declared"
    );
}

// ---------------------------------------------------------------------
// fs.write: happy path / mode / append
// ---------------------------------------------------------------------

#[test]
fn fs_write_creates_a_file_with_the_expected_bytes_and_default_mode() {
    let dir = temp_dir("happy");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let result: Table = lua
        .load(format!(r#"return fs.write("{path_str}", "hello world")"#))
        .eval()
        .expect("fs.write should evaluate for a path under a declared paths root");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<i64>("bytes").unwrap(), 11);
    assert!(!result.get::<bool>("dry_run").unwrap());
    assert_eq!(
        std::fs::read_to_string(&path).expect("written file should exist"),
        "hello world"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "04 §Outputs `fs.write`: default mode is 0o644");
    }

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_respects_a_caller_supplied_mode() {
    let dir = temp_dir("mode");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let _: Table = lua
        .load(format!(
            r#"return fs.write("{path_str}", "x", {{ mode = 384 }})"# // 0o600
        ))
        .eval()
        .expect("fs.write with a caller mode should evaluate");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_append_appends_rather_than_truncating() {
    let dir = temp_dir("append");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();
    std::fs::write(&path, "first-").expect("seed file");

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return fs.write("{path_str}", "second", {{ append = true }})"#
        ))
        .eval()
        .expect("fs.write with append should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(
        std::fs::read_to_string(&path).expect("appended file should exist"),
        "first-second"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_without_append_truncates_an_existing_file() {
    let dir = temp_dir("truncate");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();
    std::fs::write(&path, "a much longer original body").expect("seed file");

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let _: Table = lua
        .load(format!(r#"return fs.write("{path_str}", "short")"#))
        .eval()
        .expect("fs.write without append should truncate");

    assert_eq!(
        std::fs::read_to_string(&path).expect("truncated file should exist"),
        "short"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// fs.write: mkdir_p
// ---------------------------------------------------------------------

#[test]
fn fs_write_mkdir_p_creates_missing_ancestor_directories_under_a_declared_root() {
    let dir = temp_dir("mkdirp");
    let path = dir.join("a/b/c/out.txt");
    let path_str = path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return fs.write("{path_str}", "nested", {{ mkdir_p = true }})"#
        ))
        .eval()
        .expect("fs.write with mkdir_p should create the missing ancestors");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(
        std::fs::read_to_string(&path).expect("nested file should exist"),
        "nested"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_mkdir_p_does_not_escape_the_declared_paths_gate() {
    let dir = temp_dir("mkdirp-reject");
    let allowed = dir.join("allowed");
    std::fs::create_dir_all(&allowed).expect("create allowed subdir");
    // Outside `paths` entirely — mkdir_p must never reach for this,
    // regardless of whether any of its ancestors need creating.
    let outside_path = dir.join("outside/nested/out.txt");
    let outside_str = outside_path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{allowed}" }} }}"#,
        allowed = allowed.display()
    ));
    let err = lua
        .load(format!(
            r#"return fs.write("{outside_str}", "nope", {{ mkdir_p = true }})"#
        ))
        .eval::<Value>()
        .expect_err("a path outside profile.paths must be rejected even with mkdir_p");
    assert!(err.to_string().contains("profile.paths"));
    assert!(
        !dir.join("outside").exists(),
        "mkdir_p must not create any directory outside the declared paths root"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// fs.write: path policy (outside root / relative)
// ---------------------------------------------------------------------

#[test]
fn fs_write_rejects_a_path_outside_the_declared_paths_root() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "fs.write" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return fs.write("/etc/passwd", "x")"#)
        .eval::<Value>()
        .expect_err("a path outside profile.paths must be rejected");
    assert!(err.to_string().contains("profile.paths"));
}

#[test]
fn fs_write_rejects_a_relative_path() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "fs.write" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return fs.write("relative/out.txt", "x")"#)
        .eval::<Value>()
        .expect_err("a relative path must be rejected (04 §Outputs `fs.write`: must be absolute)");
    assert!(err.to_string().contains("profile.paths"));
}

// ---------------------------------------------------------------------
// fs.write: SecretRef content
// ---------------------------------------------------------------------

#[test]
fn fs_write_resolves_a_declared_secret_ref_content_into_the_file_only() {
    let dir = temp_dir("secret-ok");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();
    let var_name = format!("LM_PROVISION_TEST_FS_SECRET_{}", std::process::id());
    std::env::set_var(&var_name, "top-secret-value");

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }}, env_secrets = {{ "{var_name}" }} }}"#,
        dir = dir.display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return fs.write("{path_str}", env.ref("{var_name}"))"#
        ))
        .eval()
        .expect("fs.write should evaluate for a declared secret content");

    std::env::remove_var(&var_name);
    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(
        std::fs::read_to_string(&path).expect("file should contain the resolved secret"),
        "top-secret-value"
    );
    // The result table itself carries no `content` field at all (04
    // §Outputs `fs.write` "Result"): the resolved value is never handed
    // back to Lua, only into the file bytes.
    assert!(!result.contains_key("content").unwrap());

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_rejects_an_undeclared_secret_ref_content() {
    let dir = temp_dir("secret-undeclared");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let err = lua
        .load(format!(
            r#"return fs.write("{path_str}", env.ref("UNDECLARED_SECRET"))"#
        ))
        .eval::<Value>()
        .expect_err("an undeclared secret name must be rejected at consumption");
    assert!(err
        .to_string()
        .contains("secret 'UNDECLARED_SECRET' is not declared in profile.env_secrets"));
    assert!(!path.exists(), "no effect ran before the rejection");

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_fails_fast_when_a_declared_secret_is_missing_from_the_host_env() {
    let dir = temp_dir("secret-missing");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();
    let var_name = format!("LM_PROVISION_TEST_FS_MISSING_{}", std::process::id());
    std::env::remove_var(&var_name);

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }}, env_secrets = {{ "{var_name}" }} }}"#,
        dir = dir.display()
    ));
    let err = lua
        .load(format!(
            r#"return fs.write("{path_str}", env.ref("{var_name}"))"#
        ))
        .eval::<Value>()
        .expect_err("a declared-but-absent secret must fail fast");
    assert!(err
        .to_string()
        .contains(&format!("secret '{var_name}' missing in host env")));
    assert!(!path.exists());

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[test]
fn fs_write_dry_run_still_resolves_secrets_and_fails_fast_on_a_missing_one() {
    let dir = temp_dir("secret-dryrun");
    let path = dir.join("out.txt");
    let path_str = path.display().to_string();
    let var_name = format!("LM_PROVISION_TEST_FS_DRYRUN_MISSING_{}", std::process::id());
    std::env::remove_var(&var_name);

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }}, env_secrets = {{ "{var_name}" }} }}"#,
        dir = dir.display()
    ));
    let err = lua
        .load(format!(
            r#"return fs.write("{path_str}", env.ref("{var_name}"), {{ dry_run = true }})"#
        ))
        .eval::<Value>()
        .expect_err(
            "04 §Common conventions: dry_run still fails on missing secrets, \
             it validates everything except the effect itself",
        );
    assert!(err
        .to_string()
        .contains(&format!("secret '{var_name}' missing in host env")));

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// fs.write: dry_run skips the effect
// ---------------------------------------------------------------------

#[test]
fn fs_write_dry_run_skips_the_effect_but_still_reports_ok() {
    let dir = temp_dir("dryrun");
    let path = dir.join("should-not-exist.txt");
    let path_str = path.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "fs.write" }}, paths = {{ "{dir}" }} }}"#,
        dir = dir.display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return fs.write("{path_str}", "x", {{ dry_run = true }})"#
        ))
        .eval()
        .expect("fs.write dry_run should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert!(result.get::<bool>("dry_run").unwrap());
    assert!(
        !path.exists(),
        "dry_run must not perform the effect (04 §Common conventions)"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// =======================================================================
// mount.bind / mount.umount
// =======================================================================

// ---------------------------------------------------------------------
// mount: capability gate (register skip / declared-but-separate)
// ---------------------------------------------------------------------

#[test]
fn mount_is_nil_for_a_profile_that_declares_neither_mount_capability() {
    let lua = sandboxed_lua(r#"{ name = "demo" }"#);
    let value: Value = lua.load("return mount").eval().expect("global lookup");
    assert!(
        matches!(value, Value::Nil),
        "05 §L4 register skip: mount must not exist when no mount.* capability is declared"
    );
}

#[test]
fn mount_umount_is_nil_when_only_mount_bind_is_declared() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.bind" }, paths = { "/workspace" } }"#,
    );
    let bind: Value = lua
        .load("return mount.bind")
        .eval()
        .expect("mount.bind lookup");
    assert!(!matches!(bind, Value::Nil), "mount.bind is declared");

    let umount: Value = lua
        .load("return mount.umount")
        .eval()
        .expect("mount.umount lookup");
    assert!(
        matches!(umount, Value::Nil),
        "04 §Outputs `mount.umount`: declaring bind does not grant umount"
    );
}

#[test]
fn mount_bind_is_nil_when_only_mount_umount_is_declared() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.umount" }, paths = { "/workspace" } }"#,
    );
    let bind: Value = lua
        .load("return mount.bind")
        .eval()
        .expect("mount.bind lookup");
    assert!(matches!(bind, Value::Nil));

    let umount: Value = lua
        .load("return mount.umount")
        .eval()
        .expect("mount.umount lookup");
    assert!(!matches!(umount, Value::Nil));
}

// ---------------------------------------------------------------------
// mount.bind / mount.umount: not-supported on this (non-Linux) platform
// ---------------------------------------------------------------------
//
// The real mount / umount syscalls are Linux-only
// (`#[cfg(target_os = "linux")]` in `src/bridge/mount.rs`); on every
// other platform (including this crate's dev machine) the call must
// still succeed at the Lua level and report `ok = false` with the
// not-supported message, never a Lua error or a hang.

#[test]
#[cfg(not(target_os = "linux"))]
fn mount_bind_call_reports_not_supported_on_a_non_linux_platform() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.bind" }, paths = { "/workspace" } }"#,
    );
    let result: Table = lua
        .load(r#"return mount.bind("/workspace/src", "/workspace/dst")"#)
        .eval()
        .expect("mount.bind should evaluate (not-supported is a result, not a Lua error)");

    assert!(!result.get::<bool>("ok").unwrap());
    assert!(result
        .get::<String>("error")
        .unwrap()
        .contains("not supported on this platform"));
    assert_eq!(result.get::<String>("src").unwrap(), "/workspace/src");
    assert_eq!(result.get::<String>("dst").unwrap(), "/workspace/dst");
}

#[test]
#[cfg(not(target_os = "linux"))]
fn mount_umount_call_reports_not_supported_on_a_non_linux_platform() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.umount" }, paths = { "/workspace" } }"#,
    );
    let result: Table = lua
        .load(r#"return mount.umount("/workspace/mnt")"#)
        .eval()
        .expect("mount.umount should evaluate (not-supported is a result, not a Lua error)");

    assert!(!result.get::<bool>("ok").unwrap());
    assert!(result
        .get::<String>("error")
        .unwrap()
        .contains("not supported on this platform"));
    assert_eq!(result.get::<String>("path").unwrap(), "/workspace/mnt");
}

// ---------------------------------------------------------------------
// mount.bind / mount.umount: path policy still runs before the
// not-supported short-circuit (defence in depth, platform-independent)
// ---------------------------------------------------------------------

#[test]
fn mount_bind_rejects_a_src_outside_declared_paths_before_any_platform_check() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.bind" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return mount.bind("/etc", "/workspace/dst")"#)
        .eval::<Value>()
        .expect_err("a src outside profile.paths must be rejected regardless of platform");
    assert!(err.to_string().contains("profile.paths"));
}

#[test]
fn mount_bind_rejects_a_dst_outside_declared_paths_before_any_platform_check() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.bind" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return mount.bind("/workspace/src", "/etc")"#)
        .eval::<Value>()
        .expect_err("a dst outside profile.paths must be rejected regardless of platform");
    assert!(err.to_string().contains("profile.paths"));
}

#[test]
fn mount_umount_rejects_a_target_outside_declared_paths() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.umount" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return mount.umount("/etc")"#)
        .eval::<Value>()
        .expect_err("a target outside profile.paths must be rejected regardless of platform");
    assert!(err.to_string().contains("profile.paths"));
}

// ---------------------------------------------------------------------
// mount.bind / mount.umount: dry_run
// ---------------------------------------------------------------------

#[test]
fn mount_bind_dry_run_never_calls_the_platform_path_and_echoes_ok() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.bind" }, paths = { "/workspace" } }"#,
    );
    let result: Table = lua
        .load(r#"return mount.bind("/workspace/src", "/workspace/dst", { dry_run = true })"#)
        .eval()
        .expect("mount.bind dry_run should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert!(result.get::<bool>("dry_run").unwrap());
    assert!(!result.contains_key("error").unwrap());
}

#[test]
fn mount_umount_dry_run_never_calls_the_platform_path_and_echoes_ok() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "mount.umount" }, paths = { "/workspace" } }"#,
    );
    let result: Table = lua
        .load(r#"return mount.umount("/workspace/mnt", { dry_run = true })"#)
        .eval()
        .expect("mount.umount dry_run should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert!(result.get::<bool>("dry_run").unwrap());
    assert!(!result.contains_key("error").unwrap());
}
