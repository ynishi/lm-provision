//! M3-2 (`sh.exec` bridge) regression tests (04-bridge.md §Outputs
//! `sh.exec`; 06-secret-handling.md §Inputs "Consumption points").
//!
//! Drives `sh.exec` through the same public path a profile author's own
//! `apply`-time code would take:
//! [`lm_provision::vm::eval::evaluate_profile_source`] (registration
//! order steps 1-5) then
//! [`lm_provision::sandbox::wire_sandboxed_profile`] (steps 6-8, which
//! installs `sh.exec` when the profile declares the capability). This
//! file exercises the public crate surface end to end; `sh.rs`'s own
//! `#[cfg(test)]` module covers the same bridge from inside the crate.

use std::time::{Duration, Instant};

use lm_provision::sandbox::wire_sandboxed_profile;
use lm_provision::vm::eval::evaluate_profile_source;
use mlua::{Lua, Table, Value};

/// Evaluate `profile { <profile_expr> }` through registration order
/// steps 1-8 and return the sandboxed VM. `sh.exec` is installed on it
/// iff `profile_expr` declares `"sh.exec"` in `capabilities`.
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

const SH_EXEC_PROFILE: &str = r#"{ name = "demo", capabilities = { "sh.exec" } }"#;

// ---------------------------------------------------------------------
// capability gate (register skip / declared capability)
// ---------------------------------------------------------------------

#[test]
fn sh_is_nil_for_a_profile_that_does_not_declare_sh_exec() {
    let lua = sandboxed_lua(r#"{ name = "demo" }"#);
    let value: Value = lua.load("return sh").eval().expect("global lookup");
    assert!(
        matches!(value, Value::Nil),
        "05 §L4 register skip: sh must not exist for an undeclared capability"
    );
}

#[test]
fn sh_exec_is_callable_for_a_profile_that_declares_sh_exec() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let result: Table = lua
        .load(r#"return sh.exec({ "echo", "hi" })"#)
        .eval()
        .expect("sh.exec must be callable once declared");
    assert!(result.get::<bool>("ok").unwrap());
}

// ---------------------------------------------------------------------
// happy path / exit status
// ---------------------------------------------------------------------

#[test]
fn happy_path_captures_stdout_and_a_zero_exit_status() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let result: Table = lua
        .load(r#"return sh.exec({ "echo", "hi" })"#)
        .eval()
        .expect("sh.exec should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<i64>("status").unwrap(), 0);
    assert_eq!(result.get::<String>("stdout").unwrap(), "hi\n");
    assert!(!result.get::<bool>("dry_run").unwrap());
    assert!(!result.get::<bool>("timed_out").unwrap());
}

#[test]
fn non_zero_exit_status_is_reported_as_not_ok() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let result: Table = lua
        .load(r#"return sh.exec({ "sh", "-c", "exit 7" })"#)
        .eval()
        .expect("sh.exec should evaluate");

    assert!(!result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<i64>("status").unwrap(), 7);
}

// ---------------------------------------------------------------------
// opts.env: plain string / SecretRef
// ---------------------------------------------------------------------

#[test]
fn plain_string_env_value_is_injected_into_the_child() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let result: Table = lua
        .load(
            r#"return sh.exec(
                { "sh", "-c", "echo $LM_TEST_PLAIN" },
                { env = { LM_TEST_PLAIN = "plain-value" } }
            )"#,
        )
        .eval()
        .expect("sh.exec should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<String>("stdout").unwrap(), "plain-value\n");
}

#[test]
fn a_declared_secret_ref_env_value_resolves_into_the_child_but_never_back_to_lua() {
    let var_name = format!("LM_PROVISION_TEST_SH_SECRET_{}", std::process::id());
    std::env::set_var(&var_name, "top-secret-value");

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "sh.exec" }}, env_secrets = {{ "{var_name}" }} }}"#
    ));
    let result: Table = lua
        .load(format!(
            r#"return sh.exec(
                {{ "sh", "-c", "printenv {var_name}" }},
                {{ env = {{ [{var_name:?}] = env.ref("{var_name}") }} }}
            )"#
        ))
        .eval()
        .expect("sh.exec should evaluate");

    std::env::remove_var(&var_name);

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(
        result.get::<String>("stdout").unwrap(),
        "top-secret-value\n",
        "the resolved secret must reach the child process env"
    );
    assert!(
        !result.contains_key("env").unwrap(),
        "sh.exec's result table (04 §Outputs) carries no env field — \
         the resolved value never flows back to Lua"
    );
}

#[test]
fn an_undeclared_secret_ref_env_value_is_a_lua_error() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let err = lua
        .load(r#"return sh.exec({ "echo", "hi" }, { env = { X = env.ref("UNDECLARED_SECRET") } })"#)
        .eval::<Value>()
        .expect_err("an undeclared secret name must be rejected at consumption");
    assert!(err
        .to_string()
        .contains("secret 'UNDECLARED_SECRET' is not declared in profile.env_secrets"));
}

#[test]
fn a_declared_secret_missing_from_the_host_env_fails_fast() {
    let var_name = format!("LM_PROVISION_TEST_SH_MISSING_{}", std::process::id());
    std::env::remove_var(&var_name);

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "sh.exec" }}, env_secrets = {{ "{var_name}" }} }}"#
    ));
    let err = lua
        .load(format!(
            r#"return sh.exec(
                {{ "echo", "hi" }},
                {{ env = {{ [{var_name:?}] = env.ref("{var_name}") }} }}
            )"#
        ))
        .eval::<Value>()
        .expect_err("a declared-but-absent secret must fail fast");
    assert!(err
        .to_string()
        .contains(&format!("secret '{var_name}' missing in host env")));
}

#[test]
fn dry_run_still_resolves_secrets_and_fails_fast_on_a_missing_one() {
    let var_name = format!("LM_PROVISION_TEST_SH_DRYRUN_MISSING_{}", std::process::id());
    std::env::remove_var(&var_name);

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "sh.exec" }}, env_secrets = {{ "{var_name}" }} }}"#
    ));
    let err = lua
        .load(format!(
            r#"return sh.exec(
                {{ "echo", "hi" }},
                {{ dry_run = true, env = {{ [{var_name:?}] = env.ref("{var_name}") }} }}
            )"#
        ))
        .eval::<Value>()
        .expect_err(
            "04 §Common conventions: dry_run still fails on missing secrets, \
             it validates everything except the effect itself",
        );
    assert!(err
        .to_string()
        .contains(&format!("secret '{var_name}' missing in host env")));
}

// ---------------------------------------------------------------------
// stdin XOR stdin_file
// ---------------------------------------------------------------------

#[test]
fn supplying_both_stdin_and_stdin_file_is_a_lua_error() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let err = lua
        .load(r#"return sh.exec({ "cat" }, { stdin = "a", stdin_file = "/dev/null" })"#)
        .eval::<Value>()
        .expect_err("supplying both stdin and stdin_file must be a Lua error");
    assert!(err.to_string().contains("mutually exclusive"));
}

#[test]
fn stdin_string_is_piped_to_the_child_and_the_pipe_closes_at_eof() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let result: Table = lua
        .load(r#"return sh.exec({ "cat" }, { stdin = "piped-input" })"#)
        .eval()
        .expect("sh.exec should evaluate");
    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<String>("stdout").unwrap(), "piped-input");
}

// ---------------------------------------------------------------------
// dry_run
// ---------------------------------------------------------------------

#[test]
fn dry_run_skips_the_effect_entirely() {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-sh-exec-dry-run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("should-not-exist.txt");

    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let result: Table = lua
        .load(format!(
            r#"return sh.exec({{ "touch", {target:?} }}, {{ dry_run = true }})"#,
            target = target.display().to_string()
        ))
        .eval()
        .expect("sh.exec dry_run should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert!(result.get::<bool>("dry_run").unwrap());
    assert!(
        !target.exists(),
        "04 §Common conventions: dry_run performs no effect"
    );

    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// timeout / process-group kill
// ---------------------------------------------------------------------

#[test]
fn timeout_kills_the_process_group_and_reports_status_minus_one() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    let started = Instant::now();
    let result: Table = lua
        .load(
            r#"return sh.exec(
                { "sh", "-c", "sleep 100 & wait" },
                { timeout_sec = 0.2, term_grace_sec = 0.2 }
            )"#,
        )
        .eval()
        .expect("a timeout is not itself a Lua error");
    let elapsed = started.elapsed();

    assert!(result.get::<bool>("timed_out").unwrap());
    assert_eq!(result.get::<i64>("status").unwrap(), -1);
    assert!(!result.get::<bool>("ok").unwrap());
    assert!(
        result
            .get::<String>("stderr")
            .unwrap()
            .contains("timed out after"),
        "04 §Outputs `sh.exec`: stderr must carry the timeout suffix line"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the process-group kill must reach the backgrounded grandchild \
         `sleep 100` too, or this call would block for ~100s: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------
// on_line streaming
// ---------------------------------------------------------------------

#[test]
fn on_line_is_called_in_order_with_a_global_1_based_lineno() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    lua.load(
        r#"
        _G.seen = {}
        function on_line(stream, line, lineno)
            table.insert(_G.seen, { stream = stream, line = line, lineno = lineno })
        end
        "#,
    )
    .exec()
    .expect("install the on_line callback global");

    let result: Table = lua
        .load(r#"return sh.exec({ "printf", "a\nb\nc\n" }, { on_line = on_line })"#)
        .eval()
        .expect("sh.exec should evaluate");
    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<String>("stdout").unwrap(), "a\nb\nc\n");

    let seen: Table = lua.globals().get("seen").expect("seen global");
    assert_eq!(seen.raw_len(), 3);
    for (i, expected_line) in ["a", "b", "c"].iter().enumerate() {
        let entry: Table = seen.get(i + 1).expect("seen entry");
        assert_eq!(entry.get::<String>("stream").unwrap(), "stdout");
        assert_eq!(entry.get::<String>("line").unwrap(), *expected_line);
        assert_eq!(entry.get::<i64>("lineno").unwrap(), (i + 1) as i64);
    }
}

#[test]
fn an_on_line_callback_error_is_swallowed_and_does_not_fail_the_exec() {
    let lua = sandboxed_lua(SH_EXEC_PROFILE);
    lua.load(
        r#"
        function on_line_error(_stream, _line, _lineno)
            error("boom from on_line")
        end
        "#,
    )
    .exec()
    .expect("install the erroring on_line callback global");

    let result: Table = lua
        .load(r#"return sh.exec({ "echo", "hi" }, { on_line = on_line_error })"#)
        .eval()
        .expect("04 §Outputs `sh.exec`: callback errors are logged and swallowed");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<String>("stdout").unwrap(), "hi\n");
}
