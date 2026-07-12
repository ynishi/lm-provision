//! L1 sandbox: VM boot, stdlib strip, and print redirect.
//!
//! [`boot_vm`] wires registration steps 1-2 of the fixed order in
//! 04-bridge.md §Registration order: custom `require`
//! (step 1, delegated to [`require`]) and the `print` redirect (step 2).
//! Steps 3-5 (`env.ref`, profile evaluation, declaration extraction) are
//! implemented in [`eval`] (milestone M1-3), built on top of [`boot_vm`].
//! Steps 6-9 (batteries, capability gate, bridges, pipeline execution)
//! are out of scope through M1-3 and land in milestone M3.

pub mod eval;
pub mod require;

use mlua::{Function, Lua, MultiValue, Value};
use thiserror::Error;

/// Errors raised while booting or operating the sandboxed VM.
#[derive(Debug, Error)]
pub enum VmError {
    /// The underlying mlua VM failed during boot or a chunk load.
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
}

/// Stdlib globals stripped to `nil` per 05-sandbox-layer-contract.md §L1.
///
/// Consequence: no process / filesystem / clock access via stdlib, no
/// default module loading, no debug-hook tampering, and no runtime chunk
/// loading at all from profile code.
const STRIPPED_GLOBALS: &[&str] = &[
    "os",
    "io",
    "package",
    "debug",
    "loadfile",
    "dofile",
    "load",
    "loadstring",
];

/// Retained L1 stdlib surface (05-sandbox-layer-contract.md §L1
/// "Retained: ..."), used only by the boot-time self-check in tests.
#[cfg(test)]
const RETAINED_GLOBALS: &[&str] = &["string", "table", "math", "coroutine", "utf8"];

/// Boot a fresh sandboxed Lua VM: strip the L1 stdlib set, install the
/// embedded-module `require` allowlist, and redirect `print` to the host
/// tracing sink.
///
/// One VM is created per subcommand run (statelessness at the VM level,
/// 05-sandbox-layer-contract.md §L2); this function performs registration
/// steps 1-2 only.
pub fn boot_vm() -> Result<Lua, VmError> {
    let lua = Lua::new();

    strip_stdlib(&lua)?;
    require::install(&lua)?;
    install_print_redirect(&lua)?;

    Ok(lua)
}

fn strip_stdlib(lua: &Lua) -> mlua::Result<()> {
    let globals = lua.globals();
    for name in STRIPPED_GLOBALS {
        globals.set(*name, Value::Nil)?;
    }
    Ok(())
}

/// Redirect `print` to the host log sink (`tracing`) so profile scripts
/// never write to process stdout (stdout is the machine-readable
/// artifact, 07-cli.md §Outputs). Argument rendering matches
/// 04-bridge.md `print`: tables render as `<table>`, other userdata as
/// `<userdata>`, everything else via Lua's own `tostring`.
fn install_print_redirect(lua: &Lua) -> mlua::Result<()> {
    let print_fn = lua.create_function(|lua: &Lua, args: MultiValue| -> mlua::Result<()> {
        let mut rendered = Vec::with_capacity(args.len());
        for value in args {
            rendered.push(render_print_arg(lua, value)?);
        }
        tracing::info!(target: "lm_provision::lua_print", "{}", rendered.join("\t"));
        Ok(())
    })?;
    lua.globals().set("print", print_fn)?;
    Ok(())
}

fn render_print_arg(lua: &Lua, value: Value) -> mlua::Result<String> {
    match value {
        Value::Table(_) => Ok("<table>".to_string()),
        Value::UserData(_) | Value::LightUserData(_) => Ok("<userdata>".to_string()),
        other => {
            let tostring: Function = lua.globals().get("tostring")?;
            tostring.call(other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Table;

    #[test]
    fn stripped_globals_are_nil() {
        let lua = boot_vm().expect("boot_vm should succeed");
        for name in STRIPPED_GLOBALS {
            let value: Value = lua.globals().get(*name).expect("global lookup");
            assert!(
                matches!(value, Value::Nil),
                "expected {name} to be nil, got {value:?}"
            );
        }
    }

    #[test]
    fn retained_stdlib_is_present() {
        let lua = boot_vm().expect("boot_vm should succeed");
        for name in RETAINED_GLOBALS {
            let value: Value = lua.globals().get(*name).expect("global lookup");
            assert!(!matches!(value, Value::Nil), "expected {name} to remain");
        }
    }

    #[test]
    fn require_resolves_embedded_allowlist_and_returns_a_table() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let result: Table = lua
            .load("return require('lm.profile')")
            .eval()
            .expect("lm.profile should be requireable");
        assert_eq!(result.raw_len(), 0, "stub module should be an empty table");
    }

    #[test]
    fn require_rejects_names_outside_allowlist() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let err = lua
            .load("return require('os')")
            .eval::<Value>()
            .expect_err("require('os') must fail (not an embedded module name)");
        let message = err.to_string();
        assert!(
            message.contains("lm.profile"),
            "message should list the allowlist: {message}"
        );
    }

    #[test]
    fn print_redirect_does_not_error_and_returns_nothing_to_lua() {
        let lua = boot_vm().expect("boot_vm should succeed");
        lua.load("print('hello', 42, {}, nil)")
            .exec()
            .expect("redirected print should not raise a Lua error");
    }
}
