//! Custom `require` implementing the L1 embedded-module allowlist.
//!
//! Only the `lm.*` modules baked into the binary via [`crate::embed`] are
//! resolvable. Every other module name is a Lua error naming the allowlist
//! (05-sandbox-layer-contract.md §L1). Results are cached per VM so a
//! module is evaluated at most once (standard `require` idempotency), and
//! every chunk load is forced to text mode (no bytecode ingestion).

use mlua::{Lua, Table, Value};

use crate::embed::LM_MODULES;

/// Install the custom `require` global on `lua`, shadowing the mlua
/// default.
///
/// Must run as step 1 of the bridge registration order
/// (04-bridge.md §Registration order) — no bridges or batteries
/// primitives exist at this point, so a profile that reaches for
/// anything else fails with `attempt to call a nil value` before this
/// function ever runs.
pub fn install(lua: &Lua) -> mlua::Result<()> {
    let cache: Table = lua.create_table()?;

    let require_fn =
        lua.create_function(move |lua: &Lua, name: String| -> mlua::Result<Value> {
            let cached: Value = cache.get(name.as_str())?;
            if !matches!(cached, Value::Nil) {
                return Ok(cached);
            }

            let source = LM_MODULES
                .iter()
                .find(|(module_name, _)| *module_name == name)
                .map(|(_, source)| *source)
                .ok_or_else(|| allowlist_error(&name))?;

            let value: Value = lua
                .load(source)
                .set_name(name.as_str())
                .set_mode(mlua::ChunkMode::Text)
                .eval()?;
            cache.set(name.as_str(), value.clone())?;
            Ok(value)
        })?;

    lua.globals().set("require", require_fn)?;
    Ok(())
}

/// Build the "not in allowlist" error, naming every embedded module
/// (05-sandbox-layer-contract.md §L1: "Any other name is a Lua error
/// listing the allowlist").
fn allowlist_error(name: &str) -> mlua::Error {
    let allowlist: Vec<&str> = LM_MODULES.iter().map(|(n, _)| *n).collect();
    mlua::Error::RuntimeError(format!(
        "require: '{name}' is not in the embedded lm.* allowlist ({})",
        allowlist.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> Lua {
        let lua = Lua::new();
        install(&lua).expect("require install should succeed");
        lua
    }

    #[test]
    fn resolves_every_allowlisted_module() {
        let lua = boot();
        for (name, _) in LM_MODULES {
            let result: mlua::Result<Table> = lua.load(format!("return require('{name}')")).eval();
            assert!(
                result.is_ok(),
                "require('{name}') should succeed: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_names_outside_allowlist() {
        let lua = boot();
        let err = lua
            .load("return require('lm.nonexistent')")
            .eval::<Value>()
            .expect_err("unknown module must be a Lua error");
        let message = err.to_string();
        assert!(
            message.contains("lm.profile"),
            "message should list the allowlist: {message}"
        );
        assert!(
            message.contains("lm.nonexistent"),
            "message should name the offending module: {message}"
        );
    }

    #[test]
    fn caches_module_result_across_repeated_requires() {
        let lua = boot();
        let same: bool = lua
            .load(
                "local a = require('lm.profile')
                 local b = require('lm.profile')
                 return a == b",
            )
            .eval()
            .expect("repeated require should evaluate");
        assert!(
            same,
            "require must return the same cached table on repeat calls"
        );
    }
}
