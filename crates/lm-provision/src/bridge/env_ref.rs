//! `env.ref` factory registration (04-bridge.md §Registration order step
//! 3; 06-secret-handling.md §Inputs `env.ref`).

use mlua::{Lua, Table};

use crate::secret::SecretRef;

/// Register the profile-eval-time `env` global with only `env.ref`
/// (06-secret-handling.md §Inputs).
///
/// Must run as registration order step 3 (04-bridge.md §Registration
/// order) — before the profile file is evaluated (step 4) — so `env.ref`
/// is reachable from any declared phase payload regardless of where in
/// the profile body it appears.
///
/// `env.get` / `env.set` are deferred to milestone M3: the
/// declared-list-aware `env.get` (06 §Inputs) needs the `env` /
/// `env_secrets` allowlists, which do not exist until declaration
/// extraction (registration order step 5) — the chicken-and-egg 06
/// §Inputs "Validation timing rationale" resolves by enforcing the
/// `env_secrets` allowlist at bridge consumption time instead, not at
/// `env.ref` call time. `env.set` is an unconditional rejection (06
/// §Inputs) that has no dependency on the declared lists, but it ships
/// alongside `env.get` and the surrounding sandbox L3 policies in M3
/// rather than split across milestones.
pub fn install(lua: &Lua) -> mlua::Result<()> {
    let env_table: Table = lua.create_table()?;
    let ref_fn = lua.create_function(|_, name: String| Ok(SecretRef::new(name)))?;
    env_table.set("ref", ref_fn)?;
    lua.globals().set("env", env_table)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ref_constructs_a_secret_ref_userdata() {
        let lua = Lua::new();
        install(&lua).expect("env.ref install should succeed");

        let rendered: String = lua
            .load("return tostring(env.ref('HF_TOKEN'))")
            .eval()
            .expect("env.ref(name) should construct a SecretRef");
        assert_eq!(rendered, "[secret:HF_TOKEN]");
    }

    #[test]
    fn env_get_and_env_set_are_not_registered_in_m1() {
        let lua = Lua::new();
        install(&lua).expect("env.ref install should succeed");

        for expr in ["env.get", "env.set"] {
            let value: mlua::Value = lua
                .load(format!("return {expr}"))
                .eval()
                .unwrap_or_else(|err| panic!("{expr} lookup should not raise: {err}"));
            assert!(
                matches!(value, mlua::Value::Nil),
                "{expr} is deferred to M3 (sandbox L3 policies); expected nil, got {value:?}"
            );
        }
    }
}
