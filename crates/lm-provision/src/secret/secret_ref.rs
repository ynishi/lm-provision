//! `SecretRef` — the opaque userdata handle profile authors get back from
//! `env.ref(name)` (06-secret-handling.md §Outputs "SecretRef userdata —
//! the opacity contract").

use mlua::{MetaMethod, UserData, UserDataFields, UserDataMethods};

/// An opaque reference to a named secret.
///
/// Carries only the logical `name`; the resolved value is read from the
/// host process environment on the host thread at bridge consumption time
/// (06-secret-handling.md §Resolution) and is never stored on this type,
/// returned to Lua, or logged.
#[derive(Debug, Clone)]
pub struct SecretRef {
    name: String,
}

impl SecretRef {
    /// Wrap `name` in a new [`SecretRef`] (`env.ref(name)`,
    /// 06-secret-handling.md §Inputs). Performs no policy check — the
    /// `env_secrets` allowlist is enforced at bridge consumption time
    /// instead (06 §Inputs "Validation timing rationale": declarations
    /// are not extracted yet when `env.ref` must already be callable).
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// The logical secret name — never the resolved value.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl UserData for SecretRef {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        // Canonical-encoding hook (06 §Outputs): a marker on the shared,
        // type-level metatable so `lm.canonical` (chapter 03, milestone
        // M2) can recognize a SecretRef and encode it as the marker
        // table `{"__secret": ref:name()}`. mlua shares one metatable
        // across every SecretRef instance, so this field carries no
        // per-instance data itself — the logical name always comes from
        // the `name()` method below.
        fields.add_meta_field("__lm_secret_name", true);
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // `ref:name()` — the logical name, for report / correlation use
        // (06 §Outputs). Never the resolved value.
        methods.add_method("name", |_, this, ()| Ok(this.name.clone()));

        // `tostring(ref)` -> `"[secret:NAME]"` (06 §Outputs: "the only
        // value-bearing operation visible to Lua"). No other field or
        // method is registered here, so any other key resolves to `nil`
        // (mlua falls back to raw table lookup on the generated `__index`
        // table when no custom `__index` metamethod is installed) and
        // assignment errors (no `__newindex` is ever installed) — opacity
        // is physical (userdata), not conventional (06 §Outputs).
        methods.add_meta_method(MetaMethod::ToString, |_, this, ()| {
            Ok(format!("[secret:{}]", this.name))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::{Lua, Value};

    fn lua_with_ref(name: &str) -> (Lua, ()) {
        let lua = Lua::new();
        lua.globals()
            .set("ref", SecretRef::new(name))
            .expect("set global");
        (lua, ())
    }

    #[test]
    fn tostring_renders_the_redacted_marker() {
        let (lua, _) = lua_with_ref("HF_TOKEN");
        let rendered: String = lua
            .load("return tostring(ref)")
            .eval()
            .expect("tostring(ref) should evaluate");
        assert_eq!(rendered, "[secret:HF_TOKEN]");
    }

    #[test]
    fn name_method_returns_the_logical_name_not_the_value() {
        let (lua, _) = lua_with_ref("HF_TOKEN");
        let name: String = lua
            .load("return ref:name()")
            .eval()
            .expect("ref:name() should evaluate");
        assert_eq!(name, "HF_TOKEN");
    }

    #[test]
    fn unknown_field_access_is_nil_not_an_error() {
        let (lua, _) = lua_with_ref("HF_TOKEN");
        let value: Value = lua
            .load("return ref.anything")
            .eval()
            .expect("field access on an unregistered key must not raise");
        assert!(
            matches!(value, Value::Nil),
            "06 §Outputs: field access is unimplemented, so ref.anything is nil: {value:?}"
        );
    }

    #[test]
    fn assignment_to_the_userdata_is_a_lua_error() {
        let (lua, _) = lua_with_ref("HF_TOKEN");
        let err = lua
            .load("ref.anything = 1")
            .exec()
            .expect_err("06 §Outputs: assignment is unimplemented and must error");
        // Exact wording is Lua-runtime-owned; assert on the structural
        // fact (no __newindex means indexed assignment on a userdata
        // fails), not a literal string this crate does not control.
        let message = err.to_string();
        assert!(
            message.to_lowercase().contains("index"),
            "assignment should fail as a userdata indexing error: {message}"
        );
    }
}
