//! L3 policy layer: declaration-derived allowlists
//! (05-sandbox-layer-contract.md §L3).
//!
//! Three policies are built from the profile's declared lists (`env` /
//! `env_secrets`, `http_allowlist`, `paths`) and "shared by both the
//! batteries `std.*` surface and the host's own bridges — one allowlist,
//! seen identically by every consumer" (05 §L3). Milestone M3-1 ships
//! all three policy structs plus the Lua-facing `env.get` / `env.set`
//! wiring ([`install_env_get_set`]); [`HttpPolicy`] and [`PathPolicy`]
//! have no Lua-facing surface of their own — they are consumed
//! internally by the `net.*` / `fs.*` / `mount.*` bridge implementations
//! that land in milestone M3-2..M3-4.

use std::collections::HashSet;

use mlua::{Lua, Table};
use thiserror::Error;

/// Errors [`EnvPolicy::get`] raises, mapped 1:1 onto the `env.get` Lua
/// errors named in 06-secret-handling.md §Error surface.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvPolicyError {
    /// `name` is declared in `profile.env_secrets` — the second wall
    /// (06 §Inputs `env.get`): even a declared secret name never yields
    /// its value through the plain-read path.
    #[error("env.get('{name}'): use env.ref(), env.get() is forbidden")]
    SecretDeclared {
        /// The rejected key name.
        name: String,
    },

    /// `name` matches one of `lm.catalog_data.SECRET_KEY_SUBSTRINGS`
    /// case-insensitively, whether or not it is declared in `env` or
    /// `env_secrets`. This is a defense-in-depth extension beyond the
    /// literal 06 §Error surface list: `validate` is the stage that
    /// rejects secret-shaped keys from `profile.env` (06 §Inputs
    /// "Profile declarations"), but 07-cli.md §Invocation's `apply`
    /// pipeline (`load → declarations → gate → bridges → plan →
    /// dispatch → apply`) never runs `validate` — a profile can reach
    /// `apply` with a secret-shaped key sitting in `env` untouched.
    /// Rejecting it here too keeps 06's "second wall" framing intact
    /// even on that path (reported as an interpretive extension, not a
    /// literal 06 transcription).
    #[error(
        "env.get('{name}'): '{name}' looks like a secret-shaped key; use env.ref() and declare it in env_secrets"
    )]
    SecretShaped {
        /// The rejected key name.
        name: String,
    },

    /// `name` is not a member of `profile.env` (06 §Inputs `env.get`:
    /// "Undeclared keys are rejected").
    #[error("'{name}' is not declared in profile.env")]
    Undeclared {
        /// The rejected key name.
        name: String,
    },
}

/// L3 env policy (05 §L3 "Env policy"; 06-secret-handling.md).
///
/// Built once from the six declarations extracted at registration order
/// step 5 ([`crate::vm::eval::Declarations`]) and shared by `env.get`
/// (this milestone) and, in later milestones, the `std.*` battery
/// surface that reads plain env values on a profile's behalf (05 §L3:
/// "one allowlist, seen identically by every consumer").
#[derive(Debug, Clone)]
pub struct EnvPolicy {
    env: HashSet<String>,
    env_secrets: HashSet<String>,
    secret_key_substrings: Vec<String>,
}

impl EnvPolicy {
    /// Build a policy from the profile's declared `env` / `env_secrets`
    /// lists and the frozen secret-key substring set
    /// ([`crate::sandbox::catalog::secret_key_substrings`], the 1-SoT
    /// accessor onto `lm.catalog_data.SECRET_KEY_SUBSTRINGS`).
    pub fn new(env: &[String], env_secrets: &[String], secret_key_substrings: &[String]) -> Self {
        Self {
            env: env.iter().cloned().collect(),
            env_secrets: env_secrets.iter().cloned().collect(),
            secret_key_substrings: secret_key_substrings
                .iter()
                .map(|s| s.to_uppercase())
                .collect(),
        }
    }

    /// Case-insensitive substring match against
    /// `lm.catalog_data.SECRET_KEY_SUBSTRINGS` (06 §Inputs "Profile
    /// declarations": `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PWD`,
    /// `AUTH`, `CRED`, `APIKEY`).
    fn is_secret_shaped(&self, name: &str) -> bool {
        let upper = name.to_uppercase();
        self.secret_key_substrings
            .iter()
            .any(|substring| upper.contains(substring.as_str()))
    }

    /// `env.get(name)` (06-secret-handling.md §Inputs).
    ///
    /// `Ok(Some(value))` when `name` is declared in `env` and set in the
    /// host process environment; `Ok(None)` when declared but absent
    /// (06 does not define missing-host-env behaviour for the *plain*
    /// read path — only secret consumption is fail-fast on a missing
    /// host value, 06 §Resolution — so this mirrors ordinary
    /// `os.getenv`-style absence rather than erroring, reported as an
    /// interpretive gap-fill, not a literal 06 transcription). `Err`
    /// otherwise, naming which of the three rejection classes applied.
    pub fn get(&self, name: &str) -> Result<Option<String>, EnvPolicyError> {
        if self.env_secrets.contains(name) {
            return Err(EnvPolicyError::SecretDeclared {
                name: name.to_string(),
            });
        }
        if self.is_secret_shaped(name) {
            return Err(EnvPolicyError::SecretShaped {
                name: name.to_string(),
            });
        }
        if !self.env.contains(name) {
            return Err(EnvPolicyError::Undeclared {
                name: name.to_string(),
            });
        }
        Ok(std::env::var(name).ok())
    }
}

/// Register `env.get` and `env.set` onto the pre-existing `env` global
/// table (04-bridge.md §Registration order step 3,
/// [`crate::bridge::env_ref::install`]) — registration order step 6's
/// "batteries `std.*` registration with the declaration-derived
/// policies (env / http)" (04 §Registration order), read narrowly as
/// this crate's plan.md records it: "env facade (`env.get`) の
/// policy-bound 実装をこの step で行う".
///
/// Must run after `env.ref` (step 3) and after declaration extraction
/// (step 5, [`crate::vm::eval::evaluate_profile_source`]) has produced
/// the `env` / `env_secrets` lists `policy` is built from — the
/// chicken-and-egg [`crate::bridge::env_ref::install`]'s own doc comment
/// records ("the declared-list-aware `env.get` ... needs the `env` /
/// `env_secrets` allowlists, which do not exist until declaration
/// extraction").
pub fn install_env_get_set(lua: &Lua, policy: EnvPolicy) -> mlua::Result<()> {
    let env_table: Table = lua.globals().get("env")?;

    let get_fn = lua.create_function(move |_, name: String| -> mlua::Result<Option<String>> {
        policy
            .get(&name)
            .map_err(|err| mlua::Error::RuntimeError(err.to_string()))
    })?;
    env_table.set("get", get_fn)?;

    let set_fn = lua.create_function(|_, _args: mlua::MultiValue| -> mlua::Result<()> {
        Err(mlua::Error::RuntimeError(
            "env.set is not permitted: Lua cannot mutate the host environment".to_string(),
        ))
    })?;
    env_table.set("set", set_fn)?;

    Ok(())
}

/// L3 HTTP policy (05 §L3 "HTTP policy").
///
/// No Lua-facing surface of its own: `net.http_get` / `net.http_post` /
/// `net.transfer` (milestone M3-3) consult [`HttpPolicy::is_allowed`]
/// internally before performing a request.
#[derive(Debug, Clone)]
pub struct HttpPolicy {
    allowlist: Vec<String>,
}

impl HttpPolicy {
    /// Build a policy from the profile's declared `http_allowlist`.
    pub fn new(allowlist: &[String]) -> Self {
        Self {
            allowlist: allowlist.to_vec(),
        }
    }

    /// `url` is allowed iff it matches one of the declared patterns
    /// (05 §L3 "HTTP policy"): "a literal URL prefix, optionally with a
    /// single `*` wildcard whose match is confined to the host portion
    /// ... the wildcard never matches into the path."
    pub fn is_allowed(&self, url: &str) -> bool {
        self.allowlist
            .iter()
            .any(|pattern| Self::pattern_matches(pattern, url))
    }

    /// [`HttpPolicy::is_allowed`] as a `Result`, for bridge
    /// implementations that need a ready-made rejection error
    /// (04-bridge.md §Error surface "Policy: env / http / path
    /// allowlist violations → Lua error naming the offending value").
    pub fn check(&self, url: &str) -> Result<(), HttpPolicyError> {
        if self.is_allowed(url) {
            Ok(())
        } else {
            Err(HttpPolicyError {
                url: url.to_string(),
            })
        }
    }

    /// Split `url` into `(scheme, authority, path)` at `"://"` and the
    /// first following `/`. `authority` never contains a `/`; `path` is
    /// `""` when the URL has no path segment at all — both properties
    /// hold for `pattern` too, which is what confines a pattern's `*`
    /// to the authority component: [`Self::pattern_matches`] only ever
    /// looks for `*` inside the authority half of the split.
    fn split(url: &str) -> Option<(&str, &str, &str)> {
        let (scheme, rest) = url.split_once("://")?;
        match rest.find('/') {
            Some(idx) => Some((scheme, &rest[..idx], &rest[idx..])),
            None => Some((scheme, rest, "")),
        }
    }

    fn pattern_matches(pattern: &str, url: &str) -> bool {
        let Some((pattern_scheme, pattern_authority, pattern_path)) = Self::split(pattern) else {
            return false;
        };
        let Some((url_scheme, url_authority, url_path)) = Self::split(url) else {
            return false;
        };
        if pattern_scheme != url_scheme {
            return false;
        }

        let authority_ok = match pattern_authority.find('*') {
            None => url_authority == pattern_authority,
            Some(star_idx) => {
                let host_prefix = &pattern_authority[..star_idx];
                let host_suffix = &pattern_authority[star_idx + 1..];
                url_authority.len() >= host_prefix.len() + host_suffix.len()
                    && url_authority.starts_with(host_prefix)
                    && url_authority.ends_with(host_suffix)
            }
        };

        authority_ok && url_path.starts_with(pattern_path)
    }
}

/// `url` matched no pattern in `profile.http_allowlist`
/// (05-sandbox-layer-contract.md §L3 "HTTP policy").
#[derive(Debug, Error)]
#[error("'{url}' matches no pattern in profile.http_allowlist")]
pub struct HttpPolicyError {
    /// The rejected URL.
    pub url: String,
}

/// L3 path policy (05 §L3 "Path policy").
///
/// Lexical only — it does not chase symlinks (05 §L3: "Deployment
/// targets are fresh single-tenant pods where the profile itself
/// creates the tree; symlink-racing an already-compromised host is out
/// of threat model"). No Lua-facing surface of its own: `fs.write` /
/// `mount.bind` / `mount.umount` (milestone M3-4) consult
/// [`PathPolicy::is_allowed`] internally.
#[derive(Debug, Clone)]
pub struct PathPolicy {
    roots: Vec<String>,
}

impl PathPolicy {
    /// Build a policy from the profile's declared `paths` roots.
    pub fn new(roots: &[String]) -> Self {
        Self {
            roots: roots.to_vec(),
        }
    }

    /// `path` is accepted iff it is absolute, contains no `..` segment,
    /// and lies under a declared root with component-aligned prefix
    /// matching (05 §L3 "Path policy": "`/workspace_x` is NOT under
    /// `/workspace`").
    pub fn is_allowed(&self, path: &str) -> bool {
        if !path.starts_with('/') {
            return false;
        }
        if path.split('/').any(|segment| segment == "..") {
            return false;
        }
        self.roots.iter().any(|root| Self::under_root(root, path))
    }

    /// [`PathPolicy::is_allowed`] as a `Result`, mirroring
    /// [`HttpPolicy::check`].
    pub fn check(&self, path: &str) -> Result<(), PathPolicyError> {
        if self.is_allowed(path) {
            Ok(())
        } else {
            Err(PathPolicyError {
                path: path.to_string(),
            })
        }
    }

    fn under_root(root: &str, path: &str) -> bool {
        if path == root {
            return true;
        }
        let root_with_slash = if root.ends_with('/') {
            root.to_string()
        } else {
            format!("{root}/")
        };
        path.starts_with(&root_with_slash)
    }
}

/// `path` is not absolute, contains a `..` segment, or lies outside
/// every declared root in `profile.paths`
/// (05-sandbox-layer-contract.md §L3 "Path policy").
#[derive(Debug, Error)]
#[error("'{path}' is not absolute, contains '..', or lies outside profile.paths")]
pub struct PathPolicyError {
    /// The rejected path.
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::env_ref;
    use mlua::Lua;

    // -------------------------------------------------------------
    // EnvPolicy (pure Rust, no VM needed)
    // -------------------------------------------------------------

    #[test]
    fn get_allows_declared_non_secret_env_and_reads_host_value() {
        let var_name = format!("LM_PROVISION_TEST_ENV_GET_{}", std::process::id());
        std::env::set_var(&var_name, "value-1");
        let policy = EnvPolicy::new(std::slice::from_ref(&var_name), &[], &[]);

        let result = policy
            .get(&var_name)
            .expect("declared env should be allowed");

        std::env::remove_var(&var_name);
        assert_eq!(result, Some("value-1".to_string()));
    }

    #[test]
    fn get_returns_none_when_declared_but_absent_from_host_env() {
        let var_name = format!("LM_PROVISION_TEST_ENV_ABSENT_{}", std::process::id());
        std::env::remove_var(&var_name);
        let policy = EnvPolicy::new(std::slice::from_ref(&var_name), &[], &[]);

        let result = policy
            .get(&var_name)
            .expect("declared-but-absent should not error, 06 §Resolution only binds secrets");
        assert_eq!(result, None);
    }

    #[test]
    fn get_rejects_undeclared_name() {
        let policy = EnvPolicy::new(&[], &[], &[]);
        let err = policy
            .get("UNDECLARED")
            .expect_err("undeclared name must be rejected");
        assert_eq!(
            err,
            EnvPolicyError::Undeclared {
                name: "UNDECLARED".to_string()
            }
        );
        assert_eq!(
            err.to_string(),
            "'UNDECLARED' is not declared in profile.env"
        );
    }

    #[test]
    fn get_rejects_a_declared_secret_name_with_the_use_env_ref_message() {
        let policy = EnvPolicy::new(&[], &["HF_TOKEN".to_string()], &["TOKEN".to_string()]);
        let err = policy
            .get("HF_TOKEN")
            .expect_err("secret name must be rejected (06 §Inputs `env.get` second wall)");
        assert!(matches!(err, EnvPolicyError::SecretDeclared { .. }));
        assert!(err.to_string().contains("use env.ref()"));
    }

    #[test]
    fn get_rejects_a_secret_shaped_key_even_when_declared_in_env_and_not_in_env_secrets() {
        // Defense in depth: 07-cli.md §Invocation's `apply` pipeline never
        // runs `validate`, so a secret-shaped key could reach `env.get`
        // without ever being rejected at the declared-list level.
        let policy = EnvPolicy::new(&["MY_API_KEY".to_string()], &[], &["KEY".to_string()]);
        let err = policy
            .get("MY_API_KEY")
            .expect_err("secret-shaped key must be rejected even though declared in env");
        assert!(matches!(err, EnvPolicyError::SecretShaped { .. }));
    }

    #[test]
    fn get_treats_the_secret_key_substring_match_as_case_insensitive() {
        let policy = EnvPolicy::new(&["my_token".to_string()], &[], &["TOKEN".to_string()]);
        let err = policy
            .get("my_token")
            .expect_err("case-insensitive substring match must still reject");
        assert!(matches!(err, EnvPolicyError::SecretShaped { .. }));
    }

    // -------------------------------------------------------------
    // env.get / env.set Lua wiring
    // -------------------------------------------------------------

    #[test]
    fn env_get_is_callable_from_lua_and_returns_the_host_value() {
        let lua = Lua::new();
        env_ref::install(&lua).expect("env.ref install should succeed");
        let var_name = format!("LM_PROVISION_TEST_ENV_LUA_{}", std::process::id());
        std::env::set_var(&var_name, "lua-value");
        let policy = EnvPolicy::new(std::slice::from_ref(&var_name), &[], &[]);
        install_env_get_set(&lua, policy).expect("install_env_get_set should succeed");

        let result: String = lua
            .load(format!("return env.get('{var_name}')"))
            .eval()
            .expect("env.get should return the host value");

        std::env::remove_var(&var_name);
        assert_eq!(result, "lua-value");
    }

    #[test]
    fn env_get_rejects_a_declared_secret_name_from_lua() {
        let lua = Lua::new();
        env_ref::install(&lua).expect("env.ref install should succeed");
        let policy = EnvPolicy::new(&[], &["HF_TOKEN".to_string()], &["TOKEN".to_string()]);
        install_env_get_set(&lua, policy).expect("install_env_get_set should succeed");

        let err = lua
            .load("return env.get('HF_TOKEN')")
            .eval::<mlua::Value>()
            .expect_err("secret name must raise a Lua error");
        assert!(err.to_string().contains("use env.ref()"));
    }

    #[test]
    fn env_set_is_always_rejected_from_lua() {
        let lua = Lua::new();
        env_ref::install(&lua).expect("env.ref install should succeed");
        let policy = EnvPolicy::new(&[], &[], &[]);
        install_env_get_set(&lua, policy).expect("install_env_get_set should succeed");

        let err = lua
            .load("return env.set('X', 'Y')")
            .eval::<mlua::Value>()
            .expect_err("env.set must always be rejected (06 §Inputs `env.set` — prohibited)");
        assert!(err.to_string().to_lowercase().contains("mutate"));
    }

    // -------------------------------------------------------------
    // HttpPolicy
    // -------------------------------------------------------------

    #[test]
    fn http_wildcard_matches_a_subdomain_and_carries_the_path_prefix() {
        let policy = HttpPolicy::new(&["https://*.b2.backblazeb2.com".to_string()]);
        assert!(policy.is_allowed("https://f001.b2.backblazeb2.com/file/bucket/path"));
    }

    #[test]
    fn http_wildcard_never_matches_into_the_path() {
        let policy = HttpPolicy::new(&["https://*.b2.backblazeb2.com".to_string()]);
        assert!(!policy.is_allowed("https://attacker.com/https://f001.b2.backblazeb2.com/smuggled"));
        assert!(!policy.is_allowed("https://evil.b2.backblazeb2.com.attacker.com/x"));
    }

    #[test]
    fn http_literal_pattern_without_a_wildcard_requires_exact_authority_and_path_prefix() {
        let policy = HttpPolicy::new(&["https://huggingface.co/models/".to_string()]);
        assert!(policy.is_allowed("https://huggingface.co/models/foo/bar"));
        assert!(!policy.is_allowed("https://huggingface.co/other/foo"));
        assert!(!policy.is_allowed("https://huggingface.co.evil.com/models/foo"));
    }

    #[test]
    fn http_check_returns_the_offending_url_on_rejection() {
        let policy = HttpPolicy::new(&["https://huggingface.co/".to_string()]);
        let err = policy
            .check("https://evil.example.com/")
            .expect_err("unmatched url must be rejected");
        assert_eq!(err.url, "https://evil.example.com/");
    }

    // -------------------------------------------------------------
    // PathPolicy
    // -------------------------------------------------------------

    #[test]
    fn path_allows_the_declared_root_and_nested_children() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        assert!(policy.is_allowed("/workspace"));
        assert!(policy.is_allowed("/workspace/models/foo.bin"));
    }

    #[test]
    fn path_rejects_a_non_component_aligned_prefix() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        assert!(!policy.is_allowed("/workspace_x"));
    }

    #[test]
    fn path_rejects_relative_and_dotdot_segments() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        assert!(!policy.is_allowed("workspace/foo"));
        assert!(!policy.is_allowed("/workspace/../etc/passwd"));
    }

    #[test]
    fn path_check_returns_the_offending_path_on_rejection() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        let err = policy
            .check("/etc/passwd")
            .expect_err("outside-root path must be rejected");
        assert_eq!(err.path, "/etc/passwd");
    }
}
