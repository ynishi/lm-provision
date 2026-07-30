//! Pure path / HTTP allowlist policy (mlua-free port of the L3 policy).
//!
//! Semantics are the ones documented in spec
//! `05-sandbox-layer-contract.md` §L3: path roots + a wildcarded URL
//! allowlist whose `*` is confined to the authority component. The
//! implementation deliberately mirrors the legacy mlua-bound policy
//! byte-for-byte on the pure-Rust surface (`is_allowed` /
//! `split` / `pattern_matches` / `under_root`) so a profile author
//! cannot observe a behavioural drift when the exec path replaces the
//! legacy stack.
//!
//! `check` returns [`ExecError::PathDenied`] / [`ExecError::HttpDenied`]
//! so the registry's op handlers can bubble a policy violation through
//! the same `to_engine_error` path that already carries capability
//! denials and payload mismatches.

use std::collections::{BTreeMap, HashSet};

use dsl_kit::DslNode as _;

use super::ExecError;
use crate::profile_ast::ProfileNode;

/// Secret-injection policy derived from `profile.env_secrets`.
///
/// The injection policy resolves a phase's `env` keyed slot (name →
/// [`ProfileNode::EnvLiteral`] / [`ProfileNode::EnvSecret`]) into the
/// concrete `name → value` map that flows into a child process env
/// (spec 06 §Resolution). The plain non-secret `env` allowlist is *not*
/// needed here: an [`ProfileNode::EnvLiteral`] carries its value inline
/// and is never looked up by name against the host env, so only the
/// `env_secrets` allowlist governs injection.
///
/// The resolution rules are the spec-06 check-then-resolve protocol:
///
/// - [`ProfileNode::EnvSecret`] `{ name }` is rejected with
///   [`ExecError::SecretUndeclared`] when `name ∉ env_secrets`
///   (defense-in-depth: `validate` also enforces this, but the `apply`
///   pipeline never runs `validate`).
/// - A declared secret absent from the host process env is
///   [`ExecError::SecretMissingInHostEnv`] — fail-fast, no empty-string
///   substitution.
/// - Resolution is mode-agnostic: the caller resolves in both dry-run
///   and real mode (spec 06 §Resolution "dry-run resolves too"), so a
///   dry run that passes proves the secret plumbing.
///
/// The resolved value never appears in an [`ExecError`] (both error
/// variants carry only the logical `name`) and is never logged — only
/// the logical key names reach a trace line.
#[derive(Debug, Clone)]
pub struct EnvPolicy {
    env_secrets: HashSet<String>,
}

impl EnvPolicy {
    /// Build a policy from the profile's declared `env_secrets` list.
    pub fn new(env_secrets: &[String]) -> Self {
        Self {
            env_secrets: env_secrets.iter().cloned().collect(),
        }
    }

    /// Resolve a phase `env` keyed slot into a concrete `name → value`
    /// map. Always resolves (spec 06 §Resolution: the caller invokes
    /// this in both modes). Fail-fast on the first offending entry.
    pub fn resolve(
        &self,
        env: &BTreeMap<String, ProfileNode>,
    ) -> Result<BTreeMap<String, String>, ExecError> {
        let mut resolved = BTreeMap::new();
        for (key, node) in env {
            let value = match node {
                ProfileNode::EnvLiteral { value, .. } => value.clone(),
                ProfileNode::EnvSecret { name, .. } => {
                    if !self.env_secrets.contains(name) {
                        return Err(ExecError::SecretUndeclared { name: name.clone() });
                    }
                    std::env::var(name)
                        .map_err(|_| ExecError::SecretMissingInHostEnv { name: name.clone() })?
                }
                other => {
                    return Err(ExecError::PayloadVariant {
                        node: other.node_id().0,
                        expected: "EnvLiteral or EnvSecret",
                    })
                }
            };
            resolved.insert(key.clone(), value);
        }
        Ok(resolved)
    }
}

/// Path allowlist derived from `profile.paths`.
///
/// Lexical only — it does not chase symlinks (spec 05 §L3: "Deployment
/// targets are fresh single-tenant pods where the profile itself
/// creates the tree; symlink-racing an already-compromised host is out
/// of threat model").
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

    /// `path` is accepted iff it is absolute, contains no `..`
    /// segment, and lies under a declared root with component-aligned
    /// prefix matching (spec 05 §L3: `/workspace_x` is NOT under
    /// `/workspace`).
    pub fn is_allowed(&self, path: &str) -> bool {
        if !path.starts_with('/') {
            return false;
        }
        if path.split('/').any(|segment| segment == "..") {
            return false;
        }
        self.roots.iter().any(|root| Self::under_root(root, path))
    }

    /// [`Self::is_allowed`] as a `Result`, naming the offending path
    /// via [`ExecError::PathDenied`].
    pub fn check(&self, path: &str) -> Result<(), ExecError> {
        if self.is_allowed(path) {
            Ok(())
        } else {
            Err(ExecError::PathDenied {
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

/// HTTP allowlist derived from `profile.http_allowlist`.
#[derive(Debug, Clone)]
pub struct HttpPolicy {
    allowlist: Vec<String>,
}

impl HttpPolicy {
    /// Build a policy from the profile's declared `http_allowlist`
    /// patterns.
    pub fn new(allowlist: &[String]) -> Self {
        Self {
            allowlist: allowlist.to_vec(),
        }
    }

    /// `url` is allowed iff it matches one of the declared patterns
    /// (spec 05 §L3): "a literal URL prefix, optionally with a single
    /// `*` wildcard whose match is confined to the host portion ...
    /// the wildcard never matches into the path."
    pub fn is_allowed(&self, url: &str) -> bool {
        self.allowlist
            .iter()
            .any(|pattern| Self::pattern_matches(pattern, url))
    }

    /// [`Self::is_allowed`] as a `Result`, naming the offending URL
    /// via [`ExecError::HttpDenied`].
    pub fn check(&self, url: &str) -> Result<(), ExecError> {
        if self.is_allowed(url) {
            Ok(())
        } else {
            Err(ExecError::HttpDenied {
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

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    // -----------------------------------------------------------------
    // EnvPolicy (secret-injection resolution)
    // -----------------------------------------------------------------

    fn literal(ids: &IdGen, value: &str) -> ProfileNode {
        ProfileNode::EnvLiteral {
            id: ids.node(),
            value: value.to_string(),
        }
    }

    fn secret(ids: &IdGen, name: &str) -> ProfileNode {
        ProfileNode::EnvSecret {
            id: ids.node(),
            name: name.to_string(),
        }
    }

    #[test]
    fn env_resolves_a_literal_to_its_inline_value() {
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert("REGION".to_string(), literal(&ids, "us-west"));
        let policy = EnvPolicy::new(&[]);

        let resolved = policy.resolve(&env).expect("literal resolves");
        assert_eq!(resolved.get("REGION").map(String::as_str), Some("us-west"));
    }

    #[test]
    fn env_resolves_a_declared_secret_from_the_host_env() {
        let var = format!("LM_EXEC_ENV_SECRET_{}", std::process::id());
        std::env::set_var(&var, "resolved-secret-value");
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert("SLOT".to_string(), secret(&ids, &var));
        let policy = EnvPolicy::new(std::slice::from_ref(&var));

        let resolved = policy
            .resolve(&env)
            .expect("declared+present secret resolves");
        std::env::remove_var(&var);
        assert_eq!(
            resolved.get("SLOT").map(String::as_str),
            Some("resolved-secret-value")
        );
    }

    #[test]
    fn env_rejects_an_undeclared_secret_without_reading_the_host_value() {
        // The host var IS set, but the name is not in env_secrets, so the
        // undeclared check must fire before any host read — proving the
        // value never reaches the error surface.
        let var = format!("LM_EXEC_ENV_UNDECLARED_{}", std::process::id());
        std::env::set_var(&var, "leak-me-if-you-can");
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert("SLOT".to_string(), secret(&ids, &var));
        let policy = EnvPolicy::new(&[]);

        let err = policy
            .resolve(&env)
            .expect_err("undeclared secret must be rejected");
        std::env::remove_var(&var);
        match &err {
            ExecError::SecretUndeclared { name } => assert_eq!(name, &var),
            other => panic!("expected SecretUndeclared, got {other:?}"),
        }
        assert!(
            !err.to_string().contains("leak-me-if-you-can"),
            "the resolved value must never appear in the error: {err}"
        );
    }

    #[test]
    fn env_fails_fast_when_a_declared_secret_is_absent_from_the_host_env() {
        let var = format!("LM_EXEC_ENV_MISSING_{}", std::process::id());
        std::env::remove_var(&var);
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert("SLOT".to_string(), secret(&ids, &var));
        let policy = EnvPolicy::new(std::slice::from_ref(&var));

        let err = policy
            .resolve(&env)
            .expect_err("a declared but absent secret must fail fast");
        match err {
            ExecError::SecretMissingInHostEnv { name } => assert_eq!(name, var),
            other => panic!("expected SecretMissingInHostEnv, got {other:?}"),
        }
    }

    #[test]
    fn env_missing_secret_message_names_the_key_but_carries_no_value() {
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert("SLOT".to_string(), secret(&ids, "NEVER_SET_SECRET"));
        let policy = EnvPolicy::new(&["NEVER_SET_SECRET".to_string()]);

        let err = policy.resolve(&env).expect_err("absent secret fails");
        assert_eq!(
            err.to_string(),
            "secret 'NEVER_SET_SECRET' missing in host env"
        );
    }

    #[test]
    fn env_empty_map_resolves_to_an_empty_map() {
        let policy = EnvPolicy::new(&["ANY".to_string()]);
        let resolved = policy
            .resolve(&BTreeMap::new())
            .expect("an empty env is a valid no-op");
        assert!(resolved.is_empty());
    }

    // -----------------------------------------------------------------
    // PathPolicy
    // -----------------------------------------------------------------

    #[test]
    fn path_allows_root_and_nested_children() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        assert!(policy.is_allowed("/workspace"));
        assert!(policy.is_allowed("/workspace/models/foo.bin"));
    }

    #[test]
    fn path_rejects_a_non_component_aligned_prefix() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        assert!(!policy.is_allowed("/workspace_x"));
        assert!(!policy.is_allowed("/workspace_x/inner"));
    }

    #[test]
    fn path_rejects_relative_and_dotdot_segments() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        assert!(!policy.is_allowed("workspace/foo"));
        assert!(!policy.is_allowed("/workspace/../etc/passwd"));
        assert!(!policy.is_allowed("/../secret"));
    }

    #[test]
    fn path_rejects_paths_outside_every_root() {
        let policy = PathPolicy::new(&["/workspace".to_string(), "/tmp".to_string()]);
        assert!(policy.is_allowed("/tmp/scratch"));
        assert!(!policy.is_allowed("/etc/passwd"));
    }

    #[test]
    fn path_check_returns_the_offending_path_on_rejection() {
        let policy = PathPolicy::new(&["/workspace".to_string()]);
        let err = policy
            .check("/etc/passwd")
            .expect_err("outside-root path must be rejected");
        match err {
            ExecError::PathDenied { path } => assert_eq!(path, "/etc/passwd"),
            other => panic!("expected PathDenied, got {other:?}"),
        }
    }

    #[test]
    fn path_empty_root_set_rejects_every_path() {
        let policy = PathPolicy::new(&[]);
        assert!(!policy.is_allowed("/workspace"));
        assert!(!policy.is_allowed("/tmp/x"));
    }

    #[test]
    fn path_root_with_trailing_slash_is_treated_as_component_aligned() {
        let policy = PathPolicy::new(&["/workspace/".to_string()]);
        assert!(policy.is_allowed("/workspace/models/foo"));
        // Exact match without trailing slash is not equal and does not
        // start with `/workspace//` — a bare root written with a
        // trailing slash covers only strict children.
        assert!(!policy.is_allowed("/workspace"));
    }

    // -----------------------------------------------------------------
    // HttpPolicy
    // -----------------------------------------------------------------

    #[test]
    fn http_literal_pattern_requires_exact_authority_and_path_prefix() {
        let policy = HttpPolicy::new(&["https://huggingface.co/models/".to_string()]);
        assert!(policy.is_allowed("https://huggingface.co/models/foo/bar"));
        assert!(!policy.is_allowed("https://huggingface.co/other/foo"));
        assert!(!policy.is_allowed("https://huggingface.co.evil.com/models/foo"));
    }

    #[test]
    fn http_pattern_without_path_matches_any_path_on_the_authority() {
        let policy = HttpPolicy::new(&["https://example.com".to_string()]);
        assert!(policy.is_allowed("https://example.com/"));
        assert!(policy.is_allowed("https://example.com/get"));
        assert!(policy.is_allowed("https://example.com/deep/path"));
        assert!(!policy.is_allowed("https://other.example/"));
    }

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
    fn http_scheme_mismatch_is_rejected() {
        let policy = HttpPolicy::new(&["https://example.com".to_string()]);
        assert!(!policy.is_allowed("http://example.com/"));
    }

    #[test]
    fn http_check_returns_the_offending_url_on_rejection() {
        let policy = HttpPolicy::new(&["https://huggingface.co/".to_string()]);
        let err = policy
            .check("https://evil.example.com/")
            .expect_err("unmatched url must be rejected");
        match err {
            ExecError::HttpDenied { url } => assert_eq!(url, "https://evil.example.com/"),
            other => panic!("expected HttpDenied, got {other:?}"),
        }
    }

    #[test]
    fn http_empty_allowlist_rejects_every_url() {
        let policy = HttpPolicy::new(&[]);
        assert!(!policy.is_allowed("https://example.com/"));
    }

    #[test]
    fn http_malformed_url_without_scheme_is_rejected() {
        let policy = HttpPolicy::new(&["https://example.com".to_string()]);
        assert!(!policy.is_allowed("not-a-url"));
    }
}
