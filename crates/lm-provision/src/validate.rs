//! First-violation validation over the [`ProfileNode`] AST
//! (`03-pipeline-stage-artifacts.md` §validate).
//!
//! Respecified from the legacy Lua `lm.validate.validate(ir)` onto the
//! typed AST: the seven documented checks run in order and stop at the
//! first violation, returning `Err(ValidateError)` (single-error
//! reporting, 03 §Stability: provisional). On success it returns
//! `Ok(())` — the profile name a caller needs on success is read
//! straight off the [`ProfileNode::Spec`] node.
//!
//! ## What the typed AST subsumes or drops relative to the Lua port
//!
//! - **Check 1's `ir.schema == "lm.profile/1"` guard is not ported.**
//!   The AST carries no `schema` marker (the same reason
//!   [`crate::canonical`] emits no `schema` key): reaching this stage
//!   already means the frontend ([`crate::frontend::load_profile`])
//!   built a well-typed [`ProfileNode`], so the schema tag is a
//!   frontend invariant rather than a runtime content check. Check 1
//!   here is only "root is a `Spec` with a non-empty `name`".
//! - **Check 2's per-entry type check is subsumed by the type system.**
//!   The five declared lists (`capabilities` / `env` / `env_secrets` /
//!   `paths` / `http_allowlist`) are `Vec<String>` on the AST, so "each
//!   entry is a string" is unrepresentable-as-invalid. The Lua check 2
//!   imposes no further *content* condition (it never rejects empty
//!   strings), so nothing remains to port — check 2 is a no-op here.
//! - **Check 6 is scoped to payload-string shell-safety, the
//!   `sync.*` / `staging.*` route shape, the `env` keyed slot, and the
//!   value-node slots outside it** (`fs.write` `content`,
//!   `net.http_*` `headers`, `net.http_post` `body` — which also
//!   carries the `body` / `body_json` exclusivity rule). The
//!   typed enum removes the unknown-kind and per-field type/requiredness
//!   walk the Lua port ran against `lm.catalog_data`. [`ProfileNode::SyncPull`]
//!   / [`ProfileNode::StagingPush`] / [`ProfileNode::ShExec`] now carry
//!   an `env` keyed slot (and `sync.*` / `staging.*` a `revision`): each
//!   `env` key is shell-safety-checked (mirroring the Lua
//!   `check_env_table_field`), and each [`ProfileNode::EnvSecret`] value
//!   is cross-checked against `Spec.env_secrets` (a check the Lua port
//!   lacked — spec 06 §`env.ref` "checks `ref.name ∈ env_secrets`").
//!   `revision` carries no `shell_safe` marker in `lm.catalog_data`
//!   (`sync.pull.revision` is a bare `string`), so it is deliberately
//!   left unchecked, matching the Lua port. The remaining AST payloads
//!   are still a subset of the spec-02 catalog (e.g.
//!   [`ProfileNode::ServiceStart`] flattens `platform.kind` to a
//!   `platform_kind` string, and `custom_nodes` / `models` / `llm_models`
//!   carry an opaque JSON string rather than a structured list): only the
//!   fields the AST holds are checked, and the remaining Lua-only field
//!   checks (the `platform.kind` enum, `custom_nodes` inner-string
//!   shell-safety, …) follow whenever those fields are promoted onto the
//!   AST.
//!
//! Which fields are shell-safety-checked is driven by
//! `lm.catalog_data`'s `shell_safe` marker: `system.apt.packages`,
//! `comfyui.install.ref` (AST field `ref_name`), `python.deps.deps`,
//! `service.start.name`, and the `sync.pull` / `sync.push` /
//! `staging.push` `src` / `dst` route fields. `hooks.post_install.script`
//! is deliberately exempt (01 §Escape / fragment policy) — the AST
//! variant [`ProfileNode::PostInstall`] therefore has no shell-safety
//! check at all.

use std::collections::{BTreeMap, HashSet};

use crate::profile_ast::ProfileNode;

/// Secret-shaped-key substrings (check 3), the frozen eight-entry set
/// from 06-secret-handling.md §Inputs "Profile declarations" /
/// 02-phase-catalog.md §Shared vocabulary, transcribed here for the AST
/// validate path. Kept `pub` so any other consumer reuses this one
/// accessor rather than growing a second copy. Consumers must match
/// case-insensitively; the entries are already upper-case.
pub const SECRET_KEY_SUBSTRINGS: &[&str] = &[
    "KEY", "SECRET", "TOKEN", "PASSWORD", "PWD", "AUTH", "CRED", "APIKEY",
];

/// The `b2://` / `hf://` / `https://` schemes a `sync.*` / `staging.*`
/// route may carry (03 §validate route-shape half of check 6, mirroring
/// `lm.validate`'s `URI_ROUTE_SCHEMES`).
const URI_ROUTE_SCHEMES: &[&str] = &["b2", "hf", "https"];

/// The literal `{pod_id}` placeholder allowed inside `sync.push` /
/// `staging.push` `dst`, exempt from the shell-safety charset even
/// though `{` / `}` are not themselves shell-safe (02 §Catalog kinds
/// `sync.push`).
const POD_ID_PLACEHOLDER: &str = "{pod_id}";

/// A validate-stage rejection (first violation only,
/// 03-pipeline-stage-artifacts.md §validate). Each `Display` string
/// carries the same information the legacy Lua message did; the `ir.`
/// prefix the Lua strings used is dropped because the field names here
/// are the AST/JSON field names a text/JSON-frontend author actually
/// wrote.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidateError {
    /// The profile root is not a [`ProfileNode::Spec`]. The frontend
    /// never produces this, but [`validate`] is total.
    #[error("profile root must be a Spec node")]
    NotSpec,

    /// The `Spec` `name` is empty (check 1).
    #[error("profile name must be a non-empty string")]
    EmptyName,

    /// An `env` key is secret-shaped (check 3, case-insensitive
    /// substring match against [`SECRET_KEY_SUBSTRINGS`]).
    #[error("env[{index}] ({name:?}) is secret-shaped; declare it in env_secrets instead")]
    SecretShapedEnvKey {
        /// 1-based position within `env`.
        index: usize,
        /// The offending key.
        name: String,
    },

    /// An `env` / `env_secrets` name is not shell-safe (check 4).
    #[error("{field}[{index}] ({name:?}) is not shell-safe")]
    EnvNameNotShellSafe {
        /// `"env"` or `"env_secrets"`.
        field: &'static str,
        /// 1-based position within the list.
        index: usize,
        /// The offending name.
        name: String,
    },

    /// A `paths` entry is not a `..`-free absolute path (check 5).
    #[error("paths[{index}] ({path:?}) {reason}")]
    PathShape {
        /// 1-based position within `paths`.
        index: usize,
        /// The offending path.
        path: String,
        /// Why the path shape is rejected.
        reason: &'static str,
    },

    /// A `paths` entry is absolute and `..`-free but not shell-safe
    /// (check 5).
    #[error("paths[{index}] ({path:?}) is not shell-safe")]
    PathNotShellSafe {
        /// 1-based position within `paths`.
        index: usize,
        /// The offending path.
        path: String,
    },

    /// A phase payload failed its shell-safety / route-shape walk
    /// (check 6). The message is preformatted as
    /// `phases[<i>].<field>: <reason>` to match the legacy per-field
    /// reporting shape.
    #[error("{0}")]
    PhaseShape(String),

    /// Two `service.start` phases share a `name` (check 7).
    #[error("phases[{index}].name ({name:?}) duplicates another service.start name")]
    DuplicateServiceName {
        /// 1-based position of the duplicate phase.
        index: usize,
        /// The duplicated service name.
        name: String,
    },

    /// An `env`-map [`ProfileNode::EnvSecret`] value names a secret that
    /// is not declared in `Spec.env_secrets` (check 6, spec 06
    /// §`env.ref` "checks `ref.name ∈ env_secrets`"). This check has no
    /// counterpart in the legacy Lua validate — it is a new AST-side
    /// guard enabled by the typed `EnvSecret` value node.
    #[error("phases[{index}].env[{key}]: secret {name:?} is not declared in env_secrets")]
    UndeclaredEnvSecret {
        /// 1-based position of the phase carrying the `env` slot (or
        /// 0 when the offending slot is `Spec.env` itself).
        index: usize,
        /// The `env` map key whose value is the offending secret.
        key: String,
        /// The undeclared secret name.
        name: String,
    },

    /// A `Spec.env` value is neither [`ProfileNode::EnvLiteral`] nor
    /// [`ProfileNode::EnvSecret`] (check 4b). An `EnvRef` value would
    /// loop back into `Spec.env`; any other variant means the author
    /// wrote a phase where a value belongs.
    #[error(
        "Spec.env[{key}]: value must be EnvLiteral or EnvSecret \
         (declaration slot #{index})"
    )]
    SpecEnvValueShape {
        /// 1-based position of the offending declaration (lexicographic
        /// key order, matching the deterministic first-violation
        /// convention).
        index: usize,
        /// The `Spec.env` key whose value is malformed.
        key: String,
    },

    /// A phase-`env` [`ProfileNode::EnvRef`] value names an entry
    /// that does not exist in `Spec.env` (check 6). The resolution
    /// would fail at execution time; catching it here keeps the
    /// validate stage self-contained.
    #[error("phases[{index}].env[{key}]: reference {name:?} not declared in Spec.env")]
    UndeclaredEnvRef {
        /// 1-based position of the phase carrying the `env` slot.
        index: usize,
        /// The `env` map key whose value is the offending reference.
        key: String,
        /// The undeclared reference name.
        name: String,
    },
}

/// Run the seven validate-stage checks against `root`, in order,
/// stopping at the first violation
/// (03-pipeline-stage-artifacts.md §validate).
///
/// Returns `Ok(())` on success; the caller reads the validated name off
/// the `Spec` node itself.
pub fn validate(root: &ProfileNode) -> Result<(), ValidateError> {
    let ProfileNode::Spec {
        name,
        env,
        env_secrets,
        paths,
        phases,
        ..
    } = root
    else {
        return Err(ValidateError::NotSpec);
    };

    // Check 1: name is non-empty. (The Lua `ir.schema` guard is a
    // frontend invariant here — see the module doc.)
    if name.is_empty() {
        return Err(ValidateError::EmptyName);
    }

    // Check 2: the five declared lists are string lists — subsumed by
    // the `Vec<String>` typing; the Lua check imposes no content
    // condition beyond that, so nothing remains to port.

    // Check 3: a secret-shaped key in `Spec.env` must carry an
    // `EnvSecret` value, not an `EnvLiteral`. A literal under a
    // secret-shaped name is the shape a "secret pasted as a plain
    // string" mistake takes — under the old `Vec<String>` shape it was
    // outright rejected because every entry was inherently a plain
    // declaration. Now that `Spec.env` can carry either kind of value,
    // the check refines to the case the original rule actually cared
    // about. BTreeMap iteration is lexicographic so the first
    // violation is deterministic.
    for (idx, (key, value)) in env.iter().enumerate() {
        if is_secret_shaped_key(key) && matches!(value, ProfileNode::EnvLiteral { .. }) {
            return Err(ValidateError::SecretShapedEnvKey {
                index: idx + 1,
                name: key.clone(),
            });
        }
    }

    // Check 4: every `Spec.env` key / `env_secrets` name is shell-safe.
    for (idx, key) in env.keys().enumerate() {
        if !is_shell_safe(key) {
            return Err(ValidateError::EnvNameNotShellSafe {
                field: "env",
                index: idx + 1,
                name: key.clone(),
            });
        }
    }
    for (idx, key) in env_secrets.iter().enumerate() {
        if !is_shell_safe(key) {
            return Err(ValidateError::EnvNameNotShellSafe {
                field: "env_secrets",
                index: idx + 1,
                name: key.clone(),
            });
        }
    }

    // Check 4b: each `Spec.env` value is a value node — `EnvLiteral`
    // or `EnvSecret`. `EnvRef` in `Spec.env` would loop (a reference
    // resolves *into* `Spec.env`); a phase-only variant would mean
    // the profile author declared a phase where a value belongs.
    // An `EnvSecret` value's `name` must appear in `env_secrets`
    // (the same allowlist a phase-inline secret already goes
    // through). We build the set once and reuse it for check 6.
    let declared_secrets: HashSet<&str> = env_secrets.iter().map(String::as_str).collect();
    for (idx, (key, value)) in env.iter().enumerate() {
        match value {
            ProfileNode::EnvLiteral { .. } => {}
            ProfileNode::EnvSecret { name, .. } => {
                if !declared_secrets.contains(name.as_str()) {
                    return Err(ValidateError::UndeclaredEnvSecret {
                        index: idx + 1,
                        key: key.clone(),
                        name: name.clone(),
                    });
                }
            }
            _ => {
                return Err(ValidateError::SpecEnvValueShape {
                    index: idx + 1,
                    key: key.clone(),
                });
            }
        }
    }

    // Check 5: every `paths` entry is absolute, `..`-free, and
    // shell-safe (order mirrors 03 §validate check 5).
    for (idx, p) in paths.iter().enumerate() {
        if let Err(reason) = check_absolute_path_shape(p) {
            return Err(ValidateError::PathShape {
                index: idx + 1,
                path: p.clone(),
                reason,
            });
        }
        if !is_shell_safe(p) {
            return Err(ValidateError::PathNotShellSafe {
                index: idx + 1,
                path: p.clone(),
            });
        }
    }

    // Check 6: per-phase payload shell-safety + sync/staging route shape
    // + `env` keyed-slot checks (keys shell-safe, EnvSecret cross-ref,
    // EnvRef name resolvable against `Spec.env`).
    let declared_env_keys: HashSet<&str> = env.keys().map(String::as_str).collect();
    for (idx, phase) in phases.iter().enumerate() {
        check_phase(phase, idx + 1, &declared_secrets, &declared_env_keys)?;
    }

    // Check 7: service.start names are unique across the profile.
    let mut seen: HashSet<&str> = HashSet::new();
    for (idx, phase) in phases.iter().enumerate() {
        if let ProfileNode::ServiceStart { name, .. } = phase {
            if !seen.insert(name.as_str()) {
                return Err(ValidateError::DuplicateServiceName {
                    index: idx + 1,
                    name: name.clone(),
                });
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------
// Check 3 helper: secret-shaped key.
// ---------------------------------------------------------------------

/// `name` contains any [`SECRET_KEY_SUBSTRINGS`] entry, case-insensitive
/// (03 §validate check 3; the entries are upper-case, so the name is
/// upper-cased for the comparison — mirroring `lm.validate`'s
/// `name:upper()`).
///
/// The same match is what spec 09 §Audit log calls the "sensitive-key"
/// check — the two literal sets spec 02 §Shared vocabulary lists
/// separately (`KEY` / `SECRET` / … in upper case for validate rejection,
/// `key` / `secret` / … in lower case for audit redaction) are the same
/// eight words under case-insensitive substring match. `pub` so the
/// audit path reuses this one function rather than growing a parallel
/// definition that could drift.
pub fn is_secret_shaped_key(name: &str) -> bool {
    let upper = name.to_uppercase();
    SECRET_KEY_SUBSTRINGS
        .iter()
        .any(|substring| upper.contains(substring))
}

// ---------------------------------------------------------------------
// Shell-safety contract (03 §validate "Shell-safety contract").
// ---------------------------------------------------------------------

/// A char is shell-safe iff it is in `[A-Za-z0-9._/@:+=~-]`
/// (`lm.validate`'s `SHELL_SAFE_CLASS`).
fn is_shell_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | ':' | '+' | '=' | '~' | '-')
}

/// A string is shell-safe iff non-empty and every char is
/// [`is_shell_safe_char`] (03 §validate "Shell-safety contract").
fn is_shell_safe(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_shell_safe_char)
}

/// The `{pod_id}`-tolerant shell-safety variant: every `{pod_id}`
/// occurrence is stripped before the charset check, and a string made
/// entirely of placeholder occurrences is accepted (02 §Catalog kinds
/// `sync.push`; mirrors `lm.validate`'s
/// `is_shell_safe_allowing_pod_id_placeholder`).
fn is_shell_safe_allowing_pod_id_placeholder(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let stripped = s.replace(POD_ID_PLACEHOLDER, "");
    if stripped.is_empty() {
        // The whole string was made of placeholder occurrences.
        return true;
    }
    is_shell_safe(&stripped)
}

// ---------------------------------------------------------------------
// Absolute-path shape (check 5, and the `local_path` half of the
// sync.*/staging.* route shape).
// ---------------------------------------------------------------------

/// `Ok(())` when `value` is a non-empty, absolute, `..`-free path, else
/// the first shape violation's reason. Order mirrors 03 §validate check
/// 5's sentence (mirrors `lm.validate`'s `check_absolute_path_shape`).
fn check_absolute_path_shape(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must be a non-empty absolute path");
    }
    if !value.starts_with('/') {
        return Err("must be absolute (leading '/')");
    }
    for segment in value.split('/').filter(|s| !s.is_empty()) {
        if segment == ".." {
            return Err("must not contain a '..' segment");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// sync.*/staging.* route shape (02 §Error surface; mirrors
// `lm.validate`'s `check_uri_route_shape`).
// ---------------------------------------------------------------------

/// `scheme` matches `%a[%w+.-]*` (leading letter, then alphanumerics /
/// `+` / `.` / `-`) — the scheme portion of `lm.validate`'s
/// `URI_SCHEME_PATTERN`.
fn is_uri_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// `Ok(())` when `value` is a `<scheme>://<bucket-or-owner>/<path>` URI
/// with a recognised route scheme, a non-empty bucket and path, and no
/// `..` path segment, else the first violation's reason.
fn check_uri_route_shape(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("must be a non-empty URI".to_string());
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err("must be a <scheme>://<bucket-or-owner>/<path> URI".to_string());
    };
    if !is_uri_scheme(scheme) {
        return Err("must be a <scheme>://<bucket-or-owner>/<path> URI".to_string());
    }
    if !URI_ROUTE_SCHEMES.contains(&scheme) {
        return Err(format!(
            "scheme {scheme:?} is not a recognized sync/staging route scheme"
        ));
    }
    let Some((bucket, path)) = rest.split_once('/') else {
        return Err("missing bucket/owner or path segment".to_string());
    };
    if bucket.is_empty() || path.is_empty() {
        return Err("missing bucket/owner or path segment".to_string());
    }
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        if segment == ".." {
            return Err("must not contain a '..' segment".to_string());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Check 6: per-phase shell-safety + route shape.
// ---------------------------------------------------------------------

/// Which route shape a `sync.*` / `staging.*` `src` / `dst` field must
/// satisfy (`SYNC_ROUTE_SHAPE_BY_KIND` in `lm.validate`).
enum RouteShape {
    /// A remote `b2://` / `hf://` / `https://` route.
    UriRoute,
    /// A local absolute, `..`-free path.
    LocalPath,
}

/// Whether a phase field's shell-safety allows the `{pod_id}`
/// placeholder.
enum PodId {
    Allowed,
    Forbidden,
}

/// Run check 6 for a single phase (1-based `index`). Within a phase the
/// per-field shell-safety walk runs first (in catalog field order), then
/// the `sync.*` / `staging.*` route shape — matching `lm.validate`'s
/// `check_phase_shape` ordering.
fn check_phase(
    phase: &ProfileNode,
    index: usize,
    env_secrets: &HashSet<&str>,
    declared_env_keys: &HashSet<&str>,
) -> Result<(), ValidateError> {
    match phase {
        ProfileNode::SystemApt { packages, .. } => {
            check_list_shell_safe(packages, index, "packages")
        }
        ProfileNode::ComfyUiInstall { ref_name, .. } => {
            check_str_shell_safe(ref_name, index, "ref_name", PodId::Forbidden)
        }
        ProfileNode::PythonDeps { deps, .. } => check_list_shell_safe(deps, index, "deps"),
        ProfileNode::SyncPull { src, dst, env, .. } => {
            check_str_shell_safe(src, index, "src", PodId::Forbidden)?;
            check_str_shell_safe(dst, index, "dst", PodId::Forbidden)?;
            check_route(src, RouteShape::UriRoute, index, "src")?;
            check_route(dst, RouteShape::LocalPath, index, "dst")?;
            check_env_map(env, env_secrets, declared_env_keys, index)
        }
        ProfileNode::SyncPush { src, dst, .. } => {
            check_str_shell_safe(src, index, "src", PodId::Forbidden)?;
            check_str_shell_safe(dst, index, "dst", PodId::Allowed)?;
            check_route(src, RouteShape::LocalPath, index, "src")?;
            check_route(dst, RouteShape::UriRoute, index, "dst")
        }
        ProfileNode::StagingPush { src, dst, env, .. } => {
            check_str_shell_safe(src, index, "src", PodId::Forbidden)?;
            check_str_shell_safe(dst, index, "dst", PodId::Allowed)?;
            check_route(src, RouteShape::LocalPath, index, "src")?;
            check_route(dst, RouteShape::UriRoute, index, "dst")?;
            check_env_map(env, env_secrets, declared_env_keys, index)
        }
        // `service.start`'s `name` has always been shell-safe-checked;
        // `model` and `extra_args` join it now that they reach argv
        // positions on the launch invocation (spec 02 §Kinds with a
        // spawn-and-poll invocation). `port` / `dtype` /
        // `tensor_parallel_size` do not: the numeric pair cannot carry
        // a metacharacter, and `dtype` is checked as a string below.
        ProfileNode::ServiceStart {
            name,
            model,
            dtype,
            extra_args,
            ..
        } => {
            check_str_shell_safe(name, index, "name", PodId::Forbidden)?;
            if let Some(model) = model {
                check_str_shell_safe(model, index, "model", PodId::Forbidden)?;
            }
            if let Some(dtype) = dtype {
                check_str_shell_safe(dtype, index, "dtype", PodId::Forbidden)?;
            }
            check_list_shell_safe(extra_args, index, "extra_args")
        }
        // `comfyui.restart` `extra_args` is marked shell-safe by
        // 02-phase-catalog.md §Catalog kinds: the entries become argv
        // positions on the (still unspecified) restart invocation, so
        // they are checked exactly like `system.apt.packages`.
        ProfileNode::ComfyUiRestart { extra_args, .. } => {
            check_list_shell_safe(extra_args, index, "extra_args")
        }
        ProfileNode::ShExec { env, .. } => {
            check_env_map(env, env_secrets, declared_env_keys, index)
        }
        // `net.http_get` / `net.http_post` `headers` is a keyed slot of
        // value nodes (spec 04, spec 06 consumption point 4): the same
        // admissible-variant / cross-reference rules as an `env` slot,
        // reported under the `headers` field path. Header *names* are
        // checked for shell-safety like `env` keys are — the charset
        // (`[A-Za-z0-9._/@:+=~-]`) is a subset of the RFC 7230 token
        // charset, so a legal header name such as `Content-Type` or
        // `X-Api-Version` passes while a metacharacter-bearing one does
        // not.
        ProfileNode::NetHttpGet { headers, .. } => {
            check_value_map(headers, "headers", env_secrets, declared_env_keys, index)
        }
        ProfileNode::NetHttpPost {
            headers,
            body,
            body_json,
            ..
        } => {
            check_value_map(headers, "headers", env_secrets, declared_env_keys, index)?;
            // The two body forms name different bodies *and* different
            // content types, with no defensible precedence between
            // them, so declaring both is a rejection rather than a
            // silent pick (spec 04 §`net.http_post`).
            if body.is_some() && body_json.is_some() {
                return Err(ValidateError::PhaseShape(format!(
                    "phases[{index}]: body and body_json are mutually exclusive"
                )));
            }
            if let Some(body) = body {
                check_single_value(body, "body", env_secrets, declared_env_keys, index)?;
            }
            Ok(())
        }
        // `fs.write` `content` is a value node (spec 04 §`fs.write`,
        // spec 06 consumption point 3): the same admissible-variant /
        // cross-reference rules as one `env`-map value, minus the key
        // shell-safety (there is no key). The content itself stays
        // free-form — a literal is never shell-safety-checked.
        ProfileNode::FsWrite { content, .. } => {
            check_single_value(content, "content", env_secrets, declared_env_keys, index)
        }
        // Every remaining variant carries no `shell_safe`-marked field,
        // no route shape, and no `env` slot (`hooks.post_install.script`
        // is the escape exemption; ports / JSON-string payloads /
        // free-form content are never shell-safety-checked). See the
        // module doc.
        _ => Ok(()),
    }
}

/// Check an `env` keyed slot (spec 02 `sync.pull` / `staging.push`
/// `env`, spec 04 `sh.exec` `opts.env`):
///
/// 1. every key is shell-safe (mirrors the Lua
///    `check_env_table_field`; keys iterate in `BTreeMap` sorted order
///    so the first violation is deterministic);
/// 2. every [`ProfileNode::EnvSecret`] value names a secret declared in
///    `Spec.env_secrets` (the new AST-side cross-check).
///
/// [`ProfileNode::EnvLiteral`] values carry free-form content and are
/// not value-checked.
fn check_env_map(
    env: &BTreeMap<String, ProfileNode>,
    env_secrets: &HashSet<&str>,
    declared_env_keys: &HashSet<&str>,
    index: usize,
) -> Result<(), ValidateError> {
    for key in env.keys() {
        if !is_shell_safe(key) {
            return Err(ValidateError::PhaseShape(format!(
                "phases[{index}].env[{key}]: key is not shell-safe"
            )));
        }
    }
    for (key, value) in env {
        match value {
            ProfileNode::EnvLiteral { .. } => {}
            ProfileNode::EnvSecret { name, .. } => {
                if !env_secrets.contains(name.as_str()) {
                    return Err(ValidateError::UndeclaredEnvSecret {
                        index,
                        key: key.clone(),
                        name: name.clone(),
                    });
                }
            }
            ProfileNode::EnvRef { name, .. } => {
                if !declared_env_keys.contains(name.as_str()) {
                    return Err(ValidateError::UndeclaredEnvRef {
                        index,
                        key: key.clone(),
                        name: name.clone(),
                    });
                }
            }
            _ => {
                return Err(ValidateError::PhaseShape(format!(
                    "phases[{index}].env[{key}]: value must be EnvLiteral, EnvSecret, or EnvRef"
                )));
            }
        }
    }
    Ok(())
}

/// The admissible-variant / cross-reference rules shared by every value
/// node that sits *outside* an `env` keyed slot: `Some(reason)` when the
/// node is inadmissible, `None` when it checks out. The caller supplies
/// the field path the reason is reported under, which is the only thing
/// that differs between the `fs.write` `content`, `net.http_post`
/// `body`, and `net.http_*` `headers[key]` positions.
///
/// The rules themselves mirror one [`check_env_map`] value:
/// [`ProfileNode::EnvSecret`] must name a declared secret,
/// [`ProfileNode::EnvRef`] must name a `Spec.env` entry, and
/// [`ProfileNode::EnvLiteral`] carries free-form content that is never
/// value-checked.
fn value_node_violation(
    value: &ProfileNode,
    env_secrets: &HashSet<&str>,
    declared_env_keys: &HashSet<&str>,
) -> Option<String> {
    match value {
        ProfileNode::EnvLiteral { .. } => None,
        ProfileNode::EnvSecret { name, .. } => {
            if env_secrets.contains(name.as_str()) {
                None
            } else {
                Some(format!("secret {name:?} is not declared in env_secrets"))
            }
        }
        ProfileNode::EnvRef { name, .. } => {
            if declared_env_keys.contains(name.as_str()) {
                None
            } else {
                Some(format!("reference {name:?} not declared in Spec.env"))
            }
        }
        _ => Some("value must be EnvLiteral, EnvSecret, or EnvRef".to_string()),
    }
}

/// Check one value node occupying a named single slot (`fs.write`
/// `content`, `net.http_post` `body`). Error message shape:
/// `phases[<i>].<field>: <reason>`.
fn check_single_value(
    value: &ProfileNode,
    field: &str,
    env_secrets: &HashSet<&str>,
    declared_env_keys: &HashSet<&str>,
    index: usize,
) -> Result<(), ValidateError> {
    match value_node_violation(value, env_secrets, declared_env_keys) {
        None => Ok(()),
        Some(reason) => Err(ValidateError::PhaseShape(format!(
            "phases[{index}].{field}: {reason}"
        ))),
    }
}

/// Check a keyed slot of value nodes that is *not* the `env` slot
/// (`net.http_*` `headers`): keys must be shell-safe and each value
/// obeys [`value_node_violation`]. Error message shape:
/// `phases[<i>].<field>[<key>]: <reason>`.
///
/// The `env`-slot sibling [`check_env_map`] reports through the typed
/// [`ValidateError::UndeclaredEnvSecret`] / [`ValidateError::UndeclaredEnvRef`]
/// variants instead; those name the `env` slot in their `Display`, so a
/// second slot reports as a [`ValidateError::PhaseShape`] the same way
/// every other per-phase payload violation does.
fn check_value_map(
    map: &BTreeMap<String, ProfileNode>,
    field: &str,
    env_secrets: &HashSet<&str>,
    declared_env_keys: &HashSet<&str>,
    index: usize,
) -> Result<(), ValidateError> {
    // Keys first, then values — the same two-pass order (and therefore
    // the same deterministic first violation) `check_env_map` uses.
    for key in map.keys() {
        if !is_shell_safe(key) {
            return Err(ValidateError::PhaseShape(format!(
                "phases[{index}].{field}[{key}]: key is not shell-safe"
            )));
        }
    }
    for (key, value) in map {
        if let Some(reason) = value_node_violation(value, env_secrets, declared_env_keys) {
            return Err(ValidateError::PhaseShape(format!(
                "phases[{index}].{field}[{key}]: {reason}"
            )));
        }
    }
    Ok(())
}

/// Shell-safety of one string field, honoring the `{pod_id}` exemption
/// when `pod_id` is [`PodId::Allowed`]. Error message shape:
/// `phases[<i>].<field>: is not shell-safe`.
fn check_str_shell_safe(
    value: &str,
    index: usize,
    field: &str,
    pod_id: PodId,
) -> Result<(), ValidateError> {
    let safe = match pod_id {
        PodId::Allowed => is_shell_safe_allowing_pod_id_placeholder(value),
        PodId::Forbidden => is_shell_safe(value),
    };
    if safe {
        Ok(())
    } else {
        Err(ValidateError::PhaseShape(format!(
            "phases[{index}].{field}: is not shell-safe"
        )))
    }
}

/// Shell-safety of a `list<string>` field, entry-wise. Error message
/// shape: `phases[<i>].<field>[<j>]: is not shell-safe` (1-based `<j>`).
fn check_list_shell_safe(
    values: &[String],
    index: usize,
    field: &str,
) -> Result<(), ValidateError> {
    for (entry_idx, entry) in values.iter().enumerate() {
        if !is_shell_safe(entry) {
            return Err(ValidateError::PhaseShape(format!(
                "phases[{index}].{field}[{}]: is not shell-safe",
                entry_idx + 1
            )));
        }
    }
    Ok(())
}

/// Route shape of one `sync.*` / `staging.*` `src` / `dst` field. Error
/// message shape: `phases[<i>].<field>: <reason>`.
fn check_route(
    value: &str,
    shape: RouteShape,
    index: usize,
    field: &str,
) -> Result<(), ValidateError> {
    let result = match shape {
        RouteShape::UriRoute => check_uri_route_shape(value),
        RouteShape::LocalPath => check_absolute_path_shape(value).map_err(|r| r.to_string()),
    };
    result.map_err(|reason| ValidateError::PhaseShape(format!("phases[{index}].{field}: {reason}")))
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    /// Build a `Spec` root wrapping `phases`. `NodeId`s are opaque here.
    fn spec(name: &str, phases: Vec<ProfileNode>) -> ProfileNode {
        spec_full(name, &[], &[], &[], phases)
    }

    /// Build a `Spec` root with explicit declared lists. `env` names
    /// bind to placeholder [`ProfileNode::EnvLiteral`] values —
    /// validate check 3 / 4 look only at keys, so the values are
    /// inert for those tests. Cross-check tests that need a specific
    /// value node build the `Spec` inline.
    fn spec_full(
        name: &str,
        env: &[&str],
        env_secrets: &[&str],
        paths: &[&str],
        phases: Vec<ProfileNode>,
    ) -> ProfileNode {
        let ids = IdGen::new();
        let env_map: BTreeMap<String, ProfileNode> = env
            .iter()
            .map(|s| {
                (
                    (*s).to_string(),
                    ProfileNode::EnvLiteral {
                        id: ids.node(),
                        value: String::new(),
                    },
                )
            })
            .collect();
        ProfileNode::Spec {
            id: ids.node(),
            name: name.into(),
            version: None,
            description: None,
            capabilities: Vec::new(),
            env: env_map,
            env_secrets: env_secrets.iter().map(|s| (*s).to_string()).collect(),
            paths: paths.iter().map(|s| (*s).to_string()).collect(),
            http_allowlist: Vec::new(),
            phases,
        }
    }

    fn ids() -> IdGen {
        IdGen::new()
    }

    // -----------------------------------------------------------------
    // Check 1: root shape + name.
    // -----------------------------------------------------------------

    #[test]
    fn non_spec_root_is_rejected() {
        let g = ids();
        let node = ProfileNode::ShExec {
            id: g.node(),
            argv: vec!["ls".into()],
            env: BTreeMap::new(),
        };
        assert_eq!(validate(&node), Err(ValidateError::NotSpec));
    }

    #[test]
    fn empty_name_is_rejected() {
        assert_eq!(validate(&spec("", vec![])), Err(ValidateError::EmptyName));
    }

    #[test]
    fn a_minimal_named_spec_validates() {
        assert!(validate(&spec("demo", vec![])).is_ok());
    }

    // -----------------------------------------------------------------
    // Check 3: secret-shaped env keys.
    // -----------------------------------------------------------------

    #[test]
    fn secret_shaped_env_key_is_rejected() {
        let node = spec_full("demo", &["HF_TOKEN"], &[], &[], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::SecretShapedEnvKey {
                index: 1,
                name: "HF_TOKEN".into(),
            })
        );
    }

    #[test]
    fn secret_shaped_env_key_match_is_case_insensitive() {
        // lower-case substring still matches the upper-case set.
        let node = spec_full("demo", &["my_password"], &[], &[], vec![]);
        assert!(matches!(
            validate(&node),
            Err(ValidateError::SecretShapedEnvKey { .. })
        ));
    }

    #[test]
    fn each_secret_substring_is_detected() {
        for sub in [
            "KEY", "SECRET", "TOKEN", "PASSWORD", "PWD", "AUTH", "CRED", "APIKEY",
        ] {
            let key = format!("MY_{sub}_X");
            let node = spec_full("demo", &[key.as_str()], &[], &[], vec![]);
            assert!(
                matches!(
                    validate(&node),
                    Err(ValidateError::SecretShapedEnvKey { .. })
                ),
                "substring {sub} must be detected in {key}"
            );
        }
    }

    #[test]
    fn a_non_secret_env_key_passes_check_3() {
        let node = spec_full("demo", &["LOG_LEVEL"], &[], &[], vec![]);
        assert!(validate(&node).is_ok());
    }

    // -----------------------------------------------------------------
    // Check 4: shell-safe env / env_secrets names.
    // -----------------------------------------------------------------

    #[test]
    fn non_shell_safe_env_name_is_rejected() {
        let node = spec_full("demo", &["BAD NAME"], &[], &[], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::EnvNameNotShellSafe {
                field: "env",
                index: 1,
                name: "BAD NAME".into(),
            })
        );
    }

    #[test]
    fn non_shell_safe_env_secret_name_is_rejected() {
        let node = spec_full("demo", &[], &["BAD$SECRET"], &[], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::EnvNameNotShellSafe {
                field: "env_secrets",
                index: 1,
                name: "BAD$SECRET".into(),
            })
        );
    }

    #[test]
    fn check_3_precedes_check_4_on_env() {
        // A secret-shaped AND non-shell-safe env key surfaces the check-3
        // error first (documented ordering).
        let node = spec_full("demo", &["MY TOKEN"], &[], &[], vec![]);
        assert!(matches!(
            validate(&node),
            Err(ValidateError::SecretShapedEnvKey { .. })
        ));
    }

    // -----------------------------------------------------------------
    // Check 5: paths.
    // -----------------------------------------------------------------

    #[test]
    fn relative_path_is_rejected() {
        let node = spec_full("demo", &[], &[], &["workspace/foo"], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::PathShape {
                index: 1,
                path: "workspace/foo".into(),
                reason: "must be absolute (leading '/')",
            })
        );
    }

    #[test]
    fn dotdot_path_is_rejected() {
        let node = spec_full("demo", &[], &[], &["/workspace/../etc"], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::PathShape {
                index: 1,
                path: "/workspace/../etc".into(),
                reason: "must not contain a '..' segment",
            })
        );
    }

    #[test]
    fn empty_path_is_rejected() {
        let node = spec_full("demo", &[], &[], &[""], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::PathShape {
                index: 1,
                path: "".into(),
                reason: "must be a non-empty absolute path",
            })
        );
    }

    #[test]
    fn non_shell_safe_absolute_path_is_rejected() {
        let node = spec_full("demo", &[], &[], &["/work space"], vec![]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::PathNotShellSafe {
                index: 1,
                path: "/work space".into(),
            })
        );
    }

    #[test]
    fn a_clean_absolute_path_passes_check_5() {
        let node = spec_full("demo", &[], &[], &["/workspace/models"], vec![]);
        assert!(validate(&node).is_ok());
    }

    // -----------------------------------------------------------------
    // Check 6: per-phase shell-safety.
    // -----------------------------------------------------------------

    #[test]
    fn non_shell_safe_apt_package_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SystemApt {
                id: g.node(),
                packages: vec!["git".into(), "bad pkg".into()],
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].packages[2]: is not shell-safe".into()
            ))
        );
    }

    #[test]
    fn shell_safe_apt_packages_pass() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SystemApt {
                id: g.node(),
                packages: vec!["git".into(), "curl".into()],
            }],
        );
        assert!(validate(&node).is_ok());
    }

    #[test]
    fn non_shell_safe_comfyui_ref_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::ComfyUiInstall {
                id: g.node(),
                ref_name: "bad ref".into(),
                repo: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].ref_name: is not shell-safe".into()
            ))
        );
    }

    #[test]
    fn comfyui_restart_extra_args_are_shell_safety_checked() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::ComfyUiRestart {
                id: g.node(),
                port: 8188,
                extra_args: vec!["--listen".into(), "; rm -rf /".into()],
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].extra_args[2]: is not shell-safe".into()
            ))
        );
    }

    #[test]
    fn comfyui_restart_accepts_shell_safe_extra_args() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::ComfyUiRestart {
                id: g.node(),
                port: 8188,
                extra_args: vec!["--listen".into(), "--port=9000".into()],
            }],
        );
        assert!(validate(&node).is_ok());
    }

    #[test]
    fn post_install_script_is_exempt_from_shell_safety() {
        // hooks.post_install.script carries arbitrary shell (01 §Escape /
        // fragment policy) — it is never shell-safety-checked.
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::PostInstall {
                id: g.node(),
                script: "echo 'hi there'; rm -rf $TMP".into(),
            }],
        );
        assert!(validate(&node).is_ok());
    }

    #[test]
    fn opaque_json_payloads_are_not_shell_safety_checked() {
        // custom_nodes / models carry an opaque JSON string on the AST;
        // there is no structured inner field to check.
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::CustomNodes {
                id: g.node(),
                nodes_json: "[{\"name\": \"has space\"}]".into(),
            }],
        );
        assert!(validate(&node).is_ok());
    }

    // -----------------------------------------------------------------
    // Check 6: sync/staging route shape.
    // -----------------------------------------------------------------

    #[test]
    fn sync_pull_accepts_a_uri_src_and_absolute_dst() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "b2://bucket/model.bin".into(),
                dst: "/workspace/model.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert!(validate(&node).is_ok());
    }

    #[test]
    fn sync_pull_rejects_a_non_uri_src() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "/local/path".into(),
                dst: "/workspace/model.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].src: must be a <scheme>://<bucket-or-owner>/<path> URI".into()
            ))
        );
    }

    #[test]
    fn sync_pull_rejects_an_unrecognized_scheme() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "s3://bucket/model.bin".into(),
                dst: "/workspace/model.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].src: scheme \"s3\" is not a recognized sync/staging route scheme".into()
            ))
        );
    }

    #[test]
    fn sync_pull_rejects_a_uri_missing_its_path() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "b2://bucket".into(),
                dst: "/workspace/model.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].src: missing bucket/owner or path segment".into()
            ))
        );
    }

    #[test]
    fn sync_pull_rejects_a_dotdot_uri_path() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "b2://bucket/../secret".into(),
                dst: "/workspace/model.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].src: must not contain a '..' segment".into()
            ))
        );
    }

    #[test]
    fn sync_pull_rejects_a_relative_dst() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "b2://bucket/model.bin".into(),
                dst: "relative/dst".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].dst: must be absolute (leading '/')".into()
            ))
        );
    }

    #[test]
    fn sync_push_dst_allows_the_pod_id_placeholder() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPush {
                id: g.node(),
                src: "/workspace/out.bin".into(),
                dst: "b2://bucket/{pod_id}/out.bin".into(),
            }],
        );
        assert!(validate(&node).is_ok());
    }

    #[test]
    fn staging_push_matches_sync_push_shape() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::StagingPush {
                id: g.node(),
                src: "/workspace/stage.bin".into(),
                dst: "hf://owner/repo/stage.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert!(validate(&node).is_ok());
    }

    #[test]
    fn sync_push_rejects_a_non_uri_dst() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPush {
                id: g.node(),
                src: "/workspace/out.bin".into(),
                dst: "/not/a/uri".into(),
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].dst: must be a <scheme>://<bucket-or-owner>/<path> URI".into()
            ))
        );
    }

    #[test]
    fn shell_safety_precedes_route_shape_within_a_phase() {
        // A src that is both non-shell-safe and a bad route surfaces the
        // shell-safety error first (documented per-phase ordering).
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "not a uri".into(),
                dst: "/workspace/model.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].src: is not shell-safe".into()
            ))
        );
    }

    // -----------------------------------------------------------------
    // Check 7: service.start name uniqueness.
    // -----------------------------------------------------------------

    #[test]
    fn duplicate_service_start_names_are_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc".into(),
                    platform_kind: "vllm".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc".into(),
                    platform_kind: "ollama".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
            ],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::DuplicateServiceName {
                index: 2,
                name: "svc".into(),
            })
        );
    }

    #[test]
    fn distinct_service_start_names_pass() {
        let g = ids();
        let node = spec(
            "demo",
            vec![
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc-a".into(),
                    platform_kind: "vllm".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc-b".into(),
                    platform_kind: "ollama".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
            ],
        );
        assert!(validate(&node).is_ok());
    }

    // -----------------------------------------------------------------
    // Check 6: env keyed-slot (keys shell-safe + EnvSecret cross-ref).
    // -----------------------------------------------------------------

    fn env_of(entries: &[(&str, ProfileNode)]) -> BTreeMap<String, ProfileNode> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn env_secret_declared_in_env_secrets_passes() {
        let g = ids();
        let env = env_of(&[(
            "HF_TOKEN",
            ProfileNode::EnvSecret {
                id: g.node(),
                name: "HF_TOKEN".into(),
            },
        )]);
        let node = spec_full(
            "demo",
            &[],
            &["HF_TOKEN"],
            &[],
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "hf://owner/repo/m.bin".into(),
                dst: "/workspace/m.bin".into(),
                env,
                revision: Some("main".into()),
            }],
        );
        assert!(validate(&node).is_ok(), "{:?}", validate(&node));
    }

    #[test]
    fn env_secret_not_declared_in_env_secrets_is_rejected() {
        let g = ids();
        let env = env_of(&[(
            "TOKEN",
            ProfileNode::EnvSecret {
                id: g.node(),
                name: "UNDECLARED".into(),
            },
        )]);
        let node = spec_full(
            "demo",
            &[],
            &[],
            &[],
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "hf://owner/repo/m.bin".into(),
                dst: "/workspace/m.bin".into(),
                env,
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::UndeclaredEnvSecret {
                index: 1,
                key: "TOKEN".into(),
                name: "UNDECLARED".into(),
            })
        );
    }

    // -----------------------------------------------------------------
    // Check 6: `fs.write` content value node (spec 06 consumption
    // point 3 — same admissible variants / cross-refs as an env value).
    // -----------------------------------------------------------------

    fn fs_write_with(content: ProfileNode, g: &IdGen) -> ProfileNode {
        ProfileNode::FsWrite {
            id: g.node(),
            path: "/workspace/x".into(),
            content: Box::new(content),
        }
    }

    #[test]
    fn fs_write_literal_and_declared_secret_and_ref_content_pass() {
        let g = ids();
        let node = spec_full(
            "demo",
            &["MODEL_DIR"],
            &["HF_TOKEN"],
            &[],
            vec![
                fs_write_with(
                    ProfileNode::EnvLiteral {
                        id: g.node(),
                        value: "free-form; not shell-checked $(ok)".into(),
                    },
                    &g,
                ),
                fs_write_with(
                    ProfileNode::EnvSecret {
                        id: g.node(),
                        name: "HF_TOKEN".into(),
                    },
                    &g,
                ),
                fs_write_with(
                    ProfileNode::EnvRef {
                        id: g.node(),
                        name: "MODEL_DIR".into(),
                    },
                    &g,
                ),
            ],
        );
        assert!(validate(&node).is_ok(), "{:?}", validate(&node));
    }

    #[test]
    fn fs_write_undeclared_secret_content_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![fs_write_with(
                ProfileNode::EnvSecret {
                    id: g.node(),
                    name: "UNDECLARED".into(),
                },
                &g,
            )],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].content: secret \"UNDECLARED\" is not declared in env_secrets".into()
            ))
        );
    }

    #[test]
    fn fs_write_ref_content_to_an_undeclared_spec_env_key_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![fs_write_with(
                ProfileNode::EnvRef {
                    id: g.node(),
                    name: "MISSING".into(),
                },
                &g,
            )],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].content: reference \"MISSING\" not declared in Spec.env".into()
            ))
        );
    }

    #[test]
    fn fs_write_non_value_node_content_is_rejected() {
        let g = ids();
        let inner = ProfileNode::MountUmount {
            id: g.node(),
            path: "/x".into(),
        };
        let node = spec("demo", vec![fs_write_with(inner, &g)]);
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].content: value must be EnvLiteral, EnvSecret, or EnvRef".into()
            ))
        );
    }

    // -----------------------------------------------------------------
    // Check 6: `net.http_*` headers / body value nodes (spec 06
    // consumption point 4) + the `body` / `body_json` exclusivity rule.
    // -----------------------------------------------------------------

    fn http_post_with(
        headers: &[(&str, ProfileNode)],
        body: Option<ProfileNode>,
        body_json: Option<&str>,
        g: &IdGen,
    ) -> ProfileNode {
        ProfileNode::NetHttpPost {
            id: g.node(),
            url: "https://example.com/post".into(),
            headers: env_of(headers),
            body: body.map(Box::new),
            body_json: body_json.map(str::to_string),
            timeout_sec: None,
        }
    }

    #[test]
    fn http_headers_and_body_accept_literals_declared_secrets_and_refs() {
        let g = ids();
        let node = spec_full(
            "demo",
            &["MODEL_DIR"],
            &["API_TOKEN"],
            &[],
            vec![
                ProfileNode::NetHttpGet {
                    id: g.node(),
                    url: "https://example.com/get".into(),
                    headers: env_of(&[
                        (
                            "Accept",
                            ProfileNode::EnvLiteral {
                                id: g.node(),
                                value: "application/json".into(),
                            },
                        ),
                        (
                            "Authorization",
                            ProfileNode::EnvSecret {
                                id: g.node(),
                                name: "API_TOKEN".into(),
                            },
                        ),
                        (
                            "X-Model-Dir",
                            ProfileNode::EnvRef {
                                id: g.node(),
                                name: "MODEL_DIR".into(),
                            },
                        ),
                    ]),
                    timeout_sec: Some(5),
                },
                http_post_with(
                    &[],
                    Some(ProfileNode::EnvSecret {
                        id: g.node(),
                        name: "API_TOKEN".into(),
                    }),
                    None,
                    &g,
                ),
                http_post_with(&[], None, Some("{\"k\":1}"), &g),
            ],
        );
        assert!(validate(&node).is_ok(), "{:?}", validate(&node));
    }

    #[test]
    fn http_header_naming_an_undeclared_secret_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![http_post_with(
                &[(
                    "Authorization",
                    ProfileNode::EnvSecret {
                        id: g.node(),
                        name: "UNDECLARED".into(),
                    },
                )],
                None,
                None,
                &g,
            )],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].headers[Authorization]: secret \"UNDECLARED\" \
                 is not declared in env_secrets"
                    .into()
            ))
        );
    }

    #[test]
    fn http_header_referencing_an_undeclared_spec_env_key_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![ProfileNode::NetHttpGet {
                id: g.node(),
                url: "https://example.com/get".into(),
                headers: env_of(&[(
                    "X-Missing",
                    ProfileNode::EnvRef {
                        id: g.node(),
                        name: "MISSING".into(),
                    },
                )]),
                timeout_sec: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].headers[X-Missing]: reference \"MISSING\" not declared in Spec.env"
                    .into()
            ))
        );
    }

    #[test]
    fn non_shell_safe_http_header_name_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![http_post_with(
                &[(
                    "Bad Header",
                    ProfileNode::EnvLiteral {
                        id: g.node(),
                        value: "v".into(),
                    },
                )],
                None,
                None,
                &g,
            )],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].headers[Bad Header]: key is not shell-safe".into()
            ))
        );
    }

    #[test]
    fn declaring_both_body_forms_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![http_post_with(
                &[],
                Some(ProfileNode::EnvLiteral {
                    id: g.node(),
                    value: "raw".into(),
                }),
                Some("{\"k\":1}"),
                &g,
            )],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1]: body and body_json are mutually exclusive".into()
            ))
        );
    }

    #[test]
    fn http_body_naming_an_undeclared_secret_is_rejected() {
        let g = ids();
        let node = spec(
            "demo",
            vec![http_post_with(
                &[],
                Some(ProfileNode::EnvSecret {
                    id: g.node(),
                    name: "UNDECLARED".into(),
                }),
                None,
                &g,
            )],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].body: secret \"UNDECLARED\" is not declared in env_secrets".into()
            ))
        );
    }

    /// A header value carrying free-form content is never
    /// shell-safety-checked (only the *name* is), matching the
    /// `env`-slot rule.
    #[test]
    fn http_header_literal_value_is_not_content_checked() {
        let g = ids();
        let node = spec(
            "demo",
            vec![http_post_with(
                &[(
                    "X-Note",
                    ProfileNode::EnvLiteral {
                        id: g.node(),
                        value: "free form; $(not shell checked)".into(),
                    },
                )],
                None,
                None,
                &g,
            )],
        );
        assert!(validate(&node).is_ok(), "{:?}", validate(&node));
    }

    #[test]
    fn non_shell_safe_env_key_is_rejected() {
        let g = ids();
        let env = env_of(&[(
            "BAD KEY",
            ProfileNode::EnvLiteral {
                id: g.node(),
                value: "v".into(),
            },
        )]);
        let node = spec_full(
            "demo",
            &[],
            &[],
            &[],
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "hf://owner/repo/m.bin".into(),
                dst: "/workspace/m.bin".into(),
                env,
                revision: None,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::PhaseShape(
                "phases[1].env[BAD KEY]: key is not shell-safe".into()
            ))
        );
    }

    #[test]
    fn env_literal_value_is_not_content_checked() {
        // EnvLiteral carries free-form content — a value that would be
        // rejected as a name still passes (only keys / secret names are
        // checked).
        let g = ids();
        let env = env_of(&[(
            "LOG_FMT",
            ProfileNode::EnvLiteral {
                id: g.node(),
                value: "has spaces & $pecial".into(),
            },
        )]);
        let node = spec_full(
            "demo",
            &[],
            &[],
            &[],
            vec![ProfileNode::ShExec {
                id: g.node(),
                argv: vec!["echo".into()],
                env,
            }],
        );
        assert!(validate(&node).is_ok(), "{:?}", validate(&node));
    }

    #[test]
    fn sh_exec_env_secret_cross_check_applies() {
        let g = ids();
        let env = env_of(&[(
            "API_KEY",
            ProfileNode::EnvSecret {
                id: g.node(),
                name: "API_KEY".into(),
            },
        )]);
        let node = spec_full(
            "demo",
            &[],
            &[],
            &[],
            vec![ProfileNode::ShExec {
                id: g.node(),
                argv: vec!["run".into()],
                env,
            }],
        );
        assert_eq!(
            validate(&node),
            Err(ValidateError::UndeclaredEnvSecret {
                index: 1,
                key: "API_KEY".into(),
                name: "API_KEY".into(),
            })
        );
    }

    // -----------------------------------------------------------------
    // A broad happy-path profile.
    // -----------------------------------------------------------------

    #[test]
    fn a_broad_valid_profile_validates() {
        let g = ids();
        let node = spec_full(
            "demo",
            &["LOG_LEVEL"],
            &["HF_TOKEN"],
            &["/workspace", "/data"],
            vec![
                ProfileNode::SystemApt {
                    id: g.node(),
                    packages: vec!["git".into(), "curl".into()],
                },
                ProfileNode::ComfyUiInstall {
                    id: g.node(),
                    ref_name: "abc123".into(),
                    repo: Some("comfyanonymous/ComfyUI".into()),
                },
                ProfileNode::PythonDeps {
                    id: g.node(),
                    deps: vec!["torch".into(), "vllm".into()],
                    in_comfy_venv: false,
                },
                ProfileNode::SyncPull {
                    id: g.node(),
                    src: "b2://bucket/model.bin".into(),
                    dst: "/workspace/model.bin".into(),
                    env: BTreeMap::new(),
                    revision: None,
                },
                ProfileNode::PostInstall {
                    id: g.node(),
                    script: "echo 'done'".into(),
                },
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "vllm-svc".into(),
                    platform_kind: "vllm".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ShExec {
                    id: g.node(),
                    argv: vec!["ls".into(), "-la".into()],
                    env: BTreeMap::new(),
                },
            ],
        );
        assert!(validate(&node).is_ok(), "{:?}", validate(&node));
    }
}
