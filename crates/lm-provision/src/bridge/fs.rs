//! `fs.write` bridge (04-bridge.md §Outputs `fs.write`; milestone M3-4).
//!
//! [`install`] registers the profile-visible `fs.write(path, content,
//! opts)` primitive. Every call re-checks the capability gate at entry
//! (04-bridge.md §Common conventions: "Every bridge re-checks the
//! capability gate at entry (defence in depth over the register
//! skip)"), validates `path` against the L3 path policy
//! (05-sandbox-layer-contract.md §L3 "Path policy"), and — for a
//! `content` value that is a `SecretRef` — runs the same
//! check-then-resolve protocol `sh.exec` `opts.env` and `net.transfer`
//! `opts.auth_bearer` already share via [`crate::secret::resolve`]
//! (06-secret-handling.md §Inputs "Consumption points": the complete set
//! is `sh.exec` `opts.env`, `net.transfer` `opts.auth_bearer`, `fs.write`
//! `content`).
//!
//! Unlike `sh.exec` / `net.*`, an I/O failure here is a Lua error rather
//! than an `ok = false` result table (04-bridge.md §Outputs `fs.write`:
//! "I/O failures are Lua errors (surfaced by apply as step failure
//! text)") — this bridge opts out of the general "effect failures are
//! result tables" convention (04 §Common conventions) for that one
//! class of error.

use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mlua::{Lua, Table, Value};

use crate::sandbox::capgate::CapabilityGate;
use crate::sandbox::policy::PathPolicy;
use crate::secret::SecretRef;

/// The capability name this bridge installs under
/// (05-sandbox-layer-contract.md §L4 `KNOWN_CAPABILITIES`).
pub const CAPABILITY: &str = "fs.write";

/// `opts.mode` default: Unix file mode `0o644` (04-bridge.md §Outputs
/// `fs.write`: "default 0o644").
const DEFAULT_MODE: u32 = 0o644;

/// Register `fs.write` on `lua`'s `fs` global table.
///
/// Callers are expected to reach this only through
/// [`crate::sandbox::capgate::register_if_granted`] (04-bridge.md
/// §Registration order step 8's register-skip half) — `gate` is passed
/// in anyway and re-checked on every call, because 04 §Common
/// conventions requires every bridge to re-verify the gate at entry as
/// defence in depth over the register skip, not rely on the register
/// skip alone (the same convention [`crate::bridge::sh::install`]
/// documents).
///
/// `env_secrets` is the profile's declared `env_secrets` allowlist
/// ([`crate::vm::eval::Declarations::env_secrets`]) — the set a
/// `content` `SecretRef` value is checked against before host-thread
/// resolution (06-secret-handling.md §Inputs "Consumption points").
pub fn install(
    lua: &Lua,
    gate: CapabilityGate,
    path_policy: PathPolicy,
    env_secrets: Vec<String>,
) -> mlua::Result<()> {
    let env_secrets: HashSet<String> = env_secrets.into_iter().collect();
    let write_fn = lua.create_function(
        move |lua, (path, content, opts): (String, Value, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY).map_err(cap_error)?;
            write_entry(lua, &path, content, opts, &path_policy, &env_secrets)
        },
    )?;

    let fs_table = match lua.globals().get::<Option<Table>>("fs")? {
        Some(table) => table,
        None => {
            let table = lua.create_table()?;
            lua.globals().set("fs", table.clone())?;
            table
        }
    };
    fs_table.set("write", write_fn)?;
    Ok(())
}

/// Map any `Display`-able error (`CapGateError`, `PathPolicyError`) onto
/// the Lua-error convention 04-bridge.md §Common conventions requires
/// for "usage, policy, and secret errors" — the same helper
/// [`crate::bridge::net`] and [`crate::bridge::sh`] each already define
/// for their own bridge functions (no shared cross-module accessor
/// exists yet, and three call sites do not justify inventing one).
fn cap_error(err: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(err.to_string())
}

/// Decoded `fs.write` `opts` (04-bridge.md §Outputs `fs.write`).
struct WriteOpts {
    mode: u32,
    append: bool,
    mkdir_p: bool,
    dry_run: bool,
}

fn decode_opts(opts: Option<Table>) -> mlua::Result<WriteOpts> {
    let Some(opts) = opts else {
        return Ok(WriteOpts {
            mode: DEFAULT_MODE,
            append: false,
            mkdir_p: false,
            dry_run: false,
        });
    };
    let mode = opts
        .get::<Option<i64>>("mode")?
        .map(|mode| mode as u32)
        .unwrap_or(DEFAULT_MODE);
    let append = opts.get::<Option<bool>>("append")?.unwrap_or(false);
    let mkdir_p = opts.get::<Option<bool>>("mkdir_p")?.unwrap_or(false);
    let dry_run = opts.get::<Option<bool>>("dry_run")?.unwrap_or(false);
    Ok(WriteOpts {
        mode,
        append,
        mkdir_p,
        dry_run,
    })
}

/// `content`: `string`, or `SecretRef` (declared-secret check-then-resolve,
/// 06-secret-handling.md §Inputs "Consumption points"), sharing
/// [`crate::secret::resolve`] with `sh.exec` `opts.env` and
/// `net.transfer` `opts.auth_bearer` rather than duplicating the
/// protocol a third time.
fn decode_content(content: Value, env_secrets: &HashSet<String>) -> mlua::Result<Vec<u8>> {
    match content {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        Value::UserData(ud) if ud.is::<SecretRef>() => {
            let name = ud.borrow::<SecretRef>()?.name().to_string();
            let resolved = crate::secret::resolve(&name, env_secrets)?;
            Ok(resolved.into_bytes())
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "fs.write: content must be a string or SecretRef, got {}",
            other.type_name()
        ))),
    }
}

/// The audit-line `content_source` for `content` (09-apply-report-and
/// -ledger.md §Audit log "fs.write": "the string `\"string\"` for
/// literal content or `\"secret:<name>\"` when a SecretRef wrote the
/// file"). Peeks at `content`'s shape only — it never resolves a
/// `SecretRef` (that stays [`decode_content`]'s job) and raises the
/// identical error [`decode_content`] would for any other value, so a
/// content value this crate would reject never gets an audit line
/// emitted for it either.
fn content_source(content: &Value) -> mlua::Result<String> {
    match content {
        Value::String(_) => Ok("string".to_string()),
        Value::UserData(ud) if ud.is::<SecretRef>() => {
            let name = ud.borrow::<SecretRef>()?.name().to_string();
            Ok(format!("secret:{name}"))
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "fs.write: content must be a string or SecretRef, got {}",
            other.type_name()
        ))),
    }
}

/// `fs.write(path, content, opts) -> result` (04-bridge.md §Outputs
/// `fs.write`).
fn write_entry(
    lua: &Lua,
    path: &str,
    content: Value,
    opts: Option<Table>,
    path_policy: &PathPolicy,
    env_secrets: &HashSet<String>,
) -> mlua::Result<Table> {
    // 04 §Outputs `fs.write`: "path must be absolute and under a
    // declared paths root (Lua error otherwise)."
    path_policy.check(path).map_err(cap_error)?;
    // Decoding, the policy check above, and secret resolution below all
    // run unconditionally, before `opts.dry_run` is even read — 04
    // §Common conventions: "Dry-run therefore still fails on policy
    // violations and missing secrets ... it validates everything except
    // the effect itself."
    let source = content_source(&content)?;
    let bytes = decode_content(content, env_secrets)?;
    let opts = decode_opts(opts)?;

    // Audit line before the effect (09-apply-report-and-ledger.md
    // §Audit log "fs.write"): path + byte count + content_source —
    // content bytes are never logged.
    crate::audit::fs_write(path, bytes.len(), &source);

    if opts.dry_run {
        return build_result(lua, true, 0, true);
    }

    if opts.mkdir_p {
        ensure_parent_dirs(path_policy, Path::new(path))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(opts.append)
        .truncate(!opts.append)
        .mode(opts.mode)
        .open(path)
        .map_err(|err| {
            mlua::Error::RuntimeError(format!("fs.write: failed opening '{path}': {err}"))
        })?;
    file.write_all(&bytes).map_err(|err| {
        mlua::Error::RuntimeError(format!("fs.write: failed writing '{path}': {err}"))
    })?;

    build_result(lua, true, bytes.len() as i64, false)
}

/// Create every missing ancestor directory of `path`, checking each one
/// against `path_policy` before creating it (04-bridge.md §Outputs
/// `fs.write`: "`mkdir_p` (default false; every created ancestor is
/// itself path-gated)"). Only directories that do not already exist are
/// collected and checked — an ancestor that already exists is not being
/// "created", so it is never gated here; the walk stops the moment it
/// reaches one (at the latest, the filesystem root, which always
/// exists). `path` itself has already passed [`PathPolicy::check`] by
/// the time this runs, so this loop is the literal defence-in-depth 04
/// calls for rather than a path that can newly diverge from `path`'s own
/// already-checked root.
fn ensure_parent_dirs(path_policy: &PathPolicy, path: &Path) -> mlua::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut to_create: Vec<PathBuf> = Vec::new();
    let mut current = Some(parent);
    while let Some(dir) = current {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        to_create.push(dir.to_path_buf());
        current = dir.parent();
    }

    for ancestor in &to_create {
        path_policy
            .check(&ancestor.to_string_lossy())
            .map_err(cap_error)?;
    }

    std::fs::create_dir_all(parent).map_err(|err| {
        mlua::Error::RuntimeError(format!(
            "fs.write: failed creating parent directories for '{}': {err}",
            path.display()
        ))
    })
}

/// `{ ok, bytes, dry_run }` (04-bridge.md §Outputs `fs.write` "Result").
fn build_result(lua: &Lua, ok: bool, bytes: i64, dry_run: bool) -> mlua::Result<Table> {
    let result = lua.create_table()?;
    result.set("ok", ok)?;
    result.set("bytes", bytes)?;
    result.set("dry_run", dry_run)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_content_accepts_a_plain_string() {
        let lua = Lua::new();
        let value: Value = lua.load("return 'hello'").eval().expect("string literal");
        let bytes = decode_content(value, &HashSet::new()).expect("plain string should decode");
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn decode_content_rejects_a_non_string_non_secret_value() {
        let lua = Lua::new();
        let value: Value = lua.load("return 42").eval().expect("number literal");
        let err = decode_content(value, &HashSet::new())
            .expect_err("a number is neither a string nor a SecretRef");
        assert!(err
            .to_string()
            .contains("content must be a string or SecretRef"));
    }

    #[test]
    fn content_source_reports_string_for_a_plain_string_value() {
        let lua = Lua::new();
        let value: Value = lua.load("return 'hello'").eval().expect("string literal");
        assert_eq!(content_source(&value).expect("string content"), "string");
    }

    #[test]
    fn content_source_reports_secret_name_for_a_secret_ref_value() {
        let lua = Lua::new();
        lua.globals()
            .set("ref", crate::secret::SecretRef::new("HF_TOKEN"))
            .expect("set global");
        let value: Value = lua.load("return ref").eval().expect("SecretRef global");
        assert_eq!(
            content_source(&value).expect("SecretRef content"),
            "secret:HF_TOKEN"
        );
    }

    #[test]
    fn content_source_rejects_a_non_string_non_secret_value() {
        let lua = Lua::new();
        let value: Value = lua.load("return 42").eval().expect("number literal");
        let err = content_source(&value).expect_err("a number is neither a string nor a SecretRef");
        assert!(err
            .to_string()
            .contains("content must be a string or SecretRef"));
    }
}
