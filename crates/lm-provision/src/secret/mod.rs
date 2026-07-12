//! Secret handling (06-secret-handling.md): the `SecretRef` opacity
//! contract.
//!
//! M1-3 ships [`SecretRef`] itself and the `env.ref` factory that
//! constructs it ([`crate::bridge::env_ref`]). Host-thread resolution and
//! the three bridge consumption points (`sh.exec` `opts.env`,
//! `net.transfer` `opts.auth_bearer`, `fs.write` `content` —
//! 06 §Inputs "Consumption points") land in milestone M3 alongside the
//! bridges that consume a `SecretRef`; [`resolve`] is the one
//! check-then-resolve implementation every consumption point shares
//! (milestone M3-2 first wired it inline inside
//! [`crate::bridge::sh`]; M3-3's [`crate::bridge::net`] `auth_bearer`
//! consumption point is the second, moving the shared logic here rather
//! than duplicating it — 06 §Stability: "The consumption-point set:
//! provisional — new bridges may join, each adopting the identical
//! check-then-resolve protocol").

mod secret_ref;

use std::collections::HashSet;

pub use secret_ref::SecretRef;

/// The check-then-resolve protocol every `SecretRef` consumption point
/// runs (06-secret-handling.md §Inputs "Consumption points"): `name` must
/// be a member of the profile's declared `env_secrets` allowlist, then
/// the value is read from the host process environment on the host
/// thread (06 §Resolution — host-thread only). Never returns the value
/// to a caller that would hand it back to Lua as anything other than the
/// one effectful sink each bridge flows it into (child process env,
/// `Authorization: Bearer` header, file bytes).
///
/// Returns the literal errors 06-secret-handling.md §Error surface
/// names: `secret 'NAME' is not declared in profile.env_secrets` when
/// undeclared, `secret 'NAME' missing in host env` when declared but
/// absent (fail-fast, including under `opts.dry_run` — the caller is
/// expected to run this during opts decoding, before checking
/// `dry_run`).
pub fn resolve(name: &str, env_secrets: &HashSet<String>) -> mlua::Result<String> {
    if !env_secrets.contains(name) {
        return Err(mlua::Error::RuntimeError(format!(
            "secret '{name}' is not declared in profile.env_secrets"
        )));
    }
    std::env::var(name)
        .map_err(|_| mlua::Error::RuntimeError(format!("secret '{name}' missing in host env")))
}
