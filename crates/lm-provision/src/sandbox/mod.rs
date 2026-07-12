//! The four-layer sandbox (05-sandbox-layer-contract.md) that gates
//! every Lua execution.
//!
//! - [`isolation`] — L2, execution-control isolation (dedicated VM
//!   thread, strings-only boundary, cooperative cancellation).
//! - [`policy`] — L3, the declaration-derived env / HTTP / path
//!   allowlists.
//! - [`capgate`] — L4, the operation-level capability gate.
//! - [`catalog`] — the 1-SoT accessors both [`policy`] and [`capgate`]
//!   use to read `lm.catalog_data` (`KNOWN_CAPABILITIES`, the
//!   secret-key substring set) rather than hardcoding a second, drifting
//!   copy of either.
//!
//! [`wire_sandboxed_profile`] performs registration order steps 6-8
//! (04-bridge.md §Registration order) on top of the steps 1-5 an
//! [`ExtractedProfile`] already completed
//! ([`crate::vm::eval::evaluate_profile_source`] /
//! [`crate::vm::eval::evaluate_profile_file`]). Step 8 (cap-gated bridge
//! registration) installs [`crate::bridge::sh`]'s `sh.exec` (milestone
//! M3-2), [`crate::bridge::net`]'s `net.http_get` / `net.http_post` /
//! `net.transfer` (milestone M3-3), and [`crate::bridge::fs`]'s
//! `fs.write` plus [`crate::bridge::mount`]'s `mount.bind` /
//! `mount.umount` (milestone M3-4) via [`capgate::register_if_granted`].
//! The defer-pattern security guarantee 04 §Registration order describes
//! ("during steps 4–5 no batteries primitive and no bridge exists ... a
//! profile that reaches for one dies with `attempt to call a nil
//! value`") continues to hold for every operation a profile does not
//! declare, exactly as [`crate::vm::eval`]'s own doc comment already
//! notes for steps 1-5.

pub mod capgate;
pub mod catalog;
pub mod isolation;
pub mod policy;

use thiserror::Error;

use crate::bridge::{fs, mount, net, sh};
use crate::vm::eval::ExtractedProfile;
use capgate::{CapGateError, CapabilityGate};
use policy::{EnvPolicy, HttpPolicy, PathPolicy};

/// Errors raised while wiring the L3 policies and L4 capability gate
/// onto an already-[`ExtractedProfile`].
#[derive(Debug, Error)]
pub enum SandboxError {
    /// L4 capability gate build failed (05 §L4 load-time fail-fast).
    #[error(transparent)]
    CapGate(#[from] CapGateError),

    /// A Lua error surfaced while reading `lm.catalog_data` or wiring
    /// `env.get` / `env.set` onto the VM.
    #[error("lua error while wiring sandbox layers: {0}")]
    Lua(#[from] mlua::Error),
}

/// The result of registration order steps 1-7: an [`ExtractedProfile`]
/// (steps 1-5) plus the L3 policies and L4 capability gate built from
/// its declarations (steps 6-7).
///
/// Step 8 (cap-gated bridge registration) runs inside
/// [`wire_sandboxed_profile`] itself for `sh.exec` (milestone M3-2, via
/// [`capgate::register_if_granted`], the register-skip half of L4);
/// `net` / `fs` / `mount` land in milestones M3-3..M3-4 and register the
/// same way. `env_policy` / `http_policy` / `path_policy` remain
/// available here for those later bridges to gate their own arguments
/// (L3 stacks under L4, 05 §L4: "L4 grants the operation, L3 still
/// constrains its arguments") — `sh.exec` itself consults none of the
/// three (04-bridge.md §Outputs `sh.exec` names no env / http / path
/// policy dependency).
pub struct SandboxedProfile {
    /// Steps 1-5: the sandboxed VM, the IR, and the six extracted
    /// declarations.
    pub extracted: ExtractedProfile,
    /// L3 env policy, and the live `env.get` / `env.set` Lua bindings
    /// on `extracted.lua`'s `env` global (registration order step 6).
    pub env_policy: EnvPolicy,
    /// L3 HTTP policy, consumed internally by the `net.*` bridges
    /// (milestone M3-3) — no Lua-facing surface of its own.
    pub http_policy: HttpPolicy,
    /// L3 path policy, consumed internally by the `fs.*` / `mount.*`
    /// bridges (milestone M3-4) — no Lua-facing surface of its own.
    pub path_policy: PathPolicy,
    /// L4 capability gate (registration order step 7).
    pub capability_gate: CapabilityGate,
}

/// Wire registration order steps 6-8 onto an already-evaluated profile.
///
/// `extracted` must already have completed steps 1-5
/// ([`crate::vm::eval::evaluate_profile_source`] /
/// [`crate::vm::eval::evaluate_profile_file`]); this function does not
/// re-evaluate the profile body.
pub fn wire_sandboxed_profile(
    extracted: ExtractedProfile,
) -> Result<SandboxedProfile, SandboxError> {
    let secret_key_substrings = catalog::secret_key_substrings(&extracted.lua)?;
    let env_policy = EnvPolicy::new(
        &extracted.declarations.env,
        &extracted.declarations.env_secrets,
        &secret_key_substrings,
    );

    // Audit redaction (09-apply-report-and-ledger.md §Inputs "the
    // sensitive-key substring set") reads a distinct literal set from
    // the validate-stage `SECRET_KEY_SUBSTRINGS` above — see
    // `crate::sandbox::catalog::sensitive_key_substrings`'s own doc
    // comment. `sh.exec` is the one bridge that logs `(key, ...)` pairs
    // (its `opts.env`), so it is the one bridge this gets threaded into.
    let sensitive_key_substrings = catalog::sensitive_key_substrings(&extracted.lua)?;
    // Step 6: env.get / env.set, gated by env_policy, onto the `env`
    // global env_ref::install (step 3) already registered.
    policy::install_env_get_set(&extracted.lua, env_policy.clone())?;

    let http_policy = HttpPolicy::new(&extracted.declarations.http_allowlist);
    let path_policy = PathPolicy::new(&extracted.declarations.paths);

    // Step 7: capability gate build + assert-all-implemented.
    let capability_gate =
        CapabilityGate::build(&extracted.lua, &extracted.declarations.capabilities)?;

    // Step 8: cap-gated bridge registration — only declared operations
    // are installed (register skip). `sh.exec` (M3-2), `net.*` (M3-3),
    // and `fs.write` / `mount.*` (M3-4) all register the same way.
    capgate::register_if_granted(&extracted.lua, &capability_gate, sh::CAPABILITY, |lua| {
        sh::install(
            lua,
            capability_gate.clone(),
            extracted.declarations.env_secrets.clone(),
            sensitive_key_substrings.clone(),
        )
    })?;

    // `net.http_get` / `net.http_post` / `net.transfer` are three
    // separate `KNOWN_CAPABILITIES` entries (05 §L4), so each gets its
    // own register_if_granted call rather than being gated as one unit
    // (crate::bridge::net's own doc comment).
    capgate::register_if_granted(
        &extracted.lua,
        &capability_gate,
        net::CAPABILITY_HTTP_GET,
        |lua| net::install_http_get(lua, capability_gate.clone(), http_policy.clone()),
    )?;
    capgate::register_if_granted(
        &extracted.lua,
        &capability_gate,
        net::CAPABILITY_HTTP_POST,
        |lua| net::install_http_post(lua, capability_gate.clone(), http_policy.clone()),
    )?;
    capgate::register_if_granted(
        &extracted.lua,
        &capability_gate,
        net::CAPABILITY_TRANSFER,
        |lua| {
            net::install_transfer(
                lua,
                capability_gate.clone(),
                http_policy.clone(),
                path_policy.clone(),
                extracted.declarations.env_secrets.clone(),
            )
        },
    )?;

    capgate::register_if_granted(&extracted.lua, &capability_gate, fs::CAPABILITY, |lua| {
        fs::install(
            lua,
            capability_gate.clone(),
            path_policy.clone(),
            extracted.declarations.env_secrets.clone(),
        )
    })?;

    // `mount.bind` / `mount.umount` are two separate `KNOWN_CAPABILITIES`
    // entries (04 §Outputs `mount.umount`: "declaring bind does not
    // grant umount"), so each gets its own register_if_granted call.
    capgate::register_if_granted(
        &extracted.lua,
        &capability_gate,
        mount::CAPABILITY_BIND,
        |lua| mount::install_bind(lua, capability_gate.clone(), path_policy.clone()),
    )?;
    capgate::register_if_granted(
        &extracted.lua,
        &capability_gate,
        mount::CAPABILITY_UMOUNT,
        |lua| mount::install_umount(lua, capability_gate.clone(), path_policy.clone()),
    )?;

    Ok(SandboxedProfile {
        extracted,
        env_policy,
        http_policy,
        path_policy,
        capability_gate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::eval::evaluate_profile_source;

    #[test]
    fn wire_sandboxed_profile_installs_env_get_and_builds_the_capability_gate() {
        let source = r#"
            local profile = require('lm.profile')
            return profile {
                name = "demo",
                capabilities = { "sh.exec" },
                env = { "SOME_VAR" },
            }
        "#;
        let extracted =
            evaluate_profile_source(source, "test-profile").expect("profile should evaluate");
        let sandboxed = wire_sandboxed_profile(extracted).expect("wiring steps 6-7 should succeed");

        assert!(sandboxed.capability_gate.is_granted("sh.exec"));
        assert!(!sandboxed.capability_gate.is_granted("fs.write"));

        let env_get: mlua::Function = sandboxed
            .extracted
            .lua
            .globals()
            .get::<mlua::Table>("env")
            .expect("env global should exist")
            .get("get")
            .expect("env.get should be installed by step 6");
        let value: mlua::Value = env_get
            .call("SOME_VAR")
            .expect("env.get on a declared name should not raise");
        assert!(matches!(value, mlua::Value::Nil | mlua::Value::String(_)));
    }

    #[test]
    fn wire_sandboxed_profile_fails_fast_for_a_declared_but_unknown_capability() {
        let source = r#"
            local profile = require('lm.profile')
            return profile { name = "demo", capabilities = { "not.a.real.capability" } }
        "#;
        let extracted =
            evaluate_profile_source(source, "test-profile").expect("profile should evaluate");
        let err = wire_sandboxed_profile(extracted)
            .err()
            .expect("unknown declared capability must fail step 7's fail-fast build");
        assert!(matches!(
            err,
            SandboxError::CapGate(CapGateError::UnknownDeclared(ref name))
                if name == "not.a.real.capability"
        ));
    }
}
