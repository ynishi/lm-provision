//! L4 capability gate: operation-level enforcement
//! (05-sandbox-layer-contract.md §L4).
//!
//! [`CapabilityGate::build`] is registration order step 7 ("capability
//! gate build + assert-all-implemented", 04-bridge.md §Registration
//! order); [`register_if_granted`] is the register-skip half of step 8
//! ("cap-gated bridge registration — only declared operations are
//! installed") that milestone M3-2..M3-4's `sh` / `net` / `fs` / `mount`
//! bridge installers call into; [`CapabilityGate::require`] is the
//! entry-check half those same bridges re-run on every call (05 §L4
//! "Two-strategy enforcement").

use std::collections::HashSet;

use mlua::Lua;
use thiserror::Error;

use crate::sandbox::catalog;

/// Errors from building or querying a [`CapabilityGate`].
#[derive(Debug, Error)]
pub enum CapGateError {
    /// A declared capability is not a member of
    /// `lm.catalog_data.KNOWN_CAPABILITIES` — load-time fail-fast, before
    /// any Lua user code runs (05 §L4: "Declared-but-unknown capability
    /// → fail-fast at load ... No silent skip").
    #[error("capability '{0}' declared but not implemented by host")]
    UnknownDeclared(String),

    /// A capability was required (entry check, defence in depth) that
    /// the profile never declared (05 §L4 "Two-strategy enforcement";
    /// 04-bridge.md §Error surface "Gate").
    #[error("capability '{0}' not declared in profile.capabilities")]
    NotDeclared(String),

    /// `lm.catalog_data.KNOWN_CAPABILITIES` could not be read from the
    /// sandboxed VM (a host wiring bug, not a profile-author error).
    #[error("failed to read lm.catalog_data.KNOWN_CAPABILITIES: {0}")]
    Lua(#[from] mlua::Error),
}

/// The L4 capability gate, built once per profile evaluation from the
/// declared `capabilities` list (05-sandbox-layer-contract.md §L4).
///
/// `capabilities = {}` builds successfully and grants nothing — "a
/// pure-computation profile (validate / hash / plan work; apply can
/// execute nothing but pending steps)" (05 §L4).
#[derive(Debug, Clone)]
pub struct CapabilityGate {
    granted: HashSet<String>,
}

impl CapabilityGate {
    /// Build the gate from `declared` (the profile's `capabilities`
    /// list, [`crate::vm::eval::Declarations::capabilities`]),
    /// validating every entry against `KNOWN_CAPABILITIES`
    /// ([`catalog::known_capabilities`], the 1-SoT accessor onto
    /// `lm.catalog_data`) — the load-time fail-fast half of 05 §L4.
    /// `lua` need only have completed registration order step 1
    /// (custom `require`) for `lm.catalog_data` to resolve.
    pub fn build(lua: &Lua, declared: &[String]) -> Result<Self, CapGateError> {
        let known = catalog::known_capabilities(lua)?;
        let known_set: HashSet<&str> = known.iter().map(String::as_str).collect();

        for capability in declared {
            if !known_set.contains(capability.as_str()) {
                return Err(CapGateError::UnknownDeclared(capability.clone()));
            }
        }

        Ok(Self {
            granted: declared.iter().cloned().collect(),
        })
    }

    /// Whether `capability` is in the profile's declared set. The
    /// register-skip strategy (05 §L4) calls this to decide whether to
    /// install a bridge at all; [`Self::require`] is its entry-check
    /// sibling.
    pub fn is_granted(&self, capability: &str) -> bool {
        self.granted.contains(capability)
    }

    /// Entry check (defence in depth over the register skip, 05 §L4):
    /// every installed bridge re-validates the gate per call. Returns
    /// the literal gate-check error 04-bridge.md §Error surface names:
    /// `capability '<op>' not declared in profile.capabilities`.
    pub fn require(&self, capability: &str) -> Result<(), CapGateError> {
        if self.is_granted(capability) {
            Ok(())
        } else {
            Err(CapGateError::NotDeclared(capability.to_string()))
        }
    }
}

/// Install `capability`'s bridge only if `gate` grants it — the
/// register-skip structural guarantee (05 §L4 "Register skip
/// (structural): bridges for undeclared operations are never
/// installed — the call site hits nil"). `install` is never called at
/// all when the capability is ungranted, rather than being called and
/// discarding its result, so an undeclared bridge is provably never
/// registered on `lua`, not merely made to look absent.
///
/// Milestone M3-2..M3-4's `sh` / `net` / `fs` / `mount` bridge
/// installers call this once per operation they own; this milestone
/// ships only the mechanism, since no bridge exists yet
/// (04-bridge.md §Registration order step 8 is a no-op through M3-1).
pub fn register_if_granted<F>(
    lua: &Lua,
    gate: &CapabilityGate,
    capability: &str,
    install: F,
) -> mlua::Result<()>
where
    F: FnOnce(&Lua) -> mlua::Result<()>,
{
    if gate.is_granted(capability) {
        install(lua)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::boot_vm;

    #[test]
    fn build_succeeds_for_declared_capabilities_within_known_capabilities() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let gate = CapabilityGate::build(&lua, &["sh.exec".to_string(), "fs.write".to_string()])
            .expect("declared capabilities within KNOWN_CAPABILITIES should build");
        assert!(gate.is_granted("sh.exec"));
        assert!(gate.is_granted("fs.write"));
        assert!(!gate.is_granted("net.http_get"));
    }

    #[test]
    fn build_fails_fast_for_a_declared_but_unknown_capability() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let err = CapabilityGate::build(&lua, &["not.a.real.capability".to_string()])
            .expect_err("unknown declared capability must fail fast");
        assert!(matches!(
            err,
            CapGateError::UnknownDeclared(ref name) if name == "not.a.real.capability"
        ));
        assert_eq!(
            err.to_string(),
            "capability 'not.a.real.capability' declared but not implemented by host"
        );
    }

    #[test]
    fn empty_capabilities_is_a_valid_pure_computation_profile() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let gate = CapabilityGate::build(&lua, &[]).expect("capabilities = {} must be valid");
        assert!(!gate.is_granted("sh.exec"));
    }

    #[test]
    fn require_reports_the_gate_check_error_naming_the_missing_capability() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let gate = CapabilityGate::build(&lua, &[]).expect("empty capabilities should build");
        let err = gate
            .require("sh.exec")
            .expect_err("ungranted capability must fail the entry check");
        assert_eq!(
            err.to_string(),
            "capability 'sh.exec' not declared in profile.capabilities"
        );
    }

    #[test]
    fn require_succeeds_for_a_declared_capability() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let gate =
            CapabilityGate::build(&lua, &["sh.exec".to_string()]).expect("build should succeed");
        gate.require("sh.exec")
            .expect("declared capability must pass the entry check");
    }

    #[test]
    fn register_if_granted_skips_installation_for_an_undeclared_capability() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let gate = CapabilityGate::build(&lua, &[]).expect("empty capabilities should build");
        register_if_granted(&lua, &gate, "sh.exec", |_lua| {
            panic!("install must not run for an undeclared capability (register skip)");
        })
        .expect("register_if_granted should not error when skipping");
    }

    #[test]
    fn register_if_granted_runs_installation_for_a_declared_capability() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let gate =
            CapabilityGate::build(&lua, &["sh.exec".to_string()]).expect("build should succeed");
        let mut installed = false;
        register_if_granted(&lua, &gate, "sh.exec", |_lua| {
            installed = true;
            Ok(())
        })
        .expect("register_if_granted should run install for a declared capability");
        assert!(installed);
    }
}
