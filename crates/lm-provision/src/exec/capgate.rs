//! Pure capability gate (no mlua dependency).
//!
//! The semantic twin of the old `src/sandbox/capgate.rs`, but standalone
//! Rust: [`KNOWN_CAPABILITIES`] is the frozen vocabulary from spec 02
//! §Shared vocabulary, [`CapabilityGate::build`] fails fast on a declared
//! capability outside it, and [`CapabilityGate::require`] is the per-op
//! entry check that turns "declared ⊆ used" into a physical constraint.

use std::collections::HashSet;

use super::ExecError;

/// The frozen capability vocabulary (spec 02 §Shared vocabulary).
///
/// `mount.volume_attach` is reserved: it is a valid declaration but has
/// no corresponding op yet.
pub const KNOWN_CAPABILITIES: [&str; 9] = [
    "env.ref",
    "sh.exec",
    "net.transfer",
    "net.http_get",
    "net.http_post",
    "fs.write",
    "mount.bind",
    "mount.umount",
    "mount.volume_attach",
];

/// The set of capabilities a profile declared, validated against
/// [`KNOWN_CAPABILITIES`] at build time.
///
/// `declared = []` builds successfully and grants nothing.
#[derive(Debug, Clone)]
pub struct CapabilityGate {
    granted: HashSet<String>,
}

impl CapabilityGate {
    /// Build the gate from the profile's declared `capabilities`,
    /// rejecting any entry outside [`KNOWN_CAPABILITIES`] with
    /// [`ExecError::CapabilityUnknown`].
    pub fn build(declared: &[String]) -> Result<Self, ExecError> {
        let known: HashSet<&str> = KNOWN_CAPABILITIES.iter().copied().collect();
        for capability in declared {
            if !known.contains(capability.as_str()) {
                return Err(ExecError::CapabilityUnknown(capability.clone()));
            }
        }
        Ok(Self {
            granted: declared.iter().cloned().collect(),
        })
    }

    /// Whether `capability` was declared by the profile.
    pub fn is_granted(&self, capability: &str) -> bool {
        self.granted.contains(capability)
    }

    /// Per-op entry check: an op requiring an undeclared capability fails
    /// with [`ExecError::CapabilityDenied`]. This is the physical
    /// "declared ⊆ used" enforcement point.
    pub fn require(&self, capability: &str) -> Result<(), ExecError> {
        if self.is_granted(capability) {
            Ok(())
        } else {
            Err(ExecError::CapabilityDenied(capability.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_accepts_a_declared_subset_of_known_capabilities() {
        let gate = CapabilityGate::build(&["sh.exec".to_string(), "fs.write".to_string()])
            .expect("a declared subset of KNOWN_CAPABILITIES must build");
        assert!(gate.is_granted("sh.exec"));
        assert!(gate.is_granted("fs.write"));
        assert!(!gate.is_granted("net.http_get"));
    }

    #[test]
    fn build_rejects_an_unknown_declared_capability() {
        let err = CapabilityGate::build(&["not.a.real.capability".to_string()])
            .expect_err("an unknown declared capability must fail fast");
        assert!(matches!(
            err,
            ExecError::CapabilityUnknown(ref name) if name == "not.a.real.capability"
        ));
    }

    #[test]
    fn build_accepts_the_reserved_volume_attach_capability() {
        let gate = CapabilityGate::build(&["mount.volume_attach".to_string()])
            .expect("the reserved mount.volume_attach declaration must build");
        assert!(gate.is_granted("mount.volume_attach"));
    }

    #[test]
    fn empty_declaration_grants_nothing_but_still_builds() {
        let gate = CapabilityGate::build(&[]).expect("an empty declaration must build");
        assert!(!gate.is_granted("sh.exec"));
    }

    #[test]
    fn require_fails_for_an_undeclared_capability() {
        let gate = CapabilityGate::build(&[]).expect("empty declaration builds");
        let err = gate
            .require("sh.exec")
            .expect_err("requiring an undeclared capability must fail");
        assert_eq!(
            err.to_string(),
            "capability 'sh.exec' not declared in profile.capabilities"
        );
    }

    #[test]
    fn require_succeeds_for_a_declared_capability() {
        let gate = CapabilityGate::build(&["sh.exec".to_string()]).expect("build succeeds");
        gate.require("sh.exec")
            .expect("requiring a declared capability must pass");
    }
}
