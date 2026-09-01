//! # lm-provision-host
//!
//! The control plane: the process that keeps running after an apply
//! returns. Enforcing a pod's TTL means noticing that it expired,
//! which no one-shot CLI invocation is around to do; holding custody
//! of the acquisition and apply ledgers means being the one writer
//! that outlives every driver run. That daemon — self-hostable, so an
//! operator's machines and the record of what was spent on them stay
//! on their own hardware — is what this crate becomes.
//!
//! **It is empty today on purpose.** The crate is AGPL-3.0-or-later
//! (declared in its own manifest, not inherited from the workspace's
//! MIT / Apache-2.0), and a license boundary has to be cut before the
//! code it covers attracts contributions: relicensing afterwards needs
//! a CLA or DCO signature from every outside contributor, one at a
//! time, and any one refusal is final. Cutting it first costs an empty
//! crate.
//!
//! ## The dependency rule
//!
//! **No other crate in this workspace may depend on this one.** The
//! engine crates (`lm-provision`, `lm-provision-driver`,
//! `lm-provision-mcp`) and the neutral `lm-provision-protocol` are
//! dual-licensed MIT / Apache-2.0 permanently; a dependency edge from
//! any of them to an AGPL crate would put their users under the AGPL's
//! terms, which is precisely what the permissive promise rules out.
//! Types both sides need go in `lm-provision-protocol`, which is
//! permissive and may be depended on from either direction.
//!
//! The rule is machine-checked rather than remembered:
//! `no_permissive_crate_depends_on_the_agpl_host` in this crate's test
//! module reads the four permissive manifests and fails if any of them
//! names this crate.

#![warn(missing_docs)]

#[cfg(test)]
mod tests {
    /// **The engine → host dependency direction is empty, and stays
    /// empty.** The license boundary is the crate boundary (there is
    /// no finer line a compiler can check), so the boundary holds only
    /// as long as no permissive manifest names this crate. That is a
    /// property of four files, and reading four files is cheaper than
    /// trusting four reviews.
    ///
    /// The check is textual on purpose: it fails on a `[dependencies]`
    /// entry, a dev-dependency, a build-dependency, an optional feature
    /// edge, and on a commented-out one that is about to be
    /// uncommented — all of which are the same mistake.
    #[test]
    fn no_permissive_crate_depends_on_the_agpl_host() {
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the host crate lives under crates/");

        for permissive in [
            "lm-provision",
            "lm-provision-driver",
            "lm-provision-mcp",
            "lm-provision-protocol",
        ] {
            let manifest = crates_dir.join(permissive).join("Cargo.toml");
            let text = std::fs::read_to_string(&manifest)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", manifest.display()));
            assert!(
                !text.contains("lm-provision-host"),
                "{} names lm-provision-host. {permissive} is dual-licensed MIT/Apache-2.0 \
                 and lm-provision-host is AGPL-3.0-or-later, so this edge relicenses \
                 {permissive}'s users. The fix is to remove the dependency — move whatever \
                 is needed across into lm-provision-protocol, which is permissive and \
                 exists for exactly this — not to edit this test.",
                manifest.display()
            );
        }
    }
}
