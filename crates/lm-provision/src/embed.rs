//! Compile-time embedding of the `lm.*` Lua module set.
//!
//! Every module listed here is the *entire* `require` allowlist enforced by
//! [`crate::vm::require`] (05-sandbox-layer-contract.md §L1). Adding a
//! module is a recompile, not a deploy-time file
//! (08-push-driver-protocol.md §Inputs).
//!
//! `05-sandbox-layer-contract.md` §L1 and `00-overview.md` §Naming name
//! ten `lm.*` modules as the Lua-facing library surface. `lm.catalog_data`
//! is an eleventh embedded module: it is not part of that ten-module
//! surface list, but `00-overview.md` §Consolidated design decisions
//! ("Shared vocabulary lives in one canonical data file") and
//! `02-phase-catalog.md` §Shared vocabulary require the 22 phase kinds,
//! `KNOWN_CAPABILITIES`, and the secret-key / sensitive-key substring
//! sets to live in one data file referenced by both hosts with byte
//! equality. Embedding it here — rather than a separate build-time
//! parsed file — keeps that single-file requirement inside the same
//! `include_str!` mechanism the other ten modules already use, and folds
//! it into the same `require` allowlist for free.

/// `(module name, Lua source)` pairs baked into the binary via
/// `include_str!`. Order has no semantic meaning; it mirrors the file
/// layout under `lua/lm/`.
pub static LM_MODULES: &[(&str, &str)] = &[
    ("lm.profile", include_str!("../lua/lm/profile.lua")),
    ("lm.env", include_str!("../lua/lm/env.lua")),
    ("lm.ir", include_str!("../lua/lm/ir.lua")),
    ("lm.validate", include_str!("../lua/lm/validate.lua")),
    ("lm.canonical", include_str!("../lua/lm/canonical.lua")),
    ("lm.hash", include_str!("../lua/lm/hash.lua")),
    ("lm.plan", include_str!("../lua/lm/plan.lua")),
    ("lm.dispatch", include_str!("../lua/lm/dispatch.lua")),
    ("lm.apply", include_str!("../lua/lm/apply.lua")),
    ("lm.report", include_str!("../lua/lm/report.lua")),
    (
        "lm.catalog_data",
        include_str!("../lua/lm/catalog_data.lua"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_has_exactly_the_documented_modules() {
        // Ten spec-named `lm.*` modules (05 §L1 / 00 §Naming) plus the
        // `lm.catalog_data` shared-vocabulary data file (see the module
        // doc comment above for why it is embedded here too).
        let names: Vec<&str> = LM_MODULES.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "lm.profile",
                "lm.env",
                "lm.ir",
                "lm.validate",
                "lm.canonical",
                "lm.hash",
                "lm.plan",
                "lm.dispatch",
                "lm.apply",
                "lm.report",
                "lm.catalog_data",
            ]
        );
    }

    #[test]
    fn every_embedded_source_is_non_empty() {
        for (name, source) in LM_MODULES {
            assert!(!source.trim().is_empty(), "{name} source must not be empty");
        }
    }
}
