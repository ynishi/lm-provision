//! sha256 hash provider (03-pipeline-stage-artifacts.md §hash): the
//! Rust-side primitive `lm.hash.sha256_hex` (`lua/lm/hash.lua`) calls
//! into.
//!
//! Registered under [`PROVIDER_GLOBAL`], an internal-only global name —
//! not part of the profile-visible `std.*` battery surface
//! (04-bridge.md §Registration order step 6, milestone M3). sha256 is a
//! pure deterministic function with no declaration-derived env/http
//! policy dependency, so it carries no ordering requirement relative to
//! declaration extraction (registration order step 5): it may be
//! installed at any point before `lm.hash.sha256_hex` is actually
//! *called* (03-pipeline-stage-artifacts.md §Error surface: "hash:
//! raises when the batteries hash provider is unavailable (host wiring
//! bug — internal invariant, not a consumer state)" already treats
//! "provider not yet wired" as a distinct, detectable condition rather
//! than assuming a fixed registration slot).

use mlua::Lua;
use sha2::{Digest, Sha256};

/// The internal global name `lm.hash.sha256_hex` looks up to reach this
/// provider (`rawget(_G, "__lm_batteries_sha256_hex")` in
/// `lua/lm/hash.lua`). Not `std.*`, not `env`, not a declared bridge —
/// no profile-authored Lua has a documented path to this name.
pub const PROVIDER_GLOBAL: &str = "__lm_batteries_sha256_hex";

/// Register the sha256 hash provider on `lua`.
///
/// The registered Lua function takes the canonical bytes (a Lua
/// string) and returns the 64-character lowercase hex digest with no
/// prefix (03-pipeline-stage-artifacts.md §hash).
pub fn install(lua: &Lua) -> mlua::Result<()> {
    let sha256_hex = lua.create_function(|_, bytes: mlua::String| -> mlua::Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    })?;
    lua.globals().set(PROVIDER_GLOBAL, sha256_hex)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_registers_a_callable_provider_returning_64_char_lowercase_hex() {
        let lua = Lua::new();
        install(&lua).expect("install should succeed");

        let digest: String = lua
            .load(format!("return {PROVIDER_GLOBAL}('')"))
            .eval()
            .expect("provider should be callable");
        // NIST FIPS 180-4 SHA-256 test vector: sha256("") ==
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.len(), 64);
        assert!(digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn install_matches_the_nist_abc_test_vector() {
        let lua = Lua::new();
        install(&lua).expect("install should succeed");

        let digest: String = lua
            .load(format!("return {PROVIDER_GLOBAL}('abc')"))
            .eval()
            .expect("provider should be callable");
        // NIST FIPS 180-4 SHA-256 test vector: sha256("abc") ==
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
