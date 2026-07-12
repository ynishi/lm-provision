//! Read-only accessors onto `lm.catalog_data`, the shared-vocabulary
//! single source of truth (00-overview.md §Consolidated design decisions
//! "Shared vocabulary lives in one canonical data file";
//! 02-phase-catalog.md §Shared vocabulary).
//!
//! `KNOWN_CAPABILITIES` (05-sandbox-layer-contract.md §L4) and the
//! secret-key substring set (06-secret-handling.md §Inputs) are frozen
//! literal sets that both the Lua host and the Rust host must read
//! byte-identically. The Rust side never hardcodes its own copy of
//! either list — that would recreate exactly the drifting-second-copy
//! problem 00 §Consolidated design decisions rules out. Instead these
//! functions `require("lm.catalog_data")` through the same sandboxed VM
//! the profile itself runs in and read the tables straight out of the
//! one embedded Lua source file (`crates/lm-provision/src/embed.rs`).
//!
//! Both accessors need only registration order step 1 (custom `require`,
//! [`crate::vm::boot_vm`]) to have run — `lm.catalog_data` carries no
//! declaration-derived state, so callers may invoke these at any point
//! after boot, not only from within [`crate::sandbox::wire_sandboxed_profile`].

use mlua::{Function, Lua, Table};

/// `lm.catalog_data.KNOWN_CAPABILITIES` — the frozen, 9-entry L4
/// capability allowlist (05-sandbox-layer-contract.md §L4;
/// 02-phase-catalog.md §Shared vocabulary).
pub fn known_capabilities(lua: &Lua) -> mlua::Result<Vec<String>> {
    read_string_list(lua, "KNOWN_CAPABILITIES")
}

/// `lm.catalog_data.SECRET_KEY_SUBSTRINGS` — the frozen, 8-entry
/// secret-shaped-key substring set (06-secret-handling.md §Inputs
/// "Profile declarations"; 02-phase-catalog.md §Shared vocabulary).
/// Consumers must match case-insensitively, per 06 §Inputs.
pub fn secret_key_substrings(lua: &Lua) -> mlua::Result<Vec<String>> {
    read_string_list(lua, "SECRET_KEY_SUBSTRINGS")
}

/// `lm.catalog_data.SENSITIVE_KEY_SUBSTRINGS` — the frozen, 8-entry
/// audit-redaction substring set (09-apply-report-and-ledger.md §Inputs
/// "The sensitive-key substring set"; 02-phase-catalog.md §Shared
/// vocabulary). Distinct literal casing/ordering from
/// [`secret_key_substrings`] — chapter 06 (validate rejection) and
/// chapter 09 (audit redaction) each state their own literal list rather
/// than sharing one (`lm.catalog_data`'s own module doc comment).
/// Consumers must match case-insensitively, per 09 §Audit log.
pub fn sensitive_key_substrings(lua: &Lua) -> mlua::Result<Vec<String>> {
    read_string_list(lua, "SENSITIVE_KEY_SUBSTRINGS")
}

fn read_string_list(lua: &Lua, field: &str) -> mlua::Result<Vec<String>> {
    let require_fn: Function = lua.globals().get("require")?;
    let catalog: Table = require_fn.call("lm.catalog_data")?;
    let list: Table = catalog.get(field)?;
    list.sequence_values::<String>().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::boot_vm;

    #[test]
    fn known_capabilities_matches_the_frozen_nine_entry_set() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let caps = known_capabilities(&lua).expect("KNOWN_CAPABILITIES should be readable");
        assert_eq!(
            caps,
            vec![
                "env.ref",
                "sh.exec",
                "net.transfer",
                "net.http_get",
                "net.http_post",
                "fs.write",
                "mount.bind",
                "mount.umount",
                "mount.volume_attach",
            ]
        );
    }

    #[test]
    fn secret_key_substrings_matches_the_frozen_eight_entry_set() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let subs = secret_key_substrings(&lua).expect("SECRET_KEY_SUBSTRINGS should be readable");
        assert_eq!(
            subs,
            vec!["KEY", "SECRET", "TOKEN", "PASSWORD", "PWD", "AUTH", "CRED", "APIKEY"]
        );
    }

    #[test]
    fn sensitive_key_substrings_matches_the_frozen_eight_entry_set() {
        let lua = boot_vm().expect("boot_vm should succeed");
        let subs =
            sensitive_key_substrings(&lua).expect("SENSITIVE_KEY_SUBSTRINGS should be readable");
        assert_eq!(
            subs,
            vec!["key", "token", "secret", "password", "pwd", "auth", "cred", "apikey"]
        );
    }
}
