//! Batteries: host-provided pure-function primitives with no
//! declaration-derived policy surface.
//!
//! 04-bridge.md §Registration order step 6 ("batteries `std.*`
//! registration with the declaration-derived policies (env / http)")
//! governs the profile-visible `std.*` battery surface — that lands in
//! milestone M3, gated on the `env` / `env_secrets` / `http_allowlist`
//! declarations extracted at step 5.
//!
//! [`hash`] is different: sha256 needs no such policy (it is a pure
//! deterministic function of its input bytes), so it registers
//! independently, as an internal-only global no profile-visible `std.*`
//! surface exposes (milestone plan §未確定事項 #6: "最小: 内部 hash
//! provider のみ、std.* は空登録"). `lm.hash.sha256_hex`
//! (`lua/lm/hash.lua`) is the only Lua-facing caller.

pub mod hash;
