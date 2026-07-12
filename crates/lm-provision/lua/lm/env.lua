--- lm.env — facade module re-exporting the profile-eval `env` global.
--
-- ## Design
--
-- 01-profile-dsl-surface.md §Inputs lists `env.ref` as a value available
-- directly as a **global** at profile-eval time — not via
-- `require("lm.env")` — pre-registered by the host alongside the
-- declared-list extraction step (00-overview.md §Secret handling:
-- "`env.ref(name)` is a factory"; 06-secret-handling.md owns the
-- factory itself). `require("lm.env")` is the separate, `lm.*`-
-- allowlisted facade module for consumers (pipeline stages, other `lm.*`
-- modules) that need the same table programmatically rather than
-- through the profile-eval-time ambient global; 01 §Stability marks this
-- facade "stable" independently of the global's own stability.
--
-- `M.ref` / `M.get` / `M.set` are host-bridge concerns
-- (06-secret-handling.md), not `lm.env`'s own logic — this module never
-- re-implements them, only re-exports whatever the host has registered
-- on the profile-eval-time `env` global by the time this module is
-- first `require`d.
--
-- The re-export is conditional on the `env` global actually existing:
-- a bare `boot_vm()` VM (registration order steps 1-2 only, milestone
-- M0/M1) never registers `env` at all — `env.ref` lands at step 3
-- (milestone M1-3), `env.get` / `env.set` at step 6 (milestone M3-1,
-- crates/lm-provision/src/sandbox/policy.rs `install_env_get_set`).
-- `require("lm.env")` under such a VM must still succeed (01
-- §Stability: "the facade module ... stable"), so this module degrades
-- to the pre-M1-3 empty-table stub rather than erroring on a nil
-- global.
local M = {}

if env ~= nil then
	M.ref = env.ref
	M.get = env.get
	M.set = env.set
end

return M
