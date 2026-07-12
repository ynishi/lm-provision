--- lm.hash — sha256 of the canonical encoding.
--
-- Returns the 64-character lowercase hex profile hash
-- (03-pipeline-stage-artifacts.md §hash). The profile hash is defined
-- as `sha256_hex(canonical.encode(ir))`; because declared lists are
-- pre-sorted (chapter 01) and canonical encoding is deterministic, the
-- hash is byte-identical across declaration-order permutations of the
-- declared lists, and sensitive to phase order (which is semantic).
--
-- This module is a thin dispatcher onto the Rust-side sha256 provider
-- (`crates/lm-provision/src/batteries/hash.rs`). sha256 needs no
-- declaration-derived policy (it is a pure deterministic function of
-- its input bytes), so the provider is registered as an internal-only
-- global (`__lm_batteries_sha256_hex`) rather than through the
-- profile-visible `std.*` battery surface that 04-bridge.md
-- §Registration order step 6 wires with declaration-derived env/http
-- policies (milestone M3) — see the M2 milestone plan's unresolved
-- item #6: minimum viable is an internal hash provider only, `std.*`
-- ships empty through M2. A profile author has no path to this global
-- (it is not `std.*`, not `env`, not a declared bridge); only
-- `lm.hash.sha256_hex` calls it.

local M = {}

--- SHA-256 over `bytes` (canonical bytes, a Lua string), rendered as a
--- 64-character lowercase hex string with no prefix
--- (03-pipeline-stage-artifacts.md §hash).
---
--- Raises when the batteries hash provider is unavailable (host wiring
--- bug — internal invariant, not a consumer state, 03 §Error surface
--- "hash: raises when the batteries hash provider is unavailable").
function M.sha256_hex(bytes)
	if type(bytes) ~= "string" then
		error(string.format("lm.hash.sha256_hex: bytes must be a string, got %s", type(bytes)), 0)
	end
	local provider = rawget(_G, "__lm_batteries_sha256_hex")
	if type(provider) ~= "function" then
		error("lm.hash.sha256_hex: the batteries hash provider is unavailable (host wiring bug)", 0)
	end
	return provider(bytes)
end

return M
