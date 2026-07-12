--- lm.ir — builds the normalized IR table from a profile spec.
--
-- ## Design
--
-- `lm.ir.build(normalized)` is the sole owner of the
-- `schema = "lm.profile/1"` tag (01-profile-dsl-surface.md §Outputs). Its
-- caller, `lm.profile`, hands it an already-normalized spec: defaults
-- filled, the five declared lists stable-sorted, `phases` in
-- user-declared order (01-profile-dsl-surface.md §List-shape rule). This
-- module performs no validation of its own — definition-time shape
-- asserts are `lm.profile`'s job (01 §Error surface); `lm.ir` only
-- assembles the final table shape that every downstream pipeline stage
-- consumes (03-pipeline-stage-artifacts.md §Inputs) and that gets hashed
-- (03 §hash).
--
-- The IR table produced here is pure data: no metatables, no hidden
-- state (01 §Phase shape: plain table baseline).

local M = {}

--- Attach the wire schema tag and assemble the IR table shape
--- (01-profile-dsl-surface.md §Outputs):
---
--- ```lua
--- {
---   schema = "lm.profile/1",
---   name, version, description,
---   capabilities, env, env_secrets, paths, http_allowlist,  -- sorted
---   phases,                                                  -- user order
--- }
--- ```
---
--- @param normalized table already-normalized spec (defaults filled,
---   declared lists sorted, phases verbatim) as produced by `lm.profile`.
--- @return table the IR table.
function M.build(normalized)
	return {
		schema = "lm.profile/1",
		name = normalized.name,
		version = normalized.version,
		description = normalized.description,
		capabilities = normalized.capabilities,
		env = normalized.env,
		env_secrets = normalized.env_secrets,
		paths = normalized.paths,
		http_allowlist = normalized.http_allowlist,
		phases = normalized.phases,
	}
end

return M
