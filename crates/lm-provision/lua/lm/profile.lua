--- lm.profile — profile DSL entry point.
--
-- ## Design
--
-- `require("lm.profile")` returns a callable table. The DSL literal
-- `lm.profile { name = "..." }` a profile author writes
-- (01-profile-dsl-surface.md §Inputs) is `require("lm.profile")` bound
-- to a local, then called with Lua's table-call sugar (`f {...}` is
-- sugar for `f({...})`); the `__call` metamethod below is what makes
-- this module itself invokable that way:
--
-- ```lua
-- local profile = require("lm.profile")
-- return profile { name = "demo", phases = { ... } }
-- ```
--
-- `lm.profile(spec)` normalizes an author-facing profile spec into the
-- IR table in four steps:
--
--   1. definition-time typed asserts (spec / name / declared-list-entry
--      / phases shape — 01-profile-dsl-surface.md §Error surface).
--   2. default-fill for optional top-level fields (01 §Inputs table).
--   3. stable lexicographic sort of the five declared lists
--      (`capabilities`, `env`, `env_secrets`, `paths`, `http_allowlist`);
--      `phases` keeps user-declared order verbatim
--      (01 §List-shape rule).
--   4. delegates the final `schema = "lm.profile/1"` tag and IR table
--      shape to `lm.ir.build` (01 §Outputs).
--
-- The constructor layer (per-kind phase constructors, 01 §Stability:
-- provisional through Phase H) is out of scope here; only the
-- plain-table phase baseline (01 §Phase shape) is implemented. Per-phase
-- shape validation (chapter 02 payload schemas) is the validate stage's
-- job (03 §validate, milestone M2), not `lm.profile`'s.

local ir = require("lm.ir")

local M = {}

-- The five declared lists that are stable-sorted lexicographically by
-- `lm.profile` (01-profile-dsl-surface.md §List-shape rule). `phases` is
-- deliberately excluded: it keeps user-declared order.
local DECLARED_LIST_FIELDS = { "capabilities", "env", "env_secrets", "paths", "http_allowlist" }

-- Literal error message form from 01-profile-dsl-surface.md §Inputs:
-- "a non-string entry aborts at definition time with a typed assert
-- message (`lm.profile: <field>[<i>] must be a string, got <type>`)."
local function raise_entry_type_error(field, index, value)
	error(string.format("lm.profile: %s[%d] must be a string, got %s", field, index, type(value)), 0)
end

-- Copies + validates one declared list: every entry must be a string
-- (01 §Inputs). Defaults to `{}` when the field is absent (01 §Inputs
-- default column). A non-table field value has no literal message in
-- 01; this branch is a minimal, non-inventive safety net so a caller
-- error surfaces as an `lm.profile:`-prefixed message rather than a raw
-- `ipairs` argument error (reported as unconfirmed wording, see impl-lead
-- M1-2 report).
local function normalize_declared_list(spec, field)
	local list = spec[field]
	if list == nil then
		return {}
	end
	if type(list) ~= "table" then
		error(string.format("lm.profile: %s must be a table (list of strings), got %s", field, type(list)), 0)
	end

	local copy = {}
	for i, value in ipairs(list) do
		if type(value) ~= "string" then
			raise_entry_type_error(field, i, value)
		end
		copy[i] = value
	end

	table.sort(copy, function(a, b)
		return a < b
	end)
	return copy
end

-- Copies `phases` verbatim in user-declared order (01 §List-shape rule:
-- "phases preserves user-declared order verbatim"). Per-phase shape
-- validation (chapter 02 payload schemas) is a chapter 03 validate-stage
-- concern, not `lm.profile`'s.
local function normalize_phases(spec)
	local phases = spec.phases
	if phases == nil then
		return {}
	end
	if type(phases) ~= "table" then
		error(string.format("lm.profile: phases must be a list-shaped table, got %s", type(phases)), 0)
	end

	local copy = {}
	for i, phase in ipairs(phases) do
		copy[i] = phase
	end
	return copy
end

local function profile(spec)
	if type(spec) ~= "table" then
		error(string.format("lm.profile: spec must be a table, got %s", type(spec)), 0)
	end
	if type(spec.name) ~= "string" or spec.name == "" then
		error("lm.profile: name is required and must be a non-empty string", 0)
	end

	local normalized = {
		name = spec.name,
		version = spec.version or "0.0.0",
		description = spec.description,
		phases = normalize_phases(spec),
	}
	for _, field in ipairs(DECLARED_LIST_FIELDS) do
		normalized[field] = normalize_declared_list(spec, field)
	end

	return ir.build(normalized)
end

setmetatable(M, {
	__call = function(_, spec)
		return profile(spec)
	end,
})

return M
