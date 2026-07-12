--- lm.validate — first-violation validation stage over the IR.
--
-- ## Design
--
-- `lm.validate.validate(ir)` runs the 7 checks
-- (03-pipeline-stage-artifacts.md §validate) against the IR **in the
-- documented order**, stopping and returning `{ ok = false, error = "<msg>"
-- }` at the first violation (single-error reporting, 03 §Stability:
-- provisional). On success it returns `{ ok = true, name = ir.name }`.
--
-- `ir` is validated independently of `lm.profile` / `lm.ir` having
-- produced it — the canonical decode round-trip (chapter 03 §canonical,
-- milestone M2-2) can hand this stage an IR table that never passed
-- through `lm.profile`'s definition-time asserts, so every check here
-- re-verifies shape from scratch rather than assuming it.
--
-- Per-kind phase payload shape (check 6) walks `lm.catalog_data.fields`
-- (recursing into `.shape` for `list<table>` / `table` fields) instead of
-- re-encoding chapter 02's 22-kind schema here — `lm.catalog_data` is the
-- single source of truth (00-overview.md §Consolidated design decisions
-- "Shared vocabulary lives in one canonical data file"; `catalog_data.lua`
-- module doc: "the validate / plan / dispatch stages ... walk this table,
-- they do not extend it"). Which `string` / `list<string>` fields the
-- shell-safety half of check 6 applies to is driven by the `shell_safe`
-- marker `lm.catalog_data` carries per field (see that module's doc
-- comment for exactly which fields are marked and why); this module does
-- not hardcode a second field-name list.
--
-- Unknown phase `kind`s are not a validate-stage error
-- (02-phase-catalog.md §Unknown kinds / §Error surface: "Unknown kind:
-- not an error") — such phases are skipped entirely by check 6's
-- per-kind walk and degrade to a `zz_unknown` plan step later
-- (milestone M2-3).

local catalog_data = require("lm.catalog_data")

local M = {}

-- ---------------------------------------------------------------------
-- Shell-safety contract (03-pipeline-stage-artifacts.md §validate
-- "Shell-safety contract").
-- ---------------------------------------------------------------------

-- Base charset. `-` is placed last inside the class so Lua's pattern
-- matcher treats it as a literal, not a range operator.
local SHELL_SAFE_CLASS = "[A-Za-z0-9._/@:+=~%-]"
local SHELL_SAFE_PATTERN = "^" .. SHELL_SAFE_CLASS .. "+$"
local SHELL_SAFE_WITH_SPACES_PATTERN = "^[A-Za-z0-9._/@:+=~%- ]+$"

--- A string is shell-safe iff non-empty and matching
--- `[A-Za-z0-9._/@:+=~-]+` (03 §validate "Shell-safety contract").
function M.is_shell_safe(s)
	if type(s) ~= "string" or s == "" then
		return false
	end
	return s:match(SHELL_SAFE_PATTERN) ~= nil
end

--- The with-spaces variant of the shell-safety contract: additionally
--- allows single spaces, never double (03 §validate). No field in
--- `lm.catalog_data` is currently marked as requiring this variant (03
--- does not name which fields opt in) — exposed for a later pipeline
--- stage or catalog field to opt into; reported as unconfirmed in the
--- impl-lead M2-1 report.
function M.is_shell_safe_with_spaces(s)
	if type(s) ~= "string" or s == "" then
		return false
	end
	if s:find("  ", 1, true) then
		return false
	end
	return s:match(SHELL_SAFE_WITH_SPACES_PATTERN) ~= nil
end

-- `{pod_id}` is a literal placeholder allowed inside `sync.push` /
-- `staging.push` `dst` (02-phase-catalog.md §Catalog kinds), exempt from
-- the shell-safety charset even though `{` / `}` are not themselves
-- shell-safe characters.
local POD_ID_PLACEHOLDER = "{pod_id}"

local function is_shell_safe_allowing_pod_id_placeholder(s)
	if type(s) ~= "string" or s == "" then
		return false
	end
	local stripped = s:gsub(POD_ID_PLACEHOLDER, "")
	if stripped == "" then
		-- The whole string was made of placeholder occurrences.
		return true
	end
	return M.is_shell_safe(stripped)
end

-- ---------------------------------------------------------------------
-- Absolute-path shape (checks 5, and the sync.*/staging.* route shape
-- half of check 6).
-- ---------------------------------------------------------------------

--- Returns `true` on success, or `false, "<reason>"` on the first shape
--- violation. Order mirrors 03 §validate check 5's sentence: absolute
--- (leading `/`), free of `..` segments.
local function check_absolute_path_shape(value)
	if type(value) ~= "string" or value == "" then
		return false, "must be a non-empty absolute path"
	end
	if value:sub(1, 1) ~= "/" then
		return false, "must be absolute (leading '/')"
	end
	for segment in value:gmatch("[^/]+") do
		if segment == ".." then
			return false, "must not contain a '..' segment"
		end
	end
	return true
end

-- ---------------------------------------------------------------------
-- sync.*/staging.* route shape (02-phase-catalog.md §Error surface:
-- "Route shape violations (`sync.*` src/dst schemes, missing bucket or
-- path, `..` traversal): validate-stage reject").
-- ---------------------------------------------------------------------

local URI_ROUTE_SCHEMES = { b2 = true, hf = true, https = true }
local URI_SCHEME_PATTERN = "^(%a[%w+.%-]*)://(.*)$"

--- A `b2://` / `hf://` / `https://` route: scheme must be one of
--- `URI_ROUTE_SCHEMES`, and the remainder must carry a non-empty
--- bucket/owner segment plus a non-empty path.
local function check_uri_route_shape(value)
	if type(value) ~= "string" or value == "" then
		return false, "must be a non-empty URI"
	end
	local scheme, rest = value:match(URI_SCHEME_PATTERN)
	if not scheme then
		return false, "must be a <scheme>://<bucket-or-owner>/<path> URI"
	end
	if not URI_ROUTE_SCHEMES[scheme] then
		return false, string.format("scheme %q is not a recognized sync/staging route scheme", scheme)
	end
	local bucket, path = rest:match("^([^/]+)/(.+)$")
	if not bucket or bucket == "" or not path or path == "" then
		return false, "missing bucket/owner or path segment"
	end
	for segment in path:gmatch("[^/]+") do
		if segment == ".." then
			return false, "must not contain a '..' segment"
		end
	end
	return true
end

-- kind -> { src = "local_path" | "uri_route", dst = "local_path" | "uri_route" }
-- (02 §Catalog kinds: sync.pull downloads — src is the remote route, dst
-- is the local absolute path; sync.push / staging.push upload — src is
-- the local absolute path, dst is the remote route.)
local SYNC_ROUTE_SHAPE_BY_KIND = {
	["sync.pull"] = { src = "uri_route", dst = "local_path" },
	["sync.push"] = { src = "local_path", dst = "uri_route" },
	["staging.push"] = { src = "local_path", dst = "uri_route" },
}

--- Runs the route-shape half of check 6 for `sync.pull` / `sync.push` /
--- `staging.push` phases. Returns `nil` on success, or an error message
--- string (`phases[<i>].<field>: <reason>`) on the first violation.
local function check_sync_route_shape(payload, route_shape, path)
	for _, field in ipairs({ "src", "dst" }) do
		local value = payload[field]
		if value ~= nil then
			local shape = route_shape[field]
			local ok, reason
			if shape == "uri_route" then
				ok, reason = check_uri_route_shape(value)
			else
				ok, reason = check_absolute_path_shape(value)
			end
			if not ok then
				return string.format("%s.%s: %s", path, field, reason)
			end
		end
	end
	return nil
end

-- ---------------------------------------------------------------------
-- Per-kind payload shape walk (check 6), driven by
-- `lm.catalog_data.PHASE_KINDS_BY_KIND[kind].fields`.
-- ---------------------------------------------------------------------

local function is_shell_safety_exempt(kind, field_name)
	-- 01-profile-dsl-surface.md §Escape / fragment policy: "Inner escape:
	-- hooks.post_install carries an arbitrary shell script string ... the
	-- single sanctioned place for raw shell inside a profile" — this field
	-- is deliberately outside the shell-safety contract.
	return kind == "hooks.post_install" and field_name == "script"
end

local function check_string_field(value, spec, path, kind)
	if type(value) ~= "string" then
		return string.format("%s: must be a string, got %s", path, type(value))
	end
	if not spec.shell_safe or is_shell_safety_exempt(kind, spec.name) then
		return nil
	end
	local safe
	if spec.pod_id_placeholder then
		safe = is_shell_safe_allowing_pod_id_placeholder(value)
	else
		safe = M.is_shell_safe(value)
	end
	if not safe then
		return string.format("%s: is not shell-safe", path)
	end
	return nil
end

-- Forward-declared so `check_table_field` / `check_list_table_field` can
-- recurse into `walk_field` for nested `shape` entries.
local walk_field

local function check_list_string_field(value, spec, path)
	if type(value) ~= "table" then
		return string.format("%s: must be a list of strings, got %s", path, type(value))
	end
	for idx, entry in ipairs(value) do
		local entry_path = string.format("%s[%d]", path, idx)
		if type(entry) ~= "string" then
			return string.format("%s: must be a string, got %s", entry_path, type(entry))
		end
		if spec.shell_safe and not M.is_shell_safe(entry) then
			return string.format("%s: is not shell-safe", entry_path)
		end
	end
	return nil
end

local function check_list_table_field(value, spec, path, kind)
	if type(value) ~= "table" then
		return string.format("%s: must be a list of tables, got %s", path, type(value))
	end
	for idx, entry in ipairs(value) do
		local entry_path = string.format("%s[%d]", path, idx)
		if type(entry) ~= "table" then
			return string.format("%s: must be a table, got %s", entry_path, type(entry))
		end
		for _, sub_spec in ipairs(spec.shape or {}) do
			local sub_value = entry[sub_spec.name]
			if sub_spec.required and sub_value == nil then
				return string.format("%s.%s: is required", entry_path, sub_spec.name)
			end
			if sub_value ~= nil then
				local err = walk_field(sub_value, sub_spec, entry_path .. "." .. sub_spec.name, kind)
				if err then
					return err
				end
			end
		end
	end
	return nil
end

local function check_table_field(value, spec, path, kind)
	if type(value) ~= "table" then
		return string.format("%s: must be a table, got %s", path, type(value))
	end
	if not spec.shape then
		return nil
	end
	for _, sub_spec in ipairs(spec.shape) do
		local sub_value = value[sub_spec.name]
		if sub_spec.required and sub_value == nil then
			return string.format("%s.%s: is required", path, sub_spec.name)
		end
		if sub_value ~= nil then
			if sub_spec.enum then
				local matched = false
				for _, allowed in ipairs(sub_spec.enum) do
					if sub_value == allowed then
						matched = true
						break
					end
				end
				if not matched then
					return string.format(
						"%s.%s: must be one of %s",
						path,
						sub_spec.name,
						table.concat(sub_spec.enum, "|")
					)
				end
			else
				local err = walk_field(sub_value, sub_spec, path .. "." .. sub_spec.name, kind)
				if err then
					return err
				end
			end
		end
	end
	return nil
end

local function check_env_table_field(value, path)
	if type(value) ~= "table" then
		return string.format("%s: must be a table, got %s", path, type(value))
	end
	for key, _ in pairs(value) do
		if type(key) ~= "string" then
			return string.format("%s: keys must be strings, got %s", path, type(key))
		end
		if not M.is_shell_safe(key) then
			return string.format("%s[%s]: key is not shell-safe", path, key)
		end
	end
	return nil
end

-- Dispatches on `spec.type` (the type vocabulary `lm.catalog_data` uses).
-- `spec.type == "string|SecretRef"` (e.g. `fs.write.content`) and any
-- other type not covered below is deliberately left unchecked here — it
-- is either free-form content/credential-bearing data (never
-- shell-safety-checked, see `catalog_data.lua`'s module doc) or a
-- chapter 04 bridge-internal `opts` shape this milestone does not walk.
walk_field = function(value, spec, path, kind)
	local ftype = spec.type

	if ftype == "string" then
		return check_string_field(value, spec, path, kind)
	elseif ftype == "bool" then
		if type(value) ~= "boolean" then
			return string.format("%s: must be a boolean, got %s", path, type(value))
		end
		return nil
	elseif ftype == "number" then
		if type(value) ~= "number" then
			return string.format("%s: must be a number, got %s", path, type(value))
		end
		return nil
	elseif ftype == "list<string>" then
		return check_list_string_field(value, spec, path)
	elseif ftype == "list<table>" then
		return check_list_table_field(value, spec, path, kind)
	elseif ftype == "table" then
		return check_table_field(value, spec, path, kind)
	elseif ftype == "table<string, string|SecretRef>" then
		return check_env_table_field(value, path)
	end

	return nil
end

--- Runs the per-kind shape walk (check 6) for one phase. Returns `nil` on
--- success, or the first violation's error message.
local function check_phase_shape(phase, path)
	local kind = phase.kind
	local entry = catalog_data.PHASE_KINDS_BY_KIND[kind]
	if entry == nil then
		-- 02-phase-catalog.md §Unknown kinds / §Error surface: not a
		-- validate-stage error.
		return nil
	end

	for _, field_spec in ipairs(entry.fields) do
		local value = phase[field_spec.name]
		if field_spec.required and value == nil then
			return string.format("%s.%s: is required", path, field_spec.name)
		end
		if value ~= nil then
			local err = walk_field(value, field_spec, path .. "." .. field_spec.name, kind)
			if err then
				return err
			end
		end
	end

	local route_shape = SYNC_ROUTE_SHAPE_BY_KIND[kind]
	if route_shape then
		local err = check_sync_route_shape(phase, route_shape, path)
		if err then
			return err
		end
	end

	return nil
end

-- ---------------------------------------------------------------------
-- Secret-shaped key check (check 3).
-- ---------------------------------------------------------------------

local function is_secret_shaped_key(name)
	local upper = name:upper()
	for _, substring in ipairs(catalog_data.SECRET_KEY_SUBSTRINGS) do
		if upper:find(substring, 1, true) then
			return true
		end
	end
	return false
end

-- ---------------------------------------------------------------------
-- lm.validate.validate(ir)
-- ---------------------------------------------------------------------

local DECLARED_LIST_FIELDS = { "capabilities", "env", "env_secrets", "paths", "http_allowlist" }

local function fail(message)
	return { ok = false, error = message }
end

--- Runs the 7 validate-stage checks against `ir`, in order, stopping at
--- the first violation (03-pipeline-stage-artifacts.md §validate).
---
--- @param ir table the IR table (01-profile-dsl-surface.md §Outputs).
--- @return table `{ ok = true, name = ir.name }` on success, or
---   `{ ok = false, error = "<message>" }` on the first violation.
function M.validate(ir)
	-- Check 1: ir is a table; ir.schema == "lm.profile/1"; ir.name is a
	-- non-empty string.
	if type(ir) ~= "table" then
		return fail(string.format("ir must be a table, got %s", type(ir)))
	end
	if ir.schema ~= "lm.profile/1" then
		return fail(string.format('ir.schema must be "lm.profile/1", got %s', tostring(ir.schema)))
	end
	if type(ir.name) ~= "string" or ir.name == "" then
		return fail("ir.name must be a non-empty string")
	end

	-- Check 2: the five declared lists are string lists.
	for _, field in ipairs(DECLARED_LIST_FIELDS) do
		local list = ir[field]
		if type(list) ~= "table" then
			return fail(string.format("ir.%s must be a list of strings, got %s", field, type(list)))
		end
		for idx, entry in ipairs(list) do
			if type(entry) ~= "string" then
				return fail(string.format("ir.%s[%d] must be a string, got %s", field, idx, type(entry)))
			end
		end
	end

	-- Check 3: no `env` key is secret-shaped (case-insensitive substring
	-- match, chapter 02 §Shared vocabulary / chapter 06).
	for idx, name in ipairs(ir.env) do
		if is_secret_shaped_key(name) then
			return fail(string.format("ir.env[%d] (%q) is secret-shaped; declare it in env_secrets instead", idx, name))
		end
	end

	-- Check 4: every `env` / `env_secrets` name is shell-safe.
	for _, field in ipairs({ "env", "env_secrets" }) do
		for idx, name in ipairs(ir[field]) do
			if not M.is_shell_safe(name) then
				return fail(string.format("ir.%s[%d] (%q) is not shell-safe", field, idx, name))
			end
		end
	end

	-- Check 5: every `paths` entry is absolute, free of `..` segments,
	-- and shell-safe.
	for idx, p in ipairs(ir.paths) do
		local ok, reason = check_absolute_path_shape(p)
		if not ok then
			return fail(string.format("ir.paths[%d] (%q) %s", idx, tostring(p), reason))
		end
		if not M.is_shell_safe(p) then
			return fail(string.format("ir.paths[%d] (%q) is not shell-safe", idx, p))
		end
	end

	-- Check 6: phases is a list; each phase passes its per-kind shape
	-- walk (chapter 02), including shell-safety of payload strings and
	-- sync.*/staging.* route shape.
	if type(ir.phases) ~= "table" then
		return fail(string.format("ir.phases must be a list, got %s", type(ir.phases)))
	end
	for idx, phase in ipairs(ir.phases) do
		local path = string.format("phases[%d]", idx)
		if type(phase) ~= "table" then
			return fail(string.format("%s must be a table, got %s", path, type(phase)))
		end
		if type(phase.kind) ~= "string" or phase.kind == "" then
			return fail(string.format("%s.kind must be a non-empty string", path))
		end
		local err = check_phase_shape(phase, path)
		if err then
			return fail(err)
		end
	end

	-- Check 7: service.start names are unique across the profile.
	local seen_service_names = {}
	for idx, phase in ipairs(ir.phases) do
		if phase.kind == "service.start" and type(phase.name) == "string" then
			if seen_service_names[phase.name] then
				return fail(
					string.format("phases[%d].name (%q) duplicates another service.start name", idx, phase.name)
				)
			end
			seen_service_names[phase.name] = true
		end
	end

	return { ok = true, name = ir.name }
end

return M
