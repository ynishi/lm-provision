--- lm.plan — expands the IR into the ordered execution plan artifact.
--
-- ## Design
--
-- `lm.plan.expand(ir)` walks `ir.phases` once, buckets each phase by its
-- canonical phase id (02-phase-catalog.md §Canonical phase ordering),
-- applies the two content-sensitive rules (implicit `comfyui.restart` /
-- `comfyui.health` insertion, `python.version_check` default-value
-- suppression), assigns per-declaration `service.start` / `service.ready`
-- indices, and finally numbers every emitted step with a 1-based
-- contiguous `index` in emission order (03-pipeline-stage-artifacts.md
-- §plan).
--
-- This stage is pure Lua computation over the IR table — no bridge
-- calls, no policy checks (03 §Inputs). Per-phase *content* problems
-- (missing required fields, shell-unsafe strings, ...) are the validate
-- stage's job (03 §validate); this stage assumes `ir` already passed
-- validation and raises only on a malformed top-level `ir` (03 §Error
-- surface: "plan / dispatch: raise only on malformed stage input
-- (non-table)").
--
-- Bucket → canonical id table (02 §Canonical phase ordering, the fixed
-- emission order this module reproduces exactly):
--
-- ```
-- 1_system_apt → 2_comfyui_install → 3a_python_version_check →
-- 3_python_deps → 4_custom_nodes → 5_sync_routes → 7_models →
-- 7b_llm_models → 8_post_install → 9_comfyui_restart →
-- 10_comfyui_health → 11_service_<N>_start / 11_service_<N>_ready →
-- zz_unknown
-- ```
--
-- (the `6_` slot is intentionally unused, per 02's literal ordering
-- list — this module never emits it).
--
-- `sync.pull` / `sync.push` / `staging.push` are not individually
-- bucketed: they are collected and folded into the single plan-internal
-- `sync.routes` step (02 §Plan-internal kind) at position `5_sync_routes`.
-- A profile declaring the literal `kind = "sync.routes"` itself is *not*
-- one of these three kinds, so it falls through to the trailing
-- `zz_unknown` bucket like any other unrecognized kind (02 §Plan-internal
-- kind: "a profile declaring kind = 'sync.routes' falls into the
-- unknown-kind bucket").
--
-- Direct-operation kinds (`sh.exec`, `fs.write`, `net.http_get`,
-- `net.http_post`, `net.transfer`, `mount.bind`, `mount.umount`) and any
-- kind this module does not recognize both land in the trailing
-- `zz_unknown` bucket, in original declaration order relative to each
-- other (02 §Canonical phase ordering: "Direct-operation kinds and any
-- unknown kind land in the trailing zz_unknown bucket in declaration
-- order"). Every entry in that bucket carries the literal id
-- `"zz_unknown"` (02 §Unknown kinds: "preserved as a trailing step with
-- id zz_unknown") — the step's own `kind` field (set to the phase's
-- original `kind`) is what a downstream stage uses to tell them apart,
-- not `id`.

local M = {}

-- ---------------------------------------------------------------------
-- Constants (02 §Catalog kinds defaults / §Canonical phase ordering).
-- ---------------------------------------------------------------------

local DEFAULT_COMFYUI_PORT = 8188
local DEFAULT_PYTHON_VERSION_WANT = "3.12"

-- Setup-lifecycle kinds that get their own canonical bucket (everything
-- else is either folded into the sync.routes bundle, numbered as a
-- service step, or falls through to zz_unknown). Keyed by kind, value is
-- an accumulator list populated by the single pass over `ir.phases`
-- below.
local function new_bucket_state()
	return {
		["system.apt"] = {},
		["comfyui.install"] = {},
		["python.version_check"] = {},
		["python.deps"] = {},
		["custom_nodes"] = {},
		["sync.pull"] = {},
		["sync.push"] = {},
		["staging.push"] = {},
		["models"] = {},
		["llm_models"] = {},
		["hooks.post_install"] = {},
		["comfyui.restart"] = {},
		["comfyui.health"] = {},
	}
end

-- ---------------------------------------------------------------------
-- lm.plan.expand(ir)
-- ---------------------------------------------------------------------

--- Expands `ir` into the ordered plan artifact
--- (03-pipeline-stage-artifacts.md §plan).
---
--- @param ir table the IR table (01-profile-dsl-surface.md §Outputs).
--- @return table `{ profile_name, schema, steps = { { index, id, kind,
---   payload }, ... } }`.
function M.expand(ir)
	if type(ir) ~= "table" then
		error(string.format("lm.plan.expand: ir must be a table, got %s", type(ir)), 0)
	end

	local phases = ir.phases
	if phases == nil then
		phases = {}
	elseif type(phases) ~= "table" then
		error(string.format("lm.plan.expand: ir.phases must be a table, got %s", type(phases)), 0)
	end

	local by_kind = new_bucket_state()
	local service_steps = {}
	local zz_unknown = {}

	-- Per-declaration service.start numbering (02 §Canonical phase
	-- ordering: "service.start / service.ready are numbered per
	-- declaration index ... a service.ready inherits the index of the
	-- most recent service.start (0 when none preceded)").
	local next_service_index = 0
	local current_service_index = 0

	for _, phase in ipairs(phases) do
		local kind = phase.kind
		if kind == "service.start" then
			local idx = next_service_index
			next_service_index = next_service_index + 1
			current_service_index = idx
			service_steps[#service_steps + 1] = {
				id = string.format("11_service_%d_start", idx),
				kind = kind,
				payload = phase,
			}
		elseif kind == "service.ready" then
			service_steps[#service_steps + 1] = {
				id = string.format("11_service_%d_ready", current_service_index),
				kind = kind,
				payload = phase,
			}
		elseif by_kind[kind] ~= nil then
			table.insert(by_kind[kind], phase)
		else
			-- Direct-operation kinds and genuinely unknown kinds both land
			-- here (02 §Canonical phase ordering); declaration order across
			-- the two is preserved because this is a single pass over
			-- `phases`.
			zz_unknown[#zz_unknown + 1] = { kind = kind, payload = phase }
		end
	end

	local steps = {}
	local function emit(id, kind, payload)
		steps[#steps + 1] = { id = id, kind = kind, payload = payload }
	end

	-- 1_system_apt
	for _, phase in ipairs(by_kind["system.apt"]) do
		emit("1_system_apt", "system.apt", phase)
	end

	-- 2_comfyui_install
	for _, phase in ipairs(by_kind["comfyui.install"]) do
		emit("2_comfyui_install", "comfyui.install", phase)
	end

	-- 3a_python_version_check — suppressed when `want` (or its default)
	-- equals "3.12" (02 §Catalog kinds python.version_check).
	for _, phase in ipairs(by_kind["python.version_check"]) do
		local want = phase.want or DEFAULT_PYTHON_VERSION_WANT
		if want ~= DEFAULT_PYTHON_VERSION_WANT then
			emit("3a_python_version_check", "python.version_check", phase)
		end
	end

	-- 3_python_deps
	for _, phase in ipairs(by_kind["python.deps"]) do
		emit("3_python_deps", "python.deps", phase)
	end

	-- 4_custom_nodes
	for _, phase in ipairs(by_kind["custom_nodes"]) do
		emit("4_custom_nodes", "custom_nodes", phase)
	end

	-- 5_sync_routes — plan-internal bundle (02 §Plan-internal kind).
	-- Only emitted when at least one sync.pull / sync.push / staging.push
	-- phase was declared; the payload's three lists preserve each kind's
	-- own relative declaration order.
	local pull = by_kind["sync.pull"]
	local push_markers = by_kind["sync.push"]
	local staging_push = by_kind["staging.push"]
	if #pull > 0 or #push_markers > 0 or #staging_push > 0 then
		emit("5_sync_routes", "sync.routes", { pull = pull, push_markers = push_markers, staging_push = staging_push })
	end

	-- 7_models
	for _, phase in ipairs(by_kind["models"]) do
		emit("7_models", "models", phase)
	end

	-- 7b_llm_models
	for _, phase in ipairs(by_kind["llm_models"]) do
		emit("7b_llm_models", "llm_models", phase)
	end

	-- 8_post_install
	for _, phase in ipairs(by_kind["hooks.post_install"]) do
		emit("8_post_install", "hooks.post_install", phase)
	end

	-- 9_comfyui_restart / 10_comfyui_health, with implicit insertion (02
	-- §Canonical phase ordering: "when comfyui.install is present and the
	-- user did not declare comfyui.restart / comfyui.health, both are
	-- inserted with the default port (or the port carried by whichever of
	-- the two the user did declare)").
	local restart_list = by_kind["comfyui.restart"]
	local health_list = by_kind["comfyui.health"]
	if #by_kind["comfyui.install"] > 0 then
		if #restart_list == 0 and #health_list == 0 then
			restart_list = { { kind = "comfyui.restart", port = DEFAULT_COMFYUI_PORT } }
			health_list = { { kind = "comfyui.health", port = DEFAULT_COMFYUI_PORT } }
		elseif #restart_list == 0 then
			local port = health_list[1].port or DEFAULT_COMFYUI_PORT
			restart_list = { { kind = "comfyui.restart", port = port } }
		elseif #health_list == 0 then
			local port = restart_list[1].port or DEFAULT_COMFYUI_PORT
			health_list = { { kind = "comfyui.health", port = port } }
		end
	end
	for _, phase in ipairs(restart_list) do
		emit("9_comfyui_restart", "comfyui.restart", phase)
	end
	for _, phase in ipairs(health_list) do
		emit("10_comfyui_health", "comfyui.health", phase)
	end

	-- 11_service_<N>_start / 11_service_<N>_ready — already built above in
	-- original declaration order (interleaving multiple services keeps
	-- each service's start/ready pair adjacent when declared adjacently).
	for _, s in ipairs(service_steps) do
		steps[#steps + 1] = s
	end

	-- zz_unknown — trailing bucket, declaration order (02 §Unknown kinds).
	for _, u in ipairs(zz_unknown) do
		emit("zz_unknown", u.kind, u.payload)
	end

	-- 1-based contiguous index in emission order (03 §plan Outputs).
	for i, step in ipairs(steps) do
		step.index = i
	end

	return { profile_name = ir.name, schema = ir.schema, steps = steps }
end

return M
