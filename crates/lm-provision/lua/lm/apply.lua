--- lm.apply — executes the dispatched op stream, fail-fast.
--
-- ## Design
--
-- `lm.apply.run(dispatched, opts)` walks `dispatched.steps` (the dispatch
-- artifact `lm.dispatch.dispatch` produces, 03-pipeline-stage-artifacts.md
-- §dispatch) and drives each op step against the bridge primitive its `op`
-- names (04-bridge.md §Outputs) — `sh.exec`, `fs.write`, `net.http_get`,
-- `net.http_post`, `net.transfer`, `mount.bind`, `mount.umount` — via the
-- profile-visible globals `sh` / `fs` / `net` / `mount` those bridges
-- install (registration order step 8). `dispatch_pending` steps never call
-- a bridge at all: they are recorded as a visible skip
-- (09-apply-report-and-ledger.md §Semantics: "dispatch_pending entries are
-- successes").
--
-- This module builds each step's report entry itself (the per-op field
-- table 09 §Outputs "Apply report" defines) rather than delegating that to
-- `lm.report` — the fields come straight out of the bridge call and the op
-- step that produced it, so building them here avoids threading the raw
-- bridge result table through a second module. `lm.report` owns only the
-- top-level envelope (`ok` / `dry_run` / `profile_name` / `steps` /
-- `error`, 09 §Outputs).
--
-- ## Bridge lookup (register-skip aware)
--
-- A capability the profile did not declare never gets its bridge function
-- installed (04 §Registration order: "cap-gated bridge registration —
-- only declared operations are installed (register skip)"), so the
-- profile-visible global for it is `nil` — or, for `net.*` / `mount.*`
-- (three / two operations sharing one table), the shared table exists but
-- the specific field is `nil` when only a sibling operation was granted
-- (`crate::bridge::net::net_table` / `crate::bridge::mount::mount_table`).
-- [`bridge_fn`] below checks for exactly that and returns `nil` either way
-- — the caller, not a raw "attempt to call a nil value" Lua error, decides
-- what happens next (09 §Semantics: "fails in-report ... rather than
-- crashing the run").
--
-- ## Fail-fast and the two failure channels
--
-- Every bridge in 04-bridge.md §Outputs reports an *effect* failure (exit
-- status, transport error, OS error) as an `ok = false` result table —
-- except `fs.write`, whose I/O failures are Lua errors instead (04
-- §Outputs `fs.write`: "I/O failures are Lua errors (surfaced by apply as
-- step failure text)"). `lm.apply` therefore `pcall`s every bridge
-- invocation uniformly: a raised Lua error (a usage / policy / secret
-- error per 04 §Common conventions, or `fs.write`'s I/O-failure case) is
-- caught and folded into the same `ok = false` step-entry shape a result
-- table would have produced, carrying the caught message as this op's
-- error text. Either channel — a result table with `ok = false`, or a
-- caught Lua error — ends the run the same way: the failing step is
-- appended to `steps` as the last entry, the top-level `error` string is
-- built from it (09 §Outputs "error?"), and no further op steps run (09
-- §Semantics: "Steps after it never ran and do not appear — absence from
-- the report means 'not reached'").
--
-- A step whose bridge was never registered (capability undeclared) is
-- folded into the identical `ok = false` shape via a synthetic result
-- table naming the missing capability, rather than a caught error — there
-- is no bridge call to `pcall` in the first place (09 §Semantics).
--
-- `opts.dry_run` (this module's own `dry_run` parameter, distinct from any
-- per-step `opts.dry_run` an author's own `sync.routes` / direct-operation
-- payload happened to carry through dispatch) is propagated into every
-- bridge call this milestone's plan.md hands off ("dry_run flag を全
-- bridge call に伝播"): a step already carrying its own `opts.dry_run =
-- true` keeps it even when the top-level flag is false (a union, not an
-- override), so an apply-time `--dry-run` flag can only ever *add*
-- dry-run behaviour, never remove a per-step one a profile already opted
-- into.

local report_mod = require("lm.report")

local M = {}

-- ---------------------------------------------------------------------
-- Bridge lookup (register-skip aware, see module doc comment).
-- ---------------------------------------------------------------------

--- Returns the bridge function for `op`, or `nil` when the profile did
--- not declare the capability that installs it (register skip, 04
--- §Registration order step 8). Reading an unset global (`sh` / `net` /
--- `fs` / `mount`) is not a Lua error — it simply evaluates to `nil` — so
--- this is a plain lookup, not a `pcall`.
local function bridge_fn(op)
	if op == "sh.exec" then
		return sh and sh.exec or nil
	elseif op == "fs.write" then
		return fs and fs.write or nil
	elseif op == "net.http_get" then
		return net and net.http_get or nil
	elseif op == "net.http_post" then
		return net and net.http_post or nil
	elseif op == "net.transfer" then
		return net and net.transfer or nil
	elseif op == "mount.bind" then
		return mount and mount.bind or nil
	elseif op == "mount.umount" then
		return mount and mount.umount or nil
	end
	return nil
end

-- ---------------------------------------------------------------------
-- opts.dry_run propagation (union with any per-step opts.dry_run).
-- ---------------------------------------------------------------------

--- Shallow-copies `op_step.opts` (never `nil` — an absent `opts` becomes
--- `{}`) and forces `dry_run = true` onto the copy when either the
--- apply-level `global_dry_run` flag or the step's own `opts.dry_run` is
--- truthy. The original `op_step.opts` table is never mutated: dispatch's
--- own output stays reusable across repeated `lm.apply.run` calls (e.g. a
--- real run following a `--dry-run` preview of the same dispatched
--- stream).
local function effective_opts(op_step, global_dry_run)
	local opts = op_step.opts or {}
	if not (global_dry_run or opts.dry_run) then
		return opts
	end
	local merged = {}
	for k, v in pairs(opts) do
		merged[k] = v
	end
	merged.dry_run = true
	return merged
end

-- ---------------------------------------------------------------------
-- Bridge invocation (one call per op, matching each primitive's
-- signature, 04-bridge.md §Outputs).
-- ---------------------------------------------------------------------

--- Calls `fn` (already known non-nil, see [`bridge_fn`]) with the
--- positional arguments `op_step.op` requires. Never called directly —
--- always through `pcall` (see the module doc comment's "Fail-fast and
--- the two failure channels" section), since a usage / policy / secret
--- Lua error here must become a report step failure, not crash the run.
local function invoke_bridge(fn, op_step, global_dry_run)
	local op = op_step.op
	local opts = effective_opts(op_step, global_dry_run)
	if op == "sh.exec" then
		return fn(op_step.argv, opts)
	elseif op == "fs.write" then
		return fn(op_step.path, op_step.content, opts)
	elseif op == "net.http_get" or op == "net.http_post" then
		return fn(op_step.url, opts)
	elseif op == "net.transfer" or op == "mount.bind" then
		return fn(op_step.src, op_step.dst, opts)
	elseif op == "mount.umount" then
		return fn(op_step.path, opts)
	end
	-- Unreachable for any op `lm.dispatch` actually emits (03 §dispatch's
	-- op enum is exactly these seven plus `dispatch_pending`, handled
	-- separately by the caller) — a defensive guard against a future op
	-- enum member this module has not been taught to invoke yet.
	error(string.format("lm.apply: invoke_bridge called with an unrecognized op %q", tostring(op)), 0)
end

-- ---------------------------------------------------------------------
-- Step-entry construction (09-apply-report-and-ledger.md §Outputs "Apply
-- report" — common fields + the per-op field table).
-- ---------------------------------------------------------------------

--- `dispatch_pending` step entries are always successes (09 §Semantics):
--- `ok = true`, `status = 0`, and the dispatch-provided `note` — no
--- bridge call, no `dry_run` field (09's per-op field table lists none
--- for this op).
local function pending_entry(op_step)
	return {
		id = op_step.id,
		kind = op_step.kind,
		op = "dispatch_pending",
		ok = true,
		status = 0,
		note = op_step.note,
	}
end

--- Builds one step entry from `op_step` (the dispatch-produced op step —
--- the source of `argv` / `path` / `url` / `src` / `dst`, since not every
--- bridge result echoes them all back, e.g. `net.transfer`'s result
--- carries only whichever side its own direction produced) and
--- `bridge_result` (either a genuine bridge return value, or the synthetic
--- `{ ok = false, status = -1, error = ... }` table this module builds
--- for a missing bridge or a caught Lua error — see the module doc
--- comment). Every field access below is nil-safe so this one function
--- serves the successful-call, missing-bridge, and caught-error cases
--- alike.
local function build_step_entry(op_step, bridge_result)
	local entry = {
		id = op_step.id,
		kind = op_step.kind,
		op = op_step.op,
		ok = bridge_result.ok,
		status = bridge_result.status or (bridge_result.ok and 0 or -1),
	}
	if bridge_result.dry_run ~= nil then
		entry.dry_run = bridge_result.dry_run
	end

	local op = op_step.op
	if op == "sh.exec" then
		entry.argv = op_step.argv
		entry.stdout = bridge_result.stdout or ""
		-- `timed_out` surfaces via the stderr suffix `sh.exec` itself
		-- already appends (04 §Outputs `sh.exec`), so no separate
		-- `timed_out` field is carried into the report (09 §Outputs
		-- lists none for this op either).
		entry.stderr = bridge_result.stderr or bridge_result.error or ""
	elseif op == "fs.write" then
		entry.path = op_step.path
		entry.bytes = bridge_result.bytes or 0
	elseif op == "net.http_get" or op == "net.http_post" then
		entry.url = op_step.url
		entry.body_bytes = #(bridge_result.body or "")
		entry.stderr = bridge_result.error
	elseif op == "net.transfer" then
		-- `src` / `dst` come from the op step, not the bridge result: a
		-- `net.transfer` result only echoes back whichever side its
		-- resolved direction produced (`dst` on download, `src` on
		-- upload, 04 §Outputs `net.transfer`), while 09's per-op field
		-- table wants both on every `net.transfer` step entry.
		entry.src = op_step.src
		entry.dst = op_step.dst
		entry.bytes = bridge_result.bytes or 0
		entry.sha256 = bridge_result.sha256
		entry.stderr = bridge_result.error
	elseif op == "mount.bind" then
		entry.src = op_step.src
		entry.dst = op_step.dst
		entry.stderr = bridge_result.error
	elseif op == "mount.umount" then
		entry.path = op_step.path
		entry.stderr = bridge_result.error
	end

	return entry
end

-- ---------------------------------------------------------------------
-- Failure text (09 §Outputs `error?`: "step <id> (<kind>) failed:
-- <stderr|reason>").
-- ---------------------------------------------------------------------

--- Picks the human-readable reason a failing (non-pending) step carries.
--- `sh.exec` always has a `stderr` string (empty at worst); every other
--- op's failure text lives in the bridge's own `error` field (04 §Outputs,
--- shared by `net.*` / `mount.*`) or, for `fs.write` / a missing bridge /
--- a caught Lua error, the synthetic `bridge_result.error` this module
--- builds — `fs.write`'s own successful-path result never has an `error`
--- field at all (04 §Outputs `fs.write`: `{ ok, bytes, dry_run }`), so
--- this function is only ever reached once a failure already occurred.
local function failure_reason(op, bridge_result)
	if op == "sh.exec" then
		return bridge_result.stderr or bridge_result.error or ""
	end
	return bridge_result.error or bridge_result.stderr or "unknown error"
end

-- ---------------------------------------------------------------------
-- lm.apply.run(dispatched, opts)
-- ---------------------------------------------------------------------

--- Executes the dispatched op stream, fail-fast, and returns the apply
--- report artifact (09-apply-report-and-ledger.md §Outputs "Apply
--- report").
---
--- @param dispatched table the dispatch artifact (`lm.dispatch.dispatch`
---   output, 03-pipeline-stage-artifacts.md §dispatch: `{ profile_name,
---   steps }`).
--- @param opts table|nil `{ dry_run = bool }` — the apply-level dry-run
---   flag, propagated into every bridge call (see the module doc
---   comment).
--- @return table the apply report: `{ ok, dry_run, profile_name, steps,
---   error? }`.
function M.run(dispatched, opts)
	if type(dispatched) ~= "table" then
		error(string.format("lm.apply.run: dispatched must be a table, got %s", type(dispatched)), 0)
	end
	opts = opts or {}
	local global_dry_run = opts.dry_run and true or false

	local steps = {}
	local err_message = nil

	for _, op_step in ipairs(dispatched.steps or {}) do
		local entry
		local failing_bridge_result

		if op_step.op == "dispatch_pending" then
			entry = pending_entry(op_step)
		else
			local fn = bridge_fn(op_step.op)
			local bridge_result
			if fn == nil then
				-- 09 §Semantics: "A step whose required bridge is not
				-- registered (capability undeclared) fails in-report
				-- (status = -1, stderr names the missing capability)
				-- rather than crashing the run."
				bridge_result = {
					ok = false,
					status = -1,
					error = string.format("capability '%s' not declared in profile.capabilities", op_step.op),
				}
			else
				local call_ok, result_or_err = pcall(invoke_bridge, fn, op_step, global_dry_run)
				if call_ok then
					bridge_result = result_or_err
				else
					-- A usage / policy / secret Lua error (04 §Common
					-- conventions), or fs.write's I/O-failure case (04
					-- §Outputs `fs.write`) — either way, "surfaced by
					-- apply as step failure text" rather than crashing
					-- the whole run.
					bridge_result = { ok = false, status = -1, error = tostring(result_or_err) }
				end
			end
			entry = build_step_entry(op_step, bridge_result)
			failing_bridge_result = bridge_result
		end

		steps[#steps + 1] = entry

		if not entry.ok then
			-- Fail-fast (09 §Semantics): this is the last entry; steps
			-- after it never ran and do not appear.
			err_message = string.format(
				"step %s (%s) failed: %s",
				entry.id,
				entry.kind,
				failure_reason(op_step.op, failing_bridge_result)
			)
			break
		end
	end

	return report_mod.build({
		profile_name = dispatched.profile_name,
		dry_run = global_dry_run,
		steps = steps,
		error = err_message,
	})
end

return M
