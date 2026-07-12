--- lm.report — builds the apply report artifact.
--
-- Always emitted on both success and step failure, carrying structured
-- per-step results (09-apply-report-and-ledger.md §Outputs "Apply
-- report"). `lm.apply` owns building each per-step entry (the bridge call
-- and its per-op fields); this module owns only the top-level envelope —
-- `ok`, `dry_run`, `profile_name`, `steps`, and the optional `error`
-- string — so the "what does the report look like as a whole" question
-- has exactly one answer, independent of which op produced which step.

local M = {}

--- Builds the top-level apply report table.
---
--- @param opts table `{ profile_name, dry_run, steps, error }` — `steps`
---   is the already-built list of per-step entries (`lm.apply`'s own
---   [`M.run`] loop); `error` is the fail-fast message (09 §Outputs
---   `error?`: `"step <id> (<kind>) failed: <stderr|reason>"`) or `nil`
---   when every executed step succeeded.
--- @return table `{ ok, dry_run, profile_name, steps, error? }` (09
---   §Outputs "Apply report"): `ok` is true iff every executed step was
---   `ok` — equivalently, iff `opts.error` is absent.
function M.build(opts)
	opts = opts or {}
	local report = {
		ok = opts.error == nil,
		dry_run = opts.dry_run and true or false,
		profile_name = opts.profile_name,
		steps = opts.steps or {},
	}
	if opts.error ~= nil then
		report.error = opts.error
	end
	return report
end

return M
