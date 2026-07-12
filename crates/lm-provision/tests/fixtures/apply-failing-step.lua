-- M4-3 `apply` failure-path fixture (09-apply-report-and-ledger.md
-- §Semantics: "A step whose required bridge is not registered
-- (capability undeclared) fails in-report ... rather than crashing the
-- run."). No capability is declared at all, so `sh` is never installed
-- on the sandboxed VM (register skip, 04-bridge.md §Registration
-- order); the sh.exec step below therefore fails in-report with
-- status = -1 and a "capability not declared" error, deterministically
-- and without ever spawning a process.
local profile = require("lm.profile")
return profile({
	name = "demo-apply-failing",
	phases = {
		{ kind = "sh.exec", argv = { "echo", "hi" } },
	},
})
