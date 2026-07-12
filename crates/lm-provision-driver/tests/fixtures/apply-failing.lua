-- M5-1 driver E2E fixture for the "exit 1 + parseable report" path
-- (08-push-driver-protocol.md §Error surface: "the driver must treat
-- ... a richer signal than the exit code alone"). No capability is
-- declared at all, so `sh` is never installed on the sandboxed VM
-- (register skip, 04-bridge.md §Registration order); the sh.exec step
-- below fails in-report with status = -1 and a "capability not
-- declared" error, deterministically and without spawning a process
-- (mirrors crates/lm-provision/tests/fixtures/apply-failing-step.lua).
local profile = require("lm.profile")
return profile({
	name = "demo-driver-apply-failing",
	phases = {
		{ kind = "sh.exec", argv = { "echo", "hi" } },
	},
})
