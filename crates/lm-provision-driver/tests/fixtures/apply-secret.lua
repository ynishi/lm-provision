-- M5-1/M5-2 driver E2E fixture: a single fs.write step whose content is
-- an env.ref SecretRef (06-secret-handling.md §Inputs "Consumption
-- points"). fs.write resolves a SecretRef unconditionally before
-- checking opts.dry_run (04-bridge.md §Common conventions: "Dry-run
-- therefore still fails on policy violations and missing secrets"), so
-- this fixture exercises the driver's env-only secret-delivery
-- contract (08-push-driver-protocol.md §Driver steps step 2) even
-- under --dry-run: if `DRIVER_TEST_TOKEN` is not exported into the
-- invoked process's environment, this step fails in-report with
-- "missing in host env" rather than reporting ok.
local profile = require("lm.profile")
local token = env.ref("DRIVER_TEST_TOKEN")
return profile({
	name = "demo-driver-apply-secret",
	capabilities = { "fs.write" },
	env_secrets = { "DRIVER_TEST_TOKEN" },
	paths = { "/workspace" },
	phases = {
		{ kind = "fs.write", path = "/workspace/secret.txt", content = token },
	},
})
