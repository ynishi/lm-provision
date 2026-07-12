-- M2-5 CLI regression fixture: rejected by check 3
-- (03-pipeline-stage-artifacts.md §validate — "no `env` key is
-- secret-shaped"). `hash` / `plan` deliberately do not run validate
-- (07-cli.md §Invocation), so this fixture is only used to exercise
-- `validate`'s failure path.
local profile = require("lm.profile")
return profile({
	name = "demo-invalid",
	env = { "MY_TOKEN" },
})
