-- M4-3 `apply --dry-run` regression fixture (07-cli.md §MVP scope;
-- 02-phase-catalog.md §MVP scope real-exec coverage): an sh.exec-routed
-- kind (system.apt), a direct fs.write, and a dispatch_pending kind
-- (comfyui.health with no comfyui.install phase, so no implicit-restart
-- insertion applies) — every step must dry-run-succeed on any platform,
-- since --dry-run propagates to every dispatched op
-- (lm.apply §effective_opts).
local profile = require("lm.profile")
return profile({
	name = "demo-apply-sh-fs",
	capabilities = { "sh.exec", "fs.write" },
	paths = { "/workspace" },
	phases = {
		{ kind = "system.apt", packages = { "curl" } },
		{ kind = "fs.write", path = "/workspace/out.txt", content = "hello" },
		{ kind = "comfyui.health" },
	},
})
