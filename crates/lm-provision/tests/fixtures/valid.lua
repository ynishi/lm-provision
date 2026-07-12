-- M2-5 CLI regression fixture: a profile that validates ok (03
-- §validate) and produces a non-trivial plan (comfyui.install implies
-- comfyui.restart / comfyui.health insertion, 02 §Canonical phase
-- ordering).
local profile = require("lm.profile")
return profile({
	name = "demo-valid",
	capabilities = { "sh.exec" },
	env = { "LOG_LEVEL" },
	env_secrets = { "HF_TOKEN" },
	paths = { "/workspace" },
	http_allowlist = { "https://example.com/*" },
	phases = {
		{ kind = "system.apt", packages = { "curl" } },
		{ kind = "comfyui.install", ref = "abc123" },
	},
})
