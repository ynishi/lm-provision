-- M4-3 `apply --dry-run` regression fixture (07-cli.md §MVP scope;
-- 02-phase-catalog.md §MVP scope real-exec coverage): direct
-- net.http_get / net.http_post / net.transfer (download direction —
-- URL src, path dst) phases. `--dry-run` skips the effect at every
-- bridge (04-bridge.md §Common conventions), so no network call is ever
-- made; only http_allowlist / paths policy checks run.
local profile = require("lm.profile")
return profile({
	name = "demo-apply-net",
	capabilities = { "net.http_get", "net.http_post", "net.transfer" },
	http_allowlist = { "https://example.com/" },
	paths = { "/workspace" },
	phases = {
		{ kind = "net.http_get", url = "https://example.com/x" },
		{ kind = "net.http_post", url = "https://example.com/y", body = "hi" },
		{ kind = "net.transfer", src = "https://example.com/z", dst = "/workspace/z.bin" },
	},
})
