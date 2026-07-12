-- M4-3 `apply --dry-run` regression fixture (07-cli.md §MVP scope;
-- 02-phase-catalog.md §MVP scope real-exec coverage): direct
-- mount.bind / mount.umount phases. `--dry-run` short-circuits before
-- the platform-gated syscall path in both bridges (04-bridge.md
-- §Outputs `mount.bind` / `mount.umount`), so this dry-runs to
-- `ok = true` identically on Linux and non-Linux dev machines.
local profile = require("lm.profile")
return profile({
	name = "demo-apply-mount",
	capabilities = { "mount.bind", "mount.umount" },
	paths = { "/workspace" },
	phases = {
		{ kind = "mount.bind", src = "/workspace/src", dst = "/workspace/dst" },
		{ kind = "mount.umount", path = "/workspace/dst" },
	},
})
