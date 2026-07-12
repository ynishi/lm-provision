--- lm.catalog_data — shared vocabulary data file (single source of truth).
--
-- ## Design
--
-- 00-overview.md §Consolidated design decisions ("Shared vocabulary
-- lives in one canonical data file") requires the 22 phase kinds, the
-- `KNOWN_CAPABILITIES` set, the secret-key substring set, and the
-- sensitive-key substring set to live in exactly one place that both the
-- Lua host and the Rust host reference. This module is that place; it is
-- embedded into the Rust binary as `lm.catalog_data`
-- (`crates/lm-provision/src/embed.rs`) so the two hosts read
-- byte-identical literal sets without a second, drifting copy.
--
-- This module is pure data (02-phase-catalog.md §Inputs / §Shared
-- vocabulary). It performs no validation and exposes no behaviour; the
-- validate / plan / dispatch stages (chapter 03, milestone M2) walk this
-- table, they do not extend it.
--
-- `required` on a field entry is `true` / `false` only where chapter 02's
-- payload column gives an explicit signal (a `(required, ...)` note, a
-- trailing `?`, or a stated default). Where 02 states neither, `required`
-- is left `nil` — this module does not invent a requiredness the chapter
-- does not state (see impl-lead M1-1 report: reported as unconfirmed
-- rather than guessed).
--
-- `shell_safe = true` on a `string` (or `list<string>`, applied
-- entry-wise) field entry marks fields the validate stage (chapter 03
-- §validate check 6, milestone M2-1) must run through the shell-safety
-- contract. It is set only where 02's payload column states "shell-safe"
-- verbatim (`system.apt.packages`, `comfyui.install.ref`,
-- `python.deps.deps`, `custom_nodes.nodes[].{name,repo,ref}`,
-- `comfyui.restart.extra_args`, `service.start.name`), plus the
-- `sync.pull` / `sync.push` / `staging.push` `src` / `dst` route fields —
-- 02 §Dispatch routing documents these as reaching an argv (native CLI
-- invocation) even though the payload-column cell text does not repeat
-- "shell-safe" there; this is an interpretive extension, reported as
-- unconfirmed in the impl-lead M2-1 report rather than a literal 02
-- transcription. Fields without this flag (e.g. free-form content —
-- `staging.push.commit_message`, glob patterns — `include` / `exclude`,
-- `fs.write.content`) are deliberately never shell-safety-checked; validate
-- still enforces their declared type and requiredness.
--
-- `pod_id_placeholder = true` marks a `dst` field where the literal
-- `{pod_id}` substring is exempt from the shell-safety charset (02
-- §Catalog kinds `sync.push`: "`{pod_id}` placeholder allowed in dst").

local M = {}

-- ---------------------------------------------------------------------
-- Catalog kinds (02-phase-catalog.md §Catalog kinds, 22 user-facing
-- kinds — exhaustive). Order mirrors the two source tables: "setup
-- lifecycle" (15) then "direct operations" (7).
-- ---------------------------------------------------------------------

M.PHASE_KINDS = {
	{
		kind = "system.apt",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "packages", type = "list<string>", shell_safe = true, note = "each entry shell-safe" },
		},
	},
	{
		kind = "comfyui.install",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "ref", type = "string", required = true, shell_safe = true, note = "shell-safe" },
			{
				name = "repo",
				type = "string",
				required = false,
				default = "comfyanonymous/ComfyUI",
				note = 'format "<owner>/<name>"',
			},
		},
	},
	{
		kind = "python.version_check",
		capabilities = { "sh.exec" },
		fields = {
			{
				name = "want",
				type = "string",
				required = false,
				default = "3.12",
				note = 'e.g. "3.11"; phase is suppressed from the plan when want equals the default 3.12',
			},
		},
	},
	{
		kind = "python.deps",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "deps", type = "list<string>", shell_safe = true, note = "shell-safe" },
			{ name = "in_comfy_venv", type = "bool", note = "venv pip vs system pip" },
			{ name = "force_reinstall", type = "bool" },
		},
	},
	{
		kind = "custom_nodes",
		capabilities = { "sh.exec" },
		fields = {
			{
				name = "nodes",
				type = "list<table>",
				note = "all strings shell-safe",
				shape = {
					{ name = "name", type = "string", shell_safe = true },
					{ name = "repo", type = "string", shell_safe = true, note = 'format "<owner>/<name>"' },
					{ name = "ref", type = "string", required = false, shell_safe = true },
					{ name = "pip", type = "bool", required = false },
				},
			},
		},
	},
	{
		kind = "sync.pull",
		capabilities = { "net.transfer", "sh.exec" },
		capability_note = "net.transfer, or sh.exec when routed to a CLI (02 §Dispatch routing)",
		fields = {
			{ name = "src", type = "string", shell_safe = true, note = 'format "b2://<bucket>/<path>"' },
			{ name = "dst", type = "string", shell_safe = true, note = "absolute path, no .. segment" },
			{ name = "env", type = "table<string, string|SecretRef>", required = false },
			{ name = "revision", type = "string", required = false, note = "hf" },
		},
	},
	{
		kind = "sync.push",
		capabilities = {},
		capability_note = "none — marker only, not executed during apply",
		fields = {
			{ name = "src", type = "string", shell_safe = true, note = "absolute path" },
			{
				name = "dst",
				type = "string",
				shell_safe = true,
				pod_id_placeholder = true,
				note = 'format "b2://..." or "hf://<owner>/<repo>/<path>"; {pod_id} placeholder allowed',
			},
		},
	},
	{
		kind = "staging.push",
		capabilities = { "net.transfer", "sh.exec" },
		capability_note = "net.transfer or sh.exec (02 §Dispatch routing)",
		fields = {
			{ name = "src", type = "string", shell_safe = true, note = "same shape as sync.push" },
			{
				name = "dst",
				type = "string",
				shell_safe = true,
				pod_id_placeholder = true,
				note = "same shape as sync.push",
			},
			{ name = "env", type = "table<string, string|SecretRef>", required = false },
			{ name = "revision", type = "string", required = false },
			{ name = "commit_message", type = "string", required = false },
			{ name = "include", type = "list<string>", required = false },
			{ name = "exclude", type = "list<string>", required = false },
			{ name = "content_type", type = "string", required = false },
		},
	},
	{
		kind = "models",
		capabilities = { "net.transfer" },
		fields = {
			{
				name = "models",
				type = "list<table>",
				note = "downloads to /workspace/ComfyUI/models/<subdir>/<dst>",
				shape = {
					{ name = "src", type = "string" },
					{ name = "dst", type = "string", required = false, note = "one of dst|name" },
					{ name = "name", type = "string", required = false, note = "one of dst|name" },
					{ name = "subdir", type = "string", required = false, note = "one of subdir|kind" },
					{
						name = "kind",
						type = "string",
						required = false,
						default = "checkpoints",
						note = "one of subdir|kind",
					},
					{ name = "sha256", type = "string", required = false },
				},
			},
		},
	},
	{
		kind = "llm_models",
		capabilities = { "sh.exec" },
		capability_note = "huggingface-cli",
		fields = {
			{
				name = "models",
				type = "list<table>",
				note = "repo snapshot download",
				shape = {
					{ name = "src", type = "string", note = 'format "hf://<owner>/<repo>[@<rev>]"' },
					{ name = "dst_dir", type = "string", required = false, default = "/tmp/" },
					{ name = "revision", type = "string", required = false },
				},
			},
		},
	},
	{
		kind = "hooks.post_install",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "script", type = "string", note = "raw shell, inner escape (01)" },
		},
	},
	{
		kind = "comfyui.restart",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "port", type = "number", required = false, default = 8188 },
			{ name = "extra_args", type = "list<string>", required = false, shell_safe = true, note = "shell-safe" },
		},
	},
	{
		kind = "comfyui.health",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "port", type = "number", required = false, default = 8188, note = "60s HTTP poll loop" },
		},
	},
	{
		kind = "service.start",
		capabilities = { "sh.exec" },
		fields = {
			{
				name = "name",
				type = "string",
				required = true,
				shell_safe = true,
				note = "shell-safe, unique across the profile",
			},
			{
				name = "platform",
				type = "table",
				shape = {
					{ name = "kind", type = "string", enum = { "vllm", "ollama", "llamacpp" } },
					{ name = "model", type = "string", required = false },
					{ name = "port", type = "number", required = false },
					{ name = "dtype", type = "string", required = false },
					{ name = "tensor_parallel_size", type = "number", required = false },
					{ name = "extra_args", type = "list<string>", required = false },
				},
			},
		},
	},
	{
		kind = "service.ready",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "name", type = "string", note = "must reference a declared service.start name" },
			{
				name = "check",
				type = "table",
				shape = {
					{ name = "http", type = "string", note = 'format "<url>"' },
					{ name = "timeout_sec", type = "number", required = false, default = 60 },
				},
			},
		},
	},
	-- Direct operations (chapter 02 §Catalog kinds (direct operations)):
	-- payloads mirror the bridge signatures 1:1 (chapter 04); non-core
	-- fields forward to `opts` verbatim.
	{
		kind = "sh.exec",
		capabilities = { "sh.exec" },
		fields = {
			{ name = "argv", type = "list<string>", note = "non-empty" },
			{ name = "opts", type = "table", required = false, note = "chapter 04 §sh.exec" },
		},
	},
	{
		kind = "fs.write",
		capabilities = { "fs.write" },
		opts_catchall = true,
		fields = {
			{ name = "path", type = "string" },
			{ name = "content", type = "string|SecretRef" },
		},
	},
	{
		kind = "net.http_get",
		capabilities = { "net.http_get" },
		opts_catchall = true,
		fields = {
			{ name = "url", type = "string" },
		},
	},
	{
		kind = "net.http_post",
		capabilities = { "net.http_post" },
		opts_catchall = true,
		capability_note = "body | body_json | body_form, headers, ... forward to opts",
		fields = {
			{ name = "url", type = "string" },
		},
	},
	{
		kind = "net.transfer",
		capabilities = { "net.transfer", "sh.exec" },
		capability_note = "net.transfer, or sh.exec when routed (02 §Dispatch routing)",
		opts_catchall = true,
		fields = {
			{ name = "src", type = "string" },
			{ name = "dst", type = "string" },
		},
	},
	{
		kind = "mount.bind",
		capabilities = { "mount.bind" },
		fields = {
			{ name = "src", type = "string" },
			{ name = "dst", type = "string" },
			{ name = "recursive", type = "bool", required = false, note = "forwarded to opts" },
			{ name = "read_only", type = "bool", required = false, note = "forwarded to opts" },
		},
	},
	{
		kind = "mount.umount",
		capabilities = { "mount.umount" },
		fields = {
			{ name = "path", type = "string" },
			{ name = "lazy", type = "bool", required = false, note = "forwarded to opts" },
			{ name = "force", type = "bool", required = false, note = "forwarded to opts" },
		},
	},
}

-- O(1) lookup by kind name, derived from `PHASE_KINDS` (same data, no new
-- fields). `sync.routes` is deliberately absent — it is plan-internal,
-- not user-declarable (02 §Plan-internal kind); a profile that declares
-- `kind = "sync.routes"` falls into the unknown-kind bucket at plan time.
M.PHASE_KINDS_BY_KIND = {}
for _, entry in ipairs(M.PHASE_KINDS) do
	M.PHASE_KINDS_BY_KIND[entry.kind] = entry
end

-- Plan-internal kinds: not user-declarable (02 §Plan-internal kind).
-- Recorded here only as documentation for the plan stage (M2); this is
-- not part of the phase catalog itself.
M.PLAN_INTERNAL_KINDS = { "sync.routes" }

-- ---------------------------------------------------------------------
-- KNOWN_CAPABILITIES (05-sandbox-layer-contract.md §L4, listed in
-- 02-phase-catalog.md §Shared vocabulary). Operation-scoped, 9 entries.
-- `mount.volume_attach` is a reserved key: declaring it passes the L4
-- gate build but no bridge exists for it, so no operation is reachable.
-- ---------------------------------------------------------------------

M.KNOWN_CAPABILITIES = {
	"env.ref",
	"sh.exec",
	"net.transfer",
	"net.http_get",
	"net.http_post",
	"fs.write",
	"mount.bind",
	"mount.umount",
	"mount.volume_attach",
}

M.RESERVED_CAPABILITIES = {
	["mount.volume_attach"] = true,
}

-- ---------------------------------------------------------------------
-- Secret-shaped key substrings (02-phase-catalog.md §Shared vocabulary;
-- 06-secret-handling.md — chapter 06 rejects `env` keys containing any of
-- these, case-insensitive). 8 entries.
-- ---------------------------------------------------------------------

M.SECRET_KEY_SUBSTRINGS = {
	"KEY",
	"SECRET",
	"TOKEN",
	"PASSWORD",
	"PWD",
	"AUTH",
	"CRED",
	"APIKEY",
}

-- ---------------------------------------------------------------------
-- Sensitive-key substrings (02-phase-catalog.md §Shared vocabulary;
-- 09-apply-report-and-ledger.md — chapter 09 audit redaction drives
-- `[REDACTED]` on a case-insensitive substring match). 8 entries. Note:
-- the literal casing and ordering differ from `SECRET_KEY_SUBSTRINGS`
-- above (chapter 06 vs chapter 09 each state their own literal list;
-- this module transcribes both verbatim rather than unifying them).
-- ---------------------------------------------------------------------

M.SENSITIVE_KEY_SUBSTRINGS = {
	"key",
	"token",
	"secret",
	"password",
	"pwd",
	"auth",
	"cred",
	"apikey",
}

return M
