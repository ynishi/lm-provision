--- lm.dispatch — routes plan steps to bridge operation calls.
--
-- ## Design
--
-- `lm.dispatch.dispatch(plan)` walks `plan.steps` (the plan artifact
-- produced by `lm.plan.expand`, 03-pipeline-stage-artifacts.md §plan)
-- and maps each plan step to one or more *op steps* — the bridge
-- invocations `lm.apply` (milestone M4) will actually execute. Like
-- `lm.plan`, this stage is pure Lua: it never calls a bridge itself (03
-- §Inputs: "All five stages are pure Lua computation ... no bridge
-- calls"); it only decides *which* bridge call a step should become and
-- assembles that call's arguments.
--
-- A plan step may fan out to N op steps (03 §dispatch: "e.g. custom_nodes
-- emits clone / checkout / pip per node; sync.routes emits one step per
-- route"). Fan-out ids are built by suffixing the plan step's own `id`
-- with one of the seven literal patterns 03 §dispatch enumerates:
-- `/pull_<i>`, `/marker_<i>`, `/staging_<i>`, `/<i>`, `/<i>_clone`,
-- `/<i>_ref`, `/<i>_pip` (`<i>` is the 1-based position within that plan
-- step's own list — sync.routes' three lists and each custom_nodes /
-- models / llm_models phase's own entry list each restart their `<i>`
-- counter at 1). Plan steps that need no fan-out keep the plan step's id
-- verbatim, including the trailing zz_unknown bucket's shared literal id
-- (02-phase-catalog.md §Unknown kinds).
--
-- ## Scope boundary (what this module does and does not synthesize)
--
-- This milestone's explicit deliverable (workspace/tasks/lm-provision-impl/
-- plan.md M2-4) is the op enum, the fan-out suffix mechanics, and scheme
-- routing for the download/upload kinds (02 §Dispatch routing). Chapters
-- 00-10 give a literal CLI command *name* for exactly four cases — `b2
-- download-file-by-name`, `b2 upload-file`, `huggingface-cli download`,
-- `huggingface-cli upload` — plus `{"sh", "-c", script}` for
-- `hooks.post_install` (04-bridge.md §sh.exec: "callers that need shell
-- semantics pass {"sh", "-c", script} explicitly"). This module builds
-- concrete `sh.exec` / `net.transfer` op steps for those cases (plus the
-- direct-operation kinds, `models`, `custom_nodes`, `comfyui.install`,
-- `system.apt`, and `python.deps`, whose CLI shape is either a 1:1
-- bridge mirror or an unambiguous, singular convention for the tool
-- named — see each `dispatch_*` helper's own comment for the specific
-- literal it is following).
--
-- For phase kinds where *no* chapter gives even a command name or a
-- built-in path constant to anchor a concrete invocation on — chaper
-- 02's payload columns describe *what* `service.start` / `comfyui.health`
-- / `comfyui.restart` / `python.version_check` / `service.ready` mean,
-- but never *how* to invoke them as a shell command, and chapter 04's
-- bridge primitive set has no polling primitive for the "60s HTTP poll
-- loop" `comfyui.health` / `service.ready` describe — this module emits a
-- `dispatch_pending` step instead of inventing one (03 §dispatch:
-- "dispatch_pending steps carry payload and a human-readable note; they
-- are report-visible skips, not failures"). Each such step's `note`
-- names the missing information rather than a guessed command. This is
-- reported as an explicit, unconfirmed scope boundary in the impl-lead
-- M2-4 report, not a silent gap.

local M = {}

-- ---------------------------------------------------------------------
-- Built-in path constants (02-phase-catalog.md §Built-in path
-- constants).
-- ---------------------------------------------------------------------

local COMFYUI_INSTALL_DIR = "/workspace/ComfyUI"
local COMFYUI_VENV_PIP = "/workspace/ComfyUI/venv/bin/pip"
local MODELS_ROOT = "/workspace/ComfyUI/models"
local CUSTOM_NODES_ROOT = "/workspace/ComfyUI/custom_nodes"
local DEFAULT_MODEL_SUBDIR = "checkpoints"
local DEFAULT_LLM_MODELS_DST_DIR = "/tmp/"

-- ---------------------------------------------------------------------
-- Small helpers.
-- ---------------------------------------------------------------------

local function non_empty_table(t)
	return type(t) == "table" and next(t) ~= nil
end

--- `scheme, rest = parse_uri("b2://bucket/path")` → `"b2", "bucket/path"`.
--- Returns `nil` when `s` has no `<scheme>://` prefix (a local path).
local function parse_uri(s)
	if type(s) ~= "string" then
		return nil
	end
	local scheme, rest = s:match("^(%a[%w+.%-]*)://(.*)$")
	if not scheme then
		return nil
	end
	return scheme, rest
end

--- Parses the remainder of an `hf://` URI (everything after `hf://`)
--- into its owner / repo / revision / trailing-path parts (02
--- §Dispatch routing: "hf://<owner>/<repo>@<rev>/<path>: the @<rev>
--- suffix on the repo segment pins a revision ... @ is rejected in the
--- owner segment"). `rev` and `path` are `nil` when absent — the
--- `llm_models` shape (`hf://<owner>/<repo>[@<rev>]`, no trailing path)
--- and the `sync.pull` / `staging.push` shape (with a trailing
--- `/<path>`) share this one parser.
local function parse_hf_uri(rest)
	local owner, remainder = rest:match("^([^/]+)/(.*)$")
	if not owner then
		error("lm.dispatch: hf:// URI is missing an owner/repo segment: " .. tostring(rest), 0)
	end
	if owner:find("@", 1, true) then
		error("lm.dispatch: '@' is not allowed in the hf:// owner segment: " .. owner, 0)
	end
	local repo_and_rev, path = remainder:match("^([^/]*)(/?.*)$")
	if path == "" then
		path = nil
	elseif path and path:sub(1, 1) == "/" then
		path = path:sub(2)
	end
	local repo, rev = repo_and_rev:match("^([^@]+)@(.+)$")
	if not repo then
		repo = repo_and_rev
	end
	return owner, repo, rev, path
end

--- Copies every field of `phase` except `kind` and the names in
--- `core_fields` into a fresh table — the `opts_catchall` convention
--- `lm.catalog_data` documents for the direct-operation kinds whose
--- payload "mirrors the bridge signature[ ], with non-core fields
--- forwarded as opts" (02 §Catalog kinds (direct operations)).
local function catchall_opts(phase, core_fields)
	local opts = {}
	for k, v in pairs(phase) do
		if k ~= "kind" and not core_fields[k] then
			opts[k] = v
		end
	end
	return opts
end

--- A `dispatch_pending` op step: "report-visible skips, not failures" (03
--- §dispatch).
local function pending(id, kind, payload, note)
	return { id = id, kind = kind, op = "dispatch_pending", payload = payload, note = note }
end

-- ---------------------------------------------------------------------
-- Scheme routing (02 §Dispatch routing) — shared by sync.pull, sync.push
-- fan-out (marker only, see dispatch_sync_routes), staging.push, and a
-- directly-declared net.transfer phase.
-- ---------------------------------------------------------------------

--- Routes one download (`sync.pull` entry, or a directly-declared
--- `net.transfer` phase inferred as a download). `extra_opts` carries
--- whatever non-core fields the caller already collected (`env`,
--- `revision`, ...); it becomes the emitted step's `opts` verbatim.
---
--- b2:// with a non-empty `env` table routes to the native CLI (`b2
--- download-file-by-name <bucket> <path> <dst>` — three positional
--- arguments, the command's full documented interface, so no flag is
--- invented). hf:// with a non-empty `env` table is **not** dispatched
--- concretely here: `huggingface-cli download`'s `--local-dir` names a
--- destination *directory*, while `dst` in this shape is an exact
--- destination *file* path (04-bridge.md §net.transfer: "Download
--- streams to the destination file") — reconciling the two would require
--- inventing a post-download rename step chapters 00-10 never describe,
--- so this degrades to a `dispatch_pending` step instead (reported as an
--- unconfirmed scope boundary, see this module's header comment).
--- Everything else (public b2:// / hf://, or https://) stays on the
--- `net.transfer` bridge, which performs the scheme resolution itself
--- (04 §net.transfer).
local function dispatch_download(id, kind, src, dst, extra_opts)
	extra_opts = extra_opts or {}
	local scheme, rest = parse_uri(src)
	if scheme == "b2" and non_empty_table(extra_opts.env) then
		local bucket, path = rest:match("^([^/]+)/(.+)$")
		if not bucket or not path then
			error("lm.dispatch: malformed b2:// URI (missing bucket or path): " .. tostring(src), 0)
		end
		return {
			id = id,
			kind = kind,
			op = "sh.exec",
			argv = { "b2", "download-file-by-name", bucket, path, dst },
			opts = extra_opts,
		}
	elseif scheme == "hf" and non_empty_table(extra_opts.env) then
		return pending(
			id,
			kind,
			{ src = src, dst = dst, opts = extra_opts },
			"hf:// CLI download routing is unconfirmed: huggingface-cli download's --local-dir "
				.. "names a destination directory, but dst here is an exact destination file path "
				.. "(04 §net.transfer 'streams to the destination file'); chapters 00-10 do not "
				.. "specify how to reconcile the two"
		)
	else
		return { id = id, kind = kind, op = "net.transfer", src = src, dst = dst, opts = extra_opts }
	end
end

--- Routes one upload (`staging.push` entry, or a directly-declared
--- `net.transfer` phase inferred as an upload). Unlike downloads, an
--- hf:// / b2:// upload dst is **always** CLI-routed, unconditional on
--- `env` — 04-bridge.md §net.transfer states this outright: "Upload
--- directly to an hf:// / b2:// dst is rejected at this bridge — the
--- dispatch layer routes those to the native CLIs over sh.exec". Both
--- `b2 upload-file <bucket> <src> <path>` and `huggingface-cli upload
--- <owner>/<repo> <src> [<path-in-repo>] [--revision <rev>]` operate on
--- exact file paths in both directions, so (unlike the hf download case
--- above) there is no destination-shape mismatch to defer on. `https://`
--- dst stays on the `net.transfer` bridge (HTTP PUT).
local function dispatch_upload(id, kind, src, dst, extra_opts)
	extra_opts = extra_opts or {}
	local scheme, rest = parse_uri(dst)
	if scheme == "b2" then
		local bucket, path = rest:match("^([^/]+)/(.+)$")
		if not bucket or not path then
			error("lm.dispatch: malformed b2:// URI (missing bucket or path): " .. tostring(dst), 0)
		end
		return {
			id = id,
			kind = kind,
			op = "sh.exec",
			argv = { "b2", "upload-file", bucket, src, path },
			opts = extra_opts,
		}
	elseif scheme == "hf" then
		local owner, repo, url_rev, path_in_repo = parse_hf_uri(rest)
		local rev = url_rev or extra_opts.revision
		local argv = { "huggingface-cli", "upload", owner .. "/" .. repo, src }
		if path_in_repo then
			argv[#argv + 1] = path_in_repo
		end
		if rev then
			argv[#argv + 1] = "--revision"
			argv[#argv + 1] = rev
		end
		return { id = id, kind = kind, op = "sh.exec", argv = argv, opts = extra_opts }
	else
		return { id = id, kind = kind, op = "net.transfer", src = src, dst = dst, opts = extra_opts }
	end
end

-- ---------------------------------------------------------------------
-- sync.routes (plan-internal bundle, 02 §Plan-internal kind) fan-out.
-- ---------------------------------------------------------------------

--- `pull` entries route per `dispatch_download` (`/pull_<i>` suffix).
--- `push_markers` (`sync.push`) are never executed — 02 §Catalog kinds:
--- "none — marker only, not executed during apply" — so every entry
--- degrades to a `dispatch_pending` step (`/marker_<i>` suffix)
--- regardless of scheme; that is the spec-confirmed mapping for this
--- kind, not a deferred unknown. `staging_push` entries route per
--- `dispatch_upload` (`/staging_<i>` suffix).
local function dispatch_sync_routes(id, bundle)
	local out = {}
	for i, entry in ipairs(bundle.pull or {}) do
		out[#out + 1] = dispatch_download(
			id .. "/pull_" .. i,
			"sync.pull",
			entry.src,
			entry.dst,
			{ env = entry.env, revision = entry.revision }
		)
	end
	for i, entry in ipairs(bundle.push_markers or {}) do
		out[#out + 1] = pending(
			id .. "/marker_" .. i,
			"sync.push",
			entry,
			"sync.push is a marker only; it is not executed during apply (02 §Catalog kinds)"
		)
	end
	for i, entry in ipairs(bundle.staging_push or {}) do
		local extra_opts = {
			env = entry.env,
			revision = entry.revision,
			commit_message = entry.commit_message,
			include = entry.include,
			exclude = entry.exclude,
			content_type = entry.content_type,
		}
		out[#out + 1] = dispatch_upload(id .. "/staging_" .. i, "staging.push", entry.src, entry.dst, extra_opts)
	end
	return out
end

-- ---------------------------------------------------------------------
-- models / llm_models fan-out (`/<i>` suffix, 03 §dispatch).
-- ---------------------------------------------------------------------

--- Each `models` entry downloads to the built-in models-root path (02
--- §Built-in path constants: "models root /workspace/ComfyUI/models") —
--- `net.transfer` unconditionally, since `models`' only declared
--- capability is `net.transfer` (02 §Catalog kinds), never a CLI.
local function dispatch_models(base_id, phase)
	local out = {}
	for i, model in ipairs(phase.models or {}) do
		local subdir = model.subdir or model.kind or DEFAULT_MODEL_SUBDIR
		local filename = model.dst or model.name
		local dst = MODELS_ROOT .. "/" .. subdir .. "/" .. filename
		out[#out + 1] = {
			id = base_id .. "/" .. i,
			kind = "models",
			op = "net.transfer",
			src = model.src,
			dst = dst,
			opts = { sha256 = model.sha256 },
		}
	end
	return out
end

--- Each `llm_models` entry is a full repo-snapshot download via
--- `huggingface-cli download <owner>/<repo> --local-dir <dst_dir>
--- [--revision <rev>]` — `llm_models`' only declared capability is
--- `sh.exec (huggingface-cli)` (02 §Catalog kinds), so this always
--- CLI-routes (no `env` gate, unlike sync.pull: there is no `env` field
--- on this kind's payload to gate on). `dst_dir` is explicitly a
--- directory (catalog default `"/tmp/"`), so — unlike the sync.pull hf
--- download case — there is no destination-shape mismatch here.
local function dispatch_llm_models(base_id, phase)
	local out = {}
	for i, model in ipairs(phase.models or {}) do
		local scheme, rest = parse_uri(model.src)
		if scheme ~= "hf" then
			error(
				string.format(
					"lm.dispatch: llm_models.models[%d].src must be an hf:// URI, got %s",
					i,
					tostring(model.src)
				),
				0
			)
		end
		local owner, repo, url_rev = parse_hf_uri(rest)
		local rev = url_rev or model.revision
		local dst_dir = model.dst_dir or DEFAULT_LLM_MODELS_DST_DIR
		local argv = { "huggingface-cli", "download", owner .. "/" .. repo, "--local-dir", dst_dir }
		if rev then
			argv[#argv + 1] = "--revision"
			argv[#argv + 1] = rev
		end
		out[#out + 1] = { id = base_id .. "/" .. i, kind = "llm_models", op = "sh.exec", argv = argv }
	end
	return out
end

-- ---------------------------------------------------------------------
-- custom_nodes fan-out (`/<i>_clone`, `/<i>_ref`, `/<i>_pip`, 03
-- §dispatch).
-- ---------------------------------------------------------------------

--- Every node clones unconditionally (`/<i>_clone`); `/<i>_ref` (git
--- checkout) is emitted only when the node declares `ref`, and
--- `/<i>_pip` (pip install) only when it declares `pip = true` — mirrors
--- 02 §Catalog kinds custom_nodes.nodes[].{ref?, pip?}. `repo` is
--- `"<owner>/<name>"` (02 §Catalog kinds); this module clones it from
--- GitHub, following the same convention `comfyui.install`'s own catalog
--- default (`comfyanonymous/ComfyUI`, a real GitHub repository) already
--- assumes — an interpretive extension, reported as such, not a literal
--- transcription of chapter text.
local function dispatch_custom_nodes(base_id, phase)
	local out = {}
	for i, node in ipairs(phase.nodes or {}) do
		local node_dir = CUSTOM_NODES_ROOT .. "/" .. node.name
		out[#out + 1] = {
			id = base_id .. "/" .. i .. "_clone",
			kind = "custom_nodes",
			op = "sh.exec",
			argv = { "git", "clone", "https://github.com/" .. node.repo .. ".git", node_dir },
		}
		if node.ref ~= nil then
			out[#out + 1] = {
				id = base_id .. "/" .. i .. "_ref",
				kind = "custom_nodes",
				op = "sh.exec",
				argv = { "git", "-C", node_dir, "checkout", node.ref },
			}
		end
		if node.pip then
			out[#out + 1] = {
				id = base_id .. "/" .. i .. "_pip",
				kind = "custom_nodes",
				op = "sh.exec",
				argv = { COMFYUI_VENV_PIP, "install", "-r", node_dir .. "/requirements.txt" },
			}
		end
	end
	return out
end

-- ---------------------------------------------------------------------
-- Remaining setup-lifecycle kinds with a single, unambiguous CLI
-- convention (no fan-out; each returns one op step).
-- ---------------------------------------------------------------------

--- `apt-get install -y <packages...>` — the standard non-interactive
--- form of the one command chapter 02 names a capability for
--- (`system.apt`, `sh.exec`); no other flag is added.
local function dispatch_system_apt(id, phase)
	local argv = { "apt-get", "install", "-y" }
	for _, pkg in ipairs(phase.packages or {}) do
		argv[#argv + 1] = pkg
	end
	return { id = id, kind = "system.apt", op = "sh.exec", argv = argv }
end

--- `git clone <repo> <install-dir> && git -C <install-dir> checkout
--- <ref>`, wrapped in `{"sh", "-c", ...}` — the same shell-escape
--- convention `hooks.post_install` uses (04 §sh.exec), applied here
--- because a single `sh.exec` op step carries exactly one `argv`, and
--- cloning-then-pinning-a-ref is two commands. `ref` and `repo` are both
--- marked `shell_safe` in `lm.catalog_data`, so validate has already
--- confirmed they are safe to interpolate without quoting (03 §validate
--- "Shell-safety contract: ... Safe strings can be interpolated into
--- argv without quoting").
local function dispatch_comfyui_install(id, phase)
	local repo = phase.repo or "comfyanonymous/ComfyUI"
	local url = "https://github.com/" .. repo .. ".git"
	local script = string.format(
		"git clone %s %s && git -C %s checkout %s",
		url,
		COMFYUI_INSTALL_DIR,
		COMFYUI_INSTALL_DIR,
		phase.ref
	)
	return { id = id, kind = "comfyui.install", op = "sh.exec", argv = { "sh", "-c", script } }
end

--- `<pip> install [--force-reinstall] <deps...>`, where `<pip>` is the
--- venv-relative constant (02 §Built-in path constants) when
--- `in_comfy_venv` is true, else the system `pip` on `PATH` — mirrors
--- 02 §Catalog kinds python.deps.{in_comfy_venv, force_reinstall}.
local function dispatch_python_deps(id, phase)
	local pip = phase.in_comfy_venv and COMFYUI_VENV_PIP or "pip"
	local argv = { pip, "install" }
	if phase.force_reinstall then
		argv[#argv + 1] = "--force-reinstall"
	end
	for _, dep in ipairs(phase.deps or {}) do
		argv[#argv + 1] = dep
	end
	return { id = id, kind = "python.deps", op = "sh.exec", argv = argv }
end

-- ---------------------------------------------------------------------
-- Direct-operation kinds (02 §Catalog kinds (direct operations)): map
-- 1:1 onto the matching bridge primitive, no fan-out.
-- ---------------------------------------------------------------------

local DIRECT_OP_CORE_FIELDS = {
	["fs.write"] = { path = true, content = true },
	["net.http_get"] = { url = true },
	["net.http_post"] = { url = true },
	["net.transfer"] = { src = true, dst = true },
}

--- A directly-declared `net.transfer` phase (as opposed to one dispatch
--- itself synthesizes from `sync.routes`) still needs the same scheme
--- routing: direction is inferred from which side carries a URI scheme
--- (04 §net.transfer: "Direction is inferred after resolution: URL→path
--- = download, path→URL = upload"); URL→URL / path→path is left to the
--- bridge to reject (04 §net.transfer: "the latter points the caller at
--- fs.*"), since dispatch's job here is routing, not the validate-stage
--- content check that already ran.
local function dispatch_net_transfer_direct(id, phase)
	local opts = catchall_opts(phase, DIRECT_OP_CORE_FIELDS["net.transfer"])
	local src_scheme = parse_uri(phase.src)
	local dst_scheme = parse_uri(phase.dst)
	if src_scheme and not dst_scheme then
		return dispatch_download(id, "net.transfer", phase.src, phase.dst, opts)
	elseif dst_scheme and not src_scheme then
		return dispatch_upload(id, "net.transfer", phase.src, phase.dst, opts)
	else
		return { id = id, kind = "net.transfer", op = "net.transfer", src = phase.src, dst = phase.dst, opts = opts }
	end
end

local function dispatch_direct_op(id, kind, phase)
	if kind == "sh.exec" then
		return { id = id, kind = kind, op = "sh.exec", argv = phase.argv, opts = phase.opts or {} }
	elseif kind == "fs.write" then
		local opts = catchall_opts(phase, DIRECT_OP_CORE_FIELDS["fs.write"])
		return { id = id, kind = kind, op = "fs.write", path = phase.path, content = phase.content, opts = opts }
	elseif kind == "net.http_get" then
		local opts = catchall_opts(phase, DIRECT_OP_CORE_FIELDS["net.http_get"])
		return { id = id, kind = kind, op = "net.http_get", url = phase.url, opts = opts }
	elseif kind == "net.http_post" then
		local opts = catchall_opts(phase, DIRECT_OP_CORE_FIELDS["net.http_post"])
		return { id = id, kind = kind, op = "net.http_post", url = phase.url, opts = opts }
	elseif kind == "net.transfer" then
		return dispatch_net_transfer_direct(id, phase)
	elseif kind == "mount.bind" then
		return {
			id = id,
			kind = kind,
			op = "mount.bind",
			src = phase.src,
			dst = phase.dst,
			opts = { recursive = phase.recursive, read_only = phase.read_only },
		}
	elseif kind == "mount.umount" then
		return {
			id = id,
			kind = kind,
			op = "mount.umount",
			path = phase.path,
			opts = { lazy = phase.lazy, force = phase.force },
		}
	end
	error(
		string.format("lm.dispatch: dispatch_direct_op called with a non-direct-operation kind %q", tostring(kind)),
		0
	)
end

local DIRECT_OP_KINDS = {
	["sh.exec"] = true,
	["fs.write"] = true,
	["net.http_get"] = true,
	["net.http_post"] = true,
	["net.transfer"] = true,
	["mount.bind"] = true,
	["mount.umount"] = true,
}

-- ---------------------------------------------------------------------
-- lm.dispatch.dispatch(plan)
-- ---------------------------------------------------------------------

--- Dispatches one plan step into a list of op steps (always a list, even
--- when it fans out to exactly one, so the caller can `extend` uniformly).
local function dispatch_plan_step(plan_step)
	local id = plan_step.id
	local kind = plan_step.kind
	local phase = plan_step.payload

	if kind == "system.apt" then
		return { dispatch_system_apt(id, phase) }
	elseif kind == "comfyui.install" then
		return { dispatch_comfyui_install(id, phase) }
	elseif kind == "python.deps" then
		return { dispatch_python_deps(id, phase) }
	elseif kind == "custom_nodes" then
		return dispatch_custom_nodes(id, phase)
	elseif kind == "sync.routes" then
		return dispatch_sync_routes(id, phase)
	elseif kind == "models" then
		return dispatch_models(id, phase)
	elseif kind == "llm_models" then
		return dispatch_llm_models(id, phase)
	elseif kind == "hooks.post_install" then
		return { { id = id, kind = kind, op = "sh.exec", argv = { "sh", "-c", phase.script } } }
	elseif kind == "python.version_check" then
		return {
			pending(
				id,
				kind,
				phase,
				"python.version_check has no defined dispatch mapping — chapters 00-10 describe "
					.. "the advisory but never a check command (unconfirmed, deferred)"
			),
		}
	elseif kind == "comfyui.restart" then
		return {
			pending(
				id,
				kind,
				phase,
				"comfyui.restart has no defined dispatch mapping — chapters 00-10 never specify "
					.. "a restart command (unconfirmed, deferred)"
			),
		}
	elseif kind == "comfyui.health" then
		return {
			pending(
				id,
				kind,
				phase,
				"comfyui.health has no defined dispatch mapping — its '60s HTTP poll loop' has no "
					.. "matching bridge primitive in chapter 04 (unconfirmed, deferred)"
			),
		}
	elseif kind == "service.start" then
		return {
			pending(
				id,
				kind,
				phase,
				"service.start has no defined dispatch mapping — the platform-specific "
					.. "(vllm/ollama/llamacpp) launch command is not specified in chapters 00-10 "
					.. "(unconfirmed, deferred)"
			),
		}
	elseif kind == "service.ready" then
		return {
			pending(
				id,
				kind,
				phase,
				"service.ready has no defined dispatch mapping — its HTTP poll has no matching "
					.. "bridge primitive in chapter 04 (unconfirmed, deferred)"
			),
		}
	elseif DIRECT_OP_KINDS[kind] then
		return { dispatch_direct_op(id, kind, phase) }
	else
		-- Genuinely unrecognized kind (02 §Unknown kinds: "At dispatch it
		-- becomes a dispatch_pending step").
		return {
			pending(
				id,
				kind,
				phase,
				string.format("unrecognized phase kind %q has no dispatch mapping (02 §Unknown kinds)", tostring(kind))
			),
		}
	end
end

--- Dispatches the plan artifact into the op-step artifact
--- (03-pipeline-stage-artifacts.md §dispatch).
---
--- @param plan table the plan artifact (03 §plan Outputs).
--- @return table `{ profile_name, steps = { <op step>, ... } }`.
function M.dispatch(plan)
	if type(plan) ~= "table" then
		error(string.format("lm.dispatch.dispatch: plan must be a table, got %s", type(plan)), 0)
	end

	local out = {}
	for _, plan_step in ipairs(plan.steps or {}) do
		for _, op_step in ipairs(dispatch_plan_step(plan_step)) do
			out[#out + 1] = op_step
		end
	end

	return { profile_name = plan.profile_name, steps = out }
end

return M
