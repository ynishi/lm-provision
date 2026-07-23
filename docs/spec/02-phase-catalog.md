# 02. Phase catalog

Status: specified. Layer 1.
Upstream deps: none. MVP: Phase F.

## Purpose

The set of phase kinds a profile may declare, each kind's payload
schema, the required capability set per kind, and the plan-expansion
rules (bucketing, ordering, implicit insertion). Consumers: profile
authors (via chapter 01), the validate stage, the plan stage, the
Rust host (pre-flight static checks).

## Inputs

A phase is represented as a variant of the unified `ProfileNode` AST enum (chapter 01) deriving `DslNode`, `DslSchema`, `DslBuild`, and `DslExec`. In JSON, each phase is represented as an object with `"type": "<KindName>"`. In canonical text, each phase is spelled `<KindName>(...)`.

The catalog below is exhaustive: **22 user-facing phase variants**.

### Catalog kinds (setup lifecycle)


| kind | payload | required capability |
|---|---|---|
| `system.apt` | `packages` list\<string\>, each shell-safe | `sh.exec` |
| `comfyui.install` | `ref` string (required, shell-safe); `repo` string `"<owner>/<name>"` (default `comfyanonymous/ComfyUI`) | `sh.exec` |
| `python.version_check` | `want` string (e.g. `"3.11"`); suppressed from the plan when `want` equals the default `3.12` | `sh.exec` |
| `python.deps` | `deps` list\<string\> (shell-safe); `in_comfy_venv` bool (venv pip vs system pip); `force_reinstall` bool | `sh.exec` |
| `custom_nodes` | `nodes` list of `{ name, repo = "<owner>/<name>", ref?, pip? bool }`, all strings shell-safe | `sh.exec` |
| `sync.pull` | `src` = `b2://<bucket>/<path>`; `dst` absolute path, no `..`; `env` table\<string, string\|SecretRef\> optional; `revision` string optional (hf) | `net.transfer`, or `sh.exec` when routed to a CLI (§Dispatch routing) |
| `sync.push` | `src` absolute path; `dst` = `b2://...` or `hf://<owner>/<repo>/<path>`; `{pod_id}` placeholder allowed in dst | none — marker only, not executed during apply |
| `staging.push` | same shape as `sync.push` plus `env`, `revision`, `commit_message`, `include` list, `exclude` list, `content_type` | `net.transfer` or `sh.exec` (§Dispatch routing) |
| `models` | `models` list of `{ src, dst? \| name?, subdir? \| kind? (default "checkpoints"), sha256? }` → downloads to `/workspace/ComfyUI/models/<subdir>/<dst>` | `net.transfer` |
| `llm_models` | `models` list of `{ src = "hf://<owner>/<repo>[@<rev>]", dst_dir? (default "/tmp/"), revision? }` — repo snapshot download | `sh.exec` (huggingface-cli) |
| `hooks.post_install` | `script` string — raw shell, inner escape (chapter 01) | `sh.exec` |
| `comfyui.restart` | `port` number (default 8188); `extra_args` list\<string\> (shell-safe) | `sh.exec` |
| `comfyui.health` | `port` number (default 8188) — 60 s HTTP poll loop | `sh.exec` |
| `service.start` | `name` string (required, shell-safe, unique across the profile); `platform` = `{ kind = "vllm"\|"ollama"\|"llamacpp", model?, port?, dtype?, tensor_parallel_size?, extra_args? }` | `sh.exec` |
| `service.ready` | `name` string; `check` = `{ http = "<url>", timeout_sec? (default 60) }` | `sh.exec` |

### Catalog kinds (direct operations)

These map 1:1 onto bridge primitives (chapter 04); their payloads
mirror the bridge signatures, with non-core fields forwarded as
`opts`.

| kind | payload | required capability |
|---|---|---|
| `sh.exec` | `argv` list\<string\> (non-empty); `opts` table (chapter 04 §sh.exec) | `sh.exec` |
| `fs.write` | `path` string; `content` string \| SecretRef; other fields → opts | `fs.write` |
| `net.http_get` | `url` string; other fields → opts | `net.http_get` |
| `net.http_post` | `url` string; `body` \| `body_json` \| `body_form`, `headers`, ... → opts | `net.http_post` |
| `net.transfer` | `src`, `dst` strings; other fields → opts | `net.transfer`, or `sh.exec` when routed (§Dispatch routing) |
| `mount.bind` | `src`, `dst` strings; `recursive?`, `read_only?` → opts | `mount.bind` |
| `mount.umount` | `path` string; `lazy?`, `force?` → opts | `mount.umount` |

### Plan-internal kind

`sync.routes` — the plan stage bundles all `sync.pull` /
`sync.push` / `staging.push` phases into a single `sync.routes` step
(payload `{ pull, push_markers, staging_push }`). It is not
user-declarable; a profile declaring `kind = "sync.routes"` falls into
the unknown-kind bucket.

## Outputs

### Canonical phase ordering (plan expansion contract)

The plan stage assigns each kind a canonical phase id and emits steps
in this fixed order (the numbering is part of the contract; the `6_`
slot is intentionally unused):

```
1_system_apt → 2_comfyui_install → 3a_python_version_check →
3_python_deps → 4_custom_nodes → 5_sync_routes → 7_models →
7b_llm_models → 8_post_install → 9_comfyui_restart →
10_comfyui_health → 11_service_<N>_start / 11_service_<N>_ready →
zz_unknown
```

Rules:

- Multiple phases of the same kind share a bucket and keep their
  relative declaration order inside it.
- `service.start` / `service.ready` are numbered per declaration
  index (`11_service_0_start`, `11_service_0_ready`, ...); a
  `service.ready` inherits the index of the most recent
  `service.start` (0 when none preceded). Duplicate `service.start`
  names are a validate-stage error.
- Implicit insertion: when `comfyui.install` is present and the user
  did not declare `comfyui.restart` / `comfyui.health`, both are
  inserted with the default port (or the port carried by whichever of
  the two the user did declare).
- `python.version_check` with `want == "3.12"` (the default) is
  suppressed — the advisory has no effect.
- Direct-operation kinds and any unknown kind land in the trailing
  `zz_unknown` bucket in declaration order (§Unknown kinds).

### Unknown kinds

An unrecognized `kind` is preserved as a trailing step with id
`zz_unknown` (forward-compat: user data is never dropped by the plan
stage). At dispatch it becomes a `dispatch_pending` step; at apply it
is reported with `ok = true` and a note. Unknown kinds therefore
degrade to visible no-ops, never silent drops and never hard errors.

### Dispatch routing (kind → bridge op)

Dispatch turns each planned step into one or more bridge invocations
(chapter 03 §dispatch). Scheme-dependent routing:

- Downloads (`sync.pull`, `net.transfer` download): `b2://` or
  `hf://` src **with a non-empty `env` table** routes to the native
  CLI over `sh.exec` (`b2 download-file-by-name ...`,
  `huggingface-cli download ...`) so credentials flow through
  exec-time env injection. Public `b2://` / `hf://` and `https://`
  stay on the `net.transfer` bridge (scheme resolution in
  chapter 04).
- Uploads (`staging.push`, `net.transfer` upload): `hf://` dst →
  `huggingface-cli upload` argv; `b2://` dst → `b2 upload-file` argv;
  `https://` dst → `net.transfer` bridge (HTTP PUT).
- `hf://<owner>/<repo>@<rev>/<path>`: the `@<rev>` suffix on the repo
  segment pins a revision; a URL-carried revision wins over
  `opts.revision`. `@` is rejected in the owner segment.

### Shared vocabulary (frozen literal sets)

This chapter is the source of truth for three literal sets consumed
elsewhere.
Both the Lua modules and the Rust host embed them; the implementation
form of the sharing (single data file vs mirrored constants) is
internal, byte equality of the sets is the contract.

- Secret-shaped key substrings (chapter 06 rejects `env` keys
  containing any, case-insensitive):
  `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PWD`, `AUTH`, `CRED`,
  `APIKEY`.
- Sensitive-key substrings (chapter 09 audit redaction,
  case-insensitive): `key`, `token`, `secret`, `password`, `pwd`,
  `auth`, `cred`, `apikey`.
- `KNOWN_CAPABILITIES` (chapter 05 L4): `env.ref`, `sh.exec`,
  `net.transfer`, `net.http_get`, `net.http_post`, `fs.write`,
  `mount.bind`, `mount.umount`, `mount.volume_attach` (reserved key —
  declaring it passes the gate build but no bridge exists for it yet,
  so no operation is reachable).

### Editor completion

The per-kind payload schemas form a discriminated union on `kind`.
A codegen step emits `.d.lua` from this union for editor completion;
the same schema is walkable by the Rust host for pre-flight static
checks. The generated artifacts are derived — this chapter's tables
are the source.

### Built-in path constants

Dispatch emits hardcoded well-known paths for the ComfyUI lifecycle:
install dir `/workspace/ComfyUI`, venv pip
`/workspace/ComfyUI/venv/bin/pip`, models root
`/workspace/ComfyUI/models`, custom nodes
`/workspace/ComfyUI/custom_nodes`, service logs
`/tmp/<name>.log`, ComfyUI log `/tmp/comfyui.log`. Profiles that use
these kinds must declare `paths` roots covering them when the
corresponding bridges gate on paths.

## Error surface

- Unknown-field / malformed payload: validate-stage errors with the
  field path (`phases[<i>].<field>: ...`) — precondition class, no
  effects run.
- Shell-unsafe strings anywhere a payload string reaches an argv:
  validate-stage reject (chapter 03 §validate).
- Route shape violations (`sync.*` src/dst schemes, missing bucket or
  path, `..` traversal): validate-stage reject.
- Duplicate `service.start` name: validate-stage reject.
- Unknown kind: **not** an error (see §Unknown kinds).

## Stability

- The 22-kind catalog and per-kind payload field sets: **provisional**
  through Phase H (additive growth expected; removals are breaking).
- Canonical phase ids, fixed ordering, implicit-insertion rules:
  **stable** (hash and report ids depend on them).
- `KNOWN_CAPABILITIES`, secret-key set, sensitive-key set: **stable
  once frozen** — frozen as listed above.
- Shared vocabulary implementation form: **internal**.
- Per-kind `depends_on` + topological sort (a dependency DAG): not
  part of this contract; the fixed order above is the contract (see
  chapter 00).

## Upstream references

- chapter 00 §DSL surface — schema-as-data, shared vocabulary.
- chapter 00 §Sandbox layers — `KNOWN_CAPABILITIES` allowlist.

## MVP scope

Ships in Phase F: all 22 kinds above through
validate → plan → dispatch → apply --dry-run; real-exec coverage for
`sh.exec`-routed kinds, `fs.write`, `net.http_get` / `net.http_post`,
`net.transfer` download/upload, `mount.bind` / `mount.umount`
(Linux).

`mount.volume_attach` remains a reserved capability key with no
catalog kind and no bridge (provider-API-bound; the provisioning
boundary keeps pod lifecycle with the external pod manager,
chapter 08).
