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

The dotted label and the `<KindName>` are two spellings of the same
kind, and the correspondence is tabulated rather than derived: two
labels do not follow the mechanical UpperCamelCase rule (`comfyui`
spells `ComfyUi`, and `hooks.post_install` drops its group).

```
system.apt            SystemApt             sh.exec         ShExec
comfyui.install       ComfyUiInstall        fs.write        FsWrite
toolchain.python      ToolchainPython       net.http_get    NetHttpGet
python.version_check  PythonVersionCheck    net.http_post   NetHttpPost
python.deps           PythonDeps            net.transfer    NetTransfer
custom_nodes          CustomNodes           mount.bind      MountBind
sync.pull             SyncPull              mount.umount    MountUmount
sync.push             SyncPush
staging.push          StagingPush
models                Models
llm_models            LlmModels
hooks.post_install    PostInstall
comfyui.restart       ComfyUiRestart
comfyui.health        ComfyUiHealth
service.start         ServiceStart
service.ready         ServiceReady
```

### Catalog kinds (setup lifecycle)


| kind | payload | required capability |
|---|---|---|
| `system.apt` | `packages` list\<string\>, each shell-safe | `sh.exec` |
| `comfyui.install` | `ref` string (required, shell-safe); `repo` string `"<owner>/<name>"` (default `comfyanonymous/ComfyUI`); `install_dir` string (default `/workspace/ComfyUI`) — where the checkout lands, and what every ComfyUI-relative path derives from (§Resource-derived paths) | `sh.exec` |
| `toolchain.python` | `requirements` string optional (a `requirements.txt` to install into the venv, filtered — §Torch-family filter); `isolated` bool (default `false`: the venv **inherits** the host interpreter's packages) | `sh.exec` |
| `python.version_check` | `want` string (e.g. `"3.11"`); suppressed from the plan when `want` equals the default `3.12` | `sh.exec` |
| `python.deps` | `deps` list\<string\> (shell-safe); `in_comfy_venv` bool (venv pip vs system pip); `force_reinstall` bool | `sh.exec` |
| `custom_nodes` | `nodes` list of `{ name, repo = "<owner>/<name>", ref?, pip? bool }`, all strings shell-safe | `sh.exec` |
| `sync.pull` | `src` = `b2://<bucket>/<path>` \| `hf://<owner>/<repo>[@<rev>]/<path>` \| `https://...`; `dst` absolute path, no `..` (a **file** path, except on the hf-cli route — §Dispatch routing); `env` table\<string, string\|SecretRef\> optional; `revision` string optional (hf) | `net.transfer`, or `sh.exec` when routed to a CLI (§Dispatch routing) |
| `sync.push` | `src` absolute path; `dst` = `b2://...` or `hf://<owner>/<repo>/<path>`; `{pod_id}` placeholder allowed in dst | none — marker only, not executed during apply |
| `staging.push` | same shape as `sync.push` plus `env`, `revision`, `commit_message`, `include` list, `exclude` list, `content_type` | `net.transfer` or `sh.exec` (§Dispatch routing) |
| `models` | `models` list of `{ src = "https://...", dst? \| name?, subdir? \| kind? (default "checkpoints"), sha256? }` → downloads to `/workspace/ComfyUI/models/<subdir>/<dst>`. At least one of `dst` / `name` is required and `dst` wins when both appear; `subdir` likewise wins over `kind`. `sha256` is 64 hex characters (validate-stage reject otherwise) and drives the completion condition below. Not scheme-routed: a credential-bearing `b2://` / `hf://` source belongs on `sync.pull` (§Dispatch routing) | `net.transfer` |
| `llm_models` | `models` list of `{ src = "hf://<owner>/<repo>[@<rev>]", dst_dir? (default "/tmp/"), revision? }` — repo snapshot download, always over the hf CLI (not scheme-routed) | `sh.exec` (hf CLI) |
| `hooks.post_install` | `script` string — raw shell, inner escape (chapter 01) | `sh.exec` |
| `comfyui.restart` | `port` number (default 8188); `extra_args` list\<string\> (shell-safe) | `sh.exec` |
| `comfyui.health` | `port` number (default 8188); `timeout_sec?` number (default 180) — poll of `/object_info` | `net.http_get` |
| `service.start` | `name` string (required, shell-safe, unique across the profile); `platform` = `{ kind string, model? (shell-safe), port?, dtype? (shell-safe), tensor_parallel_size?, extra_args? (shell-safe) }`. `kind` is a free string: `"vllm"`, `"ollama"`, `"llamacpp"` are the values this catalog gives an argv shape, any other value expands to a note step (§Spawn-and-poll invocations) | `sh.exec` |
| `service.ready` | `name` string; `check` = `{ http = "<url>", timeout_sec? (default 300) }` | `net.http_get` |

### Completion conditions (which kinds can be skipped)

A kind may declare what "already done" looks like for the work it
performs. Before running that work, apply evaluates the condition; if
it already holds the work is **skipped** and the report says which
parts of the condition were true. Whether a kind has one is a property
of that kind, not a blanket contract over the catalog — the table below
is the complete list.

| kind | condition | evaluated in a dry run? |
|---|---|---|
| `models` | with `sha256`: the destination exists **and** its content has that digest. Without `sha256`: the destination exists | no — the answer is reported as undecided |

Everything else in this catalog runs every time.

Two properties this is meant to have, and one it is not:

- **Only "already done" skips.** A condition that could not be
  evaluated (an unreadable destination, a read that failed) does not
  skip; the work runs. Skipping something that was not done costs a
  broken pod, re-doing something that was costs bandwidth.
- **A skip says what was true.** The report's `note` carries the
  evaluated condition per sub-term, not a bare "skipped".
- **It is not a guarantee that the work is unnecessary.** Existence
  alone is a weak identity: a half-written file from an interrupted
  download exists. Declaring `sha256` is what buys the strong one.

### Catalog kinds (direct operations)

These map 1:1 onto bridge primitives (chapter 04); their payloads
mirror the bridge signatures, with non-core fields forwarded as
`opts`.

| kind | payload | required capability |
|---|---|---|
| `sh.exec` | `argv` list\<string\> (non-empty); `opts` table (chapter 04 §sh.exec) | `sh.exec` |
| `fs.write` | `path` string; `content` value node (bare string \| `EnvSecret` \| `EnvRef`, chapter 04 §`fs.write`); other fields → opts | `fs.write`, plus `env.ref` when `content` is an `EnvRef` node (§Shared vocabulary) |
| `net.http_get` | `url` string; `headers` table\<string, string\|SecretRef\> optional (names shell-safe); `timeout_sec?` number (default 30) | `net.http_get` |
| `net.http_post` | `url` string; `headers`, `timeout_sec?` as above; `body` value node \| `body_json` JSON string — **mutually exclusive**, and the content type follows from which one is declared (chapter 04 §`net.http_post`); `body_form` deferred | `net.http_post` |
| `net.transfer` | `src`, `dst` strings — the direction is read off the schemes: a remote scheme on `src` is a download, one on `dst` is an upload, and a scheme on both or on neither is a validate-stage reject; other fields → opts | `net.transfer`, or `sh.exec` when routed (§Dispatch routing) |
| `mount.bind` | `src`, `dst` strings; `recursive?`, `read_only?` → opts | `mount.bind` |
| `mount.umount` | `path` string; `lazy?`, `force?` → opts | `mount.umount` |

### Plan-internal kind

`sync.routes` — the plan stage bundles all `sync.pull` /
`sync.push` / `staging.push` phases into a single `sync.routes` step
(payload `{ pull, push_markers, staging_push }`). It is not
user-declarable; a profile declaring `kind = "sync.routes"` falls into
the unknown-kind bucket.

The three kinds it carries do not demand the same capability, so the
bundled step demands the **union of the resolved demands** of the
phases inside it (§Dispatch routing, "What the L4 gate sees").
`sync.push` markers contribute nothing to that union, since they are
not executed during apply.

## Outputs

### Canonical phase ordering (execution contract)

The three rules below are content-sensitive — they decide *which*
phases exist and in *what order* — so they are applied once, to the
AST, before either consumer reads it: the plan stage renders the
result, and apply executes it. A plan that described an order apply did
not follow would defeat the point of having a plan stage. The profile
as *written* is what `hash` / `canonical` see; the rewrite never
reaches them, so an inserted step cannot change a profile's hash.

The plan stage assigns each kind a canonical phase id and emits steps
in this fixed order (the numbering is part of the contract; the `6_`
slot is intentionally unused):

```
1_system_apt → 2_comfyui_install → 2b_toolchain_python →
3a_python_version_check →
3_python_deps → 4_custom_nodes → 5_sync_routes → 7_models →
7b_llm_models → 8_post_install → 9_comfyui_restart →
10_comfyui_health → 11_service_<N>_start / 11_service_<N>_ready →
zz_unknown
```

Rules:

- Multiple phases of the same kind share a bucket and keep their
  relative declaration order inside it.
- `service.start` / `service.ready` are numbered per service index
  (`11_service_0_start`, `11_service_0_ready`, ...). The index
  advances on every `service.start`, and a `service.ready` takes the
  index of the most recent one. A `service.ready` that no
  `service.start` precedes — the resume profile of §Poll deadlines —
  opens an index of its own instead of inheriting 0, so it cannot
  collide with the readiness step of the first declared service.
  Duplicate `service.start` names are a validate-stage error, and so
  is a second `service.ready` under the same `service.start`: both
  would carry `11_service_<N>_ready`, and unlike a shared bucket id
  that number is what tells two services apart.
- Implicit insertion: when `comfyui.install` is present, whichever of
  `toolchain.python` / `comfyui.restart` / `comfyui.health` the profile
  did not declare is inserted. The guard is per phase, not "none was
  declared" — a profile that declares only the restart still gets its
  health poll. The restart / health pair carries the port of the other
  one when that was declared, and the default port when neither was.

  **The venv is inserted for the same reason the restart is.** The rule
  already reads "a checkout implies a launch"; a launch runs the venv's
  interpreter, so a checkout implies a venv. Inserting the launch while
  withholding what it runs would reject a profile that wrote nothing
  but `comfyui.install` — for a phase its author never wrote. The
  inserted `toolchain.python` installs the checkout's own
  `requirements.txt`, which is what makes the result startable rather
  than merely present. A profile that wants a bare venv, a different
  requirements file, or an isolated one declares its own and nothing is
  inserted.
- `python.version_check` with `want == "3.12"` (the default) is
  suppressed. The test is a literal equality against the default
  rather than an analysis of which wants are vacuous: the step's own
  check is a prefix assertion (§Spawn-and-poll invocations), so
  `want = "3."` equally cannot fail on a 3.x host and is still
  emitted.
- Direct-operation kinds and any unknown kind land in the trailing
  `zz_unknown` bucket in declaration order. Sharing that bucket is an
  ordering statement only: each step carries its own `kind`, so a
  recognized direct operation dispatches to its bridge primitive
  (chapter 04) and runs for real. Only an *unrecognized* kind degrades
  to a no-op (§Unknown kinds).

The ids name slots, not steps, and they are not sort keys. Two phases
of one kind share a bucket and therefore share an id — what tells them
apart is their position. `3a_python_version_check` precedes
`3_python_deps` in this order but follows it in a byte comparison, and
`10_` / `11_` sort ahead of `1_`; no zero padding repairs that. The
order is carried by the position of each step in the emitted list —
the plan stamps it as a 1-based `index` field — so a consumer that
re-sorts steps by id, or keys a map on the id, silently loses the
plan. The one id that identifies a single step is the service pair's:
`11_service_<N>_start` / `_ready` carry a per-service number, which is
why the numbering rule above has to keep it unique.

### Unknown kinds

An unrecognized `kind` is preserved as a trailing step with id
`zz_unknown` (forward-compat: user data is never dropped by the plan
stage). At dispatch it becomes a `dispatch_pending` step; at apply it
is reported with `ok = true` and a note. Unknown kinds therefore
degrade to visible no-ops, never silent drops and never hard errors.

This no-op semantics is keyed on the kind being unrecognized, not on
the `zz_unknown` id: the direct-operation kinds that share the bucket
are recognized, and §MVP scope's real-exec coverage for them stands.

### Dispatch routing (kind → bridge op)

Dispatch turns each planned step into one or more bridge invocations
(chapter 03 §dispatch). Scheme-dependent routing:

- Downloads (`sync.pull`, `net.transfer` download): `b2://` or
  `hf://` src **with a non-empty `env` table** routes to the native
  CLI over `sh.exec` so credentials flow through exec-time env
  injection. Public `hf://` and `https://` stay on the `net.transfer`
  bridge, where an `hf://` source resolves to its public file URL
  (chapter 04 §`net.transfer`). A public `b2://` source has no bridge
  route: its download endpoint is deployment-specific and no profile
  field declares one, so it fails with an error pointing at the
  credential `env` route. The two CLI argv shapes:

  ```
  b2 download-file-by-name <bucket> <path> <dst>
  hf download <owner>/<repo> <path> --local-dir <dst> [--revision <rev>]
  ```

  (`hf` superseded `huggingface-cli`: on current huggingface_hub the
  old entry point prints a deprecation notice and exits 1 — observed
  live on a fresh pod, 2026-08-01. The argument shape is unchanged.)

  **A routed step is two steps**: an install, conditioned on the tool
  not already being there, then the invocation.

  ```
  pip install -q huggingface_hub   done: on_path(hf)
  pip install -q b2                done: on_path(b2)
  ```

  There is no phase kind for this and nothing to declare. Which CLI a
  step needs is decided by the route, and the route is decided by the
  source scheme and whether `env` carries credentials — all of which
  the dispatcher already reads off the payload. Asking a profile to
  also declare the tool would be asking it to restate a choice it did
  not make.

  The condition is an `Assert`, not a `||` inside the command. The
  inline form runs the same test where nothing can read it: the step
  always reports as having run, so a converged apply is
  indistinguishable from a first one and `plan` cannot say whether an
  install is coming. `Cli`'s completion condition is
  `Assert::CommandOnPath`, a `PATH` lookup — evaluated in both modes,
  because it is a read and a cheaper one than the git predicate's.

  **`dst` means different things on these two routes.** `b2` takes the
  destination file path; `hf` exposes no output-file flag
  at all, only `--local-dir`, so the file lands at
  `<dst>/<path>` and `dst` names a *directory*. The asymmetry is the
  CLI's, and a profile author has to know it — a `sync.pull` with an
  `hf://` src and a credential `env` writes into `dst` as a directory,
  while the same phase with a `b2://` src writes `dst` itself.

  The alternative — downloading to a temporary directory and renaming
  into a file path — is deliberately not synthesized: it would add an
  invented step to the operator's pod that no chapter describes, to
  hide a convention the CLI states plainly.
- Uploads (`staging.push`, `net.transfer` upload): `hf://` dst →
  `hf upload` argv; `b2://` dst → `b2 upload-file` argv;
  `https://` dst → `net.transfer` bridge (HTTP PUT). The absence of an
  `env` condition here is deliberate, not an omission of the download
  rule: writing to a bucket or a repo needs credentials in every case,
  so a `b2://` / `hf://` dst is CLI-routed unconditionally.
- `models` and `llm_models` are not scheme-routed at all: `models`
  always takes the `net.transfer` bridge (its `src` grammar is
  `https://` only), and `llm_models` always takes the hf CLI. A
  credential-bearing download is expressed with `sync.pull`, which is
  where the routing rule above applies.
- `hf://<owner>/<repo>@<rev>/<path>`: the `@<rev>` suffix on the repo
  segment pins a revision; a URL-carried revision wins over
  `opts.revision`. `@` is rejected in the owner segment. This holds on
  both sides — on an upload dst as on a download src — and it is where
  `staging.push`'s `revision` lands: whichever revision survives that
  precedence becomes `--revision` on the `hf` argv.

**What the L4 gate sees.** Routing is decided from the payload alone,
so the capability a routed kind requires is known statically, before
anything runs. The gate therefore requires the **resolved** capability
rather than the union of both routes: a profile granting
`net.transfer` but not `sh.exec` passes with a public `hf://` download
and fails the gate as soon as a credential `env` moves that same phase
onto the CLI route. Granting the union up front would defeat the
point of declaring capabilities — it would let a shell run under a
profile that never asked for one (chapter 05 §L4).

The `dst` route-shape check (§Error surface) validates path syntax —
absolute, no `..` — and nothing more. Whether `dst` names a file or a
directory follows from the route, as described above, and is not
separately checked; a profile that swaps schemes changes the meaning
of a `dst` that still validates.

#### Spawn-and-poll invocations

`comfyui.restart` and `service.start` background their server and
return immediately; readiness is the following phase's job
(`comfyui.health` / `service.ready`, which canonical ordering places
directly after them).

**Why the split.** Apply is normally driven over SSH, where holding a
connection open for the lifetime of a server process is the thing most
likely to fail. Spawning detached and asking again over a fresh call
survives a dropped connection; a foreground launch does not. This
holds even when the host is expected to stay up — the failure mode
being avoided is the transport's, not the server's. Do not "fix" these
into blocking launches.

Two consequences follow, and are intended:

- the launch step reports only whether the *spawn* was accepted;
  whether the server survived its first second and then came up is the
  settle check's and the poll step's verdict
- a crash *after* the poll succeeded is not detected, and nothing
  guards against a double start. Process supervision (a restart policy,
  a watchdog) would be a new concept in this spec, not a fix to these
  kinds. The pid file below is **not** supervision: it is read only
  inside the readiness window, by the poll that follows the launch.

The redirect in each command is load-bearing: the host reads the
child's stdout / stderr to EOF, so a backgrounded process still
holding those pipes would block apply for as long as it runs. Sending
its output to a log file closes them.

Each launch also records `$!` in a pid file beside its log and
`kill -0`s it after a one-second settle, so a command that is missing
or rejects its arguments fails the launch step instead of surfacing as
a readiness timeout a few minutes later. The pid file is what the
following poll reads to notice a death during the wait (§Poll
deadlines). The `comfyui.restart` launch is brace-grouped because `&`
binds looser than `&&`: without the group the whole `cd … && nohup …`
list would be backgrounded and `$!` would name that subshell rather
than the server.

| kind | invocation |
|---|---|
| `comfyui.restart` | `sh -c "cd /workspace/ComfyUI && { nohup /workspace/ComfyUI/venv/bin/python /workspace/ComfyUI/main.py --port <port> <extra_args…> > /tmp/comfyui.log 2>&1 & pid=$!; echo $pid > /tmp/comfyui.pid; sleep 1; kill -0 $pid 2>/dev/null \|\| { echo 'comfyui died immediately' >&2; tail -100 /tmp/comfyui.log >&2; exit 1; }; }"` |
| `service.start` `vllm` | `sh -c "nohup python -m vllm.entrypoints.openai.api_server --model <model> [--port <port>] [--dtype <dtype>] [--tensor-parallel-size <n>] <extra_args…> > /tmp/<name>.log 2>&1 & <settle>"` |
| `service.start` `ollama` | `sh -c "nohup ollama serve > /tmp/<name>.log 2>&1 & <settle>"` — binds 11434 and takes its address from `OLLAMA_HOST`, so neither model nor port appears on the command line |
| `service.start` `llamacpp` | `sh -c "nohup llama-server --model <model> [--port <port>] <extra_args…> > /tmp/<name>.log 2>&1 & <settle>"` |

`<settle>` is the same tail on every `service.start`:
`pid=$!; echo $pid > /tmp/<name>.pid; sleep 1; kill -0 $pid 2>/dev/null || { echo 'service <name> died immediately' >&2; tail -100 /tmp/<name>.log >&2; exit 1; }`.

`--port` / `--dtype` / `--tensor-parallel-size` are synthesized only
when the corresponding optional payload field is declared. When a field
is unset the flag is omitted and each platform's own default takes over
— 8000 for `vllm`, 8080 for `llamacpp` (`ollama` reads `OLLAMA_HOST`).
`extra_args` is appended verbatim after the declared flags, so an
author who prefers to write `["--port", "9000"]` there directly stays
in control; declaring both puts the flag on the argv twice, which the
platform CLI will normally reject as a duplicate — validate does not
police that overlap.

`ollama` is the one platform whose argv carries neither field: a
`model` or a `port` declared on it is accepted and then dropped, since
`ollama serve` takes its address from `OLLAMA_HOST` and its model at
request time. The payload shape is uniform across platforms and the
meaning is not; a profile that wants `ollama` on another port sets
that variable in the service environment rather than the payload.

`service.start` expands to a **note** step instead of a command when
the platform is not one of the three above, or when `vllm` / `llamacpp`
is declared without a `model`. Neither case has an argv to run:
`--model` with nothing after it consumes the next token as the model,
launching something the profile did not ask for. A profile that needs a
launch this catalog does not cover expresses it through
`hooks.post_install`, where the shell escape is sanctioned and visible
(chapter 01 §Escape / Fragment Policy).

An unrecognized `platform.kind` is therefore **not** a validate-stage
error: `kind` is a free string at the JSON boundary, the three values
above are the ones this catalog gives an argv shape, and everything
else surfaces at apply as the note step just described. Validate
checks the shell-safety of the payload's strings, not the membership
of `kind` (§Error surface).

`comfyui.health` polls `/object_info`, not `/`. The root path serves
the UI's HTML and answers 200 before the backend can take an API call,
so polling it reports ready too early.

`python.version_check` runs the comparison rather than describing it:
`python3 -c 'import sys; assert sys.version.startswith("<want>"),
"python version mismatch: want <want>, got " + sys.version'`. A
mismatch exits non-zero and fails the step, with the interpreter's real
version in the captured stderr.

#### Poll deadlines

| kind | payload field | default |
|---|---|---|
| `comfyui.health` | `timeout_sec?` | 180 s |
| `service.ready` | `check.timeout_sec?` | 300 s |

Both polls GET every 2 s until a 2xx answers or the deadline passes; a
deadline reached is a step failure carrying the last status seen.

The two defaults are separate because they wait for different things.
A ComfyUI cold boot spends its budget before the API answers —
ComfyUI-Manager's prestartup script alone took 49.7 s on the pod this
was measured on, with model and custom-node scanning after it. An
inference engine's start-up is dominated by weight loading and CUDA
graph capture (a vllm engine init measured ~100 s on the same pod), so
its deadline is a multiple of that rather than of an HTTP round trip.
A single flat 60 s deadline shared by both failed apply on servers
that were merely still starting.

A declared `timeout_sec` replaces the default in both directions,
including downwards — a profile that wants to fail fast asks for it.
Omitting the field is not the same statement as declaring the default
value: an absent `timeout_sec` is omitted from the canonical encoding,
so profiles written before the field existed keep their hash.

Each poll also watches the process it is waiting for. On every
iteration where the server did not answer, the poll re-reads the pid
file its launch wrote (`/tmp/comfyui.pid` for `comfyui.health`,
`/tmp/<name>.pid` for `service.ready`) and checks that the pid still
exists; when a pid **it has already seen running** is gone, the step
fails immediately with the last 100 lines of the launch log rather than
waiting out the deadline. The launch's own one-second settle check
cannot cover this: an inference engine typically crashes tens of
seconds in, on `bind()` after its import phase, and reporting that as a
300 s timeout hides a crash behind a deadline.

The "already seen running" condition is what makes the check safe for a
**resume profile** — a `comfyui.health` / `service.ready` declared
without the launch that pairs with it, polling a server an earlier
apply started. Such a poll finds whatever pid file that earlier apply
left at the well-known path; because the pid never reads as alive
*during this poll*, it can never turn into a death verdict, and the
step behaves exactly as it did before the check existed. A stale file
is therefore inert, not a source of wrong failures.

The cost of that condition is a small blind spot, accepted knowingly: a
launch that dies between its own settle check and the first probe of
the poll is never observed alive, so it surfaces as a timeout rather
than as a death. That window is a couple of seconds wide, while the
crash class this exists for lands tens of seconds in — comfortably
inside the watched window.

A pid file that is absent, empty, or unparsable is likewise *not* read
as a death: the launch writes it just after backgrounding the server,
and losing that race must not fail a poll that would otherwise succeed.
The check is skipped entirely for a poll with no pid file.

Reading that pid file is a file read inside the provisioner, not a
bridge operation: neither poll composes a `sh.exec` or an `fs.write`
step to look at it, and nothing outside the poll observes the read. Both
kinds therefore require `net.http_get` and nothing else — the capability
of the only effect they expand into, which is the GET they issue
(chapter 05 §L4).

### Shared vocabulary (frozen literal sets)

This chapter is the source of truth for two literal sets consumed
elsewhere. The host embeds them; the implementation form of the
sharing (single data file vs mirrored constants) is internal, byte
equality of the set literal is the contract.

- Secret-shaped key substrings — **one set, two consumers**: chapter
  06 rejects a *literal* bound to an `env` key containing any of them
  (a `SecretRef` under the same key is exactly what it asks for, which
  is why a credential `env` can still put a phase on the CLI route
  above), and chapter 09 redacts an audit field whose name contains
  any of them.
  `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PWD`, `AUTH`, `CRED`,
  `APIKEY`.

  Matching is case-insensitive in this exact sense: the candidate key
  is upper-cased through the Unicode uppercase mapping and tested for
  containment of these ASCII spellings. Byte equality is a statement
  about the shared literal above, not about the comparison. A
  lower-case mirror of the same eight words is not a second set — it
  is a second spelling of one fact, and a chapter that carried one
  could be edited on its own without any consumer observing the
  divergence. Chapters 00 and 09 call this set the *sensitive-key
  substring set*; the two names name the same eight substrings.
- `KNOWN_CAPABILITIES` (chapter 05 L4): `env.ref`, `sh.exec`,
  `net.transfer`, `net.http_get`, `net.http_post`, `fs.write`,
  `mount.bind`, `mount.umount`, `mount.volume_attach` (reserved key —
  declaring it passes the gate build but no bridge exists for it yet,
  so no operation is reachable).

  Every other key in that set is demanded by at least one row of the
  catalog above; `mount.volume_attach` is the single reserved
  exception. `env.ref` is the one demand that does not follow from the
  kind: dereferencing a `Spec.env` entry is an effect of its own, so
  **any phase carrying an `EnvRef` value node demands it** — in
  `fs.write` content, in an `env` keyed slot, in a header map, or in a
  POST body — on top of whatever its kind requires. Spelling it per
  kind instead would leave the same hole in every slot the capability
  column does not mention.

### Authoring support

The per-kind payload schemas form a discriminated union on `kind`,
expressed as the `ProfileNode` enum (chapter 01). The machine-derived
`DslSchema` is what tooling reads: it drives the canonical-text
grammar, the JSON bridge, and machine-generated examples, and it is
walkable by the host for pre-flight static checks. These artifacts are
derived — this chapter's tables are the source.

A `codegen` step emitting a `.d.lua` annotation file served the
removed Lua authoring frontend and no longer exists (chapter 07
§MVP scope).

### Resource-derived paths

Every ComfyUI-relative path is derived from **one** root, the
`comfyui_root` resource. `comfyui.install` produces it — its
`install_dir`, or `/workspace/ComfyUI` when the phase declares none —
and the phases that consume ComfyUI require it (chapter 01 §Assumed
resources):

| path | resource | derivation |
|---|---|---|
| models root | `comfyui_root` | `<comfyui_root>/models` |
| custom nodes root | `comfyui_root` | `<comfyui_root>/custom_nodes` |
| entry point | `comfyui_root` | `<comfyui_root>/main.py` |
| venv directory | `comfyui_root` | `<comfyui_root>/.venv` — where `toolchain.python` puts it |
| venv pip | `venv` | `<venv>/bin/pip` |
| venv python | `venv` | `<venv>/bin/python` |

The last two are derived from the **bound venv**, not from the root: a
profile that assumes a venv somewhere else gets that one. The venv
directory row is where `toolchain.python` places what it creates when
nothing has bound one already.

Requiring kinds:

| kind | requires | when |
|---|---|---|
| `models` | `comfyui_root` | always |
| `toolchain.python` | `comfyui_root` | always — it puts the venv inside |
| `comfyui.restart` | `comfyui_root`, `venv` | always |
| `python.deps` | `venv` | only under `in_comfy_venv` |
| `custom_nodes` | `comfyui_root` | always |
| `custom_nodes` | + `venv` | when an entry sets `pip` |

A profile using any of them without producing or assuming what it
requires is rejected (chapter 03 §validate check 8b).

#### Torch-family filter

Every `requirements.txt` this provisioner installs — ComfyUI's own via
`toolchain.python`, and each custom node's — is filtered first:

```
^[[:space:]]*(torch|torchvision|torchaudio|xformers|bitsandbytes|triton)([[:space:]=<>~!;]|$)
```

A GPU pod image ships a torch built against its own driver, and a venv
created without `isolated` inherits it. **Inheritance loses to a wheel
installed inside the venv**: a requirements file pinning `torch>=2.7`
has pip satisfy it from PyPI, the wheel's CUDA no longer matches the
driver, and the only symptom is `torch.cuda.is_available()` answering
false at launch — long after the phase that caused it reported success.

The filter is a pipe (`grep -viE '<pattern>' <file> | pip install -r
/dev/stdin`) rather than a rewrite: the requirements belong to the
repository that shipped them.

### Built-in path constants

The paths that are **not** resource-derived remain fixed: service logs
`/tmp/<name>.log`, service pid files `/tmp/<name>.pid`, ComfyUI log
`/tmp/comfyui.log`, ComfyUI pid file `/tmp/comfyui.pid`, and the
`llm_models` default destination `/tmp/`. Profiles that use these kinds
must declare `paths` roots covering them — and covering the resolved
`comfyui_root` — when the corresponding bridges gate on paths.

A transfer creates its destination's parent directories, which is what
the predecessor implementation does immediately before every model copy.
A `models` entry names a subdirectory, and whether that subdirectory
exists is a property of whatever produced the root — a ComfyUI checkout
ships `models/checkpoints` but not `models/lora`, and a root declared by
a profile ships nothing. The path has already passed the `paths` policy
by then, so no directory is created outside a declared root.

The pid file of a launch always sits beside its log, differing only in
extension: the poll that follows derives one path from the other's
convention, so the two constants are a pair, not two independent
choices (§Spawn-and-poll invocations).

## Error surface

- Unknown-field / malformed payload: validate-stage errors with the
  field path (`phases[<i>].<field>: ...`) — precondition class, no
  effects run.
- Shell-unsafe strings anywhere a payload string reaches an argv:
  validate-stage reject (chapter 03 §validate).
- Route shape violations (`sync.*` src/dst schemes, missing bucket or
  path, `..` traversal): validate-stage reject.
- Duplicate `service.start` name: validate-stage reject.
- A second `service.ready` under the same `service.start` (both would
  expand to `11_service_<N>_ready`): validate-stage reject
  (§Canonical phase ordering).
- A `models` element with neither `dst` nor `name`, and a
  `net.transfer` whose direction is not fixed by a scheme on exactly
  one side: validate-stage reject.
- Unknown kind: **not** an error (see §Unknown kinds).
- Unrecognized `platform.kind` on `service.start`: **not** an error —
  it expands to a note step (§Spawn-and-poll invocations).

## Stability

- The 23-kind catalog and per-kind payload field sets: **provisional**
  through Phase H (additive growth expected; removals are breaking).
- Canonical phase ids, fixed ordering, implicit-insertion rules:
  **stable** (hash and report ids depend on them).
- `KNOWN_CAPABILITIES` and the secret-shaped key set (the
  sensitive-key set is the same set under another name): **stable once
  frozen** — frozen as listed above.
- Shared vocabulary implementation form: **internal**.
- Per-kind `depends_on` + topological sort (a dependency DAG): not
  part of this contract; the fixed order above is the contract (see
  chapter 00).

## Upstream references

- chapter 00 §DSL surface — schema-as-data, shared vocabulary.
- chapter 00 §Sandbox layers — `KNOWN_CAPABILITIES` allowlist.

## MVP scope

Ships in Phase F: all 23 kinds above through
validate → plan → dispatch → apply --dry-run; real-exec coverage for
`sh.exec`-routed kinds, `fs.write`, `net.http_get` / `net.http_post`,
`net.transfer` download/upload, `mount.bind` / `mount.umount`
(Linux).

`mount.volume_attach` remains a reserved capability key with no
catalog kind and no bridge (provider-API-bound; the provisioning
boundary keeps pod lifecycle with the external pod manager,
chapter 08).
