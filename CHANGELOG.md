# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A completion condition per lifecycle step, and one vocabulary for
  writing it.** Every kind used to answer "is this finished?" in its own
  shape, or not at all: six ad-hoc forms across payload fields and host
  Rust. There is now one `Assert` — an expression over predicates,
  folding to four answers (`Satisfied` / `Unsatisfied` / `NotChecked` /
  `CheckFailed`) rather than a boolean, because "I did not look" and
  "I looked and could not tell" are different things to a reader of a
  plan. Four entity types derive their own: `ModelFile` (present, and
  matching a declared digest), `Checkout` (a repository is there and
  holds the named ref), `Service` (the recorded process is alive and was
  launched with exactly these arguments), `Venv` (there is an
  interpreter in it).
- **A second apply converges instead of repeating.** A model file that
  is already there is not fetched again, a clone that exists is not
  attempted again, a server already running with these arguments is not
  relaunched, a venv that exists is not recreated. Each skip names the
  part of the condition that held, so the report says what was true
  rather than only that something was skipped.
- **`toolchain.python`** (23rd catalog kind). Creates the virtual
  environment ComfyUI runs in and installs a declared `requirements.txt`
  into it. Inherits the host interpreter's packages unless the profile
  sets `isolated` — a GPU pod's torch is built against its own driver,
  and a venv that cannot see it makes pip fetch a wheel whose CUDA does
  not match, which surfaces only as a launch that never becomes ready.
- **Resources: `produces` / `requires` / `assumes`.** A phase can only
  reach a path something created. `comfyui.install` produces
  `comfyui_root` (its `install_dir`, defaulting to `/workspace/ComfyUI`),
  `toolchain.python` produces `venv` under it, and the phases that
  consume them require them back. `Spec.assumes` is where a profile
  states that something is already present. Validate rejects a profile
  whose requirement nothing binds — by resource name, before any effect
  runs. The check is a scope check over the canonical phase order, not a
  dependency graph: nothing is reordered.
- **Every ComfyUI-relative path derives from one declared root.** The
  models root, the custom-nodes root, the entry point and the venv were
  six constants in host code that a profile could not see or point
  elsewhere; they are now derivations of `comfyui_root`, and moving it
  moves what `paths` must cover.
- **Independent transfers in one `models` phase run at the same time.**
  Independence is decided over the composed steps — transfers to
  distinct destinations may overlap and nothing else may — so a phase
  whose steps are not independent keeps its order.
- **Byte-level progress while a transfer is still running.** A
  `net.transfer.progress` event every fifteen seconds plus the first
  chunk and the last, carrying bytes / total / percent / elapsed. No
  rate and no estimate: an ETA asserts the next minutes look like the
  last, and nothing here has looked at the network to say so.

### Changed

- **Breaking (a profile that consumes ComfyUI must produce or assume
  it).** A `models`, `custom_nodes`, `comfyui.restart` or venv-scoped
  `python.deps` phase with no `comfyui.install` and no `assumes` entry
  is now rejected at validate and at apply. The shape is real — a pod
  that already carries ComfyUI — and the fix is one `assumes` line. It
  used to compose a path under a root nothing had made and fail on the
  pod with `no such file`.
- **A checkout implies a venv, the way it already implied a launch.**
  When `comfyui.install` is present, an undeclared `toolchain.python` is
  inserted alongside the restart and health poll that were already being
  inserted, installing the checkout's own `requirements.txt`. Inserting
  a launch while withholding what it runs would have rejected a profile
  consisting of nothing but `comfyui.install`, over a phase its author
  never wrote.
- **Every `requirements.txt` is filtered before pip sees it.** Lines
  pinning the torch family are stripped, for ComfyUI's own requirements
  and for each custom node's, through one shared pattern. A pin that
  reaches pip replaces the pod's driver-matched torch inside the venv,
  and the only symptom is `torch.cuda.is_available()` answering false at
  launch. The custom-node install previously applied no filter at all.
- **The venv is `.venv`**, matching the reference implementation. The
  earlier `venv` spelling pointed at a directory nothing had ever
  created.
- **`net.transfer` carries a real model weight.** The 16 MiB cap is
  gone, redirects are followed, and a read that stalls fails on a
  deadline instead of hanging.
- **`net.http_get` / `net.http_post` moved onto `Call`**, and dry-run
  answers each step's condition rather than restating the step.
- dsl-kit 0.10, then 0.11; the AST projection is no longer hand-built.

### Fixed

- **The venv's pip is brought current before anything is installed
  through it.** The reference implementation does this between creating
  the venv and its first install; porting that script left the line
  behind. ComfyUI at `master` would not finish installing its
  requirements in an hour, twice, on two pods; with pip upgraded first
  the same profile finished in nine minutes and the pod went on to
  produce an image. The comparison is not fully isolated — the fast run
  also had a faster link — and the code comment says so.
- **A cancelled transfer takes its partial file with it**, so a
  destination is either absent or complete and the next apply's
  condition is answering about a whole file.
- **A CLI-routed step puts its CLI on `PATH` first.** `sync.pull`,
  `staging.push` and `llm_models` route to `b2` / `hf` when the source
  scheme and a credential `env` say so, and reached for a tool the pod
  need not have: `command not found`, on a binary the profile never
  named. Each routed step now composes a guard ahead of the invocation.
  No new kind and nothing to declare — which CLI is needed follows from
  the route, and the route is already derived from the payload.
- **A transfer creates the directory it is about to write into.** Under
  the built-in root this never showed — a ComfyUI checkout ships a
  `models/` tree — but a root a profile declares for itself ships
  nothing, and even a checkout has no `models/lora`. The failure was
  `No such file or directory` on a path the author never wrote. The
  destination has already passed the `paths` policy by then, so nothing
  is created outside a declared root.

### Deprecated

### Removed

### Security

## [0.4.0] - 2026-08-06

### Added

- **Pod target registry (`lm-provision-mcp`).** `LM_PROVISION_TARGETS`
  points at a JSON file naming every pod the server may provision, and
  `lm_apply` resolves its `pod_id` against it. Entries are an array —
  a `pod_id`-keyed object would let a duplicate key resolve last-wins,
  which is the unchecked-destination shape the registry exists to
  remove. Two kinds: `ssh` (the connection fields mirror spec 08
  §Session contract's `ConnectionSpec`) and `local-exec`. `port` is
  mandatory and non-zero, `key_path` is mandatory (spec 08 refuses to
  fall back to a default key), `user` defaults to `root` and
  `remote_dir` to `/root`; unknown fields are rejected so a misspelled
  `keypath` cannot leave a documented default silently in force. Paths
  are literal — neither `~` nor environment variables are expanded.
- **`DEFAULT_SSH_USER` / `DEFAULT_REMOTE_DIR` (`lm-provision-driver`).**
  The two ConnectionSpec defaults are now named constants the CLI and
  the registry both read.

### Changed

- **Breaking (`lm_apply` resolves `pod_id` before it runs anything).**
  `pod_id` used to select nothing: every call ran against the same
  local staging directory while the ledger stamped whatever pod the
  caller named, so a row recorded an unchecked claim rather than an
  observed destination (spec 09 §Ledger). A `pod_id` with no registry
  entry is now a precondition error — no effect runs and no ledger row
  is written. **Deployments must supply `LM_PROVISION_TARGETS`**: with
  it unset the registry is empty and every apply fails. A path that is
  set but unreadable or malformed fails startup instead of degrading to
  "every pod is unknown".
- **Breaking (`lm_apply` runs the session contract).** The MCP path
  moved from the 2026-07 three-step middle onto `session::run` (spec 08
  §Session steps 0-5). The profile is now validated before the first
  transport call, so a profile that loads but fails validation is a
  precondition error rather than a pod-side report.
- **Breaking (a failed ledger append no longer discards the apply).**
  `SessionOutput` carries `ledger_warning` and the session returns the
  collected report either way; spec 09 §Error surface asks that the
  record not be swallowed, not that the outcome be thrown away. The
  duty to surface it moved to the caller: `lm-provision-driver` prints
  the warning to stderr and exits 1 even on an ok report, and the MCP
  server keeps returning `ledger_appended: false` alongside it.
- **MCP error messages no longer carry connection details.** A failure
  that crosses to the client keeps its class, the `pod_id`, and this
  server's own values (the local digest, a missing secret's name, a
  validation message) and drops what the pod or `ssh` authored. The
  full text is logged at ERROR on the server instead. The CLI is
  unchanged — the operator who wrote the registry still gets the raw
  `ssh` / `scp` diagnostic.

### Deprecated

### Removed

### Fixed

- **The MCP server no longer executes the provisioner binary.** Hashing
  the profile used to spawn the uploaded artifact locally, but that
  artifact is the `x86_64-unknown-linux-musl` build meant for the pod
  (spec 08 §Inputs) — a macOS server cannot run it, so the path could
  not work outside a test that substituted a host-native build. The
  session contract's in-process hash replaces it.
- **A repeated key inside one registry entry is rejected.** Entries
  were held as `serde_json::Value`, and building a `Value` builds a
  map, so a second `"host"` in the same entry collapsed last-wins
  before the entry was ever validated. Entries now keep their undecoded
  JSON text, and the repeat is a `duplicate field` decode error naming
  the entry.

### Security

## [0.3.0] - 2026-08-05

### Added

- **`net.transfer` bridge** now resolves public `hf://` sources to their
  `https://huggingface.co/<owner>/<repo>/resolve/<rev>/<path>` URL (default
  revision `main`, URL-carried `@<rev>` wins over `opts.revision`) and
  implements HTTP PUT uploads to `https://` destinations. Public `b2://`
  sources stay unsupported by design — the deployment's download endpoint
  is cluster- and account-specific and no profile field declares one; the
  error names the gap and points at the credential `env` route that does
  work (spec 04 §`net.transfer`).
- **validate check 8** — a second `service.ready` under the same
  `service.start` is rejected. Both would carry `11_service_<N>_ready`,
  and that number is what tells two services apart (spec 02 §Canonical
  phase ordering).
- **validate check 9 (`declared ⊇ derived`)** — the compiler walks the
  normalized plan and asserts that every `capabilities` / `paths` /
  `http_allowlist` entry the run will need appears in the corresponding
  declared list. Implicitly inserted steps count: a profile that writes
  only `comfyui.install` still has to declare the health poll's
  `net.http_get` and its URL. Built-in path constants count too:
  `models` writes under `/workspace/ComfyUI/models/...` even though the
  author never spells that path out (spec 00 §Capability derivation,
  spec 03 §validate).

### Changed

- **Breaking (canonical order becomes an execution contract, not a plan
  one).** The ordering / implicit-insertion / suppression rules now
  rewrite the AST once (`crate::normalize`) and both `plan` and `apply`
  consume the result. `apply` used to drive the authored phase list
  directly, so the three rules only affected the plan artifact; a
  `comfyui.install` alone would not spawn its restart / health poll on
  apply, and a `python.version_check` asserting the default would still
  run. Both are now fixed. The profile as *written* is what `hash` /
  `canonical` see, so an inserted step does not change a profile's hash
  (spec 02 §Canonical phase ordering).
- **Breaking (capability gate reads the resolved route).** A lifecycle
  op's demand comes from the steps its payload expands to, not from its
  kind: a credential-`env` `sync.pull` and every `staging.push` route to
  the native CLI, so they demand `sh.exec`. A profile that granted only
  `net.transfer` used to run a shell under it; it is now denied at the
  L4 gate (spec 02 §Dispatch routing "What the L4 gate sees").
- **Breaking (bridge policies see every write).** A lifecycle-composed
  transfer or HTTP poll answers to the same `paths` / `http_allowlist`
  a direct op would — the check runs on the resolved step, so an
  `hf://` source is gated as its `https://huggingface.co` URL. Profiles
  that used to reach undeclared paths / hosts through `sync.pull` /
  `models` / `comfyui.health` / `service.ready` now need those targets
  in the corresponding declared list (spec 05 §L3).
- **Breaking (`env.ref` becomes a reachable capability).** A phase
  carrying an `EnvRef` value node — in `fs.write` content, in an `env`
  keyed slot, in a header map, in a POST body — now demands `env.ref`
  on top of whatever its kind requires. Dereferencing a `Spec.env`
  entry is an effect of its own, so profiles that read one need
  `env.ref` in `capabilities` (spec 02 §Shared vocabulary).
- **Breaking (`net.transfer` direction is a validate-stage decision).**
  A remote scheme on `src` is a download, one on `dst` is an upload;
  a scheme on both sides or on neither is rejected at validate rather
  than surfaced mid-apply. `models` gains the same treatment: an
  element with neither `dst` nor `name` has nowhere to write to and is
  now a precondition error (spec 02 §Catalog kinds / §Error surface).
- **`service.ready` orphans get their own service index.** A resume
  profile that polls a server an earlier apply started no longer
  inherits `_0_` from the first declared service — it opens the next
  free index. The two never collide on `11_service_0_ready` again
  (spec 02 §Canonical phase ordering).
- **spec 02 phase catalog respec.** The 34-finding DeepReview pass
  landed as point fixes to `docs/spec/02-phase-catalog.md`:
  direct-op / `zz_unknown` no-op semantics narrowed to unrecognized
  kinds only; implicit-insertion guard restated per phase (not "neither
  declared"); `platform.kind` documented as a free string with a note
  step for unknown values; ids are slot labels rather than sort keys;
  `dst | name` / `subdir | kind` precedence stated; ollama's argv
  ignores `model` / `port`; secret-shaped and sensitive-key sets
  collapsed to one set with two consumer chapters; case-insensitivity
  and byte-equality split into separate claims; `<KindName>` ↔ dotted
  label mapping tabulated (`comfyui` → `ComfyUi`, `hooks.post_install`
  → `PostInstall`).

## [0.2.0] - 2026-08-05

### Changed

- **Breaking (profile capabilities):** `comfyui.health` and `service.ready`
  now require `net.http_get` instead of `sh.exec`. Both kinds expand into a
  single HTTP poll, so they are gated on the capability of the effect they
  perform (spec 02 §Catalog kinds, 03 §dispatch, 05 §L4); the pid file the
  poll re-reads between attempts is a provisioner-internal file read, not a
  bridge operation. A profile that declares only `sh.exec` and uses either
  kind must add `net.http_get` to its `capabilities`.

## [0.1.0] - 2026-08-03

### Added

- Typed profile AST pipeline: JSON / canonical-text frontend, validate,
  deterministic canonical encoding + SHA-256 profile hash, plan, and the
  effectful apply engine (`lm-provision` lib + CLI with `validate` /
  `hash` / `plan` / `apply --dry-run` subcommands).
- 22-kind phase catalog covering system packages, Python toolchain,
  ComfyUI install / restart / health, generic service start / readiness,
  model prefetch (`hf` CLI), sync pull / push (`https` / `hf://` / `b2://`),
  staging push, filesystem writes, shell steps, bind mounts, hooks, and
  first-class HTTP access (`net.http_get` / `net.http_post` with headers,
  body, `body_json`, and per-step `timeout_sec`).
- Secret handling: `EnvSecret` / `EnvRef` declaration-derived env policy.
  Secret values are delivered via environment or SSH stdin script only —
  never in process argv, reports, transcripts, or the ledger; audit lines
  carry names and byte lengths with `[REDACTED]` markers.
- Readiness probing with fail-fast posture: per-kind poll deadlines
  (ComfyUI health 180s, service ready 300s, overridable per step via
  `timeout_sec`) and died-during-wait detection (pid-file + settle check +
  armed liveness poll) that fails in seconds instead of burning the full
  timeout when the supervised process crashes during startup.
- Push driver (`lm-provision-driver`): one-shot session contract over SSH —
  ensure-binary (SHA-256 idempotent push of the static musl artifact),
  profile placement, apply, report / transcript collection, and an
  append-only apply ledger. Secrets travel by stdin script; keys are
  explicit (no default-key fallback).
- MCP server (`lm-provision-mcp`): `lm_validate` / `lm_hash` / `lm_plan`
  and apply-ledger inspection (`lm_ledger_list` / `lm_ledger_get`) exposed
  as MCP tools.
- External interface specifications in `docs/spec/` (00-10): profile DSL
  surface, phase catalog, pipeline stage artifacts, bridge, sandbox layer
  contract, secret handling, CLI, push-driver protocol, apply report and
  ledger, MCP.
