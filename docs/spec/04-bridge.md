# 04. Bridge

Status: specified. Layer 3.
Upstream deps: 03. MVP: Phase F.

## Purpose

The sole effectful surface between a profile and the host. Defines the
primitive set (`sh`, `net`, `fs`, `mount`, secret env values), the
order in which the execution context is built, and the shape of each
primitive.

A profile is **data**, not code: it is a `ProfileNode` AST (chapter 01)
loaded from JSON or canonical text. Every effect it can cause is one of
the primitives below, reached either directly (a direct-op phase) or
through a lifecycle phase's step composition (chapter 02 §Dispatch
routing). There is no author-supplied executable code and no embedded
interpreter — the "escape hatch" is a declared `hooks.post_install`
script argv, nothing more.

## Inputs

### Execution context build order

Building an execution context and running it is a fixed sequence. The
security-relevant point is that every allowlist is derived **before**
the first op handler is reachable:

```
1. frontend load          → ProfileNode AST      [chapter 01]
2. declaration extraction → name / capabilities / env / env_secrets /
                            paths / http_allowlist off the Spec root
3. capability gate build  → fail-fast on a declared capability outside
                            KNOWN_CAPABILITIES  [chapter 05 L4]
4. policy construction    → path / HTTP / env policies from the
                            declared lists      [chapter 05 L3]
5. payload map + phase index build (NodeId → node, NodeId → 1-based
                            phase index + kind)
6. op registry wiring     → all 22 catalog ops are registered
7. engine step loop       → per op: payload lookup → capability check →
                            policy check → mode branch (dry-run trace /
                            real effect)
```

`validate` / `hash` / `plan` stop after step 2 (they need declarations,
not a context); `apply` runs the whole sequence.

Steps 3–4 cannot be reached by a profile, because a profile has no
evaluation phase of its own — parsing produces a value, not a running
program. Under the former embedded-Lua frontend the same guarantee had
to be manufactured by a *defer pattern* (register no primitive until
declaration extraction finished, so a profile body reaching for one
died on `attempt to call a nil value`). That mechanism is gone with the
interpreter; the guarantee is now structural rather than staged.

Unlike the register-skip strategy of the Lua host, the registry
installs a handler for **every** catalog op regardless of the declared
capability set: the gate is enforced at step 7 (entry check) rather
than by omitting the handler. An op whose capability is undeclared
fails with `capability '<op>' not declared in profile.capabilities`
before its payload reaches any effect, in dry-run and real alike.

### Common conventions

- Every op re-checks the capability gate at entry (chapter 05 L4).
- **Dry-run validates everything except the effect.** `apply
  --dry-run` performs payload decode, path / HTTP policy checks, and
  secret resolution, then renders a trace line instead of running the
  effect. A dry run therefore still fails on a policy violation, an
  undeclared secret, or a secret missing from the host environment — a
  dry run that passes proves the plumbing, not just the shapes.
- Result-vs-error convention: **usage, policy, capability, and secret
  errors abort the step** (they surface as the engine's node-located
  `EvalFailed`, and the run stops fail-fast); **effect failures**
  (non-zero exit, transport failure, syscall failure) are captured on
  the step's report entry (`ok = false` plus `status` / `stderr` /
  `reason`) and also stop the run. Both shapes reach the operator as
  the apply report's last `steps` entry plus the envelope `error` line
  (chapter 09).
- Secret acceptance points are the `env` keyed slots (`sh.exec`,
  `sync.pull`, `staging.push`), the `fs.write` `content` slot, and the
  `net.http_*` `headers` slot / `net.http_post` `body` slot: the value
  node names a secret, the name is checked against declared
  `env_secrets`, and the value is resolved from the host environment
  immediately before the effect, never surfacing in the AST, the trace
  log, or the report (chapter 06).

## Outputs

Each primitive is described by the AST fields that drive it and the
effect it performs. Where the specified option set is not yet carried
by the AST, the gap is named explicitly rather than silently dropped —
those options are deferred, not withdrawn.

### `sh.exec` — `ShExec { argv, env }`

- `argv`: non-empty list of strings (program + args). No shell is
  implied — callers that need shell semantics pass
  `["sh", "-c", script]` explicitly.
- `env`: keyed slot, `name → EnvLiteral | EnvSecret` (chapter 06).
  Resolved in both modes and injected into the child environment.
- Effect: spawn the child with stdin connected to `/dev/null`, capture
  stdout / stderr, and report the exit code. A non-zero exit fails the
  step (`sh_exec: exit <n> stderr=...`). Captured streams are truncated
  to the last 4 KiB each; the report carries those tails.
- Deferred (specified, not yet carried by the AST): `cwd`, `stdin` /
  `stdin_file`, `timeout_sec`, `term_grace_sec`, the `on_line`
  streaming callback, and process-group-scoped timeout signalling.

### `net.http_get` — `NetHttpGet { url, headers, timeout_sec }` / `net.http_post` — `NetHttpPost { url, headers, body, body_json, timeout_sec }`

- The URL must pass the profile's `http_allowlist` policy
  (chapter 05 L3), checked in both modes.
- `headers`: keyed slot, `name → EnvLiteral | EnvSecret | EnvRef`
  (chapter 06) — the same value-node shape `sh.exec`'s `env` uses, and
  the fourth secret consumption point. Header *names* must be
  shell-safe (chapter 03's charset, a subset of the RFC 7230 token
  charset, so `Content-Type` / `X-Api-Version` pass); values are
  free-form and never checked. Resolution runs in both modes, so an
  undeclared or host-absent header secret fails a dry run identically.
- `body` (POST only): a value node, exactly like `fs.write`'s
  `content` but optional — a bare string spelling (`"body": "text"`)
  lowers to an `EnvLiteral` through the declared scalar shorthand.
  Resolved bytes are the request body.
- `body_json` (POST only): a JSON document carried as its serialized
  **string**, the same opaque-JSON-string payload shape `llm_models`'s
  `models_json` uses. Sent verbatim. There is no object spelling: the
  canonical text grammar has no object literal, and a JSON-only sugar
  would break front-end parity.
- **`body` and `body_json` are mutually exclusive.** Declaring both is
  a validate rejection (`phases[<i>]: body and body_json are mutually
  exclusive`) — they name different bodies *and* different content
  types, with no defensible precedence between them. The exec layer
  re-checks it before the request, the same defense-in-depth the secret
  allowlist gets: `apply` does not run validate first (chapter 07
  §Invocation), so a profile reaching apply directly must not silently
  acquire an invented precedence.
- Content type is derived from the body form: `application/json` for
  `body_json`, `application/octet-stream` for `body` and for the
  no-body case (which remains the pre-field behaviour: an empty
  octet-stream body). A `content-type` entry in `headers` (matched
  case-insensitively) always wins over the derived value, and
  *suppresses* it rather than duplicating the field.
- `timeout_sec`: per-request deadline; the effect default (30 s)
  applies when omitted.
- Effect: a single request with redirects **disabled** (the raw status
  is reported, not followed) and a 16 MiB response cap — a larger body
  is an error, never buffered unbounded. The report carries the status;
  the trace log carries the body tail (last 4 KiB).
- Redaction (chapter 09): the audit event carries the URL, the request
  header *names* (sensitive-shaped ones marked `[REDACTED]`), and — for
  POST — the body's source form (`none` / `body:string` /
  `body:secret:<name>` / `body:env_ref:<name>` / `body_json`) plus its
  byte length. Header values and body content never reach the
  transcript, the trace log, or the report.
- Every one of the five fields is omitted from the canonical encoding
  when unset (empty map / `None`), so a profile written before they
  existed keeps its bytes and its hash (chapter 03 §canonical).
- Deferred, with reasons:
  - `max_bytes` — the 16 MiB cap is not yet author-tunable; no
    consumer has needed a different one.
  - `body_form` (urlencoded) — nothing asks for it: the generic API
    surface this primitive exists for is JSON-bodied.
  - multipart upload — when a consumer needs it, it gets its **own
    catalog kind** rather than a fourth body form here: multipart
    carries per-part filenames, content types, and streaming
    concerns that do not belong in a generic request primitive.

### `net.transfer` — `NetTransfer { src, dst }`

- Policy follows the **resolved route**, not the field names: the local
  side goes through `paths` and the remote side through
  `http_allowlist`, both in both modes. On a download that is `dst` and
  the source URL; on an upload it is `src` and the destination URL.
  The allowlist sees the URL the transfer will actually reach — an
  `hf://` source is checked as its resolved `https://huggingface.co`
  URL, not as the authored URI, so a profile cannot reach a host it
  never declared.
- Effect (download): GET streamed to the `dst` file (never fully
  buffered, 16 MiB cap); on any failure the partial file is removed.
  The report carries the byte count and destination.
- **Two download mechanisms, one step.** A large file from a supplier
  that serves ranges is fetched in parallel chunks; everything else is
  the single stream above. The first request decides which: it asks for
  the opening range, so a `206` carrying `Content-Range` gives both the
  total and the first chunk, and a `200` is the whole body on the path
  it was taking anyway — **no probe request is spent either way**. The
  choice is announced as a `net.transfer.route` audit event naming the
  route and the reason, because a slow run must not be
  indistinguishable from an unavoidable one.
  - **Each chunk requests the profile's URL and follows its own
    redirect**, never a location resolved for an earlier range. A
    supplier may sign the redirect target for one byte range —
    HuggingFace documents exactly this and documents that a `Range`
    outside it fails authorization — so reusing a resolved location is
    what makes a parallel download fail against them. Nothing here
    caches or rewrites a signed URL.
  - Chunk size and concurrency are matched to HuggingFace's own client
    (10 MiB, 16 in flight). Concurrency is bounded because an unbounded
    fan-out is rude, not because a limit is documented — none is.
  - A chunk that fails is retried with backoff. Over a multi-gigabyte
    file one of sixteen connections will drop, and one drop must not
    discard the rest.
  - Nothing is installed on the pod for this. The `aria2c` route
    described in earlier revisions is no longer reached: it needs range
    support to split, which is the same condition that routes the
    transfer to the chunked path instead.
  - **Nothing above this changes with the route.** The step is the same
    step with the same condition, so a re-applied profile skips a
    finished download either way; `sha256` is verified by that
    condition reading the file, not by the transfer, so it holds for
    both; and `net.transfer.progress` keeps its shape, cadence and
    ordering (chapter 09) because the cadence lives in the transcript,
    not in the mechanism. A consumer cannot tell from the event stream
    which route ran.
  - A non-zero `aria2c` exit is an error, not a fallback: by then the
    URL was resolved and attempted, and retrying in-process would hide
    which route is broken.
- Effect (upload): PUT of the local `src` file to the destination URL,
  read under the same 16 MiB cap, sent as
  `application/octet-stream`. The report carries the byte count and the
  destination URL.
- Credential-carrying transfers do not run here. `b2://` / `hf://`
  downloads and every upload are routed to the native CLIs over
  `sh.exec` by the lifecycle layer (chapter 02 §Dispatch routing), so
  they never reach this primitive. Note that the destination
  convention differs there: `hf download` takes a
  `--local-dir`, so on that route the phase's `dst` is a *directory*,
  not the file path this primitive writes.
- A `b2://` / `hf://` source that *does* reach this primitive is the
  public scheme-resolution surface. `hf://<owner>/<repo>[@<rev>]/<path>`
  resolves to
  `https://huggingface.co/<owner>/<repo>/resolve/<rev>/<path>`, with
  `main` when the URI pins no revision and the phase's own `revision`
  filling in for an unpinned URI (a URL-carried revision still wins).
  `b2://<bucket>/<path>` would resolve to the deployment's public
  download endpoint, which is cluster- and account-specific and which
  **no profile field declares**; rather than guess a host, that call
  fails with an error naming the gap and pointing at the credential
  `env` route, which does work. `gs://` / `s3://` / `ftp://` /
  `file://` remain rejected schemes.
- The resolution rules and their URL templates live in one module
  (`exec::scheme`), read by both the direct op and the lifecycle layer's
  `sync.pull` — the templates are provisional (below), so a revision
  has one place to land.
- Deferred: `headers`, `timeout_sec`, `max_bytes`, `sha256` verification,
  `content_type`, and `auth_bearer` (the second SecretRef acceptance
  point).

### `fs.write` — `FsWrite { path, content }`

- `path` must be absolute and under a declared `paths` root
  (chapter 05 L3), checked in both modes.
- `content`: a value node — `EnvLiteral` (verbatim bytes), `EnvSecret`
  (host-env-resolved secret bytes, the third acceptance point of
  chapter 06), or `EnvRef` (a `Spec.env` entry, resolved with that
  entry's own semantics). A bare string spelling
  (`content: "text"`) lowers to an `EnvLiteral` via the declared
  scalar shorthand (dsl-kit 0.8, issue #14), so the pre-node form
  parses — and hashes — unchanged. Resolution runs in both modes
  (chapter 06 §Resolution "dry-run resolves too"); an undeclared or
  host-absent secret fails a dry run identically.
- Effect: create / truncate and write. The parent directory is **not**
  created; a missing parent is a step failure. The report carries the
  byte count.
- Deferred: `mode`, `append`, `mkdir_p` (with each created ancestor
  itself path-gated).

### `mount.bind` — `MountBind { src, dst }` / `mount.umount` — `MountUmount { path }`

- Both paths (or the umount target) must be under declared `paths`
  roots, checked in both modes.
- Linux only: elsewhere the step fails with `not supported on this
  platform (mount requires Linux)`. Profiles remain loadable on every
  platform — the rejection happens at execution, not at load.
- Privilege: real mounts need root / `CAP_SYS_ADMIN`; OS errors
  (`EPERM` etc.) propagate verbatim into the step's failure reason.
- `mount.umount` is a separate capability from `mount.bind`: declaring
  bind does not grant umount.
- Deferred: `mount.bind` `recursive` (`MS_REC`) and `read_only`
  (two-step remount with bind-undo on failure); `mount.umount` `lazy`
  (`MNT_DETACH`) and `force` (`MNT_FORCE`).

### Env value nodes — `EnvLiteral { value }` / `EnvSecret { name }`

The only inhabitants of an `env` keyed slot. `EnvLiteral` carries a
plain string; `EnvSecret` names a secret resolved host-side at
consumption time. They are value nodes, never top-level phases, and
they are inert under execution — the surrounding op consumes them. The
full contract is chapter 06.

### Trace output

Each phase produces one trace line — lifecycle phases join their
sub-step summaries with `; ` — and resolved secret values never appear
in it: an `env` map renders as its **key list** only. There is no
profile-controlled print surface, so stdout stays reserved for the
machine-readable artifact.

The per-phase summary is separate from the stderr audit transcript
that lands one structured `info` event per effect invocation (chapter
09 §Audit log). The trace buffer stays in-process for downstream
tooling that wants the joined per-phase view; the audit transcript is
the pipe the spec-08 driver collects.

## Error surface

- Capability: an op whose required capability is undeclared →
  `capability '<op>' not declared in profile.capabilities`
  (precondition, no effect ran).
- Policy: path / HTTP allowlist violation → an error naming the
  offending value and the list that excludes it (precondition, no
  effect ran, fires in dry-run too).
- Secret: undeclared name at consumption →
  `secret '<NAME>' is not declared in profile.env_secrets`; declared
  but absent from the host environment →
  `secret '<NAME>' missing in host env` (fail-fast, also under
  dry-run).
- Unsupported: a specified-but-unimplemented route (public `b2://`
  scheme resolution, mount on a non-Linux host) → an explicit
  unsupported error naming the route, and where one exists, the route
  that does work. Never a silent skip and never a fabricated
  invocation.
- Effect failures: non-zero exit / transport / syscall → the step's
  report entry carries `ok = false` with the status and captured
  output. The step's externally visible effects may be partial —
  download partials are cleaned up; `sh.exec` side effects are the
  command's own responsibility.
- Wiring: a payload missing for a node, or a payload of the wrong
  variant, is a host/AST bug rather than an author error and surfaces
  as such (`no payload recorded for node n<id>` / `payload for node
  n<id> is not a <Variant> node`).

## Stability

- Primitive set (`sh.exec`, `net.http_get`, `net.http_post`,
  `net.transfer`, `fs.write`, `mount.bind`, `mount.umount`, plus the
  env value nodes): **stable once frozen** — frozen as specified here.
- Per-primitive option sets marked *deferred* above: **provisional** —
  they land as AST fields without changing the primitive set.
- Context build order and the "allowlists derived before any op is
  reachable" invariant: **stable** (security invariant).
- Result-vs-error convention: **stable**.
- Scheme-resolution URL templates (`hf://` resolve/main, `b2://`
  public endpoint): **provisional** — endpoint churn upstream may
  force a revision; the `hf://` / `b2://` author-facing syntax is
  stable.
- Static-binary embeddability (no dynamic linkage requirements in any
  effect): **stable** (constraint from chapter 08).

## Upstream references

- chapter 00 §Boundary and stack — profile-as-data, no embedded
  interpreter.
- chapter 01 profile DSL surface — the `ProfileNode` AST these
  primitives consume.
- chapter 02 phase catalog — dispatch routing that targets these
  primitives, including the CLI-routed credential transfers.
- chapter 05 sandbox layer contract — capability gate and the policy
  layer applied here.
- chapter 06 secret handling — env value nodes and the
  check-then-resolve protocol.

## MVP scope

Ships in Phase F: `sh.exec` (argv + resolved env injection),
`net.http_get`, `net.http_post`, `net.transfer` (https download with
streaming and partial-file cleanup, public `hf://` source resolution,
and https upload), `fs.write`, `mount.bind`,
`mount.umount`, the env value nodes, and the trace log sink.

Deferred with one-line reasons:

- Per-primitive option sets listed above — the AST does not carry the
  fields yet; each is additive and changes no existing shape.
- ~~`net.transfer` public `b2://` / `hf://` scheme resolution and HTTP
  PUT upload — the credential-carrying paths already work through the
  CLI dispatch route, so the public bridge is not on the critical
  path.~~ Landed for `hf://` and for the PUT upload (§`net.transfer`
  above). Public `b2://` stays deferred for a different reason than
  effort: its download endpoint is deployment-specific and no profile
  field declares one, so implementing it means adding that declaration
  to the DSL surface (chapter 01) — a hash-visible change, and its own
  decision.
- ~~`fs.write` `content` as a secret — blocked on a dsl-kit scalar
  coercion for the `One` child slot.~~ Landed: dsl-kit 0.8 shipped the
  scalar shorthand (issue #14) and `content` is a value node now
  (§`fs.write` above).
- ~~`net.http_*` `headers` / `timeout_sec` and the POST body forms —
  the AST carried only `url`.~~ Landed: `headers` / `timeout_sec` /
  `body` / `body_json` are AST fields now (§`net.http_get` above).
  `max_bytes`, `body_form`, and multipart stay deferred with the
  reasons given there.
- `mount.volume_attach` has a reserved capability key and no
  primitive (provider-API territory behind the provisioning boundary,
  chapter 08).
