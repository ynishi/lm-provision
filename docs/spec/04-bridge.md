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
  `sync.pull`, `staging.push`): the value node names a secret, the
  name is checked against declared `env_secrets`, and the value is
  resolved from the host environment immediately before the effect,
  never surfacing in the AST, the trace log, or the report
  (chapter 06).

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

### `net.http_get` — `NetHttpGet { url }` / `net.http_post` — `NetHttpPost { url }`

- The URL must pass the profile's `http_allowlist` policy
  (chapter 05 L3), checked in both modes.
- Effect: a single request with redirects **disabled** (the raw status
  is reported, not followed), a 30 s timeout, and a 16 MiB response
  cap — a larger body is an error, never buffered unbounded. The
  report carries the status; the trace log carries the body tail
  (last 4 KiB).
- `net.http_post` currently sends an empty body with
  `Content-Type: application/octet-stream`, because the AST carries no
  body field.
- Deferred: `headers`, `timeout_sec`, `max_bytes`, and the three
  mutually exclusive POST body forms (`body` / `body_json` /
  `body_form`).

### `net.transfer` — `NetTransfer { src, dst }`

- Policy: `dst` is always checked against `paths`; `src` is checked
  against `http_allowlist` when it carries an `http://` / `https://`
  scheme. Both run in both modes.
- Effect: `http(s)://` source → GET streamed to the `dst` file (never
  fully buffered, 16 MiB cap); on any failure the partial file is
  removed. The report carries the byte count and destination.
- Credential-carrying transfers do not run here. `b2://` / `hf://`
  downloads and every upload are routed to the native CLIs over
  `sh.exec` by the lifecycle layer (chapter 02 §Dispatch routing), so
  they never reach this primitive.
- A `b2://` / `hf://` source or a URL destination that *does* reach
  this primitive is the public scheme-resolution surface
  (`hf://<owner>/<repo>/<path>` →
  `https://huggingface.co/<owner>/<repo>/resolve/main/<path>`;
  `b2://<bucket>/<path>` → the deployment-configured public endpoint).
  That resolution is **not implemented**: such a call fails with an
  explicit unsupported-scheme error rather than a silent fallback.
  `gs://` / `s3://` / `ftp://` / `file://` remain rejected schemes.
- Deferred: `headers`, `timeout_sec`, `max_bytes`, `sha256` verification,
  `content_type`, and `auth_bearer` (the second SecretRef acceptance
  point).

### `fs.write` — `FsWrite { path, content }`

- `path` must be absolute and under a declared `paths` root
  (chapter 05 L3), checked in both modes.
- `content`: string. The SecretRef form (write resolved secret bytes,
  the third acceptance point of chapter 06) is deferred — the AST
  cannot yet express a node-valued `content` (dsl-kit's `One` child
  slot requires a typed object and does not coerce a scalar).
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

The trace currently accumulates in an in-process buffer that no
subcommand emits: `apply` builds its report from the structured step
entries instead, and stderr carries only the final error line
(chapter 07 §Error surface). Wiring the trace to the stderr audit
transcript chapter 09 specifies is outstanding — see chapter 09
§Audit log.

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
- Unsupported: a specified-but-unimplemented route (public `b2://` /
  `hf://` scheme resolution, `net.transfer` upload, mount on a
  non-Linux host) → an explicit unsupported error naming the route.
  Never a silent skip and never a fabricated invocation.
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
streaming and partial-file cleanup), `fs.write`, `mount.bind`,
`mount.umount`, the env value nodes, and the trace log sink.

Deferred with one-line reasons:

- Per-primitive option sets listed above — the AST does not carry the
  fields yet; each is additive and changes no existing shape.
- `net.transfer` public `b2://` / `hf://` scheme resolution and HTTP
  PUT upload — the credential-carrying paths already work through the
  CLI dispatch route, so the public bridge is not on the critical
  path.
- `fs.write` `content` as a secret — blocked on a dsl-kit scalar
  coercion for the `One` child slot.
- `mount.volume_attach` has a reserved capability key and no
  primitive (provider-API territory behind the provisioning boundary,
  chapter 08).
