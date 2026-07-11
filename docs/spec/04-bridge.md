# 04. Bridge

Status: specified. Layer 3.
Upstream deps: 03. MVP: Phase F.

## Purpose

The sole effectful surface between Lua profile code and the host.
Defines the primitive set (`sh`, `net`, `fs`, `mount`, `env.ref`),
the registration order, and the signature of each primitive. The Rust
host carries no domain vocabulary — it implements exactly these
primitives plus the sandbox (chapter 05); everything else is Lua.

## Inputs

### Registration order (defer pattern)

The host boots one VM per subcommand run and registers in this fixed
order:

```
1. L1 stdlib strip + custom require (embedded lm.*)   [chapter 05]
2. print redirect (print → host log sink)
3. env.ref factory                                     [chapter 06]
4. profile file evaluation  → _LM_PROFILE global
5. declaration extraction (name / capabilities / env /
   env_secrets / paths / http_allowlist)
6. batteries std.* registration with the declaration-derived
   policies (env / http)                               [chapter 05 L3]
7. capability gate build + assert-all-implemented      [chapter 05 L4]
8. cap-gated bridge registration — only declared operations
   are installed (register skip)
9. pipeline execution (validate / hash / plan need only steps
   1–7; apply runs 8 then the dispatched op stream)
```

The security consequence: during steps 4–5 no batteries primitive and
no bridge exists — a profile that reaches for one dies with `attempt
to call a nil value` before any effect can run. This is a physical
guarantee, not a lint.

### Common conventions

- Every bridge re-checks the capability gate at entry (defence in
  depth over the register skip).
- Every bridge accepts `opts.dry_run` (boolean): the call performs
  all decoding, policy checks, and secret resolution, then skips the
  effect and returns `{ ok = true, dry_run = true, ...echo... }`.
  Dry-run therefore still fails on policy violations and missing
  secrets — it validates everything except the effect itself.
- Result-vs-error convention: **usage, policy, and secret errors are
  Lua errors** (abort the step with a message); **effect failures**
  (non-zero exit, transport failure, syscall failure) are returned as
  result tables with `ok = false` and an `error` / `stderr` field so
  the apply report can carry them.
- SecretRef acceptance points (`sh.exec` opts.env values,
  `net.transfer` opts.auth_bearer, `fs.write` content) all follow the
  same protocol: check the name against declared `env_secrets`,
  resolve from host env on the host thread, never hand the value to
  Lua (chapter 06).

## Outputs

### `sh.exec(argv, opts) -> result`

- `argv`: non-empty list of strings (program + args). No shell is
  implied — callers that need shell semantics pass
  `{"sh", "-c", script}` explicitly.
- `opts`:
  - `env`: table\<string, string | SecretRef\> — injected into the
    child env; SecretRefs resolved host-side.
  - `cwd`: string working directory.
  - `stdin`: string piped to child stdin (pipe closed → EOF), XOR
  - `stdin_file`: string path opened as child stdin. Supplying both
    is a Lua error.
  - `timeout_sec`: number > 0 — kill the child group after N
    seconds.
  - `term_grace_sec`: number > 0 (Unix) — on timeout, SIGTERM the
    process group first and wait up to N seconds before SIGKILL.
  - `on_line(stream, line, lineno)`: streaming callback, called per
    output line as it arrives (`stream` ∈ `"stdout"` / `"stderr"`,
    `lineno` global 1-based across both streams). Callback errors
    are logged and swallowed — they never fail the exec. Output is
    still accumulated and returned in full.
  - `dry_run`: see conventions.
- Result: `{ ok, status, stdout, stderr, dry_run, timed_out }` —
  `ok = (exit status 0 ∧ not timed out)`; `status = -1` when killed;
  on timeout `stderr` is suffixed with a `timed out after Ns
  (terminated gracefully | killed)` line.
- Process-group semantics (Unix): the child is spawned as a process
  group leader; timeout signals (SIGTERM / SIGKILL) target the whole
  group so backgrounded descendants cannot outlive the step or hold
  the output pipes open.

### `net.http_get(url, opts)` / `net.http_post(url, opts)`

- URL must pass the profile's `http_allowlist` policy (chapter 05
  L3); violation is a Lua error.
- Common `opts`: `headers` table\<string,string\>, `timeout_sec`
  (default 30), `max_bytes` (default 16 MiB — larger responses are
  rejected, never buffered unbounded), `dry_run`.
- POST body: exactly one of `opts.body` (string, verbatim),
  `opts.body_json` (table → JSON, sets `Content-Type:
  application/json` unless caller provided one), `opts.body_form`
  (table\<string,string\> → urlencoded, sets the form content type).
  Supplying more than one is a Lua error.
- Result: `{ ok, status, body, headers, dry_run, error? }` with
  `ok = (200 ≤ status < 400)`; transport failure yields
  `{ ok = false, status = -1, body = "", error }`.

### `net.transfer(src, dst, opts) -> result`

- Scheme resolution before any policy check:
  `hf://<owner>/<repo>/<path>` →
  `https://huggingface.co/<owner>/<repo>/resolve/main/<path>`;
  `b2://<bucket>/<path>` →
  `https://f<NNN>.backblazeb2.com/file/<bucket>/<path>` (the `f<NNN>`
  cluster prefix is deployment-configured);
  `gs://` `s3://` `ftp://` `file://` are rejected with an explicit
  unsupported-scheme error; anything non-URL is a local path.
- Direction is inferred after resolution: URL→path = download,
  path→URL = upload; URL→URL and path→path are Lua errors (the
  latter points the caller at `fs.*`).
- Upload directly to an `hf://` / `b2://` dst is rejected at this
  bridge — the dispatch layer routes those to the native CLIs over
  `sh.exec` (chapter 02 §Dispatch routing).
- Policy: download checks the resolved src URL against
  `http_allowlist` and the dst path against `paths`; upload checks
  the src path and the dst URL. Violations are Lua errors.
- `opts`: `headers`, `timeout_sec` (default 30), `max_bytes`
  (default 16 MiB, applies to the transferred byte count),
  `sha256` (lowercase hex — downloads verify and delete the file on
  mismatch), `content_type` (upload; default
  `application/octet-stream` unless a caller header overrides),
  `auth_bearer` (string | SecretRef → `Authorization: Bearer ...`
  header unless the caller already set one), `dry_run`.
- Download streams to the destination file (never fully buffered);
  on any failure the partial file is removed. Result:
  `{ ok, status, bytes, sha256, direction = "download", dst,
  dry_run, error? }`.
- Upload reads the file, PUTs it, and reports
  `{ ok, status, bytes, sha256, direction = "upload", src, dry_run,
  error? }`.

### `fs.write(path, content, opts) -> result`

- `path` must be absolute and under a declared `paths` root (Lua
  error otherwise).
- `content`: string, or SecretRef (declared-secret check + host-side
  resolve; the resolved bytes exist only for the duration of the
  write).
- `opts`: `mode` (integer, Unix file mode, default 0o644), `append`
  (default false = truncate), `mkdir_p` (default false; every created
  ancestor is itself path-gated), `dry_run`.
- Result: `{ ok, bytes, dry_run }`; I/O failures are Lua errors
  (surfaced by apply as step failure text).

### `mount.bind(src, dst, opts)` / `mount.umount(path, opts)`

- Linux only: on other platforms the call returns
  `{ ok = false, error = "not supported on this platform (...)" }`
  at call time — registration itself succeeds so profiles remain
  loadable everywhere.
- Both paths (or the umount target) must be under declared `paths`
  roots.
- `mount.bind` opts: `recursive` (MS_REC), `read_only` (two-step
  remount `MS_REMOUNT|MS_BIND|MS_RDONLY`; on remount failure the
  initial bind is undone so the caller never observes a writable
  mount they asked to be read-only), `dry_run`.
- `mount.umount` opts: `lazy` (MNT_DETACH), `force` (MNT_FORCE),
  `dry_run`. Separate capability from `mount.bind` — declaring bind
  does not grant umount.
- Privilege: real mounts need root / CAP_SYS_ADMIN; OS errors
  (EPERM etc.) propagate verbatim in the result `error` field.
- Result: `{ ok, dry_run, src, dst | path, ...echo..., error? }`.

### `env.ref(name) -> SecretRef`

Thin factory, registered before the profile body runs; performs no
policy check (chapter 06 owns the timing rationale). The full secret
contract is chapter 06.

### `print(...)`

Redirected to the host log sink. SecretRef arguments render as
`[secret:NAME]`; tables as `<table>`; other userdata as
`<userdata>`. Profile scripts cannot write to the process stdout
(stdout is reserved for the machine-readable artifact, chapter 07).

## Error surface

- Structural: operation not declared → the global is nil →
  `attempt to call a nil value` (precondition, no effect ran).
- Gate: direct tampering reaching a bridge with an undeclared
  capability →
  `capability '<op>' not declared in profile.capabilities` Lua error.
- Policy: env / http / path allowlist violations → Lua error naming
  the offending value (precondition, no effect ran).
- Secret: undeclared name at consumption → Lua error; declared but
  missing in host env → `secret '<NAME>' missing in host env` Lua
  error (fail-fast, also under dry-run).
- Effect failures: non-zero exit / timeout / transport / syscall →
  `ok = false` result table (retryable at the operator's discretion;
  the step's externally visible effects may be partial — download
  partials are cleaned up, sh.exec side effects are the command's
  own responsibility).

## Stability

- Primitive set and each signature above: **stable once frozen** —
  frozen as specified here.
- Registration order / defer pattern: **stable** (security
  invariant).
- Result-vs-error convention: **stable**.
- Scheme-resolution URL templates (`hf://` resolve/main, `b2://`
  public endpoint): **provisional** — endpoint churn upstream
  may force a revision; the `hf://` / `b2://` author-facing syntax
  is stable.
- Static-binary embeddability (no dynamic linkage requirements in
  any bridge): **stable** (constraint from chapter 08).

## Upstream references

- chapter 00 §Boundary and stack — mlua embedded VM as transport.
- chapter 00 §Sandbox layers — defer pattern as security invariant.
- chapter 02 phase catalog — dispatch routing that targets these
  primitives.
- chapter 06 secret handling — SecretRef protocol at consumption
  points.

## MVP scope

Ships in Phase F: `sh.exec` (full option set
including streaming and graceful timeout), `net.http_get`,
`net.http_post`, `net.transfer` (download + https upload + scheme
resolution + sha256 verify), `fs.write`, `mount.bind`,
`mount.umount`, `env.ref`, print redirect.

`mount.volume_attach` has a reserved capability key and no bridge
(provider-API territory behind the provisioning boundary,
chapter 08).
