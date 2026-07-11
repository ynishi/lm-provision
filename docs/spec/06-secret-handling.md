# 06. Secret handling (Lua-facing only)

Status: specified. Layer 3.
Upstream deps: 01, 04. MVP: Phase F.

## Purpose

The Lua-facing surface for referring to secrets without ever handing
their resolved values back to Lua. Consumer: profile author.

Audit-log redaction (report-side contract) is specified in
chapter 09, not here.

## Inputs

### `env.ref(name) -> SecretRef`

- A thin factory: wraps `name` in an opaque SecretRef userdata. It
  performs **no policy check** at call time.
- Validation timing rationale: `env.ref` is registered before the
  profile body runs, because profile bodies reference secrets inside
  declared fields (phase payloads). Checking `name` against
  `env_secrets` at ref time would require the declarations to be
  extracted first — a chicken-and-egg. The `env_secrets` allowlist
  is therefore enforced at **bridge consumption time**: every bridge
  that accepts a SecretRef checks `ref.name ∈ env_secrets` before
  resolving.
- Consumption points (the complete set): `sh.exec` `opts.env`
  values, `net.transfer` `opts.auth_bearer`, `fs.write` `content`.
  A SecretRef appearing anywhere else is inert data (it canonicalizes
  to its marker, chapter 03, and prints redacted).

### `env.get(name) -> string`

- Returns the host env value for `name` iff `name ∈ env` (the
  declared non-secret list).
- Rejects `name ∈ env_secrets` with an explicit "use env.ref(),
  env.get() is forbidden" error — the second wall: even a declared
  secret name never yields its value through the plain-read path.
- Rejects undeclared names.

### `env.set` — prohibited

Always rejected. All environment injection happens through explicit
exec-time env (`sh.exec` `opts.env`); Lua cannot mutate the host
environment.

### Profile declarations

- `env_secrets` lists the secret names a profile may reference. The
  names must be shell-safe (chapter 03 §validate).
- `env` (the plain list) must not contain secret-shaped keys —
  validate rejects any key containing one of the secret-key
  substrings (chapter 02 §Shared vocabulary, case-insensitive):
  `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PWD`, `AUTH`, `CRED`,
  `APIKEY`. Secret-shaped configuration belongs in `env_secrets`.

## Outputs

### SecretRef userdata — the opacity contract

- The only value-bearing operation visible to Lua is `tostring(ref)`
  → `"[secret:NAME]"` (redacted marker, never the value).
- `ref:name()` returns the logical name (for report / correlation
  use) — never the value.
- Field access, indexing, and arithmetic are unimplemented: there is
  no `__index` / `__newindex`, so `ref.anything` is nil and
  assignment errors. Opacity is physical (userdata), not
  conventional.
- Canonical-encoding hook: the metatable exposes `__lm_secret_name`
  so `lm.canonical` encodes the ref as the marker table
  `{"__secret":"NAME"}` (chapter 03). Decode rehydrates markers back
  into SecretRef, preserving opacity across the round-trip.

### Resolution — host thread only

- Resolution reads the host process environment (`NAME` → value) on
  the host thread, at bridge consumption time, immediately before
  the effect. The resolved value flows into exactly one of: child
  process env (`sh.exec`), an `Authorization: Bearer` header
  (`net.transfer`), or file bytes (`fs.write`). It is never
  returned to Lua, never stored, and never logged.
- Missing host env is fail-fast: a declared, consumed secret absent
  from the host environment aborts the step with
  `secret 'NAME' missing in host env` — no silent fallback, no
  empty-string substitution.
- **Dry-run resolves too**: `opts.dry_run` skips the effect but not
  the decode path, so undeclared-secret and missing-env errors
  surface identically under dry-run. A dry-run that passes proves
  the secret plumbing, not just the shapes.

## Error surface

All precondition class, fail-fast, no effect executed by the failing
step:

- SecretRef consumed with `name ∉ env_secrets` →
  `secret 'NAME' is not declared in profile.env_secrets` (Lua
  error, named per consumption point).
- Declared + consumed but absent from host env →
  `secret 'NAME' missing in host env`.
- `env.get` with a secret name → "use env.ref()" rejection; with an
  undeclared name → "not declared in profile.env" rejection.
- `env.set` → unconditional rejection.
- Secret-shaped key in `env` → validate-stage rejection
  (chapter 03).

## Stability

- SecretRef as userdata (vs pure marker table): **stable** —
  physical opacity is preferred over a structural rule; the
  IR-as-data purity tradeoff is recorded in chapter 00.
- The opacity contract (tostring form, `name()`, no field access),
  the consumption-time validation model, the resolution rules
  (host-thread, fail-fast, dry-run-resolves): **stable**.
- The consumption-point set: **provisional** — new bridges may join,
  each adopting the identical check-then-resolve protocol.
- Secret-key substring set: sourced from chapter 02 shared
  vocabulary, **stable once frozen** (frozen there).

## Upstream references

- chapter 00 §Secret handling — opacity, deferred policy,
  host-side resolution, `env.set` prohibition, fail-fast.
- chapter 01 profile DSL surface — `env` / `env_secrets` declared
  lists.
- chapter 02 phase catalog — secret-key substring set.
- chapter 04 bridge — consumption points and the check-then-resolve
  protocol.

## MVP scope

Ships in Phase F: `env.ref`, SecretRef opacity, `env.get` double
wall, `env.set` prohibition, host-thread resolution at all three
consumption points, fail-fast missing-env behaviour including under
dry-run, with negative fixtures for undeclared refs, secret-shaped
env keys, and missing host env.
