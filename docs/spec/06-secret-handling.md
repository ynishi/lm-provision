# 06. Secret handling

Status: specified. Layer 3.
Upstream deps: 01, 04. MVP: Phase F.

## Purpose

The surface for referring to a secret from a profile without the
secret's value ever entering the profile, the AST, the trace log, or
the report. Consumer: profile author.

Audit-log redaction (report-side contract) is specified in chapter 09,
not here.

## Inputs

### `EnvSecret { name }` — the secret reference

- A value node inhabiting an `env` keyed slot, or any of the sibling
  value-node slots the consumption-point list below enumerates
  (chapter 04 §Env value nodes). It carries the **logical name only**;
  there is no field, no spelling, and no encoding in which a value
  could be written.

  ```json
  { "type": "ShExec",
    "argv": ["hf", "auth", "whoami"],
    "env": { "HF_TOKEN": { "type": "EnvSecret", "name": "HF_TOKEN" } } }
  ```

- Two-stage allowlist enforcement against the declared `env_secrets`:
  - **validate stage** (chapter 03): every `EnvSecret` in every phase
    is cross-checked against `Spec.env_secrets`, so an undeclared
    reference is a static rejection — the profile never reaches apply.
  - **consumption stage** (apply): the same check runs again
    immediately before resolution, so a profile that reaches apply
    without validate (chapter 07 §Invocation: `apply` does not run
    validate first) is gated identically.

  The static half is new to the AST surface. Under the former Lua
  frontend `env.ref(name)` was a factory registered *before* the
  profile body ran, so the declared lists did not exist yet and the
  check could only happen at consumption — a chicken-and-egg that a
  declarative AST does not have.

### `EnvLiteral { value }` — the non-secret sibling

Carries a plain string written in the profile. It does **not** read the
host environment, so it needs no allowlist: what it injects is already
visible in the profile text (and in the profile hash).

### Plain host-env reads — no surface

There is no `env.get`. A profile cannot read an arbitrary host
environment variable: the only host-env read path is `EnvSecret`
resolution, gated by `env_secrets`. The former "second wall"
(`env.get` rejecting secret-shaped names with *use `env.ref()`*) is
subsumed — the plain-read path it guarded does not exist.

### Host-env writes — no surface

There is no `env.set`. Environment injection is explicit and per-step:
the `env` keyed slot of the consuming phase. Nothing a profile
expresses can mutate the host process environment.

### Profile declarations

- `env_secrets` lists the secret names a profile may reference. The
  names must be shell-safe (chapter 03 §validate).
- `env` (the plain list) must not contain secret-shaped keys — validate
  rejects any key containing one of the secret-key substrings
  (chapter 02 §Shared vocabulary, case-insensitive): `KEY`, `SECRET`,
  `TOKEN`, `PASSWORD`, `PWD`, `AUTH`, `CRED`, `APIKEY`. Secret-shaped
  configuration belongs in `env_secrets`.

## Outputs

### The opacity contract

- An `EnvSecret` node has no value-bearing field. Opacity is a property
  of the *shape*, not of a runtime wrapper: there is nothing to
  dereference, index, or stringify into a value.
- Canonical encoding (chapter 03) renders it as the marker
  `{"__secret":"NAME"}`, so the profile hash covers the reference
  without covering any value, and a canonical round-trip rehydrates the
  same node.
- The resolved value exists only inside the host's resolution map for
  the duration of one step. That map's diagnostic rendering prints
  **keys only** — a resolved value cannot reach the trace log through a
  stray debug format.
- The report (chapter 09) carries the step's argv, status, and captured
  output; it never carries the resolution map.

> **Predecessor.** The Lua-facing form was a `SecretRef` userdata whose
> only visible operation was `tostring(ref)` → `"[secret:NAME]"`, with
> `__index` / `__newindex` closed so opacity was physical rather than
> conventional. With no language runtime handed the reference, the
> userdata is unnecessary: a node that has no value field cannot leak
> one. The `[secret:NAME]` rendering survives as the audit-log
> redaction form (chapter 09).

### Resolution — host process, consumption time

- Resolution reads the host process environment (`NAME` → value) at
  consumption time, immediately before the effect. The resolved value
  flows into exactly one destination — the consuming step's own sink,
  enumerated per consumption point below — and is never stored,
  returned, or logged.
- Consumption points currently implemented. All four follow the
  identical check-then-resolve protocol; they differ only in where the
  resolved value goes.

  1. The `env` keyed slot of `sh.exec` (`ShExec`) → the child process
     environment.
  2. The `env` keyed slot of `sync.pull` (`SyncPull`) and
     `staging.push` (`StagingPush`) → the child process environment of
     the credential-carrying CLI dispatch route (chapter 02 §Dispatch
     routing).
  3. The `fs.write` `content` value node → file bytes (chapter 04
     §`fs.write`).
  4. The `net.http_get` / `net.http_post` `headers` keyed slot → an
     HTTP request header value, and the `net.http_post` `body` value
     node → the HTTP request body (chapter 04 §`net.http_get`). This
     is the point an API bearer token goes through:
     `"headers": { "Authorization": { "type": "EnvSecret", "name":
     "API_TOKEN" } }`. The audit transcript carries header *names*
     (sensitive-shaped ones marked `[REDACTED]`) and the body's source
     form plus byte length — never a header value, never body content.
- Consumption point specified but deferred (chapter 04): a
  `net.transfer` `auth_bearer` (→ an `Authorization: Bearer` header).
  It will adopt the identical check-then-resolve protocol. Note this is
  `net.transfer`'s own surface: the `net.http_*` header route above
  already covers bearer auth on the request primitives.
- Missing host env is fail-fast: a declared, consumed secret absent
  from the host environment aborts the step with
  `secret 'NAME' missing in host env` — no silent fallback, no
  empty-string substitution.
- **Dry-run resolves too**: `apply --dry-run` skips the effect but not
  the resolution, so undeclared-secret and missing-env errors surface
  identically under dry-run. A dry-run that passes proves the secret
  plumbing, not just the shapes.

## Error surface

All precondition class, fail-fast, no effect executed by the failing
step:

- `EnvSecret` whose `name ∉ env_secrets` →
  `secret 'NAME' is not declared in profile.env_secrets` at
  consumption, and a validate-stage rejection naming the phase index
  and env key before that.
- Declared + consumed but absent from host env →
  `secret 'NAME' missing in host env`.
- Secret-shaped key in `env` → validate-stage rejection (chapter 03).
- Non-shell-safe name in `env` / `env_secrets` → validate-stage
  rejection (chapter 03).

## Stability

- Secret opacity by node shape (a reference with no value field):
  **stable**. It replaces the userdata mechanism while strengthening
  the guarantee — the earlier tradeoff note (physical opacity vs
  IR-as-data purity, chapter 00) is resolved in favour of both.
- Two-stage (validate + consumption) allowlist enforcement, and the
  resolution rules (host-process, consumption-time, fail-fast,
  dry-run-resolves): **stable**.
- The `{"__secret":"NAME"}` canonical marker: **stable** (chapter 03
  owns the encoding).
- The consumption-point set: **provisional** — the deferred point above
  joins it, adopting the identical protocol.
- Secret-key substring set: sourced from chapter 02 shared vocabulary,
  **stable once frozen** (frozen there).

## Upstream references

- chapter 00 §Secret handling — opacity, host-side resolution,
  no-host-env-mutation, fail-fast.
- chapter 01 profile DSL surface — `env` / `env_secrets` declared
  lists.
- chapter 02 phase catalog — secret-key substring set.
- chapter 03 pipeline stage artifacts — the validate-stage
  cross-check and the canonical secret marker.
- chapter 04 bridge — env value nodes and the consumption points.

## MVP scope

Ships in Phase F: `EnvSecret` / `EnvLiteral` value nodes, the
two-stage allowlist enforcement, host-process resolution at the three
implemented consumption points, and fail-fast missing-env behaviour
including under dry-run — with negative fixtures for undeclared
references, secret-shaped `env` keys, and a missing host env.

Deferred: the `net.transfer` `auth_bearer` consumption point, blocked
on the corresponding AST field (chapter 04 §MVP scope). The `fs.write`
`content` point landed with dsl-kit 0.8's scalar shorthand (chapter 04
§`fs.write`); the `net.http_*` `headers` / `body` point (4) landed with
the HTTP request fields (chapter 04 §`net.http_get`).
