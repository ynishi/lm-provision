# 05. Sandbox layer contract

Status: specified. Layer 3.
Upstream deps: 04. MVP: Phase F.

## Purpose

The four-layer sandbox that gates every profile execution. Contract for
what each layer enforces and what a consumer (profile author, security
reviewer, host maintainer) can rely on. Layers compose: an operation
must pass every applicable layer; passing one never bypasses another.

## Inputs

The layers are configured from exactly two sources: the frontend set
compiled into the binary (L1) and the profile's declared lists
(L3 + L4). There is no host-side configuration file and no ambient
default-allow.

## Outputs

### L1 — data-only ingestion

- A profile is parsed into a `ProfileNode` AST (chapter 01) from JSON
  or canonical text. **Neither frontend can express behaviour**: the
  result of parsing is a value, not a program. There is no host-side
  eval, no interpreter, and therefore no chunk-loading, bytecode, or
  module-resolution surface to restrict.
- `.lua` paths are rejected before any I/O
  (`Lua profiles are no longer supported`, chapter 07 §Profile input
  format), so the removed authoring frontend cannot be reached by a
  filename.
- Effects reachable from a profile are exactly the primitives of
  chapter 04, selected by *which phase kinds the profile declares* —
  not by what code it runs.

> **Predecessor.** L1 previously specified an mlua stdlib nil-out
> (`os`, `io`, `package`, `debug`, `load*`, ...), a custom `require`
> restricted to embedded `lm.*` modules, and a bytecode prohibition.
> Those mechanisms existed to keep author-supplied *code* from reaching
> the host. With the embedded VM removed there is no author-supplied
> code, so the guarantee is structural rather than enforced. The
> attack surface they closed is closed by absence.

### L2 — execution model

- One execution context per subcommand run, built from the profile
  root (chapter 04 §Execution context build order) and discarded when
  the run ends. Nothing persists between runs.
- Execution is a step loop over the AST inside the host process; there
  is no separate VM, no cross-thread value exchange, and no live
  reference a profile could retain.
- The loop is bounded by a step ceiling so a pathological AST cannot
  spin indefinitely. Per-effect timeouts belong to the individual
  primitives (chapter 04); a host-level wall-clock run timeout and
  cooperative cancellation remain out of the current contract
  (see Stability).

> **Predecessor.** L2 previously specified a dedicated VM thread owned
> by an isolation driver exchanging strings only, with the driver drop
> tearing the VM down. Statelessness and the absence of shared live
> references survive; the thread-isolation mechanism does not, because
> there is no second language runtime to isolate.

### L3 — policy layer (declaration-derived allowlists)

Three policies are built from the profile's declared lists before any
op is reachable, and consulted in **both** dry-run and real mode
(chapter 04 §Common conventions):

- **Secret env policy** (`env_secrets`): an `EnvSecret` value node is
  resolved from the host environment only when its name appears in
  `env_secrets`; an undeclared name is rejected, and a declared name
  absent from the host environment is a fail-fast error. This is the
  only path by which the host environment is read (chapter 06).
- **HTTP policy** (`http_allowlist`): a URL is allowed iff it matches
  one of the declared patterns. A pattern is a literal URL prefix,
  optionally with a single `*` wildcard whose match is confined to the
  authority component (e.g. `https://*.b2.backblazeb2.com`); the
  wildcard never matches into the path.
- **Path policy** (`paths`): a path is accepted iff it is absolute,
  contains no `..` segment, and lies under a declared root with
  component-aligned prefix matching (`/workspace_x` is NOT under
  `/workspace`). This is a lexical policy: it does not chase symlinks.
  Deployment targets are fresh single-tenant pods where the profile
  itself creates the tree; symlink-racing an already-compromised host
  is out of threat model. An `openat2` / `RESOLVE_BENEATH`-based
  upgrade slot remains available if the threat model changes.

An empty declared list denies everything in its domain: a profile that
declares no `paths` cannot write any path, and one that declares no
`http_allowlist` cannot reach any URL.

The `env` declared list (the non-secret allowlist) is currently
consumed by **validate only** — it must contain no secret-shaped key
and every entry must be shell-safe (chapter 03 §validate). It carries
no execution-time role, because the plain host-env read surface it used
to gate (`env.get`) no longer exists: a non-secret env value is written
into the profile as an `EnvLiteral` and never read from the host. The
list is retained as a declaration and as the anchor for the
secret-shaped-key rejection; re-binding it to an execution-time role is
a design opening, not a silent gap (see Stability).

### L4 — capability gate (operation-level)

- `KNOWN_CAPABILITIES` (frozen, chapter 02): `env.ref`, `sh.exec`,
  `net.transfer`, `net.http_get`, `net.http_post`, `fs.write`,
  `mount.bind`, `mount.umount`, `mount.volume_attach` (reserved).
- Granularity is the operation, not the namespace: declaring
  `net.transfer` does not grant `net.http_get`.
- Enforcement is a per-op **entry check**: every op handler validates
  the gate before touching its payload's targets, in dry-run and real
  alike. Lifecycle phases are gated by the capability of the effect
  they expand into (e.g. every `sh.exec`-composing lifecycle op
  requires `sh.exec`; `sync.pull` / `staging.push` / `models` require
  `net.transfer`).
- Declared-but-unknown capability → fail-fast at context-build time
  (`capability '<x>' declared but not implemented by host`), before
  any op runs. No silent skip.
- `capabilities = []` is valid and means a pure-computation profile
  (validate / hash / plan work; apply can execute nothing).
- L3 and L4 stack: L4 grants the operation, L3 still constrains its
  arguments (a granted `fs.write` still cannot write outside `paths`).

> **Predecessor.** L4 previously specified a two-strategy model:
> register skip (bridges for undeclared operations were never
> installed, so the call site hit nil) plus the entry check as defence
> in depth. Register skip was a property of a *namespace exposed to
> author code*; with no such namespace, the registry installs every op
> and the entry check is the single enforcement point. The
> "declared ⊆ used" guarantee is unchanged — what changed is that a
> denial is now a named error instead of a nil-call.

## Error surface

- L1: a `.lua` path → load rejection; malformed JSON / text → parse
  error (both precondition class, before any effect).
- L2: an engine-internal failure aborts the subcommand; the context is
  discarded and no partial state survives the process.
- L3: policy rejection → an error naming the offending secret name /
  URL / path and the declared list that excludes it, recorded on the
  step's report entry (precondition class, fires under dry-run too).
- L4: gate-check error naming the missing capability; context-build
  fail-fast for unknown declared capabilities.

All sandbox errors leave the target system untouched except for
effects already performed by **earlier** steps of the same apply
(fail-fast model, chapter 09).

## Stability

- Layer count and the responsibility split (ingestion / execution
  model / policy / capability): **stable**.
- L1 as data-only ingestion, and the rejection of `.lua` paths:
  **stable**.
- L2 statelessness (one context per run, nothing persisted):
  **stable**. Host-level per-run wall-clock timeout and cooperative
  cancellation: **provisional** (not part of the current contract).
- L3 semantics as specified (secret-env gating, single-`*` authority
  wildcard, lexical path policy, empty-list-denies-all): **stable**.
  The symlink-aware path-policy upgrade: **provisional**. An
  execution-time role for the `env` declared list: **provisional**.
- L4 entry-check enforcement and the frozen `KNOWN_CAPABILITIES` set:
  **stable**. `mount.volume_attach` reserved key: **provisional**.

## Upstream references

- chapter 00 §Sandbox layers — layer definitions.
- chapter 01 profile DSL surface — the declared lists that configure
  L3 and L4.
- chapter 02 phase catalog — `KNOWN_CAPABILITIES` and shared
  vocabulary.
- chapter 04 bridge — context build order; result-vs-error convention.
- chapter 06 secret handling — the secret-env policy in detail.

## MVP scope

Ships in Phase F: all four layers wired as specified for the on-pod
binary, with negative fixtures for undeclared capabilities,
out-of-root paths, undeclared URLs, undeclared secret names, and
secret-shaped `env` keys.
