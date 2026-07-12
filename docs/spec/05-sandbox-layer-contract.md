# 05. Sandbox layer contract

Status: specified. Layer 3.
Upstream deps: 04. MVP: Phase F.

## Purpose

The four-layer sandbox that gates every Lua execution. Contract for
what each layer enforces and what a consumer (profile author,
security reviewer, host maintainer) can rely on. Layers compose: an
operation must pass every applicable layer; passing one never
bypasses another.

## Inputs

The layers are configured from exactly two sources: the embedded
module set compiled into the binary (L1) and the profile's declared
lists (L3 + L4). There is no host-side configuration file and no
ambient default-allow.

## Outputs

### L1 — stdlib restriction + require allowlist

- The VM boots with the mlua safe stdlib set, then the host strips
  these globals to nil: `os`, `io`, `package`, `debug`, `loadfile`,
  `dofile`, `load`, `loadstring`.
  - Consequence: no process / filesystem / clock access via stdlib,
    no default module loading, no debug-hook tampering, and **no
    runtime chunk loading at all** from profile code.
- Retained: `string`, `table`, `math`, `coroutine`, `utf8`, the base
  functions (`type`, `pairs`, `ipairs`, `tostring`, `assert`,
  `error`, `pcall`, ...), and `print` (redirected, chapter 04).
- Custom `require`: resolves only the embedded module allowlist —
  the ten Lua-facing `lm.*` modules
  (`lm.profile`, `lm.env`, `lm.ir`, `lm.validate`, `lm.canonical`,
  `lm.hash`, `lm.plan`, `lm.dispatch`, `lm.apply`, `lm.report`)
  plus `lm.catalog_data`, the single shared-vocabulary data file
  (22 phase kinds, `KNOWN_CAPABILITIES`, the secret-key and
  sensitive-key substring sets) that chapter 02 §Shared vocabulary
  mandates as one canonical source referenced by both the Lua and
  Rust hosts — from sources baked into the binary at compile time
  (`include_str!`). `lm.catalog_data` carries no logic and no
  effectful surface: it is a pure data table, requireable so the
  domain modules (`lm.validate` et al.) read the same bytes the Rust
  host reads. Results are cached (standard require idempotency, one
  evaluation per module per VM). Any other name is a Lua error
  listing the allowlist. There is no filesystem require path.
- Bytecode prohibition: every host-initiated chunk load (profile
  file, embedded modules) is forced to text mode; combined with the
  stripped `load*` family there is no bytecode ingestion path.

### L2 — execution control (isolation runtime)

- The VM runs on a dedicated thread owned by an isolation driver;
  the host and the VM exchange **strings only** (eval results and
  serialized JSON), never live Lua references. Dropping the driver
  tears the VM down.
- One VM per subcommand run; nothing persists between runs
  (statelessness at the VM level).
- Cooperative cancellation and wall-clock timeout are capabilities
  of the isolation layer; the current contract does not bind a global
  per-run timeout (step-level timeouts are `sh.exec` /
  `net.*` opts, chapter 04). A host-level run timeout is
  provisional (see Stability).

### L3 — policy layer (declaration-derived allowlists)

Three policies are built from the profile's declared lists and shared
by both the batteries `std.*` surface and the host's own bridges —
one allowlist, seen identically by every consumer:

- **Env policy** (`env` / `env_secrets`):
  - `env.get(key)` — allowed iff `key ∈ env`. A key in
    `env_secrets` is rejected with an explicit "use env.ref()"
    error (second wall, chapter 06). Undeclared keys are rejected.
  - `env.set` — always rejected: Lua never mutates the host
    environment.
- **HTTP policy** (`http_allowlist`): a URL is allowed iff it
  matches one of the declared patterns. A pattern is a literal URL
  prefix, optionally with a single `*` wildcard whose match is
  confined to the host portion (e.g.
  `https://*.b2.backblazeb2.com`); the wildcard never matches into
  the path.
- **Path policy** (`paths`): a path is accepted iff it is absolute,
  contains no `..` segment, and lies under a declared root with
  component-aligned prefix matching (`/workspace_x` is NOT under
  `/workspace`). This is a lexical policy: it does not chase
  symlinks. Deployment targets are fresh single-tenant pods where
  the profile itself creates the tree; symlink-racing an
  already-compromised host is out of threat model. An
  openat2/`RESOLVE_BENEATH`-based upgrade slot exists in the
  batteries layer if the threat model changes.

### L4 — capability gate (operation-level)

- `KNOWN_CAPABILITIES` (frozen, chapter 02): `env.ref`, `sh.exec`,
  `net.transfer`, `net.http_get`, `net.http_post`, `fs.write`,
  `mount.bind`, `mount.umount`, `mount.volume_attach` (reserved).
- Granularity is the operation, not the namespace: declaring
  `net.transfer` does not grant `net.http_get`.
- Two-strategy enforcement:
  1. **Register skip** (structural): bridges for undeclared
     operations are never installed — the call site hits nil.
  2. **Entry check** (defence in depth): every installed bridge
     re-validates the gate per call.
- Declared-but-unknown capability → fail-fast at load
  (`capability '<x>' declared but not implemented by host`), before
  any Lua user code runs. No silent skip.
- `capabilities = {}` is valid and means a pure-computation profile
  (validate / hash / plan work; apply can execute nothing but
  pending steps).
- L3 and L4 stack: L4 grants the operation, L3 still constrains its
  arguments (a granted `fs.write` still cannot write outside
  `paths`).

## Error surface

- L1: forbidden stdlib access → nil-value error at the call site;
  forbidden require → allowlist error (both precondition class,
  before effects).
- L2: VM-thread failure / cancellation surfaces to the host as an
  isolation error aborting the subcommand (runtime class; the VM is
  discarded, no partial state survives).
- L3: policy rejection → Lua error naming the key / URL / path and
  the declared list that excludes it.
- L4: structural nil-call, or gate-check error naming the missing
  capability; load-time fail-fast for unknown declared capabilities.

All sandbox errors leave the target system untouched except for
effects already performed by **earlier** steps of the same apply
(fail-fast model, chapter 09).

## Stability

- Layer count, responsibility split, and the two-strategy L4 model:
  **stable**.
- L1 strip set and the embedded require allowlist mechanism:
  **stable** (the allowlist contents grow with the `lm.*` module
  set).
- L3 semantics as specified (env dual-list, single-`*` host
  wildcard, lexical path policy): **stable**. The symlink-aware
  path-policy upgrade: **provisional**.
- Host-level per-run wall-clock timeout: **provisional** (not part
  of the current contract).
- `mount.volume_attach` reserved key: **provisional**.

## Upstream references

- chapter 00 §Sandbox layers — layer definitions, defer pattern.
- chapter 02 phase catalog — `KNOWN_CAPABILITIES` and shared
  vocabulary.
- chapter 04 bridge — registration order; result-vs-error
  convention.

## MVP scope

Ships in Phase F: all four layers wired as specified for the on-pod
binary, with negative fixtures for undeclared capabilities,
out-of-root paths, undeclared URLs, and secret-shaped env reads.
