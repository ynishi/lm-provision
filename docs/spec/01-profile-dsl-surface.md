# 01. Profile DSL surface

Status: specified. Layer 1.
Upstream deps: none. MVP: Phase F.

## Purpose

The Lua-facing surface that a profile author writes against. Defines
how a profile file is loaded, what globals it may reference during
evaluation, and what shape the resulting profile object (the IR table)
has.

## Inputs

### Profile file

- Encoding: UTF-8 Lua 5.4 source. Bytecode is not loadable (chapter 05
  L1 — `load` / `loadstring` / `loadfile` / `dofile` are absent and
  the host loads every chunk in text mode).
- Entry-point convention: the host wraps the file body in a function
  and evaluates it inside the sandboxed VM. The file must `return` the
  table produced by `lm.profile {...}`. Returning any non-table value
  aborts loading with `profile.lua must return a table from
  lm.profile {...}`.
- Evaluation environment: at profile-eval time the following are
  available — the L1-retained standard library (`string`, `table`,
  `math`, `coroutine`, `utf8`, base functions), `print` (redirected to
  the host log sink), `require` (embedded `lm.*` allowlist only), and
  `env.ref` (pre-registered secret-reference factory, chapter 06).
  Bridge primitives (`sh`, `net`, `fs`, `mount`) and the batteries
  `std.*` namespace are **not** registered yet (defer pattern,
  chapter 04) — a profile body that calls one fails with `attempt to
  call a nil value` before any effect can run.

### `lm.profile(spec)` fields

| field | type | required | default | rule |
|---|---|---|---|---|
| `name` | string | yes | — | non-empty |
| `version` | string | no | `"0.0.0"` | — |
| `description` | string | no | `nil` | — |
| `capabilities` | list\<string\> | no | `{}` | entries from `KNOWN_CAPABILITIES` (chapter 05 L4) |
| `env` | list\<string\> | no | `{}` | non-secret env allowlist; secret-shaped keys rejected at validate (chapter 06) |
| `env_secrets` | list\<string\> | no | `{}` | secret allowlist; reachable only via `env.ref` |
| `paths` | list\<string\> | no | `{}` | absolute, no `..` segment, shell-safe |
| `http_allowlist` | list\<string\> | no | `{}` | literal URL prefixes; one `*` wildcard allowed in the host portion |
| `phases` | list\<phase\> | no | `{}` | phase tables per chapter 02 |

Every entry of the five declared lists must be a Lua string; a
non-string entry aborts at definition time with a typed assert
message (`lm.profile: <field>[<i>] must be a string, got <type>`).

### List-shape rule (stable sort vs user order)

- The five declared lists (`capabilities`, `env`, `env_secrets`,
  `paths`, `http_allowlist`) are copied and **stable-sorted
  lexicographically** by `lm.profile`. Declaration order carries no
  meaning; the canonical form (chapter 03) is therefore independent of
  the author's ordering and the profile hash is byte-identical across
  reorderings of these lists.
- `phases` preserves user-declared order verbatim. Phase order is
  step semantics, not a declaration; chapter 02 defines how the plan
  stage re-buckets it.

### Phase shape: plain table baseline + constructor layer

- Baseline (stable, wire-level): each phase is a plain Lua table
  `{ kind = "<kind>", ...payload fields... }` with `kind` naming a
  catalog entry (chapter 02). No metatables, no hidden state — the
  IR is pure data.
- Constructor layer (provisional): per-kind constructors that surface
  unknown-kind and unknown-field errors at definition time and emit
  exactly the plain-table shape above. Because constructors compile to
  the identical IR, chapter 03 canonical / hash / plan are unaffected
  by their introduction. The constructor surface is provisional
  until Phase H; the plain-table form remains accepted.

### Escape / fragment policy

- Inner escape: `hooks.post_install` carries an arbitrary shell
  `script` string (chapter 02). This is the single sanctioned place
  for raw shell inside a profile.
- Outer escape: fragment reuse is done with ordinary host-side Lua
  functions composed *before* `lm.profile {...}` is called (pure
  computation over plain tables). The DSL vocabulary is not grown for
  templating.

## Outputs

- The IR table: the normalized spec with `schema = "lm.profile/1"`
  attached by `lm.ir.build`. Shape:

  ```lua
  {
    schema         = "lm.profile/1",
    name           = "...",
    version        = "...",
    description    = "..." | nil,
    capabilities   = { ... },  -- sorted
    env            = { ... },  -- sorted
    env_secrets    = { ... },  -- sorted
    paths          = { ... },  -- sorted
    http_allowlist = { ... },  -- sorted
    phases         = { {kind = "...", ...}, ... },  -- user order
  }
  ```

- This table is simultaneously: the value the host extracts
  declarations from (capability gate + policies, chapter 05), the
  input to every pipeline stage (chapter 03), and the object whose
  canonical encoding is hashed.

### Capability enforcement model

The declared `capabilities` set is the allowlist. Enforcement of
"used ⊆ declared" is **physical, at apply time**: bridges for
undeclared operations are never registered (structural nil-call
reject) and every bridge entry re-checks the gate (chapter 05 L4).
Definition-time derivation of the used set from the catalog is the
constructor layer's job and shares its provisional status.

## Error surface

All are precondition errors: not retryable, no side effects have run,
the VM is discarded afterwards.

- Definition-time asserts from `lm.profile`: spec not a table, `name`
  missing/empty, declared-list entry not a string, `phases` not a
  list-shaped table.
- `require("<name>")` for a module outside the embedded `lm.*`
  allowlist: Lua error naming the allowlist.
- Bridge / batteries primitive referenced during profile evaluation:
  `attempt to call a nil value` (defer pattern, physical guarantee).
- Profile file does not return a table: `profile.lua must return a
  table from lm.profile {...}`.
- Deeper shape rules (shell-safety, route shape, secret-shaped env
  keys, path absoluteness) are validate-stage errors — chapter 03.

## Stability

- Plain-table phase shape, declared-list stable-sort rule, IR field
  set, `schema = "lm.profile/1"` tag: **stable**.
- Constructor surface (namespace and per-kind signatures):
  **provisional** through Phase H.
- `lm.env` facade module (`require("lm.env")` re-exporting the host
  `env` table): **stable**.
- Preset `extends`: not part of this contract (see chapter 00 — a
  profile is one complete definition).

## Upstream references

- chapter 00 §DSL surface — assertion form, list-shape rule,
  escape / fragment policy.
- chapter 02 phase catalog — phase kinds, payload schemas, per-kind
  capability requirements.

## MVP scope

Ships in Phase F: plain-table DSL, five declared lists with stable
sort, `hooks.post_install` inner escape, defer-pattern evaluation
environment, `env.ref` pre-load availability.

Constructor layer and `.d.lua` editor codegen ride the same IR and
can be added without breaking this contract (chapter 02 owns the
schema they are generated from).
