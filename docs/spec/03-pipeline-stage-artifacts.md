# 03. Pipeline stage artifacts

Status: specified. Layer 2.
Upstream deps: 01, 02. MVP: Phase F.

## Purpose

Contract for each pipeline stage — validate, canonical, hash, plan,
dispatch — as an independent artifact. Downstream consumers observe
these artifacts; upstream stages produce them. All five stages are
pure Lua computation over the IR table (no bridge calls); only the
apply stage (chapter 04 consumers) has effects.

## Inputs

- validate: the IR table from chapter 01.
- canonical: a `ProfileNode` AST value (encode). Decode
  (canonical bytes → AST) is not defined in the current scope; see
  §canonical.
- hash: a `ProfileNode` AST value (the function computes the
  canonical bytes internally).
- plan: the IR table.
- dispatch: the plan artifact.

## Outputs

### validate — `lm.validate.validate(ir)`

Returns `{ ok = true, name = <profile name> }` on success, or
`{ ok = false, error = "<message>" }` on the **first** violation
(single-error reporting; validation stops at the first failure).

Checks, in order:

1. `ir` is a table; `ir.schema == "lm.profile/1"`; `ir.name` is a
   non-empty string.
2. The five declared lists are string lists.
3. No `env` key is secret-shaped (chapter 02 §Shared vocabulary,
   case-insensitive substring match) — secret names belong in
   `env_secrets`.
4. Every `env` / `env_secrets` name is shell-safe.
5. Every `paths` entry is absolute (`/`-leading), free of `..`
   segments, and shell-safe.
6. `phases` is a list; each phase passes its per-kind shape walk
   (chapter 02) including shell-safety of payload strings and
   `sync.*` / `staging.*` route shape.
7. `service.start` names are unique across the profile.

Shell-safety contract: a string is shell-safe iff non-empty and
matching `[A-Za-z0-9._/@:+=~-]+` (the with-spaces variant additionally
allows single spaces, never double). Safe strings can be interpolated
into argv without quoting.

### canonical — `canonical::encode(&ProfileNode) -> String`

Encode produces deterministic JSON bytes over the `ProfileNode` AST
(chapter 01). The encoding is a function of the AST's *type
structure* alone; the wire text that produced the AST (canonical
text vs JSON, whitespace, key order, optional-field spelling) is
irrelevant. The two frontends (canonical text grammar / JSON serde
bridge) that represent the same logical profile yield the same AST,
and therefore byte-identical canonical output.

- **NodeId is excluded** from every variant. `IdGen` mints fresh
  ids per parse-run (they differ between the two frontends and
  between runs); keeping them would break the frontend-parity
  guarantee.
- **Variant tag**: each `ProfileNode` variant encodes as an object
  carrying `"type": "<VariantName>"` (Rust variant identifier —
  same discriminator the JSON serde bridge uses on input).
- **Objects**: keys sorted lexicographically (recursive). Object
  keys are the Rust field identifiers (`packages`, `argv`, `url`,
  `ref_name`, `nodes_json`, `port`, `check_url`, `name`,
  `platform_kind`, `deps`, `in_comfy_venv`, `path`, `content`,
  `src`, `dst`, `script`, `models_json`, `want`, plus the `Spec`
  fields).
- **Declared lists**: the `Spec` fields `capabilities`, `env`,
  `env_secrets`, `paths`, and `http_allowlist` are set-shaped
  (declaration-order independent). Canonical sorts them
  lexicographically before encoding (the AST is not mutated).
- **Phase order**: `Spec.phases` is order-preserving — phase order
  is semantic.
- **`Option<String>`**: `None` omits the key entirely; `Some(x)`
  emits `"key":"x"`.
- **Empty `Vec`** encodes as `[]`. The typed AST removes the
  array/object ambiguity that motivated the legacy
  empty-table-as-`{}` rule, so that rule is retired.
- **Strings**: `"` `\` and the named control escapes
  (`\n` `\r` `\t` `\b` `\f`); any other codepoint `< 0x20` as
  `\u00xx` (lowercase hex); all other characters pass through as
  their UTF-8 bytes.
- **Numbers**: the current AST carries only `u16` (port), rendered
  as decimal integer. Float payload fields do not exist in the
  AST, so the legacy `%.17g` branch has no encode input.
- **Booleans**: `true` / `false`.

Secret markers (`{"__secret":"NAME"}`) are not part of the current
AST canonical form because `ProfileNode` has no secret *value*
type — the `env_secrets` field carries only *names* (bare strings). If
a future AST revision introduces a secret value type (e.g. an
`env` payload wired to `SecretRef`), the marker convention may be
reintroduced at that time.

Decode (canonical bytes → AST) is out of scope in the current
revision: the ledger persists JSON Lines and does not require
canonical→AST reconstruction. Encode alone is sufficient for the
hash contract below.

### hash — `canonical::hash(&ProfileNode) -> String`

SHA-256 over the canonical bytes, rendered as a 64-character
lowercase hex string with no prefix. The profile hash is defined as
`sha256_hex(canonical::encode(node))`. Because canonical sorts the
declared lists (`capabilities`, `env`, `env_secrets`, `paths`,
`http_allowlist`) and excludes `NodeId` during encoding, the hash is:

- byte-identical across declaration-order permutations of the
  declared lists;
- byte-identical across the two frontends (text grammar / JSON
  serde bridge) for the same logical profile;
- sensitive to phase order (which is semantic).

### plan — `lm.plan.expand(ir)`

Returns:

```lua
{
  profile_name = ir.name,
  schema       = ir.schema,
  steps = {
    { index = 1, id = "<phase id>", kind = "<kind>", payload = <phase table> },
    ...
  },
}
```

`index` is a 1-based contiguous counter in emission order; `id` is
the canonical phase id (chapter 02 §Canonical phase ordering,
including the sync bundle, implicit insertions, per-index service
ids, and the trailing `zz_unknown` bucket).

### dispatch — `lm.dispatch.dispatch(plan)`

Returns `{ profile_name, steps = { <op step>, ... } }` where each op
step carries:

- `id`: the plan phase id, optionally suffixed for fan-out
  (`/pull_<i>`, `/marker_<i>`, `/staging_<i>`, `/<i>`, `/<i>_clone`,
  `/<i>_ref`, `/<i>_pip`).
- `kind`: the originating phase kind.
- `op`: one of `sh.exec` | `fs.write` | `net.http_get` |
  `net.http_post` | `net.transfer` | `mount.bind` | `mount.umount` |
  `dispatch_pending`.
- op-specific fields: `argv` (sh.exec), `path` + `content`
  (fs.write), `url` (http_*), `src` + `dst` (transfer / bind),
  `path` (umount), plus `opts` forwarded to the bridge verbatim.
- `dispatch_pending` steps carry `payload` and a human-readable
  `note`; they are report-visible skips, not failures.

A single plan step may fan out to N op steps (e.g. `custom_nodes`
emits clone / checkout / pip per node; `sync.routes` emits one step
per route). Scheme routing rules are chapter 02 §Dispatch routing.

## Error surface

- validate: precondition errors, returned as `{ ok = false, error }`
  (never thrown). Not retryable without editing the profile. No
  effects have run.
- canonical encode: total over `ProfileNode` (every variant / field
  type has a defined encoding); does not raise. Decode is not
  defined in this revision.
- hash: raises when the batteries hash provider is unavailable
  (host wiring bug — internal invariant, not a consumer state).
- plan / dispatch: raise only on malformed stage input (non-table);
  content-level problems were validate's job. Unknown kinds degrade
  per chapter 02 §Unknown kinds.
- Missing host env for a declared secret is **not** detected by any
  of these five stages — it surfaces fail-fast at bridge consumption
  time during apply (chapter 06), including under `--dry-run`.

## Stability

- Canonical form (all encode rules above — variant tag under
  `"type"`, `NodeId` exclusion, declared-list sort, phase-order
  preservation, `Option::None` key elision, empty-`Vec`-as-`[]`,
  string escape, integer rendering, recursive object-key sort):
  **stable** — the profile hash depends on every one of them.
- Hash function (SHA-256, lowercase hex, no prefix): **stable**.
- Canonical **decode**: not defined in the current revision (see
  §canonical). May be introduced in a future spec revision if a
  bidirectional round-trip becomes required.
- validate result shape, plan artifact shape, dispatch artifact
  shape and the op enum: **stable**.
- Single-error validate reporting (vs multi-error collection):
  **provisional** — may widen to an error list; `ok` / `error`
  fields keep their meaning.
- Pipeline compose form (combinator pipeline vs direct module
  calls): implementation choice, not required by this spec.

## Upstream references

- chapter 01 profile DSL surface — `ProfileNode` AST shape,
  optional-field defaults, declared-list shape rule.
- chapter 02 phase catalog — per-kind payload schemas, phase
  ordering, dispatch routing, shared vocabulary.
- chapter 06 secret handling — `env.ref` validation-time deferral
  (why stages 1–5 never resolve secrets). The AST-canonical
  secret marker convention is deferred until the AST gains a
  secret value type; see §canonical.

## MVP scope

Ships in Phase F: all five stages wired behind
the CLI subcommands (chapter 07) and exercised by the example-profile
regression suite (validate rejects for `bad-*` fixtures; hash
byte-identity across reordered fixtures; full dispatch fan-out under
`apply --dry-run`).

The AST-based `canonical::encode` / `canonical::hash` land as a
self-contained Rust module. CLI wiring (`validate` / `hash` / `plan`
subcommands operating on `ProfileNode`) is a follow-up scope: this
revision defines the contract and ships the encoder + hash + a
frontend-parity test suite proving the byte-identity guarantee
between the text and JSON frontends.
