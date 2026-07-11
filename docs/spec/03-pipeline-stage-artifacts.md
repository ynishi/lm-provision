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
- canonical: any IR-shaped Lua value (encode); canonical JSON bytes
  (decode).
- hash: canonical bytes (a Lua string).
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

### canonical — `lm.canonical.encode(ir)` / `lm.canonical.decode(bytes)`

Encode produces deterministic JSON bytes:

- Objects: keys sorted lexicographically (recursive).
- Arrays (contiguous integer-keyed tables): element order preserved.
- **Empty-table rule**: an empty table encodes as `{}` — empty array
  and empty object are indistinguishable in canonical form.
- Strings: `"` `\` and control characters escaped (`\n` `\r` `\t`
  `\b` `\f`, others as `\u00XX`).
- Numbers: integers with `|v| < 1e15` as `%d`; other finite numbers
  as `%.17g`; NaN / ±Inf raise an error (not encodable).
- Secret markers: the table `{ __secret = "NAME" }` (exactly one key)
  is the canonical representation of a secret reference. A SecretRef
  userdata (chapter 06) opts in via the `__lm_secret_name` metamethod
  and encodes to the identical marker — userdata refs and literal
  marker tables are canonical-equivalent.
- Any other userdata / function / thread value raises an error.

Decode is the inverse: canonical JSON bytes → IR table, with
`{"__secret":"NAME"}` markers rehydrated into SecretRef userdata on
the Lua side (opacity preserved through the round-trip). Encode ∘
decode is byte-identity on canonical bytes. This bidirectionality is
what enables ledger reconstruction and cross-pod profile persistence
(chapter 09).

### hash — `lm.hash.sha256_hex(bytes)`

SHA-256 over the canonical bytes, rendered as a 64-character
lowercase hex string with no prefix. The profile hash is defined as
`sha256_hex(canonical.encode(ir))`. Because declared lists are
pre-sorted (chapter 01) and canonical encoding is deterministic, the
hash is byte-identical across declaration-order permutations of the
declared lists, and sensitive to phase order (which is semantic).

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
- canonical encode: raises on non-finite numbers and non-encodable
  types. decode: raises on malformed canonical bytes. Precondition
  class.
- hash: raises when the batteries hash provider is unavailable
  (host wiring bug — internal invariant, not a consumer state).
- plan / dispatch: raise only on malformed stage input (non-table);
  content-level problems were validate's job. Unknown kinds degrade
  per chapter 02 §Unknown kinds.
- Missing host env for a declared secret is **not** detected by any
  of these five stages — it surfaces fail-fast at bridge consumption
  time during apply (chapter 06), including under `--dry-run`.

## Stability

- Canonical form (all encode rules above, including the empty-table
  rule and the secret-marker convention): **stable** — the profile
  hash depends on every one of them.
- Hash function (SHA-256, lowercase hex, no prefix): **stable**.
- validate result shape, plan artifact shape, dispatch artifact
  shape and the op enum: **stable**.
- Single-error validate reporting (vs multi-error collection):
  **provisional** — may widen to an error list; `ok` / `error`
  fields keep their meaning.
- Pipeline compose form (combinator pipeline vs direct module
  calls): implementation choice, not required by this spec.

## Upstream references

- chapter 01 profile DSL surface — IR shape, list-shape rule.
- chapter 02 phase catalog — per-kind payload schemas, phase
  ordering, dispatch routing, shared vocabulary.
- chapter 06 secret handling — marker convention, `env.ref`
  validation-time deferral (why stages 1–5 never resolve secrets).

## MVP scope

Ships in Phase F: all five stages wired behind
the CLI subcommands (chapter 07) and exercised by the example-profile
regression suite (validate rejects for `bad-*` fixtures; hash
byte-identity across reordered fixtures; full dispatch fan-out under
`apply --dry-run`).

Canonical **decode** is contract-complete here but is exercised only
by the ledger path (chapter 09); it has no CLI subcommand of its own.
