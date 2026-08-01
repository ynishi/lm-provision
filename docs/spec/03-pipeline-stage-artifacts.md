# 03. Pipeline stage artifacts

Status: specified. Layer 2.
Upstream deps: 01, 02. MVP: Phase F.

## Purpose

Contract for each pipeline stage — validate, canonical, hash, plan,
dispatch — as an independent artifact. Downstream consumers observe
these artifacts; upstream stages produce them. All five stages are
pure computation over the `ProfileNode` AST (no effects); only the
apply stage (chapter 04 consumers) has effects.

## Inputs

Every stage takes the `ProfileNode` AST (chapter 01) produced by the
frontend from a JSON or canonical-text profile:

- validate: the AST root.
- canonical: the AST root (encode). Decode (canonical bytes → AST) is
  not defined in the current scope; see §canonical.
- hash: the AST root (the function computes the canonical bytes
  internally).
- plan: the AST root.
- dispatch: a lifecycle phase node (see §dispatch).

## Outputs

### validate — `validate(&ProfileNode) -> Result<(), ValidateError>`

Succeeds with no artifact, or fails on the **first** violation
(single-error reporting; validation stops at the first failure). The
profile name a caller wants on success is read off the `Spec` node,
not returned by the stage. The CLI renders success as
`{"ok": true, "name": "<profile>"}` (chapter 07).

Checks, in order:

1. The root is a `Spec` whose `name` is non-empty. The legacy
   `schema == "lm.profile/1"` content guard is **not** part of this
   stage: the wire tag is a frontend invariant (reaching validate at
   all means a well-typed AST was built), and the AST carries no
   `schema` field.
2. *(subsumed by the type system)* The five declared lists are
   `Vec<String>` on the AST, so "each entry is a string" is
   unrepresentable-as-invalid. No content condition remains.
3. No `env` key is secret-shaped (chapter 02 §Shared vocabulary,
   case-insensitive substring match) — secret names belong in
   `env_secrets`.
4. Every `env` / `env_secrets` name is shell-safe.
5. Every `paths` entry is absolute (`/`-leading), free of `..`
   segments, and shell-safe.
6. Each phase passes its per-kind walk: shell-safety of the payload
   strings the catalog marks shell-safe, `sync.*` / `staging.*` route
   shape, shell-safety of every `env` keyed-slot key, and — new to the
   AST surface — a cross-check that every `EnvSecret` value names an
   entry of `Spec.env_secrets` (chapter 06 §`EnvSecret`, validate
   stage). The unknown-kind and per-field requiredness walk the Lua
   port ran is subsumed by the typed enum.
7. `service.start` names are unique across the profile.

Because the AST payload is still a projection of the full spec-02
catalog (`custom_nodes` / `models` / `llm_models` carry an opaque JSON
string), the field-level checks for those payloads land when the
fields are promoted onto the AST. `service.start` flattens `platform`
into named fields (`model?` / `port?` / `dtype?` /
`tensor_parallel_size?` / `extra_args?`); the string-valued three
(`model` / `dtype` / `extra_args`) are shell-safety-checked, since
they reach argv positions on the launch invocation.
`hooks.post_install.script` is deliberately exempt from
shell-safety (chapter 01 §Escape / Fragment Policy).

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

- **`env` keyed slots**: a phase's `env` field (chapter 01 §Env keyed
  slots) encodes as an object keyed by variable name, entries in key
  order. An empty map omits the key entirely, so adding the field to
  a variant does not change the canonical bytes — and therefore the
  hash — of a profile that declares no env.
- **Env value nodes**: an `EnvLiteral` encodes as its plain string, so
  a literal injection reads as `"MODE":"fast"`. An `EnvSecret` encodes
  as the secret marker `{"__secret":"NAME"}` — the hash covers *which
  secret is referenced*, never a value, and the marker is the same
  convention the ledger and audit log use (chapters 06, 09).
- **`fs.write` `content`**: the content slot holds a value node and
  encodes by the env-value rules above — a literal content is its
  bare string, byte-identical to the pre-node `content: String`
  encoding (so literal-content profiles keep their hash), a secret /
  ref is its marker object (chapter 04 §`fs.write`).
- **Payload fields added after the fact**: `comfyui.restart`'s
  `extra_args` and `service.start`'s `model` / `dtype` / `extra_args`
  follow the same omit-when-unset rule as `env`, and for the same
  reason — they were introduced once profiles were already being
  hashed, so the common case (none declared) must keep its existing
  bytes. A non-empty `extra_args` encodes in **declaration order**:
  the entries are argv positions, so the declared-list sort above does
  not apply to them.

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

### plan — `plan::expand(&ProfileNode) -> Value`

Returns:

```json
{
  "profile_name": "<Spec.name>",
  "steps": [
    { "index": 1, "id": "<phase id>", "kind": "<kind>", "payload": { } }
  ]
}
```

`index` is a 1-based contiguous counter in emission order; `id` is
the canonical phase id (chapter 02 §Canonical phase ordering,
including the sync bundle, implicit insertions, per-index service
ids, and the trailing `zz_unknown` bucket).

The artifact carries **no `schema` field**: the AST has no schema
marker, and consumers read `profile_name` / `steps` only.

Unlike canonical, plan does **not** sort payload lists — the
declared-list sort is a hash-byte-identity rule, while plan is an
operator-facing rendering in which declaration order is the honest
thing to show (§Stability notes plan JSON key order is not part of
the shape either way).

### dispatch — lifecycle step composition

Dispatch is the reduction of one lifecycle phase to the smallest
things an effect can execute. It is a stage, not a persisted artifact:
`apply` composes each lifecycle phase's steps immediately before
running them, and the operator observes the result through the apply
report (chapter 09) rather than through a separate dispatch dump.

A composed step is one of:

| step | effect executed | report `op` |
|---|---|---|
| shell | `sh.exec` with the composed argv plus the phase's resolved `env` | `sh.exec` |
| transfer | `net.transfer` from `src` to `dst` | `net.transfer` |
| HTTP poll | repeated `net.http_get` until 2xx or the deadline | `net.http_get` |
| note | none — records what the phase decided | `note` |

Each composed step becomes one report entry with the id
`<phase_index>_<kind>_<n>` (direct-op phases keep the plain
`<phase_index>_<kind>`). A single phase may fan out to N steps
(`custom_nodes` emits clone / checkout / pip per node; `models` emits
one download per entry). Scheme routing rules — including which
transfers are routed to a native CLI over `sh.exec` — are chapter 02
§Dispatch routing.

A phase whose invocation cannot be constructed from the AST fields
alone expands to a single **note** step recording that fact, rather
than fabricating an argv. This replaces the legacy `dispatch_pending`
op: the report says what happened (`note`) instead of implying a
pending dispatch that no longer exists. Notes are report-visible
skips, not failures.

## Error surface

- validate: precondition errors, returned as a typed error value (the
  CLI renders it as the final `validate failed: <message>` line). Not
  retryable without editing the profile. No effects have run.
- canonical encode: total over `ProfileNode` (every variant / field
  type has a defined encoding); cannot fail. Decode is not defined in
  this revision.
- hash: total — SHA-256 over the encoder's output, with no external
  provider to be unavailable.
- plan / dispatch: total over a well-typed AST; content-level problems
  were validate's job. A non-`Spec` root yields an empty plan rather
  than an error, and unknown kinds degrade per chapter 02 §Unknown
  kinds.
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
- chapter 06 secret handling — the `EnvSecret` declared-name
  cross-check run by validate, and why no stage here ever *resolves*
  a secret (resolution is consumption-time, during apply).

## MVP scope

Ships in Phase F: all five stages wired behind
the CLI subcommands (chapter 07) and exercised by the example-profile
regression suite (validate rejects for `bad-*` fixtures; hash
byte-identity across reordered fixtures; full dispatch fan-out under
`apply --dry-run`).

All five stages operate on `ProfileNode` and are wired behind their
subcommands; the frontend-parity test suite proves the byte-identity
guarantee between the text and JSON frontends, including for the `env`
keyed slot.
