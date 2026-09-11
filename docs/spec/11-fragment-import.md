# 11. Fragment import

Status: draft (design settled at spec level; §MVP scope increments 1–3
— local imports, remote imports + cache, and the `pin` resolver
subcommand — are implemented in `crates/lm-provision/src/resolve.rs`,
`crates/lm-provision/src/to_bridge_json.rs`, and
`crates/lm-provision/src/pin.rs`).
Layer 2.
Upstream deps: 01, 02, 03. MVP: post-H increment (§MVP scope).

## Purpose

Profile reuse without templating. A profile can import a **fragment** —
a hash-pinned, immutable document carrying phases and the declarations
those phases need — and the profile's identity stays what it always
was: the canonical hash of the fully expanded AST.

This chapter revises the outer half of chapter 01 §Escape / Fragment
Policy. The original policy ("fragment reuse is performed by external
tools generating profiles") kept the DSL small but pushed every reuse
need into ad-hoc generators — the trajectory that gave CSS fifteen
years of preprocessor toolchains and Kubernetes YAML its
Helm/Kustomize/ksonnet sprawl. The survey behind this revision found
the stable middle ground is neither external generation nor a
programmable config language: it is a **data-level import with a
mandatory content-hash pin**, the shape Dhall (semantic integrity
imports), GitHub Actions (`uses: repo@sha`) and Nix (`flake.lock`)
each arrived at independently. String templating and scripting
constructs remain out of the DSL — that half of the policy stands.

## Adopted conventions

Where an established rule exists, this design follows it rather than
inventing one:

| convention | source | adopted form |
|---|---|---|
| hash the *expanded normal form*, not the source text | Dhall semantic integrity check (dhall-lang `standard/imports.md`) | pin = fragment's expanded canonical hash; refactoring a fragment's internal split never changes its identity |
| a remote import may not import a local path | Dhall referential sanity check | remote fragments import remote fragments only |
| a fragment's relative imports resolve against the fragment's own location | Dhall import chaining; Docker Compose `include` project-directory rule | fragment-relative resolution, never consumer-relative |
| cache keyed by hash; a hash hit makes no network request | Dhall cache MUST rule | `${XDG_CACHE_HOME:-~/.cache}/lm-provision/fragments/<hash>` |
| a URL is a location hint, never an identity | Deno's published HTTP-imports retrospective | trust derives from the pin; any mirror serving matching bytes is equivalent |
| the name→location resolver is static-file-servable | GOPROXY protocol (fixed GET paths, no query params) | `index.json` is the resolver; no registry service |

**Hash spelling**: the pin is a 64-character lowercase hex SHA-256
with **no prefix** — the spelling `canonical::hash` (chapter 03),
`index.json` `profile_hash`, and `fetch --expect-hash` already use.
Dhall and OCI both write `sha256:<hex>`; consistency with this
repository's own settled convention wins over consistency with
theirs. If a second algorithm ever becomes necessary, a prefixed form
can be introduced then — an unprefixed 64-hex string remains
unambiguous.

## The `Import` node

A new `ProfileNode` variant, legal in any `Spec.phases` /
`Fragment.phases` list position:

| field | type | required | rule |
|---|---|---|---|
| `src` | string | yes | source form per §Source forms |
| `hash` | string | remote: yes / local: no | 64-char lowercase hex; the fragment's expanded canonical hash |

JSON form:

```json
{
  "type": "Import",
  "src": "https://raw.githubusercontent.com/ynishi/lm-provision/main/docs/profiles/qwen3p6-27b-awq-0.1.0.json",
  "hash": "426ee76b2e055bd80003697443d5b1a2703396f0158013f5a48a0b0fc1c4daed"
}
```

Canonical text form:

```text
Import(
    src: "https://raw.githubusercontent.com/.../qwen3p6-27b-awq-0.1.0.json",
    hash: "426ee76b..."
)
```

The pin is mandatory for remote sources: an unpinned remote import is
rejected at resolve, not fetched-then-warned. For local sources the
pin is optional — a working-tree fragment changes on every edit, and
the consuming profile's own expanded hash already covers whatever the
fragment contained at hash time. A local pin, when written, is
verified exactly like a remote one.

## Fragment documents

A fragment is a top-level `Fragment` node — a `Spec` cut down to what
a reusable unit can honestly own:

| field | carried | notes |
|---|---|---|
| `name`, `version`, `description` | yes | same rules as `Spec` |
| `capabilities`, `env_secrets`, `paths`, `http_allowlist`, `sh_egress` | yes | set-shaped, merged by union (§Resolution) |
| `env`, `assumes` | yes | keyed tables, merged disjointly (§Resolution) |
| `phases` | yes | phase nodes per chapter 02, `Import` included |
| machine requirements (`requires_*`), `provider` | **no** | machine shape is the consumer's declaration; a fragment cannot know what else the profile runs |
| `artifacts` | **no** | what a run is *for* belongs to the profile |

Published fragments follow the profile immutability convention
(docs/profiles README): a `name-version.json` never changes; edits
ship as a new version with a new hash.

## Source forms

| form | example | rule |
|---|---|---|
| remote | `https://host/path.json` | **https only**; http is rejected |
| relative path | `./frag.json`, `../shared/frag.json` | resolved against the importing document's own location |
| absolute path | `/opt/fragments/frag.json` | operator-host path |

Not source forms: `file://` URLs (RFC 8089 itself documents the
implementation divergence; bare paths carry the same meaning without
it), `~/` home paths (a profile that resolves differently per operator
host is not the same profile), environment-variable imports, and any
fallback/`missing` construct. Parser selection follows the extension
rule the fetch surface already applies (`.json` → serde bridge,
otherwise canonical text).

## Resolution

Resolve is a new pipeline stage between load and validate:

```text
load → resolve → validate → canonical / hash → plan → …
```

Everything downstream of resolve sees a plain expanded `Spec`. The
`Import` and `Fragment` variants never reach canonical: the ledger,
the plan artifact, the uploaded payload and the on-pod provisioner
(chapters 03, 08, 09) are untouched by this chapter. Fetching happens
on the operator host at resolve time; `http_allowlist` is a *pod
runtime* policy and does not govern it.

Expansion, per `Import` node, in order:

1. **Fetch or read** `src`. Remote fetch consults the cache first
   (§Cache); a cache hit under the pinned hash makes no request.
2. **Recurse**: resolve the fragment's own imports (import chaining —
   its relative `src` values resolve against *its* location; a remote
   fragment's relative import stays same-origin and therefore
   remote). A cycle is an error. The **referential sanity check**
   applies: a fragment reached via https may only import https
   sources.
3. **Verify the pin**: compute the fragment's expanded canonical hash
   (chapter 03 rules applied to the expanded `Fragment` node) and
   compare. On mismatch nothing is kept and nothing merges — the
   `fetch --expect-hash` contract, applied transitively.
4. **Splice phases**: the fragment's expanded phase list replaces the
   `Import` node in place. Phase order is semantic on both sides and
   is preserved.
5. **Merge declarations**:
   - `capabilities`, `env_secrets`, `paths`, `http_allowlist`,
     `sh_egress` — set union. These are order-independent sets
     (chapter 03 sorts them before hashing), so union is the whole
     rule.
   - `env`, `assumes` — disjoint-key merge. A key declared by both
     sides with different values is an error, **not an override**:
     late-binding override semantics are how GCL-lineage languages
     made "where does this value come from" unanswerable, and this
     spec declines the trap. Identical entries deduplicate silently.

Validate then runs on the expanded profile, so every existing check
(scope check 8b, `UndeclaredEnvRef`, secret shapes) sees fragment
contributions exactly as if they had been written inline.

**Identity**: `canonical::hash` of the expanded AST is *the* profile
hash — `lm-provisioner hash` on a document containing imports resolves
first and hashes the result. A profile with no `Import` node expands
to itself, byte-for-byte: every existing profile keeps the hash its
ledger rows already carry.

## Cache

`${XDG_CACHE_HOME:-$HOME/.cache}/lm-provision/fragments/<hash>`,
storing the fragment's **expanded form in serde-bridge JSON** keyed by
its expanded hash. Canonical decode remains deferred (chapters 00/03):
integrity comes from parse-then-rehash on read, not from the byte
format. Lookup precedes network; a hit is parsed through the ordinary
JSON frontend and its expanded canonical hash recomputed against the
key before use. An entry that fails to parse, or fails to re-hash to
its key, is discarded and refetched — never trusted, and never an
error: both failures are cache misses, which keeps a cache directory
shared across tool versions fail-safe.

Only **remote** pinned imports are cached. A local import — pinned or
not — reads its file every time: the read is cheaper than the cache
round-trip, and a working tree wants edits visible immediately. (An
unpinned import has no key to cache under in any case.)

A cache entry names **content, not a derivation**. The expansion
function (§Resolution) participates at authoring time, when a pin is
minted, and at fetch time, when fetched source is verified — never on
the hit path. If expansion rules ever change, a warm entry that still
hashes to its pin remains valid (it is the very content the author
pinned); what breaks — loudly, at fetch — is only the ability to
re-derive that content from source.

The store is deliberately dumb: content-addressed files in a
self-describing wire format, nothing else. That keeps two doors open
with no further mechanism. Mirroring: a URL being a location hint
(§Adopted conventions), any host serving bytes that expand and hash
to the pin is a legitimate source — including a host serving the
pre-expanded form, of which this cache is simply the local instance.
Vendoring: committing a fragment file into the consuming repository
and importing it by local path with a pin is already expressible.
Both are the recovery paths for cold-fetch availability; neither is
built as a feature.

Writing an entry uses the same expanded-AST → bridge-JSON serializer
that the driver preflight needs in order to upload an expanded
payload (chapter 08 steps 1–2: the pod re-parses and re-hashes what
it receives). Every consumer of that serializer rests on one required
invariant: `hash(parse(serialize(ast))) == hash(ast)`.

## The resolver layer (`name@version`)

The one-line spelling lives **outside the DSL**. A CLI convenience
(chapter 07 addition, same increment as remote imports) resolves
`name@version` against an `index.json` — already published, already
carrying `name` / `version` / `path` / `profile_hash` per entry — and
writes the resulting `src` + `hash` pair into the document **at
authoring time**. The wire format is always the explicit pinned form;
what the resolver produced is what the file says. This is the GOPROXY
shape: the resolver is a static file any host can serve, and the
verification material travels with the consumer, not the registry.

## Non-goals

- **No parameter substitution.** A fragment is chosen, not
  configured: the Unsloth-style "model list" ships one pinned
  fragment per model (its `Models` / `ServiceStart` / `ServiceReady`
  phases), and picking a model means importing a different fragment —
  not patching a scalar through a template hole.
- **No override / inheritance semantics** (§Resolution rule 5).
- **No registry service.** Static hosting plus hash pins, as today.
- **No fragment-side machine requirements.** A merge rule
  (presumably per-field max) is definable but not needed to start;
  deferred until a real fragment wants it.

## Error surface

| error | stage | condition |
|---|---|---|
| `ImportUnresolved` | resolve | fetch/read of `src` failed |
| `ImportHashRequired` | resolve | remote `src` with no `hash` |
| `ImportHashMismatch` | resolve | expanded canonical hash ≠ pin; nothing kept |
| `ImportCycle` | resolve | a fragment reachable from itself |
| `ImportDepthExceeded` | resolve | the chain is longer than the resolver's depth limit — a chain that never repeats a document is not a cycle, and expansion recurses, so the limit is what turns a runaway chain into an error instead of an exhausted stack |
| `ImportSchemeDenied` | resolve | non-https remote / `file://` / `~/` / env form |
| `ImportReferentialSanity` | resolve | remote fragment importing a local path |
| `ImportMergeCollision` | resolve | `env` / `assumes` key declared by both sides with different values |
| `ImportNotAFragment` | resolve | import target's root is not a `Fragment` node (importing a full `Spec` profile is not defined) |
| `ImportPinShape` | resolve | a written pin is not a 64-char hex SHA-256 — an authoring mistake, reported before any content comparison |

All resolve errors name the import chain (consumer → … → fragment)
that produced them.

There is no `--force` and no bypass flag on any resolve or fetch
path, and none may be added: a run that proceeded past a failed pin
would be a profile whose identity is not what its document says.
Accepting changed upstream content is an **authoring act** —
rewriting the document's `src` + `hash` pair, preferably through the
resolver (§The resolver layer) — never a runtime switch.
`ImportHashMismatch` may print the hash it computed, but copying that
value into the document blesses whatever the wire delivered; the
report says so alongside the hash.

## Stability

Draft — nothing in this chapter is frozen. Two guarantees and one
prohibition are fixed now because they gate everything else: (1)
profiles without `Import` nodes keep their existing canonical bytes
and hash; (2) the pin is the expanded canonical hash, so a fragment's
internal refactoring never invalidates consumers; (3) no force/bypass
flag exists on the resolve or fetch paths (§Error surface) — a flag,
once shipped, could not be removed without breaking users, and its
existence would make profile identity advisory.

## Upstream references

- `dsl-kit`: `Import` and `Fragment` are ordinary `ProfileNode`
  variants — schema, PEG grammar, JSON bridge and builder derive as
  in chapter 01. Resolve is a host-side stage, not an engine concern.
- Precedents cited in §Adopted conventions: dhall-lang
  `standard/imports.md` (semantic hash, referential sanity, chaining,
  cache), Docker Compose `include`, Deno HTTP-imports retrospective,
  `go.dev/ref/mod` (GOPROXY, sumdb), Nix flake manual.

## MVP scope

Three increments, in order; each leaves the tool consistent:

1. **Local imports**: `Import` + `Fragment` nodes, resolve stage,
   relative/absolute paths, expansion + merge + validate integration,
   expanded-hash identity. No network, no cache.
2. **Remote imports**: https fetch, mandatory pins, referential
   sanity, XDG cache. `docs/profiles` starts publishing fragments
   (first real use: per-model fragments for the shared serve
   profiles).
3. **Resolver**: `name@version` → `src`+`hash` rewriting in the CLI
   against `index.json`.
