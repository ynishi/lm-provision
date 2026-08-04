# lm-provision External Interface Specification — Overview

Spec-first redesign. Each chapter specifies one external interface of
the system: what a consumer (profile author, CLI user, MCP client,
pod-side runtime, downstream ledger reader) can rely on. Internal
implementation is out of scope in these specs unless a stability
guarantee requires it.

## Grounding

These specs are **not** greenfield: they are grounded in a working
reference implementation (a Rust workspace whose host crate carries
the whole pipeline, plus a profile regression suite). Chapters 01–07
and the report half of 09 describe behaviour that implementation
already proves; 08 (driver side), the ledger half of 09, and 10 are
the contracts the next build phases implement against. Where a
chapter marks something provisional, it is a genuine design opening —
not an unimplemented TODO. Where a chapter marks something *specified
but not yet implemented* (currently: the audit transcript of 09 and
the per-primitive option sets of 04), it says so at the point of use.

**The embedded-Lua frontend is gone.** The original design split the
system as "Rust host / Lua domain" and authored profiles as Lua code
executed in an embedded mlua VM. Profiles are now data — JSON or
canonical text parsed into the `ProfileNode` AST — and the whole
pipeline is Rust. Chapters below record the decisions that were made
under the old split and note where each one was superseded, rather
than deleting the rationale.

## Naming and vocabulary separation

Three distinct vocabularies must not be conflated. Every chapter
uses the terms in exactly this sense.

| Vocabulary | Meaning |
|---|---|
| `lm-provision` | Tool name — the CLI binary, the crate group, the MCP server. What operators install and invoke. |
| `lm.profile/1` | Wire schema tag — literal string embedded in every canonical artifact. Identifies the artifact format, not the tool. |
| `ProfileNode` (dsl-kit AST) | The typed Rust enum AST (`dsl-kit`) defining the Profile Spec and Phase variants. Single source of truth for Schema, PEG Parser, JSON bridge, Builder, and MCP debugging. |

The wire schema tag `lm.profile/1` is intentionally independent of
the tool name so the artifact identity survives a tool rename.

Throughout these specs, **AST** (and the typed `ProfileNode`) names
the normalized in-memory profile structure produced by the `dsl-kit` DSL surface
(chapter 01) and consumed by the pipeline stages (chapter 03).


## Chapter dependency layers

Chapters form a directed acyclic graph. Downstream chapters may cite
upstream chapters, not the reverse. Both writing order and reading
order follow the layer order below. Chapter numbers are assigned so
`NN` increases along the DAG.

```
Layer 1 — Surface / Schema
    01  Profile DSL surface        02  Phase catalog
              │                            │
              └─────────────┬──────────────┘
                            ▼
Layer 2 — Contract
    03  Pipeline stage artifacts
        (validate / canonical / hash / plan / dispatch)
                            │
              ┌─────────────┼─────────────────────┐
              ▼             ▼                     ▼
Layer 3 — Runtime
    04  Bridge          05  Sandbox layer    06  Secret handling
        (sh / net /         contract             (EnvSecret node,
         fs / mount /       (L1 / L2 /            two-stage allowlist,
         env values)        L3 / L4)              host-side resolve)
              │             │                     │
              └──────┬──────┴─────────────────────┘
                     ▼
Layer 4 — Operator surface
    07  CLI          08  Push driver      09  Apply report,
                         protocol             audit redact,
                         (upload /            ledger schema
                          invoke /
                          collect)
                     │
              ┌──────┴──────┐
              ▼             ▼
Layer 5 — Integration
    10  MCP — lm-provision-mcp
        (wraps 07 subcommands, cites 08 protocol and 09 schema)
```

## Chapters

| # | Spec | Layer | Upstream deps | MVP | Status |
|---|---|---|---|---|---|
| 01 | Profile DSL surface | 1 | — | F | specified |
| 02 | Phase catalog | 1 | — | F | specified |
| 03 | Pipeline stage artifacts | 2 | 01, 02 | F | specified |
| 04 | Bridge (sh / net / fs / mount / env values) | 3 | 03 | F | specified |
| 05 | Sandbox layer contract (L1 / L2 / L3 / L4) | 3 | 04 | F | specified |
| 06 | Secret handling | 3 | 01, 04 | F | specified |
| 07 | CLI | 4 | 03 | G | specified |
| 08 | Push driver protocol (on-pod agent model) | 4 | 07, 04, 06 | G | specified |
| 09 | Apply report + audit redact + ledger schema | 4 | 08 | G | specified |
| 10 | MCP — lm-provision-mcp | 5 | 07, 08, 09 | H | specified |

MVP Phase mapping follows the on-pod agent model rollout (capital
"Phase F/G/H" always names a rollout milestone; lowercase "phase"
always names a profile execution unit):

- **Phase F** — local build up to on-pod apply proven by hand.
  01 through 06 must be spec-level frozen so the static provisioner
  binary can be built and executed inside a pod. This is the
  smallest self-contained slice: DSL surface, phase catalog, pipeline
  artifacts, bridges, sandbox, and secret handling.
- **Phase G** — automated push driver.
  07 + 08 + 09 spec-frozen so upload, invoke, report collection, and
  the append-only ledger form one operator-facing contract group.
- **Phase H** — MCP surface.
  10 spec-frozen so downstream integrations (an external pod manager
  delegating provisioning in particular) can bind to a stable tool
  schema.

## Chapter skeleton template

Every chapter file follows the same structure so consumers find the
same section in every spec.

```
# NN. <Chapter title>

## Purpose

Which consumer this contract is written for, and what single
external interface it defines.

## Inputs

Everything the consumer supplies. Types, allowed values, required vs
optional. For file-shaped inputs: format, encoding, size bounds.
For structured inputs: schema reference (chapter number).

## Outputs

Everything the consumer observes. Return values, stdout / stderr
shape, exit codes, artifact files, side effects.

## Error surface

Enumerated error classes: precondition, transport, sandbox, runtime.
For each: how it is signalled, whether it is retryable, whether the
system is left in a well-defined state after failure.

## Stability

Which parts are stable (breaking change requires a major bump),
which are provisional (may change until Phase H closes), which are
internal (may change without notice, not part of the consumer
contract).

## Upstream references

The other spec chapters this contract depends on, and which
sections of each are cited.

## MVP scope

Which sub-features land in the Phase declared in the overview
table, and which are deferred. One-line reason per deferral.
```

## Consolidated design decisions

Decisions fixed at spec level. Each decision names the chapter that
absorbs it, so the graph stays acyclic.

### Boundary and stack

- ~~**Rust host / Lua domain, 100% split.**~~ **Superseded: one Rust
  stack over a typed AST.** All domain logic (validate, canonical,
  hash, plan, dispatch, apply orchestration, report shape) originally
  lived in Lua modules, with Rust as a pure infrastructure executor
  carrying no domain vocabulary. The split cost a language boundary in
  the middle of every stage and made the schema, the grammar, and the
  validator three separate things to keep in step. Domain logic is now
  Rust over the `ProfileNode` AST, with the schema as the single
  source both frontends and the validator derive from.
  Absorbed by 03 (pipeline shape) and 04 (bridge as sole effectful
  surface).
- ~~**mlua embedded VM is the transport.**~~ **Superseded: a profile
  is data.** There is no interpreter and no transport between
  languages: parsing a profile yields a value, and applying it is a
  step loop over that value. The property the VM boundary was meant to
  provide — that author input cannot reach the host except through the
  declared primitives — now holds because author input is not code.
  Absorbed by 04; simplifies 05 (the L1 / L2 mechanisms it required
  are no longer necessary).
- **Stateless.** No client-side state machine, no drift detection,
  no Terraform-style desired-state reconciliation. A single apply
  runs the phase sequence once, fail-fast, and returns a report.
  Absorbed by 07, 08, and 09.

### DSL surface (from 01 and 02)

- **Phase constructors.** 01 uses phase constructors so `kind` and
  field typos surface at definition time. The compiled IR keeps
  the same shape, so 03 canonical / hash / plan are unaffected.
  Absorbed by 01; referenced by 03 in the stability-of-canonical-form
  note.
- **Capability derivation.** The phase catalog (02) declares
  required capabilities per phase kind; the compiler derives the
  profile's capability set by walking the IR. The walk runs over the
  **expanded plan** (03 §plan), not the declared phase list: implicit
  insertion happens at plan time (`comfyui.install` expands to install
  + restart + health), so deriving from the phases as written misses
  the inserted steps' capabilities — `net.http_get` for the health
  poll — and the built-in path constants (02 §Built-in path
  constants) those steps touch, leaving them to fail at the L4 entry
  check during apply instead. Declared
  `capabilities` / `env` / `paths` / `http_allowlist` fields become
  `declared ⊇ derived` assertions rather than free-form declarations.
  Absorbed by 01 (assertion form) and 02 (per-kind required
  capabilities); consumed by 05 (sandbox uses declared set as
  allowlist).
- **Schema as data with editor completion.** Phase schema is a
  discriminated union expressed in a schema library. The `.d.lua`
  codegen step this originally implied served Lua authoring and was
  removed with it; the machine-derived `DslSchema` is what tooling
  reads now.
  Absorbed by 02; referenced by 04 for primitive signatures.
- **Ten-phase lifecycle: bucketed surface, deferred.** Surfacing the
  lifecycle as buckets instead of a flat list with hidden reorder
  is a breaking change and is deferred out of MVP Phase F unless
  explicitly promoted.
  Recorded in 01 and 02 as a deferred item.
- **Escape / fragment policy.** Inner escape stays inside
  `hooks/sh`; fragment reuse is done outside the profile — by whatever
  generates the JSON / canonical text against the exported schema —
  rather than growing DSL vocabulary. (The original wording named
  "extracting host Lua functions" as the outer escape; the principle
  survives the frontend that motivated it.)
  Absorbed by 01; referenced by 04 (shell primitive).
- **Declared lists are stable-sorted; phase order is user-defined.**
  `capabilities`, `env`, `env_secrets`, `paths`, and
  `http_allowlist` are stable-sorted so hash is independent of
  declaration order. The `phases` list preserves user order because
  setup semantics depend on it.
  Absorbed by 01 (list-shape rule) and 03 (canonical-form invariant).

### Sandbox layers (from 05)

- **Four-layer sandbox.** L1 = keeping author input from reaching the
  host as code. L2 = execution model (statelessness, bounded run).
  L3 = policy implementations for secret env, path, and HTTP
  allowlist. L4 = capability gate over the operation set (`sh.exec`,
  `net.transfer`, `net.http_get`, `net.http_post`, `fs.write`,
  `mount.bind`, `mount.umount`, `env.ref`, plus reserved
  `mount.volume_attach`).
  L1 and L2 originally named concrete mlua mechanisms — stdlib
  nil-out, an embedded-module require allowlist, a bytecode
  prohibition, and a dedicated VM thread with a cancel hook. Those
  mechanisms went with the VM; the two layers keep their
  responsibilities and are now satisfied structurally (05 §L1 / §L2
  record each predecessor).
  Absorbed by 05.
- **`KNOWN_CAPABILITIES` allowlist.** The initial known set is
  operation-scoped (`sh.exec`, not `sh`) so bearer-authenticated
  `net.transfer` can be declared without granting plain
  `net.http_get`.
  Absorbed by 05; referenced by 02 (phase kinds cite capabilities
  from this set).
- **Declared lists are derived before any effect is reachable.**
  Originally a *defer pattern*: primitives were registered only after
  declared-list extraction finished, so a profile reaching for one
  during extraction died on `attempt to call a nil value`. With no
  author code to run during extraction, the ordering is a property of
  the pipeline rather than a staged registration — the invariant is
  unchanged and strengthened.
  Absorbed by 05; referenced by 04 (context build order).

### Secret handling (from 06 and 09)

- **A secret reference is opaque.** Originally a `SecretRef` userdata
  whose only defined operation was `tostring` → `[secret:NAME]`, with
  field access and indexing unimplemented. It is now the `EnvSecret`
  AST node, which carries a name and has no value field at all —
  opacity became a property of the shape, so the userdata mechanism
  is unnecessary.
  Absorbed by 06.
- ~~**`env.ref(name)` is a factory; policy check is deferred to
  bridge consumption.**~~ **Superseded: checked at both stages.** The
  deferral existed because `env.ref` was registered before the
  declared lists were extracted — a chicken-and-egg a declarative AST
  does not have. Validate now rejects an undeclared reference
  statically, *and* consumption re-checks it.
  Absorbed by 06; validate-stage check recorded in 03.
- ~~**`env.get(name)` rejects secret-shaped keys.**~~ **Superseded:
  no plain-read surface exists.** The "second wall" guarded a path by
  which a profile could read an arbitrary host env var. That path is
  gone; the only host-env read is `EnvSecret` resolution, gated by
  `env_secrets`. The secret-shaped-key rejection survives as a
  validate rule on the declared `env` table (scoped to literal-valued
  keys — 05 §L3).
  Absorbed by 06.
- **Secret resolution happens host-side, never in the profile.** The
  resolved value flows into the consuming step's child-process
  environment and nowhere else; it never enters the AST, the trace,
  or the report.
  Absorbed by 06 and 04 (implementation constraint).
- **Host environment mutation is prohibited.** All environment
  injection goes through the consuming phase's explicit `env` keyed
  slot; nothing a profile expresses can mutate the host env. (The
  original rule named `env.set`, the Lua surface that had to be
  withheld.)
  Absorbed by 06.
- **Missing host env is fail-fast.** If a declared secret is absent
  from the host environment at apply time, apply fails with a
  specific error; no silent fallback.
  Absorbed by 06; error class recorded in 03 and 09.
- **Audit redact rule is a report-side contract, not an
  authoring-side contract.** Case-insensitive substring match on
  `key / token / secret / password / pwd / auth / cred / apikey`
  drives `[REDACTED]` in the audit log; `content_source` becomes
  `"secret:<name>"` when a `SecretRef` writes a file.
  Absorbed by 09, not 06 — the consumer is the ledger reader, not
  the profile author.

### On-pod agent model (from 07 and 08)

- **On-pod agent binary.** The profile is applied by an
  `lm-provision` binary shipped into the pod. The outer driver only
  uploads the binary, invokes it, and collects the report.
  Absorbed by 08.
- **Provisioning-only boundary.** Pod lifecycle
  (create / start / stop) stays with the external pod manager; only
  provisioning is owned by lm-provision. The pod-provider API client
  is not pulled into the core.
  Absorbed by 08; referenced by 10.
- **Static provisioner.** The binary is musl-static and carries no
  language runtime and no runtime file dependencies, so the target
  environment carries zero prerequisites for the binary itself.
  (Originally this meant embedding the Lua runtime and the `lm.*`
  modules via `include_str!`; removing the interpreter satisfies the
  constraint more directly.)
  Absorbed by 08; constrains 04 (effects must be embeddable).
- **Append-only ledger.** Apply outcomes are stored as
  `(pod_id, profile_hash, report)` in an append-only ledger. The
  ledger is the source of truth for downstream analysis (external
  pod-manager integration, audit, SLA reporting); its schema has a
  stability tier separate from the driver protocol.
  Absorbed by 09.

### DSL framework alignment

lm-provision is positioned as: surface = constructor-based DSL;
artifact = IR as data; execution = Def → Compile → Exec pipeline.
The following refinements are adopted.

- **Phase catalog uses a discriminated-union schema.** Per-kind
  payload schemas are expressed as a discriminated union — the
  `ProfileNode` enum — from which the schema, the canonical-text
  grammar, and the JSON bridge are all derived. This is the canonical
  implementation of the schema-as-data decision. The `.d.lua` codegen
  half of the original decision went with the Lua frontend.
  Absorbed by 02.
- **Shared vocabulary has one source of truth.** The 22 phase kinds
  (enumerated in 02), `KNOWN_CAPABILITIES`, the secret-key substring
  set (used by 06 to reject secret-shaped `env` declarations), and
  the sensitive-key substring set (used by 09 for audit redaction)
  are defined once. With a single host there is no cross-language
  mirroring left to keep in step; byte equality of the sets remains
  the contract and the implementation form is internal.
  Absorbed by 02 (Inputs, Stability); referenced by 05, 06, 09.
- **Canonical stage is round-trippable — deferred to encode-only.**
  The bidirectional contract (encode AST → bytes, decode bytes → AST)
  was specified to enable ledger reconstruction and cross-pod profile
  persistence. Only encode is defined in the current revision: the
  ledger persists the report and the hash, and no consumer has needed
  reconstruction. Secret references survive encoding as the
  `{"__secret":"NAME"}` marker, so a future decode has an
  opacity-preserving form to rehydrate into.
  Absorbed by 03 (canonical stage Outputs).

Deferred applications, recorded so a future revision can cite the
original rationale:

- **Pipeline compose form left to implementation.** The spec defines
  each pipeline stage as an independent contract. Whether the host
  wires them as a combinator pipeline (`(ctx) -> ctx, err`) or as
  direct module calls is not required by the spec.
  Recorded in 03 Stability.
- **Preset `extends` deferred.** A profile is one complete
  definition; preset inheritance is a future revision when authors
  need to share common bases (capabilities, paths, phase groups)
  without breaking hash byte-identity of leaf profiles.
  Recorded in 01 Stability.
- **Phase order stays declarative-hardcoded until the kind set
  grows.** The physical step order is expressed as a hardcoded list
  plus implicit-phase insertion (e.g., `comfyui.install` implies
  `comfyui.restart` and `comfyui.health`). Promotion to per-kind
  `depends_on` fields with topological sort (a dependency DAG) is a
  future revision, not MVP.
  Recorded in 02 Stability.
- ~~**`SecretRef` stays userdata, not a marker table.**~~
  **Resolved — the tradeoff dissolved.** The decision weighed physical
  opacity (userdata with `__index` closed) against 100 % IR-as-data
  purity, and refused to trade the former for the latter. Removing
  the language runtime removed the party the reference had to be kept
  opaque *from*: `EnvSecret` is pure data **and** has no field a value
  could be read out of. Both sides of the tradeoff are now satisfied.
  Recorded in 06.

## Conventions

- Interfaces are specified as inputs, outputs, error surface, and
  stability.
- Anything not written in a chapter is unspecified and may change.
- Cross-references between chapters name the chapter number and
  section title, not line numbers, so the specs can move without
  breaking citations.
- Stability tiers used across all chapters:
  - `stable` — breaking change requires a major version bump.
  - `provisional` — may change until Phase H closes; consumers are
    expected to pin.
  - `internal` — may change at any point; not part of the consumer
    contract.
- Chapter files are named `NN-<slug>.md` in this directory. This
  overview is `00-overview.md` and is the single canonical entry
  point.
