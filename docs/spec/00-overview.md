# lm-provision External Interface Specification — Overview

Spec-first redesign. Each chapter specifies one external interface of
the system: what a consumer (profile author, CLI user, MCP client,
pod-side runtime, downstream ledger reader) can rely on. Internal
implementation is out of scope in these specs unless a stability
guarantee requires it.

## Grounding

These specs are **not** greenfield: they are grounded in a working
reference implementation (Rust host crate + embedded `lm.*` Lua
modules + an example-profile regression suite). Chapters 01–07 and
the report/redaction half of 09 describe behaviour that
implementation already proves; 08 (driver side), the ledger half of
09, and 10 are the contracts the next build phases implement
against. Where a chapter marks something provisional, it is a
genuine design opening — not an unimplemented TODO.

## Naming and vocabulary separation

Three distinct vocabularies must not be conflated. Every chapter
uses the terms in exactly this sense.

| Vocabulary | Meaning |
|---|---|
| `lm-provision` | Tool name — the CLI binary, the crate group, the MCP server. What operators install and invoke. |
| `lm.profile/1` | Wire schema tag — literal string embedded in every canonical artifact. Identifies the artifact format, not the tool. |
| `lm.*` (Lua modules) | The Lua-facing library surface (`lm.profile`, `lm.env`, `lm.validate`, `lm.canonical`, `lm.hash`, `lm.plan`, `lm.dispatch`, `lm.apply`, `lm.report`, `lm.ir`). What profile authors `require`. |

The wire schema tag `lm.profile/1` is intentionally independent of
the tool name so the artifact identity survives a tool rename.

Throughout these specs, **IR** (intermediate representation) names
the normalized in-memory profile table produced by the DSL surface
(chapter 01) and consumed by the pipeline stages (chapter 03). The
`lm.ir` module owns it. Chapters use "IR" consistently for this
value; no separate "AST" vocabulary exists in this spec set.

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
        (sh / net /         contract             (Lua-facing only:
         fs / mount /       (L1 / L2 /            SecretRef userdata,
         secret)            L3 / L4)              env.ref factory,
              │             │                     env.get reject)
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
| 04 | Bridge (sh / net / fs / mount / secret) | 3 | 03 | F | specified |
| 05 | Sandbox layer contract (L1 / L2 / L3 / L4) | 3 | 04 | F | specified |
| 06 | Secret handling (Lua-facing only) | 3 | 01, 04 | F | specified |
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

- **Rust host / Lua domain, 100% split.** All domain logic
  (validate, canonical, hash, plan, dispatch, apply orchestration,
  report shape) lives in Lua modules. The Rust host is a pure
  infrastructure executor: mlua VM setup, bridge implementations,
  sandbox layer wiring, CLI transport, audit log. Rust carries no
  domain vocabulary.
  Absorbed by 03 (Lua-side pipeline shape) and 04 (bridge as sole
  effectful surface).
- **mlua embedded VM is the transport.** The Rust host embeds Lua
  via mlua; Lua code is not invoked as a subprocess over JSON. The
  boundary is function calls across the mlua bridge, not a wire
  protocol.
  Absorbed by 04; constrains 05 (sandbox layers must be expressible
  as mlua configuration + register-time gating).
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
  profile's capability set by walking the IR. Declared
  `capabilities` / `env` / `paths` / `http_allowlist` fields become
  `declared ⊇ derived` assertions rather than free-form declarations.
  Absorbed by 01 (assertion form) and 02 (per-kind required
  capabilities); consumed by 05 (sandbox uses declared set as
  allowlist).
- **Schema as data with editor completion.** Phase schema is a
  discriminated union expressed in a schema library; a codegen step
  emits `.d.lua` for editors.
  Absorbed by 02; referenced by 04 for bridge signatures.
- **Ten-phase lifecycle: bucketed surface, deferred.** Surfacing the
  lifecycle as buckets instead of a flat list with hidden reorder
  is a breaking change and is deferred out of MVP Phase F unless
  explicitly promoted.
  Recorded in 01 and 02 as a deferred item.
- **Escape / fragment policy.** Inner escape stays inside
  `hooks/sh`; fragment reuse is done by extracting host Lua
  functions (outer escape) rather than growing DSL vocabulary.
  Absorbed by 01; referenced by 04 (shell bridge).
- **Declared lists are stable-sorted; phase order is user-defined.**
  `capabilities`, `env`, `env_secrets`, `paths`, and
  `http_allowlist` are stable-sorted so hash is independent of
  declaration order. The `phases` list preserves user order because
  setup semantics depend on it.
  Absorbed by 01 (list-shape rule) and 03 (canonical-form invariant).

### Sandbox layers (from 05)

- **Four-layer sandbox.** L1 = standard-library nil-out plus embedded
  `lm.*` require allowlist plus bytecode / `string.dump` prohibition.
  L2 = execution-control isolation (thread isolation, cancel hook,
  wall-clock timeout). L3 = policy trait implementations for env,
  path, and HTTP allowlist. L4 = capability gate over the operation
  set (`sh.exec`, `net.transfer`, `net.http_get`, `net.http_post`,
  `fs.write`, `mount.bind`, `mount.umount`, `env.ref`, plus reserved
  `mount.volume_attach`).
  Absorbed by 05.
- **`KNOWN_CAPABILITIES` allowlist.** The initial known set is
  operation-scoped (`sh.exec`, not `sh`) so bearer-authenticated
  `net.transfer` can be declared without granting plain
  `net.http_get`.
  Absorbed by 05; referenced by 02 (phase kinds cite capabilities
  from this set).
- **Defer pattern as security invariant.** Bridge primitives are
  registered only after declared-list extraction completes. A
  profile that tries to reach a bridge primitive during declaration
  extraction fails with `attempt to call a nil value` before any
  effect can run. This is a physical guarantee, not a lint.
  Absorbed by 05; referenced by 04 (registration order).

### Secret handling (from 06 and 09)

- **`SecretRef` userdata is opaque.** The only defined operation is
  `tostring` returning `[secret:NAME]`. Field access, indexing, and
  arithmetic are unimplemented.
  Absorbed by 06.
- **`env.ref(name)` is a factory; policy check is deferred to
  bridge consumption.** Validation-time policy checks would create a
  chicken-and-egg with the declared list (which itself contains
  refs).
  Absorbed by 06; timing recorded in 03.
- **`env.get(name)` rejects secret-shaped keys.** Secret names are
  reachable only via `env.ref`. This is a second wall on top of the
  userdata opacity.
  Absorbed by 06.
- **Secret resolution happens on the host thread, not in Lua.** The
  resolved value flows into child process env, HTTP body, or file
  bytes; it is never handed back to Lua.
  Absorbed by 06 (Lua-facing rule) and 04 (bridge implementation
  constraint).
- **`env.set` is prohibited.** All environment injection goes
  through explicit exec-time env; Lua cannot mutate the host env.
  Absorbed by 06.
- **Missing host env is fail-fast.** If a declared secret is absent
  from the host environment at apply time, apply fails with a
  specific error; no silent fallback.
  Absorbed by 06; error class recorded in 03 and 09.
- **Audit redact rule is a report-side contract, not a Lua-side
  contract.** Case-insensitive substring match on
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
- **Static provisioner.** The binary is musl-static and embeds the
  Lua runtime plus the `lm.*` modules via `include_str!`, so the
  target environment carries zero dependency prerequisites.
  Absorbed by 08; constrains 04 (bridges must be embeddable).
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

- **Phase catalog uses discriminated-union schema + typed codegen.**
  Per-kind payload schemas are expressed as a discriminated union in
  a schema library; a codegen step emits `.d.lua` for editor
  completion. The same schema is walkable by the Rust host for
  pre-flight static checks. This is the canonical implementation of
  the schema-as-data decision.
  Absorbed by 02.
- **Shared vocabulary lives in one canonical data file.** The 22
  phase kinds (enumerated in 02), `KNOWN_CAPABILITIES`, the secret-key substring set
  (used by 06 to reject secret-shaped plain env reads), and the
  sensitive-key substring set (used by 09 for audit redaction) live
  in one canonical data file. Both the Lua host and the Rust host
  reference the same file. The implementation form — Lua source
  parsed at Rust build, a shared YAML / JSON, or equivalent — is
  not fixed by this spec.
  Absorbed by 02 (Inputs, Stability); referenced by 05, 06, 09.
- **Canonical stage is round-trippable.** The canonical stage
  contract is bidirectional: encode (IR → canonical JSON bytes) and
  decode (canonical JSON bytes → IR). Secret refs survive the
  round-trip as marker tables and are rehydrated back into
  `SecretRef` on the Lua side, preserving opacity. This enables
  ledger reconstruction and cross-pod profile persistence.
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
- **`SecretRef` stays userdata, not a marker table.** Keeping the
  Lua-facing form as userdata preserves physical opacity (`__index`
  returns nothing, `__newindex` is closed). Converting to a pure
  marker table would raise IR-as-data purity to 100 % at the cost
  of downgrading opacity from a physical guarantee to a structural
  rule; the tradeoff is not accepted.
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
