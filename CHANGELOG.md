# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.3.0] - 2026-08-05

### Added

- **`net.transfer` bridge** now resolves public `hf://` sources to their
  `https://huggingface.co/<owner>/<repo>/resolve/<rev>/<path>` URL (default
  revision `main`, URL-carried `@<rev>` wins over `opts.revision`) and
  implements HTTP PUT uploads to `https://` destinations. Public `b2://`
  sources stay unsupported by design — the deployment's download endpoint
  is cluster- and account-specific and no profile field declares one; the
  error names the gap and points at the credential `env` route that does
  work (spec 04 §`net.transfer`).
- **validate check 8** — a second `service.ready` under the same
  `service.start` is rejected. Both would carry `11_service_<N>_ready`,
  and that number is what tells two services apart (spec 02 §Canonical
  phase ordering).
- **validate check 9 (`declared ⊇ derived`)** — the compiler walks the
  normalized plan and asserts that every `capabilities` / `paths` /
  `http_allowlist` entry the run will need appears in the corresponding
  declared list. Implicitly inserted steps count: a profile that writes
  only `comfyui.install` still has to declare the health poll's
  `net.http_get` and its URL. Built-in path constants count too:
  `models` writes under `/workspace/ComfyUI/models/...` even though the
  author never spells that path out (spec 00 §Capability derivation,
  spec 03 §validate).

### Changed

- **Breaking (canonical order becomes an execution contract, not a plan
  one).** The ordering / implicit-insertion / suppression rules now
  rewrite the AST once (`crate::normalize`) and both `plan` and `apply`
  consume the result. `apply` used to drive the authored phase list
  directly, so the three rules only affected the plan artifact; a
  `comfyui.install` alone would not spawn its restart / health poll on
  apply, and a `python.version_check` asserting the default would still
  run. Both are now fixed. The profile as *written* is what `hash` /
  `canonical` see, so an inserted step does not change a profile's hash
  (spec 02 §Canonical phase ordering).
- **Breaking (capability gate reads the resolved route).** A lifecycle
  op's demand comes from the steps its payload expands to, not from its
  kind: a credential-`env` `sync.pull` and every `staging.push` route to
  the native CLI, so they demand `sh.exec`. A profile that granted only
  `net.transfer` used to run a shell under it; it is now denied at the
  L4 gate (spec 02 §Dispatch routing "What the L4 gate sees").
- **Breaking (bridge policies see every write).** A lifecycle-composed
  transfer or HTTP poll answers to the same `paths` / `http_allowlist`
  a direct op would — the check runs on the resolved step, so an
  `hf://` source is gated as its `https://huggingface.co` URL. Profiles
  that used to reach undeclared paths / hosts through `sync.pull` /
  `models` / `comfyui.health` / `service.ready` now need those targets
  in the corresponding declared list (spec 05 §L3).
- **Breaking (`env.ref` becomes a reachable capability).** A phase
  carrying an `EnvRef` value node — in `fs.write` content, in an `env`
  keyed slot, in a header map, in a POST body — now demands `env.ref`
  on top of whatever its kind requires. Dereferencing a `Spec.env`
  entry is an effect of its own, so profiles that read one need
  `env.ref` in `capabilities` (spec 02 §Shared vocabulary).
- **Breaking (`net.transfer` direction is a validate-stage decision).**
  A remote scheme on `src` is a download, one on `dst` is an upload;
  a scheme on both sides or on neither is rejected at validate rather
  than surfaced mid-apply. `models` gains the same treatment: an
  element with neither `dst` nor `name` has nowhere to write to and is
  now a precondition error (spec 02 §Catalog kinds / §Error surface).
- **`service.ready` orphans get their own service index.** A resume
  profile that polls a server an earlier apply started no longer
  inherits `_0_` from the first declared service — it opens the next
  free index. The two never collide on `11_service_0_ready` again
  (spec 02 §Canonical phase ordering).
- **spec 02 phase catalog respec.** The 34-finding DeepReview pass
  landed as point fixes to `docs/spec/02-phase-catalog.md`:
  direct-op / `zz_unknown` no-op semantics narrowed to unrecognized
  kinds only; implicit-insertion guard restated per phase (not "neither
  declared"); `platform.kind` documented as a free string with a note
  step for unknown values; ids are slot labels rather than sort keys;
  `dst | name` / `subdir | kind` precedence stated; ollama's argv
  ignores `model` / `port`; secret-shaped and sensitive-key sets
  collapsed to one set with two consumer chapters; case-insensitivity
  and byte-equality split into separate claims; `<KindName>` ↔ dotted
  label mapping tabulated (`comfyui` → `ComfyUi`, `hooks.post_install`
  → `PostInstall`).

## [0.2.0] - 2026-08-05

### Changed

- **Breaking (profile capabilities):** `comfyui.health` and `service.ready`
  now require `net.http_get` instead of `sh.exec`. Both kinds expand into a
  single HTTP poll, so they are gated on the capability of the effect they
  perform (spec 02 §Catalog kinds, 03 §dispatch, 05 §L4); the pid file the
  poll re-reads between attempts is a provisioner-internal file read, not a
  bridge operation. A profile that declares only `sh.exec` and uses either
  kind must add `net.http_get` to its `capabilities`.

## [0.1.0] - 2026-08-03

### Added

- Typed profile AST pipeline: JSON / canonical-text frontend, validate,
  deterministic canonical encoding + SHA-256 profile hash, plan, and the
  effectful apply engine (`lm-provision` lib + CLI with `validate` /
  `hash` / `plan` / `apply --dry-run` subcommands).
- 22-kind phase catalog covering system packages, Python toolchain,
  ComfyUI install / restart / health, generic service start / readiness,
  model prefetch (`hf` CLI), sync pull / push (`https` / `hf://` / `b2://`),
  staging push, filesystem writes, shell steps, bind mounts, hooks, and
  first-class HTTP access (`net.http_get` / `net.http_post` with headers,
  body, `body_json`, and per-step `timeout_sec`).
- Secret handling: `EnvSecret` / `EnvRef` declaration-derived env policy.
  Secret values are delivered via environment or SSH stdin script only —
  never in process argv, reports, transcripts, or the ledger; audit lines
  carry names and byte lengths with `[REDACTED]` markers.
- Readiness probing with fail-fast posture: per-kind poll deadlines
  (ComfyUI health 180s, service ready 300s, overridable per step via
  `timeout_sec`) and died-during-wait detection (pid-file + settle check +
  armed liveness poll) that fails in seconds instead of burning the full
  timeout when the supervised process crashes during startup.
- Push driver (`lm-provision-driver`): one-shot session contract over SSH —
  ensure-binary (SHA-256 idempotent push of the static musl artifact),
  profile placement, apply, report / transcript collection, and an
  append-only apply ledger. Secrets travel by stdin script; keys are
  explicit (no default-key fallback).
- MCP server (`lm-provision-mcp`): `lm_validate` / `lm_hash` / `lm_plan`
  and apply-ledger inspection (`lm_ledger_list` / `lm_ledger_get`) exposed
  as MCP tools.
- External interface specifications in `docs/spec/` (00-10): profile DSL
  surface, phase catalog, pipeline stage artifacts, bridge, sandbox layer
  contract, secret handling, CLI, push-driver protocol, apply report and
  ledger, MCP.
