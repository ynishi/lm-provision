# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

- **Breaking (profile capabilities):** `comfyui.health` and `service.ready`
  now require `net.http_get` instead of `sh.exec`. Both kinds expand into a
  single HTTP poll, so they are gated on the capability of the effect they
  perform (spec 02 §Catalog kinds, 03 §dispatch, 05 §L4); the pid file the
  poll re-reads between attempts is a provisioner-internal file read, not a
  bridge operation. A profile that declares only `sh.exec` and uses either
  kind must add `net.http_get` to its `capabilities`.

### Deprecated

### Removed

### Fixed

### Security

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
