# lm-provision

Spec-first pod provisioning: a Rust host + typed profile AST DSL for
declaratively provisioning LLM / GPU compute (RunPod-style pods, local
hosts). A profile is a declarative document — JSON or canonical text —
that is validated, hashed, planned, and applied by a single static
binary with zero dependencies on the target pod.

## Workspace

| Crate | What it is |
|---|---|
| [`lm-provision`](crates/lm-provision) | Core library + CLI (`validate` / `hash` / `plan` / `apply [--dry-run]`). Typed `ProfileNode` AST, deterministic canonical encoding + SHA-256 profile hash, pure-Rust effect engine — no embedded scripting runtime. |
| [`lm-provision-driver`](crates/lm-provision-driver) | Push driver: one-shot session over SSH — ensure-binary (idempotent SHA-256 push of the musl artifact), place profile, apply, collect report / transcript, append to the apply ledger. |
| [`lm-provision-mcp`](crates/lm-provision-mcp) | MCP server exposing `lm_validate` / `lm_hash` / `lm_plan` and apply-ledger inspection as MCP tools. |

## Highlights

- **Declarative phase catalog (22 kinds)** — system packages, Python
  toolchain, ComfyUI install / restart / health, generic service
  start / readiness, model prefetch, `https` / `hf://` / `b2://`
  transfers, filesystem writes, shell steps, hooks, and first-class
  HTTP steps (headers / body / `body_json` / `timeout_sec`).
- **Deterministic profile hash** — canonical byte encoding over the AST
  (frontend-independent, declaration lists sorted, phase order
  preserved) feeding an append-only apply ledger.
- **Secrets never leak** — `EnvSecret` / `EnvRef` resolve through a
  declaration-derived env policy; values travel via environment or SSH
  stdin script only, never in argv / reports / transcripts, and audit
  output redacts to names + byte lengths.
- **Fail-fast readiness** — per-kind poll deadlines (health 180s /
  ready 300s, overridable per step) plus died-during-wait detection
  that fails in seconds when the supervised process crashes during
  startup instead of burning the whole timeout.
- **Static musl binary** — the provisioner runs on the pod with zero
  preinstalled dependencies; the driver pushes it on demand.

## Quickstart

```sh
# Author a profile (JSON), then locally:
lm-provision validate profile.json
lm-provision hash profile.json
lm-provision plan profile.json

# Apply on the target host (or via the push driver from your machine):
lm-provision apply profile.json            # effectful
lm-provision apply profile.json --dry-run  # print steps, resolve secrets, no effects

# One-shot provision of a remote pod over SSH:
lm-provision-driver apply \
  --ssh root@<host>:<port> --key ~/.ssh/<key> \
  --profile profile.json --artifact target/x86_64-unknown-linux-musl/release/lm-provision
```

## Specifications

External interfaces are specified in [`docs/spec/`](docs/spec) (00-10:
profile DSL surface, phase catalog, pipeline stage artifacts, bridge,
sandbox layer contract, secret handling, CLI, push-driver protocol,
apply report and ledger, MCP). The implementation lands against those
specs; the specs are the normative surface.

## License

Dual-licensed under either of:

- MIT License ([`LICENSE-MIT`](LICENSE-MIT))
- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option.
