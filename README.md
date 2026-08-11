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

- **Declarative phase catalog (23 kinds)** — system packages, Python
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

### MCP server: pod target registry

`lm-provision-mcp` resolves `lm_apply`'s `pod_id` against a **pod target
registry** — a JSON file naming every pod the server may provision.
Point `LM_PROVISION_TARGETS` at it:

```sh
export LM_PROVISION_TARGETS=/etc/lm-provision/targets.json
```

```json
{
  "targets": [
    { "pod_id": "dev-local", "kind": "local-exec", "staging_dir": "/tmp/lm-staging" },
    { "pod_id": "pod-abc123", "kind": "ssh", "host": "pod.example.com", "port": 21001,
      "user": "root", "key_path": "/path/to/key", "remote_dir": "/root" }
  ]
}
```

`kind: "ssh"` requires `host`, `port` (non-zero — RunPod maps a per-pod
external port) and `key_path` (no fallback to a default key); `user`
defaults to `root` and `remote_dir` to `/root`. `kind: "local-exec"`
runs on the server's own host and defaults `staging_dir` to
`LM_PROVISION_STAGING_DIR`. Paths are literal — neither `~` nor
environment variables are expanded.

A `pod_id` with no entry is rejected before anything runs, so a ledger
row records a destination the server was configured for. Operational
notes:

- **Migrating an existing deployment**: servers started without
  `LM_PROVISION_TARGETS` resolve nothing and every `lm_apply` fails.
  Write one registry file, point the variable at it, restart the
  server. There is no fallback to the previous behaviour of running
  every apply on the server's own host.
- **Adding a pod**: the registry is read once at startup, so edit the
  file and **restart the server**; there is no reload path.
- **Where to keep it**: the file carries real host names, users and key
  paths — keep it outside the repository (e.g. under `/etc`), or add it
  to `.gitignore` if it must live inside one.
- **`dry_run` still connects** for `ssh` targets: the driver uploads the
  binary and hashes it on the pod before invoking `apply --dry-run`, so
  only the pod-side apply effects are skipped. There is no way to check
  a registry entry without contacting the pod.

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
