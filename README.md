# lm-provision

Spec-first pod provisioning: a Rust host + typed profile AST DSL for
declaratively provisioning LLM / GPU compute (RunPod-style pods, local
hosts). A profile is a declarative document — JSON or canonical text —
that is validated, hashed, planned, and applied by a single static
binary with zero dependencies on the target pod.

## Workspace

| Crate | What it is |
|---|---|
| [`lm-provision`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision) | Core library + CLI (`validate` / `hash` / `plan` / `apply [--dry-run]` / `fetch` / `pin`). Typed `ProfileNode` AST, deterministic canonical encoding + SHA-256 profile hash, pure-Rust effect engine — no embedded scripting runtime. Fragment imports (spec 11): hash-pinned local + https fragment reuse with an XDG-cached expansion pass, plus a `pin` authoring subcommand that rewrites `name@version` imports against an `index.json`. |
| [`lm-provision-driver`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-driver) | Push driver. `apply`: one-shot session over SSH — ensure-binary (idempotent SHA-256 push of the musl artifact), place profile, apply, collect report / transcript, append to the apply ledger. `acquire` / `release` / `sweep` / `check`: obtain a machine meeting the profile's declared requirements, give it back, give back every machine whose recorded lease has run out, or judge one that already exists. |
| [`lm-provision-mcp`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-mcp) | MCP server exposing `lm_validate` / `lm_hash` / `lm_plan` and apply-ledger inspection as MCP tools. |
| [`lm-provision-protocol`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-protocol) | The wire types shared across the license boundary: the append-only apply-ledger row schema (`LedgerRow` / `ArtifactRow`) and the acquisitions record (`AcquisitionRow` — the lease `sweep` reads), both in JSON Lines encoding — appended by the driver, taken custody of by the host. Neutral and permissive so both sides may depend on it. |
| [`lm-provision-host`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-host) | The control plane, **AGPL-3.0-or-later**. Empty scaffold today; becomes the self-hostable daemon that outlives a driver run — TTL enforcement, acquisition and ledger custody. The boundary was cut before the implementation, because relicensing after outside contributions arrive is no longer a decision one can make alone. |

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

# Or start from a shared profile (docs/profiles/) — verified fetch,
# kept only if the canonical hash matches the pin from index.json:
lm-provision fetch \
  https://raw.githubusercontent.com/ynishi/lm-provision/main/docs/profiles/comfyui-base-0.1.0.json \
  --expect-hash <hash-from-index.json> -o profile.json

# Fragment reuse: write `Import` nodes with the `name@version`
# shorthand and let `pin` rewrite them into the explicit src+hash
# pair against an index.json (spec 11 §The resolver layer). The
# rewrite is verified end-to-end before it lands.
lm-provision pin profile.json \
  --index https://raw.githubusercontent.com/ynishi/lm-provision/main/docs/profiles/index.json

# Apply on the target host (or via the push driver from your machine):
lm-provision apply profile.json            # effectful
lm-provision apply profile.json --dry-run  # print steps, resolve secrets, no effects

# One-shot provision of a remote pod over SSH:
lm-provision-driver apply \
  --ssh root@<host>:<port> --key ~/.ssh/<key> \
  --profile profile.json --artifact target/x86_64-unknown-linux-musl/release/lm-provision

# Obtain a machine the profile requires, then give it back.
# --dry-run defaults to on: this renders the request and sends nothing.
lm-provision-driver acquire --profile profile.json
lm-provision-driver acquire --profile profile.json --dry-run false
lm-provision-driver release --id <id> --profile profile.json
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

External interfaces are specified in [`docs/spec/`](https://github.com/ynishi/lm-provision/blob/main/docs/spec) (00-10:
profile DSL surface, phase catalog, pipeline stage artifacts, bridge,
sandbox layer contract, secret handling, CLI, push-driver protocol,
apply report and ledger, MCP). The implementation lands against those
specs; the specs are the normative surface.

## License

The engine — `lm-provision`, `lm-provision-driver`, `lm-provision-mcp`
and `lm-provision-protocol` — is dual-licensed under either of:

- MIT License ([`LICENSE-MIT`](https://github.com/ynishi/lm-provision/blob/main/LICENSE-MIT))
- Apache License, Version 2.0 ([`LICENSE-APACHE`](https://github.com/ynishi/lm-provision/blob/main/LICENSE-APACHE))

at your option, **and will remain so permanently**. Provisioning a pod
is what these crates do, and nothing about how someone runs a control
plane changes the terms on which they may do that.

`lm-provision-host`, and any control-plane crate added beside it later,
is **AGPL-3.0-or-later**: it is a service one can host for others, and
the AGPL is the license that keeps a hosted modification available to
the people using it.

The two sides still share a vocabulary — the ledger rows the driver
writes and the host reads. Those types live in
`lm-provision-protocol`, which stays permissive precisely so that
depending on it commits no one to anything. The direction that would
break the promise, an engine crate depending on the host, is empty and
machine-checked: `no_permissive_crate_depends_on_the_agpl_host` in the
host crate reads the four permissive manifests and fails if any of
them names it.
