# lm-provision

Spec-first pod provisioning: a Rust host + typed profile AST DSL for
declaratively provisioning LLM / GPU compute (RunPod-style pods, local
hosts). A profile is a declarative document — JSON or canonical text —
that is validated, hashed, planned, and applied by a single static
binary with zero dependencies on the target pod.

## Workspace

| Crate | What it is |
|---|---|
| [`lm-provision`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision) | Core library + the pod-side binary **`lm-provisioner`** (`validate` / `hash` / `plan` / `apply [--dry-run]` / `fetch` / `pin`). Typed `ProfileNode` AST, deterministic canonical encoding + SHA-256 profile hash, pure-Rust effect engine — no embedded scripting runtime. Fragment imports (spec 11): hash-pinned local + https fragment reuse with an XDG-cached expansion pass, plus a `pin` authoring subcommand that rewrites `name@version` imports against an `index.json`. |
| [`lm-provision-cli`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-cli) | The operator CLI: the **`lm-provision`** binary, and the one command an operator installs. `apply` / `check` act on a pod; `logs` / `exec` / `cp` work the pod an apply left running; `machine list` / `acquire` / `release` / `sweep` / `endpoints` are the fleet; `mcp` serves the MCP tools over stdio. |
| [`lm-provision-driver`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-driver) | Push-driver library, behind `lm-provision apply` and the machine subcommands. The session: ensure-binary (resolve the provisioner for a version to the release build CI published, verify its SHA-256, cache it, and push it idempotently), place profile, apply, collect report / transcript, append to the apply ledger. The machine side: obtain one meeting the profile's declared requirements (stamping its lease onto the machine's own name), read a platform's own list, give a machine back, give back every machine whose lease has run out. |
| [`lm-provision-mcp`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-mcp) | MCP server library, served by `lm-provision mcp`: `lm_validate` / `lm_hash` / `lm_plan`, `lm_apply`, `lm_machine_list`, and apply-ledger inspection as MCP tools. |
| [`lm-provision-protocol`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-protocol) | The wire types shared across the license boundary: the append-only apply-ledger row schema (`LedgerRow` / `ArtifactRow`) and the acquisitions record (`AcquisitionRow` — the audit trail of what was bought and what came back), both in JSON Lines encoding — appended by the driver, taken custody of by the host. Neutral and permissive so both sides may depend on it. |
| [`lm-provision-host`](https://github.com/ynishi/lm-provision/blob/main/crates/lm-provision-host) | The control plane, **AGPL-3.0-or-later**, `publish = false`. The TTL-enforcement daemon: it runs `lm-provision machine sweep` every interval — as a child process, not as a linked library, so the AGPL side depends on nothing permissive — and answers one health endpoint saying whether the last sweep worked and what it did. Enforcing is its default (`--dry-run false`, the opposite of the CLI's): installing it *is* the consent to release expired machines. Ledger custody is next. |

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
- **Static musl binary, built by CI** — the provisioner runs on the pod
  with zero preinstalled dependencies. Every tag publishes it beside a
  `.sha256`; the driver resolves a version to that release build,
  verifies the digest, caches it, and pushes it on demand. Provisioning
  a pod needs a network, not a toolchain.

## Install

Two binaries, and which is which matters: **`lm-provision`** is the
operator CLI you install and run, and **`lm-provisioner`** is the static
musl binary it pushes to a pod and runs there. The CLI is the one to
install; the provisioner comes down from the release on demand, so you
only want it locally to run a profile against the machine you are
sitting at.

```sh
# Fresh install. Upgrading from 0.9.0 or earlier: see below first.
cargo install lm-provision       # the pod-side binary: lm-provisioner
cargo install lm-provision-cli   # the operator CLI: lm-provision
```

**Upgrading from 0.9.0 or earlier: uninstall the old `lm-provision`
package first.** Up to 0.9.0 the `lm-provision` *package* owned the
`lm-provision` *binary name*; from 0.10 the `lm-provision-cli` package
owns it, and cargo does not hand a binary name from one installed
package to another. On a host with the old version installed:

```sh
cargo uninstall lm-provision     # frees the name (removes the old lm-provision binary)
cargo install lm-provision       # the pod-side binary: lm-provisioner
cargo install lm-provision-cli   # the operator CLI: lm-provision
```

- Without the uninstall, `cargo install lm-provision-cli` is refused:
  "binary `lm-provision` already exists in destination as part of
  `lm-provision`". Reinstalling `lm-provision` on its own does **not**
  free the name — measured on this rename, a reinstall over 0.9.0 left
  the old `lm-provision` binary in place and the refusal stood — which
  is why the step is an uninstall, not a reinstall.
- `--force` on the CLI install overwrites the file but leaves cargo's
  install record attributing `lm-provision` to the old package, so a
  later `cargo install lm-provision` may delete the CLI as a binary
  that package stopped producing. If that has happened, run
  `cargo install lm-provision-cli` once more; nothing else is damaged.

## Quickstart

The pod-side subcommands below (`validate` / `hash` / `plan` / `apply` /
`fetch` / `pin`, chapter 07) are `lm-provisioner`'s; you rarely type
them yourself, because `lm-provision apply` is what gets them run on the
machine.

```sh
# Author a profile (JSON), then locally — the pod-side binary, run on
# your own host:
lm-provisioner validate profile.json
lm-provisioner hash profile.json
lm-provisioner plan profile.json

# Or start from a shared profile (docs/profiles/) — verified fetch,
# kept only if the canonical hash matches the pin from index.json:
lm-provisioner fetch \
  https://raw.githubusercontent.com/ynishi/lm-provision/main/docs/profiles/comfyui-base-0.1.0.json \
  --expect-hash <hash-from-index.json> -o profile.json

# Fragment reuse: write `Import` nodes with the `name@version`
# shorthand and let `pin` rewrite them into the explicit src+hash
# pair against an index.json (spec 11 §The resolver layer). The
# rewrite is verified end-to-end before it lands.
lm-provisioner pin profile.json \
  --index https://raw.githubusercontent.com/ynishi/lm-provision/main/docs/profiles/index.json

# Apply on the target host itself (or via the push driver from your
# machine, below):
lm-provisioner apply profile.json            # effectful
lm-provisioner apply profile.json --dry-run  # print steps, resolve secrets, no effects

# One-shot provision of a remote pod over SSH. The provisioner pushed
# to the pod is the release build for this CLI's own version —
# fetched once, checksum-verified, cached under $XDG_CACHE_HOME:
lm-provision apply \
  --ssh root@<host>:<port> --key ~/.ssh/<key> \
  --profile profile.json

# Or name the machine and let the platform say where it is — the
# address and port come out of the platform's own description of it.
# The identity file can live in ~/.config/lm-provision/.env as
# LM_PROVISION_SSH_KEY, beside RUNPOD_API_KEY, instead of --key:
lm-provision apply \
  --provider runpod --pod-id <id> \
  --profile profile.json

# After apply: the pod's own output, without typing an ssh line.
lm-provision logs --provider runpod --pod-id <id> vllm-qwen --follow
lm-provision exec --provider runpod --pod-id <id> -- nvidia-smi
lm-provision cp   --provider runpod --pod-id <id> :/tmp/vllm-qwen.log ./

# A port of the pod's on a port of yours — the reach a platform's own
# endpoints do not have (a service on the pod's loopback, a port the
# profile never declared, a proxy that ends a long request). This one
# verb dials its own ssh rather than the shared connection, so the
# process you stop is the process carrying the tunnel. Foreground
# until Ctrl-C, or --detach for a pid to kill later:
lm-provision port-forward --provider runpod --pod-id <id> 18000:8000
lm-provision port-forward --provider runpod --pod-id <id> --detach 18000:8000
# {"pid":12345,"address":"127.0.0.1","forwards":[{"local":18000,"remote":8000}]}
# on stdout; kill that pid to stop it.

# Pin another released version, or push a local build of your own
# (the override for developing the provisioner itself):
lm-provision apply ... --provisioner-version 0.8.0
lm-provision apply ... \
  --provisioner-path target/x86_64-unknown-linux-musl/release/lm-provisioner

# The fleet. --dry-run defaults to on where something is spent or
# destroyed: those render the request and send nothing.
lm-provision machine list --provider runpod          # read-only
lm-provision machine acquire --profile profile.json
lm-provision machine acquire --profile profile.json --dry-run false
lm-provision machine release --id <id> --profile profile.json
lm-provision machine sweep --provider runpod --dry-run false

# What the fleet serves: every OpenAI-compatible endpoint this host
# knows — acquired deployments (asked about through their platforms),
# detached port-forwards whose ssh still runs, and your own static rows
# in ~/.config/lm-provision/endpoints.json:
#   [{"name": "deepinfra-ds", "base_url": "https://api.deepinfra.com/v1/openai",
#     "model": "deepseek-ai/DeepSeek-V4-Flash", "api_key_env": "DEEPINFRA_API_KEY"}]
# Keys travel by NAME; no value is ever written.
lm-provision machine endpoints                        # the JSON artifact
eval "$(lm-provision machine endpoints --format env)" # DEEPINFRA_DS_BASE_URL / _MODEL / _API_KEY="$DEEPINFRA_API_KEY"
lm-provision machine endpoints --format litellm > litellm.yaml   # a model_list for the LiteLLM proxy

# A third platform: DeepInfra GPU Instances — a container with an
# address, reached over ssh as `ubuntu`. The token goes in the .env as
# DEEPINFRA_API_KEY (curl >= 8.3.0 reads it by name; the value is never
# on an argv). The profile names the image and your public key under
# the platform's own keys and declares no ports: the service maps
# none, so anything past sshd is reached with port-forward.
#   "provider": {
#     "deepinfra.container_image": "di-cont-ubuntu-torch:latest",
#     "deepinfra.ssh_authorized_key": "ssh-ed25519 AAAA... you@host"
#   }
lm-provision machine acquire --provider deepinfra --profile profile.json --dry-run false
lm-provision apply --provider deepinfra --pod-id <id> --remote-dir /home/ubuntu \
  --profile profile.json

# A fourth: DeepInfra Deployments — the platform runs the model, so
# what is acquired is an endpoint and not a host. The profile declares
# requires_gpu and exactly one ServiceStart ("platform_kind": "vllm",
# "model" = the Hugging Face repo id) and nothing else: no
# requires_ports, no requires_disk, no other phase — anything this
# platform cannot run is refused by name rather than dropped. Same
# DEEPINFRA_API_KEY as the instances above.
# The account needs a display name first (dashboard → Settings): the
# service prefixes every deployment's model_name with it and answers
# 409 "missing display name" without one. The replica range can be
# said once for every managed platform as deploy.min_replicas /
# deploy.max_replicas; a platform's own key (below) wins over it.
#   "provider": {
#     "deploy.min_replicas": "0",
#     "deploy.max_replicas": "1",
#     "deepinfra-deploy.settings.min_instances": "0",   # same thing, this
#     "deepinfra-deploy.settings.max_instances": "1",   #   platform's spelling
#     "deepinfra-deploy.hf.revision": "main",
#     "deepinfra-deploy.hf.token_env": "HF_TOKEN",   # a private repo:
#            # the name, imported inside curl; the value is on no argv
#     "deepinfra-deploy.container_image": "vllm/vllm-openai:v0.8.4",
#     "deepinfra-deploy.gpu": "H100-80GB"            # or let
#            # requires_gpu.min_vram_gb pick the cheapest that fits
#   }
lm-provision machine acquire --provider deepinfra-deploy \
  --profile docs/profiles/deepinfra-deploy-qwen-0.1.0.json   # shows the exact body
lm-provision machine acquire --provider deepinfra-deploy \
  --profile docs/profiles/deepinfra-deploy-qwen-0.1.0.json --dry-run false
# The artifact's connection is an endpoint rather than an ssh address:
# {"connection":{"endpoint":{"base_url":"https://api.deepinfra.com/v1/openai",
#   "model":"deploy_id:<id>","api_key_env":"DEEPINFRA_API_KEY"}}}
# `model` names the deployment by id, so the lease stamped into
# model_name never travels in a request. list / release / sweep work as
# on any other platform; apply / logs / exec / cp / port-forward do not
# apply and say so — there is no session to open.

# A fifth: Together AI dedicated endpoints (v2), driven by the service's
# own CLI `tg` (python package `together`, on PATH) — the v2 API takes
# three calls to create and five steps to release, and `tg` folds each
# into one verb. Keys: TOGETHER_API_KEY and TOGETHER_PROJECT_ID (from
# `tg whoami`) in the .env. The profile declares requires_gpu, exactly
# one ServiceStart whose "model" is a model the service serves (`tg beta
# models public --product dedicated`), no engine arguments (the engine
# is the platform's), no ports, no disk. The hardware is the certified
# config the CLI picks when the model has exactly one; name it with
# "together.config" (a cr_… id from `tg beta models configs <model>`)
# otherwise. Any other together.* key is refused rather than dropped.
#   "provider": {
#     "deploy.min_replicas": "1",          # shared with deepinfra-deploy;
#     "deploy.max_replicas": "1",          #   together.* wins when both given
#     "together.min_replicas": "1",        # 0/0 (created stopped) is refused
#     "together.max_replicas": "1",
#     "together.inactive_timeout": "60"    # minutes, 30-1440
#   }
lm-provision machine acquire --provider together \
  --profile docs/profiles/together-dedicated-0.1.0.json --dry-run false
# {"connection":{"endpoint":{"base_url":"https://api-inference.together.ai/v1",
#   "model":"<project-slug>/lmp-exp-…","api_key_env":"TOGETHER_API_KEY"}}}
# The lease is the endpoint's name (a v2 endpoint has no other operator-
# written field), listed under the project slug; `model` is that name.
# `release` converges: the first call scales the deployment to zero and
# is refused while it stops; call it again (or let the sweep) to delete.

# The MCP server, on stdio (see below for what it reads):
lm-provision mcp
```

### MCP server: which provisioner it pushes

`lm-provision mcp` needs no configuration to have a provisioner: unset,
it resolves the release its own version was built alongside, the same
way `apply` does. `LM_PROVISION_BINARY` overrides that with either
form — an `https://` archive URL (verified against the `.sha256` beside
it, so a fork's release or an in-network mirror works), or a local path
(used as given, for developing the provisioner itself):

```sh
# neither line is required; this is what the two overrides look like
export LM_PROVISION_BINARY=https://github.com/<fork>/lm-provision/releases/download/v0.8.0/lm-provision-x86_64-unknown-linux-musl.tar.xz
export LM_PROVISION_BINARY=target/x86_64-unknown-linux-musl/release/lm-provisioner
```

Any other scheme is refused rather than read as a filename — a mistyped
`http://` reported as a missing file sends you looking for a file.

### MCP server: pod target registry

`lm-provision mcp` resolves `lm_apply`'s `pod_id` against a **pod target
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

The engine — `lm-provision`, `lm-provision-cli`, `lm-provision-driver`,
`lm-provision-mcp` and `lm-provision-protocol` — is dual-licensed under
either of:

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
host crate reads the permissive manifests and fails if any of them
names it.
