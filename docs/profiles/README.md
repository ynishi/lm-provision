# Shared profiles

Ready-to-use lm-provision profiles, distributed as plain JSON. Nothing
here needs a registry service: every profile's identity is its
deterministic hash, so any static host — including this directory
served over GitHub Pages or fetched raw from the repository — is a
trustworthy source once the hash checks out.

## Fetch and verify

`index.json` lists every profile with its expected `profile_hash`.
`lm-provisioner fetch` downloads a profile and keeps it **only** if its
canonical hash matches that pin — on a mismatch nothing is written.
(`lm-provisioner` is the pod-side binary; `fetch` and `hash` are its
subcommands, and they are just as usable on your own machine. The
operator CLI that pushes it to a pod is `lm-provision`.)

```sh
lm-provisioner fetch \
  https://raw.githubusercontent.com/ynishi/lm-provision/main/docs/profiles/comfyui-base-0.1.0.json \
  --expect-hash 426ee76b2e055bd80003697443d5b1a2703396f0158013f5a48a0b0fc1c4daed \
  -o profile.json
```

The hash is computed over the canonical AST encoding, so it is stable
across whitespace and key order (`lm-provisioner hash` prints the same
value locally). Plain `curl` + `lm-provisioner hash` works too if you
prefer to compare by eye.

Keep a `.json` extension on the `-o` destination: the parser is
selected by extension, so `-o comfy` would route these JSON profiles
to the canonical-text parser and the fetch would refuse.

## Files are immutable

A published `name-version.json` never changes; edits ship as a new
version with a new hash. That is what makes a pinned hash worth
writing down.

## Models are yours to declare

Shared profiles deliberately ship **no model weights**. A baked-in
checkpoint URL ages badly and encodes a licensing decision the profile
author cannot make for you. Add a `Models` phase yourself, pointing at
the official repository of the model you intend to run:

```json
{
  "type": "Models",
  "models_json": "[{\"src\":\"https://huggingface.co/<org>/<repo>/resolve/main/<file>.safetensors\",\"dst\":\"<file>.safetensors\",\"subdir\":\"checkpoints\"}]"
}
```

Keep the download host inside the profile's `http_allowlist`, and use
the model's official organization on Hugging Face (or an `hf://`
source) rather than a mirror.
