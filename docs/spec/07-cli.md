# 07. CLI

Status: specified. Layer 4.
Upstream deps: 03. MVP: Phase G (the binary ships in Phase F;
this chapter freezes its operator contract).

## Purpose

The `lm-provision` command-line binary. Defines subcommands, flags,
stdout / stderr split, and exit codes. This same binary is what the
push driver ships into the pod (chapter 08) — the CLI contract *is*
the pod-side invocation contract.

## Inputs

### Invocation

```
lm-provision <subcommand> <profile-path> [flags]
```

| subcommand | pipeline stages run | effects |
|---|---|---|
| `validate <path>` | load → declarations → validate | none (read-only) |
| `hash <path>` | load → declarations → canonical → hash | none (read-only) |
| `plan <path>` | load → declarations → plan | none (read-only) |
| `apply <path> [--dry-run]` | load → declarations → gate → bridges → plan → dispatch → apply | executes the dispatched op stream (dry-run: decode + policy + secret resolution only, chapter 04) |
| `fetch <url> --expect-hash <hex> -o <path>` | GET → stage → load → declarations → canonical → hash → admit-or-refuse | one HTTP GET, one file written at `<path>` — and only on a hash match; a refusal writes nothing new (a file already at `<path>` from an earlier run is not touched either way, except by the rename that lands an admitted profile) |
| `pin <path> --index <url-or-path>` | load-as-JSON → rewrite `name@version` → verify (chapter 11 §Resolution) → overwrite | rewrites the profile at `<path>` in place — HTTP GET the fragments the rewritten pins name, verify each, then rename over the original; a verify failure writes nothing (the temp file is removed and the original is left intact) |

`fetch` is the one subcommand whose positional argument is a URL, not
a path: it retrieves a shared profile (e.g. from a raw repository URL
of a published profile directory) and keeps it only when its canonical
hash matches the pin the caller took from the source's index. The hash
is computed over the canonical AST encoding, so it is what makes any
static host a trustworthy source; `--expect-hash` is required because
an unverified fetch adds nothing over `curl`. The staging file shares
the destination's extension so it routes to the same parser the
destination would (§Profile input format).

`pin` is the authoring-time counterpart to fragment resolve
(chapter 11 §The resolver layer): it walks the JSON profile at
`<path>`, finds every `Import` whose `src` matches the `name@version`
shorthand (`name` and `version` drawn from `[A-Za-z0-9._-]`, joined by
exactly one `@`, no scheme and no `/`), looks each pair up in
`--index`'s `{"profiles":[{name,version,path,profile_hash}]}` list,
and rewrites the import into the explicit `src` + `hash` pair the
resolve stage consumes. `--index` is either an https URL — fetched
under the same 4 MB cap and 30 s deadline `fetch` uses — or a local
path. Before overwriting the target, the rewritten document is
materialized to a temp file next to it and run through the full
resolve stage: every rewritten fragment is fetched, and every pin is
re-verified against the fragment's own expanded canonical hash. A
document that does not resolve never overwrites the original.

MVP is JSON-only (the canonical text form is not rewritable without
losing whitespace and comment shape — deferred).

### Profile input format

The profile path is loaded into the `ProfileNode` AST (chapter 01) by
the frontend, which selects the parser purely by file extension:

| extension | frontend |
|---|---|
| `.json` | JSON serde bridge (`serde_bridge::from_json_value`) |
| anything else (`.txt`, `.profile`, no extension, ...) | canonical text grammar (PEG, chapter 01 §Canonical Text Format) |
| `.lua` | rejected before any I/O: `Lua profiles are no longer supported` |

Both accepted frontends build the identical AST, so the profile hash
is frontend-independent (chapter 01 §Spec fields). Lua authoring was
removed together with the embedded VM; profiles are data, not code.

### Global flags

- `--log-level <filter>` (default `info`): tracing filter for the
  human-readable stderr stream (e.g. `lm_provision=debug`). The
  `RUST_LOG` environment variable, when set, takes precedence.
- `--json`: reserved. Machine-readable stdout is already the default
  for every subcommand; the flag is accepted for forward
  compatibility and currently changes nothing.

### Environment

- Declared secrets are read from the process environment at bridge
  consumption time (chapter 06). The operator (or push driver,
  chapter 08) must export every consumed `env_secrets` name before
  invoking `apply` — including `apply --dry-run`.

## Outputs

### Stream split

- **stdout** carries exactly one machine-readable artifact per run
  (below). Profile `print` output does not reach stdout (chapter 04
  print redirect).
- **stderr** carries human-readable tracing (progress, audit lines
  per chapter 09 redaction rules).

### Per-subcommand stdout

- `validate`: the validate result as pretty-printed JSON —
  `{"ok": true, "name": "<profile>"}` on success. On failure nothing
  is printed to stdout; the error goes to stderr (see exit codes).
- `hash`: the 64-character lowercase hex profile hash followed by a
  newline. Nothing else.
- `plan`: the plan artifact (chapter 03 §plan) as pretty-printed
  JSON.
- `apply`: the apply report (chapter 09) as pretty-printed JSON —
  printed on **both** success and step failure, so the collecting
  side always receives the report even when apply fails.
- `fetch`: `{"ok": true, "name": "<profile>", "hash": "<hex>",
  "path": "<out>"}` as pretty-printed JSON on success. On refusal
  (transport error / timeout / oversized body, non-profile or
  non-`Spec` body, hash mismatch) nothing is printed to stdout, the
  staging file is removed, and `<path>` is not written — though a
  file that was already there before the run survives, so "the path
  exists" is only evidence of verification for the run that reported
  `ok`. The error goes to stderr (`fetch failed: <message>`).
- `pin`: `{"ok": true, "pinned": [{"name": "...", "version": "...",
  "src": "...", "hash": "..."}]}` as pretty-printed JSON. A profile
  with no `name@version` imports succeeds with `"pinned": []` and
  does not touch the file (idempotent). On any failure — index
  unreadable / missing entry / verify failure — nothing is printed
  to stdout, the temp file next to the target is removed, and the
  original file is left byte-identical. The error goes to stderr
  (`pin failed: <message>`).

## Error surface

### Exit codes

| code | meaning |
|---|---|
| 0 | subcommand succeeded (`validate` ok / hash printed / plan printed / apply report `ok = true` / `fetch` admitted) |
| 1 | any failure: profile load error (including a `.lua` path), validate rejection, capability / policy / secret error, apply report `ok = false`, I/O or exec-engine error |
| 2 | CLI usage error (unknown subcommand / flag) — emitted by the argument parser with usage text on stderr |

Failure detail is on stderr as the final error line (e.g.
`validate failed: <message>`, `apply failed: <message>`). For
`apply`, the report on stdout carries the structured failing-step
detail; the stderr line is a human summary.

### Error classes (mapped from upstream chapters)

- Precondition (load / validate / policy / secret / gate): nothing
  executed; safe to re-run after editing the profile or environment.
- Runtime (bridge effect failures): apply stops at the failing step
  (fail-fast, chapter 09); earlier steps' effects persist. Re-running
  apply re-executes from the beginning — idempotency is the
  responsibility of the profile's steps (the setup-command vocabulary
  of chapter 02 is idempotent-friendly but not enforced).
- Transport (binary missing / profile file unreadable): standard OS
  errors, exit 1.
- Fetch refusal (HTTP transport error / timeout / body over the size
  cap / non-success status / non-profile or non-`Spec` body / hash
  mismatch): exit 1, staging removed, destination not written; safe
  to re-run against a corrected URL or pin.
- Pin refusal (non-JSON target / malformed profile JSON / index
  unreadable / index shape wrong / no matching `name@version`
  entry / rewritten document does not resolve): exit 1, temp file
  removed, original left untouched; safe to re-run against a
  corrected index or profile.

## Stability

- Subcommand names and the subcommand set (`validate` / `hash` /
  `plan` / `apply` / `fetch` / `pin`): **provisional** through Phase
  H (additions expected; renames are breaking).
- Exit code mapping (0 / 1 / 2 as above): **stable once frozen** —
  frozen here.
- Per-subcommand stdout artifacts (shape ownership: chapter 03 for
  validate / plan, this chapter for the hash line, chapter 09 for
  the report): **stable once frozen** — frozen here.
- stdout / stderr stream split: **stable** (the push driver's
  collection step depends on it).
- `--json` flag semantics: **provisional** (reserved).

## Upstream references

- chapter 03 pipeline stage artifacts — subcommand backends and
  artifact shapes.
- chapter 04 bridge — apply execution semantics, dry-run contract.
- chapter 06 secret handling — environment prerequisites.
- chapter 09 apply report — the apply stdout artifact and audit
  stderr rules.

## MVP scope

Ships in Phase G: `validate`, `hash`, `plan`, `apply --dry-run`,
`apply`. The binary side ships in Phase F, including a
whole-directory `apply --dry-run` regression over the example
profiles. `fetch` landed after the MVP set, alongside the shared
profile directory (`docs/profiles/`) it consumes.

A `canonical` subcommand (dump canonical bytes without hashing) is
intentionally absent — hash is the operator-facing artifact; the
canonical stage is exercised through `hash` and the ledger
(chapter 09).

A `codegen` subcommand emitting a `.d.lua` EmmyLua annotation file
was specified and shipped while profiles were authored in Lua. It was
removed with the Lua frontend: editor completion for a `.d.lua` stub
only serves Lua authoring, and the JSON / canonical-text surface is
described instead by the machine-derived `DslSchema` (chapter 01
§Core Schema Source of Truth), which needs no separate emit step.
