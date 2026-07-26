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

## Error surface

### Exit codes

| code | meaning |
|---|---|
| 0 | subcommand succeeded (`validate` ok / hash printed / plan printed / apply report `ok = true`) |
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

## Stability

- Subcommand names and the four-subcommand set: **provisional**
  through Phase H (additions expected; renames are breaking).
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
profiles.

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
