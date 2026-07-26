# 09. Apply report + audit redact + ledger schema

Status: specified (the ledger is the Phase G build target).
Layer 4. Upstream deps: 08. MVP: Phase G.

## Purpose

The apply report shape, the audit-log redaction rules, and the
append-only ledger schema. Consumers: the ledger reader (audit, SLA,
downstream analysis) and the push driver's collect step.

## Inputs

- The apply run (chapter 04 bridges driven by the dispatched op
  stream, chapter 03).
- The sensitive-key substring set (chapter 02 shared vocabulary):
  `key`, `token`, `secret`, `password`, `pwd`, `auth`, `cred`,
  `apikey` — case-insensitive substring match on key names.

## Outputs

### Apply report (stdout artifact, chapter 07)

```
{
  ok           = bool,     -- true iff every executed step ok
  dry_run      = bool,
  profile_name = string,
  steps        = [ <step entry>, ... ],  -- in execution order
  error?       = string,   -- present iff ok = false:
                           -- "step <id> (<kind>) failed: <stderr|reason>"
}
```

Step entry — common fields:

```
{ id, kind, op, ok = bool, status = int, dry_run?, reason?, ...op fields... }
```

- `id`: `<phase_index>_<kind>` for a direct-op phase, and
  `<phase_index>_<kind>_<n>` for the `n`-th sub-step of a lifecycle
  phase (chapter 03 §dispatch). Unique within a report.
- `kind`: the phase kind; `op`: the effect actually run.
- `status`: process exit code / HTTP status / `0` for a successful
  effectless step / `-1` for a failure that happened before the
  effect.
- `dry_run`: present (and `true`) for effect-bearing steps under
  `--dry-run`. An effectless `note` step does not carry it.
- `reason`: present iff `ok = false` — the failure text that also
  drives the envelope's `error` line.

Per-op additional fields:

| op | fields |
|---|---|
| `sh.exec` | `argv`, `stdout`, `stderr` (captured tails, real mode) |
| `fs.write` | `path`, `bytes` |
| `net.http_get` / `net.http_post` | `url` (status in the common `status` field) |
| `net.transfer` | `src`, `dst`, `bytes` |
| `mount.bind` | `src`, `dst` |
| `mount.umount` | `path` |
| `note` | `note` — a visible skip; `ok = true`, `status = 0` |

A lifecycle sub-step's entry carries the same fields as a direct op's:
its declared inputs (`argv` / `src` + `dst` / `url`) always, plus the
observations from running it (`status`, `stdout` / `stderr`, `bytes`,
the destination actually written) in real mode. Under `--dry-run` the
inputs are present and the observations are absent — nothing ran, so a
status or captured output there would be fabricated.

One gap remains: a step that *fails* carries `status = -1` and its
`reason`, not the partial observation that accompanied the failure
(the captured stderr behind a non-zero exit, say). The failure text
quotes it, but it is not in a structured field.

Semantics:

- **Fail-fast**: apply stops at the first step with `ok = false`;
  that step is the last entry in `steps` and populates `error`.
  Steps after it never ran and do not appear — absence from the
  report means "not reached".
- A step whose required capability is undeclared fails in-report
  (`status = -1`, `reason` names the missing capability) rather than
  crashing the run. The same holds for a path / URL policy rejection
  and an undeclared or missing secret — including under `--dry-run`.
- `note` entries are successes: they record what a lifecycle phase
  decided when it had no concrete invocation to make, so the report
  stays a complete trace of the plan, executed or not. `note`
  replaces the former `dispatch_pending` op, which implied a pending
  dispatch that the exec layer no longer has.
- Report content is redaction-safe by construction: a secret's value
  never enters the AST, the resolution map is never serialised into
  the report (chapter 06), and argv is shell-safety-checked by
  validate — so argv / stdout / stderr carry at most values the
  executed command itself chose to print.

### Audit log (stderr transcript)

**Status: specified, not yet implemented.** The binary installs a
stderr tracing subscriber honouring `--log-level` / `RUST_LOG`
(chapter 07 §Global flags), but no effect currently emits a tracing
event: stderr carries only the final error line. The exec layer does
build a per-phase trace line, and wiring it to this transcript under
the rules below is the outstanding work (chapter 04 §Trace output).
The rules are frozen here so the wiring has a contract to satisfy
rather than being invented at implementation time.

Every effect invocation emits one structured tracing line before the
effect. Redaction rules:

- Env keys: key **names** are logged; a name matching the
  sensitive-key set is logged as `<KEY> [REDACTED]`. Values are
  never logged, sensitive or not.
- Secret markers: an `EnvSecret` reference renders as
  `[secret:NAME]` in every audit field.
- `fs.write`: logs path + byte count + `content_source` — the
  string `"string"` for literal content or `"secret:<name>"` once the
  secret-content form lands (chapter 04 §`fs.write`). Content bytes
  are never logged.
- HTTP: URL, status, and body byte counts are logged; header
  **names** are logged, header values never (headers may carry
  tokens); bodies never.
- `sh.exec`: argv is logged verbatim (validate's shell-safety and
  the env-injection design keep secrets out of argv); stdin is
  logged as a byte count only.
- General redact helper: any (key, value) pair surfaced into logs
  passes the sensitive-key check; matching keys get `[REDACTED]`
  values.

### Ledger (append-only)

One row per apply invocation:

```
{
  pod_id       = string,   -- driver-provided provisioning context
  profile_hash = string,   -- 64-hex, chapter 03 hash of the applied profile
  report       = <apply report>,  -- verbatim, as collected
  collected_at = string,   -- RFC 3339 UTC, driver clock
}
```

- Append-only: rows are never mutated or deleted; corrections are
  new rows. The ledger is the source of truth for downstream
  analysis (external pod-manager integration, audit, SLA reporting).
- `(pod_id, profile_hash)` is deliberately **not** unique — re-applies
  and retries append additional rows; the full history is the value.
- Storing canonical bytes alongside rows is a consumer choice, not
  part of the row schema. Reconstructing the profile AST from those
  bytes would need a canonical **decode** path, which chapter 03
  leaves undefined in this revision — a consumer needing more than
  the hash keeps the source profile.
- Physical encoding (JSON Lines file, SQLite table, ...) is the
  ledger owner's choice: the row schema and append-only semantics
  are the contract, the storage engine is internal.

## Error surface

- Ledger append failures (disk / transport): driver-side, retryable;
  the report itself is not lost while the collect-step output is
  retained. An apply is not "unrecorded-successful" — drivers must
  treat append failure as an operational error to retry, not
  swallow.
- Report parse failure at collect time: chapter 08 error surface
  (transport corruption class).

## Stability

- Report top-level shape (`ok` / `dry_run` / `profile_name` /
  `steps` / `error`) and the fail-fast + `note` semantics:
  **stable once frozen** — frozen here.
- Per-op step fields: **provisional** through Phase H (additive
  growth as bridges gain fields; removals are breaking).
- Redaction substring set: **stable once frozen** — frozen in
  chapter 02.
- Redaction rules (names-not-values, `content_source`, marker
  rendering): **stable**.
- Ledger row schema + append-only semantics: **stable** — a tier
  separate from the driver protocol (ledger readers outlive driver
  implementations).
- Ledger physical encoding: **internal**.

## Upstream references

- chapter 00 §Secret handling — audit redact as a report-side
  contract (the consumer is the ledger reader, not the profile
  author).
- chapter 00 §On-pod agent model — append-only ledger as the source
  of truth.
- chapter 02 phase catalog — sensitive-key substring set.
- chapter 03 pipeline stage artifacts — hash, canonical decode.
- chapter 08 push driver protocol — collect step,
  `(pod_id, hash, report)` derivation.

## MVP scope

Ships in Phase G: ledger append + `collected_at` stamping in the
driver.

The report shape, the fail-fast semantics, and `note` entries ship
binary-side in Phase F; Phase G consumes them unchanged.

The stderr audit transcript and its redaction rules are specified but
not yet emitted (see §Audit log). This does not weaken the report
contract — the report never carried secret values in the first place —
but an operator watching stderr today sees only the final error line.
