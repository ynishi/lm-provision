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
{ id, kind, op, ok = bool, status = int, dry_run?, ...op fields... }
```

Per-op additional fields:

| op | fields |
|---|---|
| `sh.exec` | `argv`, `stdout`, `stderr` (`timed_out` surfaces via stderr suffix and `status = -1`) |
| `fs.write` | `path`, `bytes` |
| `net.http_get` / `net.http_post` | `url`, `body_bytes`, `stderr` (= bridge `error`) |
| `net.transfer` | `src`, `dst`, `bytes`, `sha256`, `stderr` (= bridge `error`) |
| `mount.bind` | `src`, `dst`, `stderr` (= bridge `error`) |
| `mount.umount` | `path`, `stderr` (= bridge `error`) |
| `dispatch_pending` | `note` — a visible skip; `ok = true`, `status = 0` |

Semantics:

- **Fail-fast**: apply stops at the first step with `ok = false`;
  that step is the last entry in `steps` and populates `error`.
  Steps after it never ran and do not appear — absence from the
  report means "not reached".
- A step whose required bridge is not registered (capability
  undeclared) fails in-report (`status = -1`, stderr names the
  missing capability) rather than crashing the run.
- `dispatch_pending` entries are successes: they record what the
  dispatch layer intentionally skipped (chapter 02 §Unknown kinds,
  `sync.push` markers) so the report is a complete trace of the
  plan, executed or not.
- Report content is redaction-safe by construction: secrets never
  enter the Lua side (chapter 06), so argv / stdout / stderr carry
  at most the `[secret:NAME]` marker or values the executed command
  itself chose to print.

### Audit log (stderr transcript)

Every bridge invocation emits one structured tracing line before the
effect. Redaction rules:

- Env keys: key **names** are logged; a name matching the
  sensitive-key set is logged as `<KEY> [REDACTED]`. Values are
  never logged, sensitive or not.
- Secret markers: a SecretRef renders as `[secret:NAME]` everywhere
  (print redirect, audit fields).
- `fs.write`: logs path + byte count + `content_source` — the
  string `"string"` for literal content or `"secret:<name>"` when a
  SecretRef wrote the file. Content bytes are never logged.
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
- The canonical decode path (chapter 03) reconstructs the profile IR
  from a stored canonical form when a ledger consumer needs more
  than the hash; storing canonical bytes alongside rows is a
  consumer choice, not part of the row schema.
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
  `steps` / `error`) and the fail-fast + pending semantics:
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

The report shape, fail-fast semantics, pending entries, and every
redaction rule above ship binary-side in Phase F; Phase G consumes
them unchanged.
