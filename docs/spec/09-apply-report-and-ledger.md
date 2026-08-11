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

A step that *fails* carries the same observations when it made any
before failing: a non-zero `sh` exit reports that exit code in
`status` and its captured `stdout` / `stderr`, alongside `reason`.
`status = -1` is therefore reserved for a failure that observed
nothing — one raised before the effect ran (an undeclared capability,
a policy rejection, an unresolvable secret) or by an effect that
produced no output to report.

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

The binary installs a stderr tracing subscriber honouring
`--log-level` / `RUST_LOG` (chapter 07 §Global flags) and emits one
structured `info` event per effect invocation, before the effect
runs. ANSI colour is suppressed when stderr is not a terminal so a
spec-08 driver that captures the pipe reads plain text.

Every event carries `op` (the catalog op name, e.g. `sh.exec`),
`kind` (the phase kind), and `mode` (`"dry-run"` / `"real"`) so a
consumer can partition the stream. Emission runs in both modes,
mirroring the "dry-run does policy / resolves secrets too" rule
(spec 06 / 07) — a dry-run trace is what the profile *would* run,
a real trace is what it *did*.

One event per effect is the rule; `net.transfer.progress` (below) is
the single exception, and it takes an `op` of its own so that a
consumer partitioning by `op` is unaffected by it.

#### Transfer progress

A transfer is the one effect whose duration is measured in minutes,
and a `models` phase runs up to four of them at once — so
`net.transfer` is followed by repeated `net.transfer.progress`
events while it runs. This is the only op that emits more than one
event per invocation.

```
op          = "net.transfer.progress"
kind        = <phase kind>
mode        = "real"          -- a dry run performs no transfer
step        = <report id>     -- "<phase_index>_<kind>[_<n>]"
dst         = <destination path>
bytes       = <written so far>
total       = <declared total> | "unknown"
percent     = <bytes/total>   | "unknown"
elapsed_sec = <since the request>
state       = "running" | "done"
```

- **`step` is the join to the report.** It is the id of the `steps`
  entry the transfer will write, so an interleaved stream partitions
  by it exactly: each partition is one transfer's whole account.
  Without it, four concurrent transfers are one stream of numbers
  that do not add up.
- **Cadence: 15 s, on a clock.** Shorter than the transfer read
  timeout (60 s) so that silence is readable — the events are driven
  by arriving chunks, so a supplier that stopped is heard as nothing
  further, and a reader needs a missing event to be news before the
  timeout turns the transfer into an error. A bytes-based rule would
  instead go quiet exactly when the supplier slowed down. Twenty
  minutes at four concurrent transfers is ~330 lines.
- **First and last always emit**, whatever the interval: the first so
  that an operator learns the step, destination and declared size as
  soon as bytes move, and the `"done"` one because it is the only
  place the real size appears for a supplier that declared no
  `Content-Length`, and because it closes one stream out of several.
- **A stream that stops on `"running"` did not finish.** A failed or
  cancelled transfer emits no `"done"` event.
- **No rate, and no estimated time remaining.** Both are host
  arithmetic dressed as observation: an average over twenty minutes
  lags a stall by minutes, and an ETA from it is a prediction the pod
  has no standing to make. `bytes` at a known cadence is the
  measurement; a consumer wanting a rate differences two events.
- **Append-only, never redrawn.** No ANSI progress bar and no
  carriage return: the consumer is a driver capturing a pipe
  (chapter 08), where a cursor move is a corrupted record.
- The **apply report is unchanged** — progress belongs to the
  transcript. The report is the result of an apply, not a running
  commentary on one.
- **The shape does not vary with the download mechanism.** A transfer
  is carried either in parallel ranges or as one stream (chapter 04
  §`net.transfer`), and the fields, cadence and ordering above are the
  same for both — the cadence is decided by the transcript, which reads
  whichever mechanism ran. The parallel route's `bytes` is the total
  written across every chunk, so it rises smoothly even though no
  single chunk is contiguous with the file's start. Which mechanism it
  was is said once, by `net.transfer.route`, and never repeated here:
  folding it into the progress events would invite a consumer to depend
  on it.

#### Transfer route

Emitted once per download, before its progress, naming the mechanism
chosen and why.

```
op     = "net.transfer.route"
mode   = "real"          -- a dry run performs no transfer
dst    = <destination path>
route  = "chunked" | "in-process"
reason = <why that route>
```

The choice is made from what the supplier answers rather than from the
profile, so it cannot be worked out by reading the profile — and the
two routes differ by a factor of several on a large weight. Without
this line a run that fell back is indistinguishable from one that was
always going to be slow.

Redaction rules:

- Env keys: key **names** are logged; a name matching the
  sensitive-key set is logged as `<KEY> [REDACTED]`. Values are
  never logged, sensitive or not.
- Secret markers: an `EnvSecret` reference renders as
  `[secret:NAME]` in every audit field.
- `fs.write`: logs path + byte count + `content_source` — the
  string `"string"` for literal content, `"secret:<name>"` for an
  `EnvSecret` content node, `"env_ref:<name>"` for an `EnvRef`
  pointing at a `Spec.env` entry (chapter 04 §`fs.write`). Content
  bytes are never logged, whatever the source.
- HTTP: URL, status, and body byte counts are logged; request header
  **names** are logged through the same helper the env keys use — so a
  sensitive-shaped name such as `Authorization` renders as
  `Authorization [REDACTED]` — and header values never (headers may
  carry tokens); bodies never. `net.http_post` additionally logs
  `body_source`, the body's origin named the way `fs.write`'s
  `content_source` is: `"none"` (no body declared), `"body:string"` /
  `"body:secret:<name>"` / `"body:env_ref:<name>"` for the `body`
  value node, or `"body_json"` (chapter 04 §`net.http_post`).
- `sh.exec`: argv is logged verbatim (validate's shell-safety and
  the env-injection design keep secrets out of argv); stdin is
  logged as a byte count only.
- `net.transfer.progress`: destination path, byte counts and elapsed
  seconds only. It deliberately does **not** repeat the source URL —
  a presigned link carries its credential in the query, and while the
  one pre-effect `net.transfer` event does log it (above), repeating
  it on every progress event would multiply that exposure for no
  added information.
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

The stderr audit transcript ships with the report (see §Audit log): one
structured `info` event per effect invocation, redacted by the rules
above and captured by the driver alongside the report.
