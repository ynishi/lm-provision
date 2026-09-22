# 09. Apply report + audit redact + ledger schema

Status: specified (the ledger is the Phase G build target; revised
2026-09-01 to add the acquisitions record — the second append-only
file, one row per machine bought).
Layer 4. Upstream deps: 08. MVP: Phase G.

## Purpose

The apply report shape, the audit-log redaction rules, and the two
append-only row schemas: the ledger (what was applied) and the
acquisitions record (what is running). Consumers: the ledger reader
(audit, SLA, downstream analysis), the push driver's collect step, and
the expiry sweep (chapter 08).

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
  artifacts?   = [ <artifact entry>, ... ],  -- absent when none declared
}
```

Artifact entry — one per path the profile's `artifacts` slot declared
(chapter 01 §Collected artifacts), recorded by the driver's
pull-artifacts step (chapter 08 §Session steps):

```
{
  path      = string,   -- the declared pod-side path
  collected = bool,     -- whether the pull landed it on the operator host
  dest?     = string,   -- where it landed, present iff collected
  error?    = string,   -- why it did not, present iff not collected
}
```

A `collected = false` entry is a recorded debt, not bookkeeping: the
run's work product exists only on the pod, and chapter 08's release
gate refuses to delete the machine while its newest real apply
carries one. The field is additive to the frozen row schema: a row
written before it existed reads back as one declaring no artifacts,
and a row declaring none is written without the key — old rows and
new undeclaring rows are byte-compatible in both directions.

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

### Acquisitions record (append-only)

The ledger says what was applied; it says nothing about what is
*running*. `acquire` creates a billable machine and the only place its
identifier landed was the run's stdout — close the terminal and the
machine keeps billing with nothing on the host that knows it exists.
The acquisitions record is the host's answer to "what did I buy and
what have I not given back":

```
{
  id           = string,   -- the identifier the service gave the machine
  provider     = string,   -- which platform, as the operator named it
                           -- (`runpod`, `vast`, `deepinfra`,
                           -- `deepinfra-deploy`, `together`) — what a sweep looks
                           -- the adapter up by
  acquired_at  = string,   -- RFC 3339 UTC, driver clock
  expires_at   = string,   -- RFC 3339 UTC: acquired_at + the lease
  profile_hash = string,   -- 64-hex, chapter 03 hash of the profile the
                           -- machine was acquired for
  release      = [ string, ... ],  -- the argv that destroys it, `{id}`
                           -- unsubstituted, verbatim as the adapter
                           -- rendered it
  released_at? = string,   -- RFC 3339 UTC, present on a correction row
}
```

- **Append-only, and a release is a new row.** Giving a machine back
  appends a second row naming the same `id` with `released_at` set; the
  acquisition row is never touched. Same rule as §Ledger and the same
  reason, sharper here: a file only ever appended to cannot lose an
  earlier statement to a half-finished rewrite, and this is the file
  whose whole job is to outlive the process that wrote it.
- **`outstanding` = the machines still believed to be running**: the
  rows whose `id` no row in the file — acquisition or correction — has
  given a `released_at`, one entry per machine however many rows name
  it. It is an id-join over the whole file rather than a flag on a row,
  because a flag would have to be written by going back and mutating
  the row that carries it. Reading the file to answer is the price of
  never rewriting it, and the file holds one row per machine bought and
  one per machine returned — a fleet's worth, not a log's worth.
- A correction for an `id` the file never acquired retires nothing and
  is not itself outstanding: that is the shape a release against a
  machine acquired elsewhere leaves behind, and it is not an error.
- `release` is **credential-free by construction**: every target here
  takes its key from the environment or from its own CLI's key file,
  never from the command line (chapter 06), so the recorded argv holds
  a program name and its arguments and nothing to redact.
- **The lease is recorded, not enforced by the writer.** The `acquire`
  that stamped `expires_at` exits long before that moment passes; what
  acts on it is chapter 08's `sweep`.
- **This file is the audit trail, not the enforcement inventory.** What
  it answers is who bought what, when, under which profile, and how it
  was given back. What enforces the lease is the same `expires_at`
  written onto the machine itself at create time (chapter 08
  §Acquisitions and sweep: the `lmp-exp-` stamp), and the inventory a
  sweep works from is the platform's own list. The distinction is the
  whole point: a file can be lost, or written on a host that is not the
  one sweeping, and correctness must not turn on that. A failed append
  therefore costs the audit trail a row rather than costing a machine
  its expiry.
- **The record still has work of its own.** It is what a sweep run
  without `--provider` reads, which is what reaches machines created
  before the stamp existed; it is where a release argv is kept verbatim
  for a machine whose profile has moved on; and it is the only place
  that says which profile a machine was bought for.
- **Absent from the platform's list means gone.** When a sweep did list
  the platform an outstanding row names, and the row's `id` is not in
  the answer, the machine is not running whatever the row says —
  somebody released it by hand, or a correction was lost. A correction
  is appended so the file says the bill has ended, and no release call
  is spent on it. Only when that platform was actually listed: a
  platform nobody asked supports no such conclusion.
- Append failures are the ledger's error class with a sharper cost —
  see §Error surface.

### Forwards record (append-only, pruned)

`port-forward --detach` leaves an `ssh` running and prints its pid; the
terminal that printed it closes, and the tunnel is a process nobody can
name. The forwards record is the host's answer to "which tunnels did I
open and which still exist":

```
{
  pid          = int,      -- the detached ssh, as printed
  started_at?  = int,      -- the kernel's start time for that pid
                           -- (Linux: /proc/<pid>/stat field 22); absent
                           -- where the writer could not read one
  opened_at    = string,   -- RFC 3339 UTC, driver clock
  address      = string,   -- the local bind address
  forwards     = [ { local = int, remote = int }, ... ],
  pod?         = { provider = string, id = string },  -- when the pod
                           -- was named by platform and id
}
```

- **A pid alone does not name a process.** Pids are reused, and a row
  read after a reboot would point at whatever holds the number now. A
  row is *live* when the pid exists **and**, where one was recorded,
  its start time is the one recorded — the check every pidfile
  convention that survives a reboot makes. A row with no start time is
  judged on the pid alone, the weaker answer its writer declared.
- **Pruned on write.** Each `--detach` drops the rows whose process is
  gone before appending its own, so the file is the list of tunnels
  that exist, not of every tunnel ever opened. A record that cannot be
  read is not rewritten: nothing is dropped from a file nobody could
  read.
- Same encoding, same error class, same neutral home as the
  acquisitions record, and for the same reason: written by the operator
  CLI today, read by the inventory and the control plane later.

### Endpoint inventory (a reading, not a record)

`machine endpoints` (chapter 08) and `lm_endpoint_list` (chapter 10)
read three sources into one document — the acquisitions record,
the forwards record, and the operator's static rows — and write
nothing. One row per endpoint:

```
{
  name         = string,   -- the profile's service.start name for an
                           -- acquired machine (the platform id when the
                           -- row predates `service`), the operator's
                           -- name for a static row
  kind         = "deployment" | "tunnel" | "pod" | "serverless",
  provider?    = string,   id? = string,
  base_url?    = string,   -- absent on a `pod` no forward reaches
  model?       = string,
  api_key_env? = string,   -- the variable's NAME, never its value
  expires_at?  = string,   -- the lease, for an acquired machine
  source       = string,   -- "acquisitions" | "forwards" | <static path>
}
```

- **The key is a name.** No row, rendering, or record written here
  carries a key's value (chapter 06). A consumer that needs the value
  reads it from its own environment under that name — which is what
  the `env` rendering's `"$NAME"` and the `litellm` rendering's
  `os.environ/NAME` say.
- **The acquisitions row carries `service`** (additive to the frozen
  schema): the one `service.start` name the profile declared, so an
  endpoint is reached by the name the profile gave it. A row written
  before the field reads back without it and is named by its id.
- **A tunnel's model is read off the pod** (`/v1/models` on the local
  port, the one question an OpenAI-compatible server answers without a
  key); absent when the pod does not answer.
- The static file is a JSON array of `{name, base_url, model?,
  api_key_env?}`; a field outside those four is refused by name rather
  than dropped, since a mistyped `api_key_env` silently dropped would
  be a row with no key that looked complete.

## Error surface

- Ledger append failures (disk / transport): driver-side, retryable;
  the report itself is not lost while the collect-step output is
  retained. An apply is not "unrecorded-successful" — drivers must
  treat append failure as an operational error to retry, not
  swallow.
- Acquisitions append failures: the same class, and the same rule
  against swallowing, with the failure mode the record exists to
  prevent happening as it fails — a machine that is running with
  nothing on the host that knows it. A failed append after a
  successful acquire must put the machine's id and the append error
  where the operator will see them, and must **not** be reported as a
  failed acquire: the machine exists, and a caller told "nothing
  happened" will not go looking for it. A failed correction after a
  successful release is the mirror and is cheaper — the id stays
  outstanding, and the next sweep spends one release call on a machine
  that is already gone.
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
  implementations). The `artifacts` field (2026-08-30) is the
  additive form that stability permits: optional, absent-means-none,
  and never re-encoding a row that does not carry it.
- Ledger physical encoding: **internal**.
- Acquisitions row schema + append-only semantics: **stable**, on the
  ledger's tier and for the ledger's reason — the control plane that
  takes custody of the file outlives the driver that writes it. Growth
  is the ledger's additive form: optional, absent-means-unknown, and
  never re-encoding a row that does not carry the new field. Physical
  encoding: **internal**.

  The file's **role** was narrowed (2026-09-01) without its schema
  changing: it is the audit trail, and the inventory a sweep enforces
  from is the platform's own list (chapter 08 §Acquisitions and sweep).
  Readers gain from that rather than lose — the rows still say
  everything they said, and a lost row no longer means a machine that
  nothing comes back for.

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
