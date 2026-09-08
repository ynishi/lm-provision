# 08. Push driver protocol (on-pod agent model)

Status: specified (the session contract below is the Phase G build
target; revised 2026-08-01 from first real-pod usage feedback;
revised 2026-08-30 to add the artifacts retrieval contract — step 4b
and the release gate; revised 2026-09-01 to name the operator-side
preflight, whose resolve stage decides what step 1 uploads, and to add
the acquisition lease and the expiry sweep).
Layer 4. Upstream deps: 07, 04, 06, 11.
MVP: Phase G.

## Purpose

The contract between a caller (operator machine, an external pod
manager, or CI) and a pod that provisioning should land on. It is a
**session contract**: the caller supplies connectivity, a profile,
and secret values — the driver session owns everything from there
(binary delivery included) through to a collected report and a ledger
row. Individual session steps can be gated on or off, but the base
shape is declarative one-shot apply: given a reachable pod, one
driver invocation converges it (the Terraform / K8s `apply` posture).

Pod lifecycle: the driver's `acquire` / `release` / `sweep`
subcommands create and delete a machine through the provider's own
CLI; start / stop stay outside — see §Stability.

### Session contract

```
Input  (everything the caller must know)
  ConnectionSpec  = ssh { host, port, user (default root), key_path }
                    (a provider exec-API variant is additive, later)
  profile         = local path (canonical text or JSON, chapter 01)
  provisioner     = a version (default: the driver's own), resolved
                    to the release build CI published for it —
                    downloaded once, verified against the SHA-256
                    beside it, cached. A local path overrides it
                    (used by the ensure-binary step's strategies)
  secrets         = present in the driver host environment; the name
                    list is derived from the profile's `env_secrets`,
                    a missing name fails before any connection
  StepPlan        = per-step gates + strategies (§Session steps)
       │
       ▼   driver session
  0. ensure-binary → 1. place-profile → 2. hash-verify → 3. invoke
       → 4. collect → 4b. pull-artifacts → 5. ledger
       │
       ▼
Output = collected apply (report JSON, stderr transcript, exit code,
         profile_hash, collected_at) + the declared artifacts pulled
         to the operator host with per-path outcomes + a ledger row
         (chapter 09)
```

The 2026-07 revision of this chapter defined only steps 1-4's middle
(upload / invoke / collect) and left binary acquisition, placement
paths, key material, secret transport, and report retrieval to "the
driver's choice". First real-pod usage (2026-08-01) executed that
contract manually and every one of those choices became by-hand work;
this revision pulls them inside the contract. The old three-step
definitions are not discarded — they survive verbatim as the middle
of §Session steps.

## Inputs

### The provisioner binary artifact

- A single statically linked executable, target
  `x86_64-unknown-linux-musl` (additional targets are additive).
- Carries no language runtime and loads nothing at run time: the
  domain logic is compiled Rust and a profile is data (chapter 05 L1).
  The pod needs zero preinstalled dependencies for the binary itself
  to run.
- Build shape (crate contract): one Cargo workspace; the host crate
  produces `[[bin]] name = "lm-provision"` — the artifact this
  protocol ships. Sibling crates in the same workspace produce the
  driver side and the MCP server (chapter 10); neither is uploaded
  into the pod.
- **Who builds it: CI, not the operator.** The release workflow builds
  the musl target on every tag and publishes the archive beside its
  `.sha256`. The driver resolves a *version* to that asset, verifies
  the digest, and caches the result under the operator's cache
  directory; a local path is an override for developing the
  provisioner itself, not the way in. Requiring the local build made
  what runs on a pod a property of whichever machine ran the driver —
  some working tree, some toolchain, under a version number nothing
  recorded.
- External tools invoked *by profiles* (`apt-get`, `git`, `pip`,
  `curl`, `b2`, `hf`, ...) are pod-image prerequisites
  of the specific profile, not of the binary. A missing tool fails
  the corresponding step at apply time with the exec error in the
  report.

## Session steps

Every step defaults to **on**; a gate turns a step off explicitly.
Gating a step off is a declaration that its work is not wanted — it
is never an implicit promise that the work happened elsewhere. When a
skipped step's postcondition is actually needed later (e.g.
`--skip-install` but no binary at the pod path), the session fails
fast as an invoke-time precondition error (§Error surface), before
any effect runs.

```
0. ensure-binary  — make <bin> exist at the pod path
                    strategy: fetch-release (default; the version's
                              release asset, checksum-verified and
                              cached on the operator host)
                              push-local-artifact (override: a path
                              the operator names)
                              cargo-install  (additive, later)
                    idempotent: the pod-side sha256 is compared to
                    the local artifact's; identical → no-op, so
                    re-running a session is re-convergence, not
                    re-transfer   gate: skip-install
1. place-profile  — put the profile at the pod path (always
                    overwritten; it is small and step 2 verifies it).
                    What is placed is what the preflight below
                    resolved: a profile that imports a fragment
                    (chapter 11) travels as its expanded form, written
                    in the JSON bridge spelling; a profile with no
                    import travels as its own file, byte for byte
2. hash-verify    — run `<bin> hash <profile>` on the pod, compare
                    with the locally computed hash (the
                    profile-integrity check)   gate: skip-verify
3. invoke         — run:  <bin> apply <profile-path> [--dry-run]
                    with every consumed env_secrets name exported
                    into the process environment (chapter 06)
                    gate: dry-run / validate-only select the
                    subcommand form; `plan`-like preview = dry-run
4. collect        — capture stdout (the apply report JSON), stderr
                    (the audit/progress transcript), and the exit
                    code (follows invoke)
4b. pull-artifacts — pull each path the profile's `artifacts` slot
                    declares (chapter 01 §Collected artifacts) to
                    `<artifacts-dir>/<pod_id>/<pod path>` on the
                    operator host (a directory recursively), and
                    record the per-path outcome; runs only after a
                    real apply — a dry run / validate produced
                    nothing and records nothing. A failed pull does
                    not fail the session: the report is already
                    collected and the recorded debt is the point —
                    but it does cost the zero exit, and the ledger
                    row carries it into the release gate below.
                    gate: no-artifacts (the declared paths are still
                    recorded, all uncollected — gating the pull off
                    is not a way to erase the declaration)
5. ledger         — append (pod_id, profile_hash, report,
                    collected_at, artifacts) to the ledger
                    (chapter 09)   gate: no-ledger
```

- The driver may run `validate` / `hash` / `plan` remotely or
  locally first — the binary is the same and the artifacts are
  identical (chapter 07); `hash` before and after upload doubles as
  a profile-integrity check (that is step 2's whole job).
- Steps 1-4's middle is the 2026-07 three-step contract verbatim
  (upload / invoke / collect); nothing about the invoke command
  form, the stdio contract, or the exit mapping changed.

### Operator-side preflight

Before step 0 the driver reads the profile on its own host, through
the library rather than the pod: **load → resolve → validate → hash**
(chapter 11 §Resolution's pipeline, then chapter 03's hash). Every
part of it happens before the first transport call, so a profile the
operator host can already refuse costs no connection and leaves no
half-provisioned pod (§Error surface).

Resolve is the operator's stage by construction: a fragment may be a
path in the operator's working tree, and fetching one is governed by
the operator host's network, not the pod's (chapter 11 §Resolution).
That is why step 1 uploads the expansion — the pod cannot be asked to
redo work whose inputs it does not have. It is also why the hash step
2 compares is the *expanded* canonical hash: chapter 11 §Identity
makes that hash the profile's identity, and the pod's own
`lm-provision hash` computes the same number because it, too,
resolves before hashing.

The pod's half of steps 1-2 is therefore unchanged: it re-parses and
re-hashes the document it receives, and knows nothing about where
that document came from. Nor does anything change for the profiles
that exist today — with no `Import` node a profile expands to itself
(chapter 11 §Stability guarantee 1), and the file placed on the pod
is the caller's own bytes.

### Secret delivery

Secret delivery is env-only: the driver injects secrets into the
invocation environment. Secrets never appear in the command line, in
the profile file, or on stdout/stderr (chapter 09 redaction).

Per-transport realization:

- **provider exec API**: the API's env field.
- **SSH**: values travel on the **ssh channel's stdin**, and a
  pod-side wrapper reads them into the environment before exec'ing
  the binary. Embedding `NAME=value` in the remote command string is
  **not** a conforming delivery: the value lands in the driver
  host's process list and shell history. (First real-pod usage did
  exactly this by hand — the leak surface is why the spelling is now
  pinned.)

### Release gate

The accident this contract exists to remove: work is produced on a
machine, the machine is deleted, the work goes with it — and every
step of that was somebody following procedure. The declaration
(chapter 01 §Collected artifacts) makes retrieval a session step; the
gate makes the deletion wait for it:

- `release` reads the ledger before touching the provider. The row it
  judges by is the **newest real apply** recorded for the machine's
  id — dry-run rows are skipped (they produce nothing and record no
  artifacts, and must not stand in for the real apply behind them).
- If that row carries any `collected = false` artifact, the release
  is refused at admission — exit 3, nothing destroyed, the
  uncollected paths named. Re-running apply (which re-pulls) is the
  way through the gate; `--force` is the operator's way around it,
  stating that what is still on the machine is deleted with it.
- An unreadable ledger refuses the same way (absent `--force`): a
  gate that fails open makes a corrupt ledger the easiest way through
  it.
- A machine with no recorded apply passes — the gate can only weigh
  what an apply recorded. The join key is the ledger's `pod_id`, so a
  session driven for a machine that `acquire` created should carry
  that machine's id as its pod-id (the apply default of the SSH host
  records rows the gate will never look up).

### Acquisitions and sweep

The release gate above keeps a machine alive until its work is
collected. Nothing kept it from living forever: `acquire` created a
billable machine and left no record of it on the operator host, so a
`release` that never came meant an id that sank with the terminal
scrollback and a machine that billed until someone noticed.

- **Every acquire records the machine** in the acquisitions record
  (chapter 09 §Acquisitions record) — id, platform, the profile hash,
  the release argv verbatim, and the lease — before it waits for the
  machine to come up. A dry-run acquire records nothing: it created
  nothing.
- **Every acquire carries a lease**: `--ttl-hours`, default 24. The
  fleet is ephemeral by design and a machine bought for longer than a
  day is a decision, not a default; there is no opt-out flag, because
  an unleased machine is one nothing ever comes back for. The lease is
  **recorded, not enforced in-band** — the acquiring process exits
  long before the hours pass, and `expires_at` is a statement for
  whoever reads the record next.
- **Every acquire also stamps the lease onto the machine.** The create
  call writes `expires_at` into the field the platform gives an
  operator to name a resource — a pod's `name`, an instance's `label` —
  as `lmp-exp-` followed by RFC 3339 UTC with the separators removed
  and the seconds truncated: `lmp-exp-20260902T063000Z`. Colon-free,
  because these fields are constrained differently on every platform
  and a colon is the likeliest character to be refused. The prefix is
  fixed and matched whole; a field holding anything else is not a
  lease. The stamped instant and the recorded `expires_at` come from
  one clock reading, so the machine and the record cannot disagree, and
  a profile that also names the machine (`provider.runpod.name`) does
  **not** win — a name that displaced the stamp would put the machine
  out of the sweeper's reach.
- **The platform's list is the inventory; the record is not.** A record
  is a file: it can be lost, or written on a host that is not the one
  sweeping, while the machine keeps billing. The list cannot be, because
  the list *is* the fleet. This is the shape every established reaper
  has (Netflix's Janitor Monkey, `aws-nuke`, `cloud-nuke`, the AWS
  Instance Scheduler, the Kubernetes TTL controllers): enumerate from
  the API, read the policy off the resource's own tag, act. It is what
  lets anything holding the account's credential enforce leases with no
  state to keep in step.
- **`sweep --provider <name>` is that mode** (repeatable). For each
  named platform it lists the account's machines, reads the stamp off
  each one, and splits them three ways: *expired* (stamp read, lease
  reached) go through the same release gate and are released from the
  adapter's own release argv; *live* are left alone; *unknown* —
  carrying no `lmp-exp-` stamp — are **reported and never released on
  the listing's evidence** (the record half below may still release
  such a machine when a recorded lease names its id — the pre-stamp
  path — and the machine then appears in the artifact as both
  `unknown` and `released`).
  Marking an unrecognised machine and warning its owner before deleting
  it (Janitor Monkey's answer) needs an owner to warn and a mark to
  keep; neither is in this MVP, so the answer stops at telling the
  operator it is there. Listing needs the platform's credential **even
  under `--dry-run`**: there the key buys the question, not the kill.
- **`sweep` also reads the record**, with or without `--provider`. It
  takes the outstanding rows (chapter 09), keeps those whose
  `expires_at` has been reached (`<= now`, one clock reading for the
  run), and for each one applies **the same release gate** against the
  ledger before releasing it from the argv the record carries — not
  from a re-rendered profile, which may have changed or gone since the
  machine was bought. A successful release appends the correction row.
  This is the whole sweep when no platform is named, and it is what
  still reaches machines created before leases were stamped onto them.
- **The two halves meet on the machine id.** A machine both halves see
  is released once, by the platform half: the stamp on the machine
  outranks the row about it, because the machine is the thing being
  billed. A machine the platform lists without a stamp is left to the
  record, which is how a pre-stamp machine still expires. An
  outstanding row whose id is **absent** from its platform's list — and
  only when that platform was actually listed this run — is a machine
  that is gone: no release is spent on it, and a correction is appended
  so the audit trail says the bill has ended.
- **Idempotency is by convergence, not by reading error text.** Nothing
  matches "not found" against a platform CLI's output to decide a
  machine is already gone: that text differs per platform, per version
  and per locale, and depending on its spelling is depending on
  somebody else's prose. A machine already gone is simply absent from
  the next listing. Two sweeps racing can therefore cost one of them
  one failed entry for one tick, and the tick after that lists the
  machine as absent and is done with it — the same retry-until-empty
  shape `aws-nuke` settles for.
- **`sweep` has no `--force`.** Forcing is a statement that the work
  still on a machine may be deleted with it, and a scheduled sweep is
  the least informed thing in the system about whether that is true. A
  gated machine is reported and left running; the operator escalates
  by hand with `release --force`.
- `--dry-run` **defaults to true**, as `acquire`'s does and for the
  same reason: the command destroys machines, and an operator asking
  which ones should not find out by them being gone.
- Output is one JSON document (chapter 07 §Stream split: one
  machine-readable artifact per run, everything the provider's CLI
  said on stderr): `dry_run`, the number of
  machines found expired (once per machine, however many halves saw
  it), the ids released (under `--dry-run`, the ids that would be), the
  refused and failed ones with a reason each, and `unknown` — the
  listed machines carrying no stamp, as `{id, name_or_label}`. A
  platform that could not be listed at all is a `failed` entry under
  the **platform's** name rather than a machine's: what could not be
  read is the whole plane. Exit 0 when nothing failed — **a gate
  refusal is not a sweep failure**, it is the gate working, and a
  non-zero exit from a scheduled sweep would say the opposite. A
  machine that expired and could **not** be released is exit 1: nobody
  decided that, and it is still billing. So is a platform nobody could
  ask, for the same reason — and so is an expired machine whose gate
  could not read the ledger at all: an unreadable ledger holds the
  machine (fail closed) but as a `failed` entry, not a refusal, because
  a corrupt ledger read as a refusal would keep every expired machine
  billing behind a zero exit forever.
- A continuously running host daemon that enforces leases without
  being invoked is the control plane's job (chapter 09's record is
  the shared vocabulary for exactly that); `sweep` is the operator's
  hand on the same file.

## Outputs

- stdout: exactly one JSON apply report (chapter 09), emitted on
  success **and** on step failure.
- stderr: human-readable transcript (tracing lines, audit-redacted).
- exit code: chapter 07 mapping (0 = report `ok = true`; 1 =
  failure of any class; 2 = usage).
- The driver derives `(pod_id, profile_hash, report)` — `pod_id`
  from its own provisioning context, `profile_hash` via the `hash`
  subcommand — and appends it, with step 4b's per-artifact outcomes,
  to the ledger (chapter 09, session step 5).

## Error surface

- Transport failures (upload incomplete, exec channel dropped,
  stdout truncated): driver-side; retryable; the pod may hold a
  partially provisioned state — re-invoking apply re-runs from the
  first step (chapter 07 runtime class).
- Invoke-time precondition failures (missing secret env, an import
  the operator host could not resolve — chapter 11 §Error surface,
  validate reject, a gated-off step's missing postcondition such as
  `skip-install` with no binary on the pod): exit 1 / session error
  with a stderr line and (for apply) no effects run on the pod.
- Pod-side apply failures: exit 1 **with** the structured report on
  stdout — the driver must treat "exit 1 + parseable report" as a
  richer signal than the exit code alone (the failing step, its
  stderr, and every completed step are in the report).
- Collect-time parse failure (stdout not valid JSON): driver-side
  error class of its own — it indicates transport corruption or a
  host crash, never a normal apply failure (the binary's stdout
  contract is unconditional, chapter 07).

## Stability

- The invoke command form, the stdio/exit-code contract, and env-only
  secret delivery: **stable** (unchanged from the 2026-07 freeze).
- The session-step list and gate names: **provisional** — step
  strategies (`fetch-release`, `cargo-install`, an exec-API
  ConnectionSpec) are additive.
- ~~Provisioning boundary: pod lifecycle (create / start / stop /
  delete) stays with the external pod manager; only provisioning is
  owned by `lm-provision`. The pod-provider API client is **not**
  pulled into this repo. **Stable** (re-affirmed by the 2026-08-01
  revision: real-pod usage worked cleanly with lifecycle outside).~~
  Superseded (2026-08-12): the driver now owns machine create and
  delete itself — `acquire` renders the provider request from the
  profile's machine requirements and spawns the provider's CLI,
  `release` deletes by id the same way. Start / stop stay with the
  external pod manager. What remains **stable** is the narrower
  half of the old bullet: no provider SDK is linked into this repo —
  the provider is reached only through its CLI.

  Revised (2026-08-30): `acquire`'s artifact also carries the
  **created-machine connection data** — the caller's `ConnectionSpec`
  inputs (§Session contract), projected per platform from the
  service's own description by the adapter (a managed pod service's
  `publicIp` + port mappings; each platform names its own fields).
  `acquire` waits, bounded, until the platform has answered for every
  declared port before judging the verdict and reporting: a machine
  inspected mid-boot is not a refused machine, and an artifact
  without the address sends every caller back to the provider —
  arranging the provider credential in its own shell — for a fact
  the driver already paid to learn (first artifacts verification did
  exactly that by hand). The projection is part of the adapter
  seam; the wait bound is the driver's own (**internal**).
- The acquisition lease and the sweep (2026-09-01): the **recording**
  is chapter 09's stable tier — a row written today is read by the
  control plane later, which is the whole reason the schema sits on
  the neutral side of the license boundary. The sweep's own surface
  (flag names, the artifact's field names, the default lease of 24
  hours) is **provisional**: it is one operator-invoked realization of
  the lease, and a host daemon enforcing the same rows without being
  invoked is the intended successor, not a replacement of the record.

  Revised (2026-09-01): the lease is also **stamped onto the machine**
  and the platform's list is what a sweep enumerates, so enforcement no
  longer depends on the record at all. The stamp's spelling — the
  `lmp-exp-` prefix and the separator-free RFC 3339 form — is
  **stable** in the same sense the row schema is: a machine created
  today is read by a sweeper released later, possibly on another host,
  and a sweeper that stopped recognising the stamp would leave the
  machine running. Which field on which platform carries it is the
  adapter seam (**internal**).
- Static-binary embeddability constraint (musl, no language runtime,
  no runtime file dependencies): **stable**.
- Binary target set (musl x86_64 as the baseline): **provisional**
  (additive).
- ~~Driver implementation home (standalone CLI wrapper vs an external
  pod manager calling the protocol directly): **internal** — the
  protocol, not the caller, is the contract.~~ Superseded
  (2026-08-01): with no in-repo driver, every caller re-implemented
  the session by hand (first real-pod usage was scp + ssh + manual
  env assembly + manual report retrieval). The in-repo
  `lm-provision-driver` binary is now the **reference
  implementation** of the session contract; an external pod manager
  may still drive the protocol directly — the session contract, not
  the reference binary, remains the normative surface.

## Upstream references

- chapter 00 §On-pod agent model — binary, provisioning boundary,
  static provisioner, ledger.
- chapter 04 bridge — embeddability constraint on every primitive.
- chapter 06 secret handling — env-only secret delivery, fail-fast.
- chapter 07 CLI — invocation surface, stream split, exit codes.
- chapter 11 fragment import — the resolve stage the preflight runs,
  and the expanded canonical hash step 2 compares.

## MVP scope

Ships in Phase G: the session steps 0-5 against the Phase F binary
(SSH ConnectionSpec, push-local-artifact strategy, per-step gates),
ledger append (chapter 09), and the call path that lets an external
pod manager delegate provisioning to this protocol.

The binary half of this contract ships in Phase F (subcommands,
report-on-stdout, exit codes, env-secret injection);
Phase G adds the driver half without modifying the binary contract.

Deferred with one-line reasons: `cargo-install` ensure-binary strategy
(the release assets cover the same need without a toolchain on the
operator host — `fetch-release`, deferred here for the same "not
published yet" reason, shipped in 0.9.0 once the tagged releases
existed to fetch from);
exec-API ConnectionSpec (no provider SDK in scope — even `acquire` /
`release` reach the provider through its CLI, an exec adapter would
pull an API client in deliberately); marking an unstamped machine and
warning its owner before deleting it, Janitor Monkey style (there is no
owner to warn and no mark to keep — unstamped machines are reported
only).
