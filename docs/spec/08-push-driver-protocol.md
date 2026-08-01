# 08. Push driver protocol (on-pod agent model)

Status: specified (the session contract below is the Phase G build
target; revised 2026-08-01 from first real-pod usage feedback).
Layer 4. Upstream deps: 07, 04, 06.
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

Pod lifecycle (create / start / stop / delete) stays outside — see
§Stability.

### Session contract

```
Input  (everything the caller must know)
  ConnectionSpec  = ssh { host, port, user (default root), key_path }
                    (a provider exec-API variant is additive, later)
  profile         = local path (canonical text or JSON, chapter 01)
  artifact        = local path to the musl binary (used by the
                    ensure-binary step's push strategy)
  secrets         = present in the driver host environment; the name
                    list is derived from the profile's `env_secrets`,
                    a missing name fails before any connection
  StepPlan        = per-step gates + strategies (§Session steps)
       │
       ▼   driver session
  0. ensure-binary → 1. place-profile → 2. hash-verify → 3. invoke
       → 4. collect → 5. ledger
       │
       ▼
Output = collected apply (report JSON, stderr transcript, exit code,
         profile_hash, collected_at) + a ledger row (chapter 09)
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
                    strategy: push-local-artifact (default)
                              fetch-release  (additive, later)
                              cargo-install  (additive, later)
                    idempotent: the pod-side sha256 is compared to
                    the local artifact's; identical → no-op, so
                    re-running a session is re-convergence, not
                    re-transfer   gate: skip-install
1. place-profile  — put the profile file at the pod path (always
                    overwritten; it is small and step 2 verifies it)
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
5. ledger         — append (pod_id, profile_hash, report,
                    collected_at) to the ledger (chapter 09)
                    gate: no-ledger
```

- The driver may run `validate` / `hash` / `plan` remotely or
  locally first — the binary is the same and the artifacts are
  identical (chapter 07); `hash` before and after upload doubles as
  a profile-integrity check (that is step 2's whole job).
- Steps 1-4's middle is the 2026-07 three-step contract verbatim
  (upload / invoke / collect); nothing about the invoke command
  form, the stdio contract, or the exit mapping changed.

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

## Outputs

- stdout: exactly one JSON apply report (chapter 09), emitted on
  success **and** on step failure.
- stderr: human-readable transcript (tracing lines, audit-redacted).
- exit code: chapter 07 mapping (0 = report `ok = true`; 1 =
  failure of any class; 2 = usage).
- The driver derives `(pod_id, profile_hash, report)` — `pod_id`
  from its own provisioning context, `profile_hash` via the `hash`
  subcommand — and appends it to the ledger (chapter 09, session
  step 5).

## Error surface

- Transport failures (upload incomplete, exec channel dropped,
  stdout truncated): driver-side; retryable; the pod may hold a
  partially provisioned state — re-invoking apply re-runs from the
  first step (chapter 07 runtime class).
- Invoke-time precondition failures (missing secret env, validate
  reject, a gated-off step's missing postcondition such as
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
- Provisioning boundary: pod lifecycle (create / start / stop /
  delete) stays with the external pod manager; only provisioning is
  owned by `lm-provision`. The pod-provider API client is **not**
  pulled into this repo. **Stable** (re-affirmed by the 2026-08-01
  revision: real-pod usage worked cleanly with lifecycle outside).
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

## MVP scope

Ships in Phase G: the session steps 0-5 against the Phase F binary
(SSH ConnectionSpec, push-local-artifact strategy, per-step gates),
ledger append (chapter 09), and the call path that lets an external
pod manager delegate provisioning to this protocol.

The binary half of this contract ships in Phase F (subcommands,
report-on-stdout, exit codes, env-secret injection);
Phase G adds the driver half without modifying the binary contract.

Deferred with one-line reasons: `fetch-release` / `cargo-install`
ensure-binary strategies (distribution surface not published yet);
exec-API ConnectionSpec (no concrete provider client in scope —
lifecycle boundary keeps provider SDKs out, an exec adapter would
re-open that question deliberately).
