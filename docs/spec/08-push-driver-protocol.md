# 08. Push driver protocol (on-pod agent model)

Status: specified (the driver side is the Phase G build target).
Layer 4. Upstream deps: 07, 04, 06.
MVP: Phase G.

## Purpose

The protocol between the outer driver (operator machine, an external
pod manager, or CI) and the on-pod `lm-provision` binary: what gets
uploaded, how the
binary is invoked, and how the report is collected. The protocol is
defined at the command + stdio level so it is transport-agnostic
(SSH, provider exec API, `docker exec` all satisfy it).

## Inputs

### The provisioner binary artifact

- A single statically linked executable, target
  `x86_64-unknown-linux-musl` (additional targets are additive).
- Embeds the Lua runtime (vendored Lua 5.4 via mlua) and every
  `lm.*` module (`include_str!`, chapter 05 L1) — the pod needs zero
  preinstalled dependencies for the binary itself to run.
- Build shape (crate contract): one Cargo workspace; one host crate
  producing `[[bin]] name = "lm-provision"`; the `lua/lm/*.lua`
  sources are compile-time inputs of that crate. Adding an `lm.*`
  module is a recompile, not a deploy-time file.
- External tools invoked *by profiles* (`apt-get`, `git`, `pip`,
  `curl`, `b2`, `huggingface-cli`, ...) are pod-image prerequisites
  of the specific profile, not of the binary. A missing tool fails
  the corresponding step at apply time with the exec error in the
  report.

### Driver steps

```
1. upload   — place the binary and the profile file on the pod
              (any byte-transport; paths are the driver's choice)
2. invoke   — run:  <bin> apply <profile-path> [--dry-run]
              with every consumed env_secrets name exported into the
              process environment (chapter 06)
3. collect  — capture stdout (the apply report JSON), stderr (the
              audit/progress transcript), and the exit code
```

- The driver may run `validate` / `hash` / `plan` remotely or
  locally first — the binary is the same and the artifacts are
  identical (chapter 07); `hash` before and after upload doubles as
  a profile-integrity check.
- Secret delivery is env-only: the driver injects secrets into the
  invocation environment (provider secret store, SSH `env`,
  exec-API env field). Secrets never appear in the command line, in
  the profile file, or on stdout/stderr (chapter 09 redaction).

## Outputs

- stdout: exactly one JSON apply report (chapter 09), emitted on
  success **and** on step failure.
- stderr: human-readable transcript (tracing lines, audit-redacted).
- exit code: chapter 07 mapping (0 = report `ok = true`; 1 =
  failure of any class; 2 = usage).
- The driver derives `(pod_id, profile_hash, report)` — `pod_id`
  from its own provisioning context, `profile_hash` via the `hash`
  subcommand — and appends it to the ledger (chapter 09).

## Error surface

- Transport failures (upload incomplete, exec channel dropped,
  stdout truncated): driver-side; retryable; the pod may hold a
  partially provisioned state — re-invoking apply re-runs from the
  first step (chapter 07 runtime class).
- Invoke-time precondition failures (missing secret env, validate
  reject): exit 1 with a stderr line and (for apply) no effects run
  on the pod.
- Pod-side apply failures: exit 1 **with** the structured report on
  stdout — the driver must treat "exit 1 + parseable report" as a
  richer signal than the exit code alone (the failing step, its
  stderr, and every completed step are in the report).
- Collect-time parse failure (stdout not valid JSON): driver-side
  error class of its own — it indicates transport corruption or a
  host crash, never a normal apply failure (the binary's stdout
  contract is unconditional, chapter 07).

## Stability

- The three-step protocol shape and the stdio/exit-code contract:
  **stable once frozen** — frozen here.
- Provisioning boundary: pod lifecycle (create / start / stop /
  delete) stays with the external pod manager; only provisioning is
  owned by `lm-provision`. The pod-provider API client is **not**
  pulled into this repo. **Stable.**
- Static-binary embeddability constraint (musl, vendored Lua,
  embedded modules, no runtime file dependencies): **stable**.
- Binary target set (musl x86_64 as the baseline): **provisional**
  (additive).
- Driver implementation home (standalone CLI wrapper vs an external
  pod manager calling the protocol directly): **internal** — the
  protocol, not the caller, is the contract.

## Upstream references

- chapter 00 §On-pod agent model — binary, provisioning boundary,
  static provisioner, ledger.
- chapter 04 bridge — embeddability constraint on every primitive.
- chapter 06 secret handling — env-only secret delivery, fail-fast.
- chapter 07 CLI — invocation surface, stream split, exit codes.

## MVP scope

Ships in Phase G: upload / invoke / collect against the Phase F
binary, ledger append (chapter 09), and the call path that lets an
external pod manager delegate provisioning to this protocol.

The binary half of this contract ships in Phase F (subcommands,
report-on-stdout, exit codes, env-secret injection);
Phase G adds the driver half without modifying the binary contract.
