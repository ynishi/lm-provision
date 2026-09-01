# 05. Sandbox layer contract

Status: specified. Layer 3.
Upstream deps: 04. MVP: Phase F.

## Purpose

The four-layer sandbox that gates every profile execution. Contract for
what each layer enforces and what a consumer (profile author, security
reviewer, host maintainer) can rely on. Layers compose: an operation
must pass every applicable layer; passing one never bypasses another.

## Inputs

The layers are configured from exactly two sources: the frontend set
compiled into the binary (L1) and the profile's declared lists
(L3 + L4). There is no host-side configuration file and no ambient
default-allow.

## Outputs

### L1 — data-only ingestion

- A profile is parsed into a `ProfileNode` AST (chapter 01) from JSON
  or canonical text. **Neither frontend can express behaviour**: the
  result of parsing is a value, not a program. There is no host-side
  eval, no interpreter, and therefore no chunk-loading, bytecode, or
  module-resolution surface to restrict.
- `.lua` paths are rejected before any I/O
  (`Lua profiles are no longer supported`, chapter 07 §Profile input
  format), so the removed authoring frontend cannot be reached by a
  filename.
- Effects reachable from a profile are exactly the primitives of
  chapter 04, selected by *which phase kinds the profile declares* —
  not by what code it runs.

> **Predecessor.** L1 previously specified an mlua stdlib nil-out
> (`os`, `io`, `package`, `debug`, `load*`, ...), a custom `require`
> restricted to embedded `lm.*` modules, and a bytecode prohibition.
> Those mechanisms existed to keep author-supplied *code* from reaching
> the host. With the embedded VM removed there is no author-supplied
> code, so the guarantee is structural rather than enforced. The
> attack surface they closed is closed by absence.

### L2 — execution model

- One execution context per subcommand run, built from the profile
  root (chapter 04 §Execution context build order) and discarded when
  the run ends. Nothing persists between runs.
- Execution is a step loop over the AST inside the host process; there
  is no separate VM, no cross-thread value exchange, and no live
  reference a profile could retain.
- The loop is bounded by a step ceiling so a pathological AST cannot
  spin indefinitely. Per-effect timeouts belong to the individual
  primitives (chapter 04); a host-level wall-clock run timeout and
  cooperative cancellation remain out of the current contract
  (see Stability).

> **Predecessor.** L2 previously specified a dedicated VM thread owned
> by an isolation driver exchanging strings only, with the driver drop
> tearing the VM down. Statelessness and the absence of shared live
> references survive; the thread-isolation mechanism does not, because
> there is no second language runtime to isolate.

### L3 — policy layer (declaration-derived allowlists)

Three policies are built from the profile's declared lists before any
op is reachable, and consulted in **both** dry-run and real mode
(chapter 04 §Common conventions):

- **Secret env policy** (`env_secrets`): an `EnvSecret` value node is
  resolved from the host environment only when its name appears in
  `env_secrets`; an undeclared name is rejected, and a declared name
  absent from the host environment is a fail-fast error. This is the
  only path by which the host environment is read (chapter 06).
- **HTTP policy** (`http_allowlist`): a URL is allowed iff it matches
  one of the declared patterns. A pattern is a literal URL prefix,
  optionally with a single `*` wildcard whose match is confined to
  the authority component (e.g. `https://*.b2.backblazeb2.com`); the
  wildcard never matches into the path. The **authority** halves of
  pattern and URL compare **case-insensitively** and with a trailing
  `.` ignored on either side (RFC 3986 §3.1 for the scheme, RFC 1035
  §2.3.3 / §3.1 for DNS names — the two spellings name the same
  authority). A `*.X` pattern additionally matches the apex `X` — the
  operator expectation for "X and everything under it"; the same
  authority rules govern `sh_egress` host patterns, and one shared
  matcher answers to both so a declared host string means the same
  thing wherever it lives.
- **Path policy** (`paths`): a path is accepted iff it is absolute,
  contains no `..` segment, and lies under a declared root with
  component-aligned prefix matching (`/workspace_x` is NOT under
  `/workspace`). This is a lexical policy: it does not chase symlinks.
  Deployment targets are fresh single-tenant pods where the profile
  itself creates the tree; symlink-racing an already-compromised host
  is out of threat model. An `openat2` / `RESOLVE_BENEATH`-based
  upgrade slot remains available if the threat model changes.

An empty declared list denies everything in its domain: a profile that
declares no `paths` cannot write any path **through the bridge write
ops below**, and one that declares no `http_allowlist` cannot reach any
URL.

The path policy's reach is **every write that reaches a bridge**, and
it does not depend on how the profile spelled the write.

It is consulted by the direct bridge ops that carry a path as a
declared field — `fs.write`, `net.transfer`, `mount.bind` (`src` and
`dst`), `mount.umount` (chapter 04) — and equally by the transfer
sub-steps a lifecycle phase composes: a `sync.pull` writing outside
`paths` is denied exactly as the `net.transfer` spelling of it would
be. The targets are read off the resolved steps, so neither the field
name nor the phase kind changes the answer. Each checks at op entry,
dry-run and real alike.

The same targets are what validate asserts `paths` covers **before**
apply (chapter 00 §Capability derivation): the walk runs over the
expanded plan, so a `models` destination under the resolved
`comfyui_root` (chapter 02 §Resource-derived paths) — a path the author
never spells out — has to be declared like any other. What used to be
an unstated exemption for built-in constants is now a stated
requirement, and it surfaces as a precondition error rather than as a
denial on the pod. Declaring a different `install_dir` moves the
destination, and therefore moves what `paths` has to cover.

`sh.exec` puts writes structurally out of reach: a subprocess — `git
clone`, a CLI downloader, `pip install` — writes wherever the pod's
filesystem permissions allow, and none of that traffic passes an op
handler. So under `sh.exec` the `paths` list is a declaration plus a
lint over the bridge ops, not a sandbox over the profile's effects: it
states where a profile intends to write and rejects bridge calls that
contradict that statement. Reading it as a containment boundary is
wrong in the same way, and for the same reason, as expecting the
lexical policy above to survive a symlink — the enforcement point is
the op, not the kernel. A containment boundary would have to be imposed
outside the profile (container / mount namespace / seccomp), which is a
deployment concern rather than a spec-05 one.

#### `sh_egress` — the subprocess egress pin

`sh_egress` is the one place spec-05 does reach a subprocess's effect,
and only its **network egress**, not its filesystem. It is an opt-in
host allowlist: a profile that declares `sh_egress` has every `sh.exec`
subprocess routed through an egress proxy, and a destination host absent
from the list is refused. The declaration is **host-independent** (it
names hosts, e.g. `huggingface.co` or `*.hf.co`, with the same single
`*.` authority wildcard the `http_allowlist` patterns carry); how the
route is supplied and enforced is not.

- **Absent or empty means no pin.** Unlike `paths` / `http_allowlist`,
  whose empty state denies all, an empty `sh_egress` leaves subprocesses
  unrouted — the pin is opt-in, so a profile written before it existed is
  unchanged in behaviour and in hash. An empty declared list is therefore
  indistinguishable from an absent one, and both mean "do not pin". A
  profile that wants "allow nothing" declares a host it will never reach,
  or declares no `sh.exec` capability at all (validate rejects a
  `sh_egress` declared without `sh.exec`, since the pin would then route
  nothing).
- **Supply is a deployment concern**, the same side of the line the
  containment boundary above sits on. The host either self-hosts an
  in-process proxy on loopback (the default) or points at an external
  egress gateway; the profile does not choose, and does not carry the
  proxy's address.
- **Enforcement is two layers, both best-effort, neither a containment
  claim.** A *soft* layer routes every subprocess that honours the proxy
  environment (`HTTPS_PROXY` / `HTTP_PROXY`) and checks each CONNECT host
  — and the TLS ClientHello's SNI, to refuse a fronted name — against the
  allowlist, tunnelling opaquely without decoding TLS. The SNI refusal
  reads the **plaintext outer `server_name` only**: it does not see a
  name hidden by Encrypted ClientHello, nor a `Host` / `:authority`
  header fronted inside the established tunnel (inspect-once, not
  per-request), and it says so — the endpoint pinning below is the
  backstop for both. A *hard* layer (Linux, self-hosted proxy only)
  additionally pins each subprocess's address-carrying network syscalls
  — `connect(2)`, `sendto(2)`, `sendmsg(2)`, `sendmmsg(2)` — at the
  syscall via a seccomp supervisor, and denies `io_uring` outright (a
  ring would submit connects the filter cannot see), so a subprocess
  that ignores the proxy environment still cannot reach off-host. The
  allowed destinations are exactly **the proxy's own endpoint and the
  host's configured DNS resolvers on port 53** (read once from
  `/etc/resolv.conf`), not any loopback service — everything else is
  refused. Unix-domain sockets are outside this pin (local IPC is not
  network egress). Which layer takes effect is decided by the host at
  run time; the profile states intent, never mechanism.

What it does **not** do, stated as plainly as the `paths` limits above:
it does not gate the filesystem (that is `paths`, and under `sh.exec`
still only a lint over bridge ops); it does not close a supply-chain
hijack from a *permitted* host (a poisoned package from an allowed
registry arrives over an allowed connection — that is a hash-pin problem,
not an egress one); and the hard layer admits the host's configured DNS
resolvers on port 53 so a subprocess that resolves before proxying keeps
working, which leaves DNS tunnelling *through those resolvers* as a
narrower residual channel than open egress. (Port 53 to an address that
is not a configured resolver is refused: a port number is not evidence
of a protocol.) The pin closes the **exfiltration** half of the
`sh.exec` gap — a credential or a work product leaving for an undeclared
host — and says nothing more.

A note on ports, since the same host string configures both L3 host
allowlists: the `sh_egress` CONNECT pin matches the **host** and admits
any port on a declared host, while `http_allowlist` matches the full
authority **including the port** (`https://example.com` does not cover
`https://example.com:8443`). The HTTP side is not widened to match —
that would loosen a security allowlist — so a non-default HTTP port is
declared explicitly.

The `env` declared table (the non-secret declarations) carries two
separable roles, and only one of them is a policy role.

Its **key set** gates nothing. The host-env read surface it used to
gate (`env.get`) no longer exists: a non-secret env value is written
into the profile as an `EnvLiteral` and never read from the host, so
there is no read for an allowlist to constrain. What remains on the
keys is a validate-stage shape rule — every key shell-safe, and no
secret-shaped key bound to a literal value (chapter 03 §validate) —
plus the declaration itself. Re-binding the key set to a *gating* role,
the way `paths` and `http_allowlist` constrain their ops at execution
time, is a design opening, not a silent gap (see Stability).

Its **values** do have an execution-time role: the exec layer builds
its env policy over `Spec.env` and resolves a phase's `EnvRef` by
looking the referenced name up in this table at consumption time
(chapter 01 §Profile-scoped env table). That is a resolution source,
not an allowlist — it decides what a reference *is*, never what a step
is *permitted to reach*.

The secret-shaped-key rejection is scoped to **literal-valued** keys.
`HF_TOKEN: EnvSecret(name: "HF_TOKEN")` is accepted: a secret-shaped
name bound to an `EnvSecret` is the shape the rule wants authors to
reach for, and it is checked on the other axis instead — the referenced
name must appear in `env_secrets` (chapter 06). What the rule rejects
is `HF_TOKEN: EnvLiteral(value: "hf_…")`, the shape a secret pasted as
a plain string takes.

### L4 — capability gate (operation-level)

- `KNOWN_CAPABILITIES` (frozen, chapter 02): `env.ref`, `sh.exec`,
  `net.transfer`, `net.http_get`, `net.http_post`, `fs.write`,
  `mount.bind`, `mount.umount`, `mount.volume_attach` (reserved).
- Granularity is the operation, not the namespace: declaring
  `net.transfer` does not grant `net.http_get`.
- Enforcement is a per-op **entry check**: every op handler validates
  the gate before touching its payload's targets, in dry-run and real
  alike. Lifecycle phases are gated by the capability of the effect
  they expand into (e.g. every `sh.exec`-composing lifecycle op
  requires `sh.exec`; `sync.pull` / `staging.push` / `models` require
  `net.transfer`; the two HTTP polls `comfyui.health` /
  `service.ready` expand into a GET and so require `net.http_get`,
  not `sh.exec` — the pid file they re-read between attempts is a
  provisioner-internal read, not a bridge op, chapter 02
  §Poll deadlines).
- Declared-but-unknown capability → fail-fast at context-build time
  (`capability '<x>' declared but not implemented by host`), before
  any op runs. No silent skip.
- `capabilities = []` is valid and means a pure-computation profile
  (validate / hash / plan work; apply can execute nothing).
- L3 and L4 stack: L4 grants the operation, L3 still constrains its
  arguments (a granted `fs.write` still cannot write outside `paths`).

> **Predecessor.** L4 previously specified a two-strategy model:
> register skip (bridges for undeclared operations were never
> installed, so the call site hit nil) plus the entry check as defence
> in depth. Register skip was a property of a *namespace exposed to
> author code*; with no such namespace, the registry installs every op
> and the entry check is the single enforcement point. The
> "declared ⊆ used" guarantee is unchanged — what changed is that a
> denial is now a named error instead of a nil-call.

## Error surface

- L1: a `.lua` path → load rejection; malformed JSON / text → parse
  error (both precondition class, before any effect).
- L2: an engine-internal failure aborts the subcommand; the context is
  discarded and no partial state survives the process.
- L3: policy rejection → an error naming the offending secret name /
  URL / path and the declared list that excludes it, recorded on the
  step's report entry (precondition class, fires under dry-run too).
- L4: gate-check error naming the missing capability; context-build
  fail-fast for unknown declared capabilities.

All sandbox errors leave the target system untouched except for
effects already performed by **earlier** steps of the same apply
(fail-fast model, chapter 09).

## Stability

- Layer count and the responsibility split (ingestion / execution
  model / policy / capability): **stable**.
- L1 as data-only ingestion, and the rejection of `.lua` paths:
  **stable**.
- L2 statelessness (one context per run, nothing persisted):
  **stable**. Host-level per-run wall-clock timeout and cooperative
  cancellation: **provisional** (not part of the current contract).
- L3 semantics as specified (secret-env gating, single-`*` authority
  wildcard, lexical path policy, empty-list-denies-all): **stable**.
  The symlink-aware path-policy upgrade: **provisional**. An
  execution-time **gating** role for the `env` declared table's key
  set: **provisional** (the table's values already carry a resolution
  role — `EnvRef` lookup — which is stable). Which ops consult the
  policies is now **stable and uniform**: every step that reaches a
  bridge answers to them, whether the profile spelled it as a direct
  op or a lifecycle phase composed it. A `sync.pull` writing outside
  `paths`, or a `comfyui.health` polling a host outside
  `http_allowlist`, is denied exactly as the `net.transfer` /
  `net.http_get` spelling of the same effect would be — the targets
  are read off the expanded steps, so the check does not depend on how
  the phase was written. That subprocess *writes* under `sh.exec` are
  outside the policy is structural rather than provisional: closing it
  is a deployment-side concern, not a layer change.
- The `sh_egress` subprocess egress pin (§`sh_egress`): its **contract**
  — opt-in host allowlist, absent/empty means no pin, supply is a
  deployment concern, enforcement is best-effort and not a containment
  claim, exfiltration-only — is **stable**. Its **enforcement
  mechanisms** are **provisional**: the soft (proxy env + host/SNI
  allowlist) and hard (Linux seccomp `connect` pin) layers are what the
  current host implements, and a host may add or drop a mechanism (an OS
  netns route where one is available, a tighter loopback-only DNS policy)
  without changing what a profile declares. The allowset of the hard
  layer (the proxy endpoint + configured DNS resolvers) and the set of
  syscalls it traps (`connect` / `sendto` / `sendmsg` / `sendmmsg`, plus
  the `io_uring` denial) are provisional for the same reason.
- L4 entry-check enforcement and the frozen `KNOWN_CAPABILITIES` set:
  **stable**. `mount.volume_attach` reserved key: **provisional**.

## Upstream references

- chapter 00 §Sandbox layers — layer definitions.
- chapter 01 profile DSL surface — the declared lists that configure
  L3 and L4.
- chapter 02 phase catalog — `KNOWN_CAPABILITIES` and shared
  vocabulary.
- chapter 04 bridge — context build order; result-vs-error convention.
- chapter 06 secret handling — the secret-env policy in detail.

## MVP scope

Ships in Phase F: all four layers wired as specified for the on-pod
binary, with negative fixtures for undeclared capabilities,
out-of-root paths, undeclared URLs, undeclared secret names, and
secret-shaped `env` keys.
