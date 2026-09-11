# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`lm-provision-cli`: one command an operator installs.** The
  binary is `lm-provision`, and everything an operator does is a
  subcommand of it: `apply` and `check` act on a pod, the new
  `machine` group is the fleet, and `mcp` serves the MCP tools over
  stdio. Two binaries and a server to install and keep in step was a
  deployment story nobody asked for; one is the shape every tool of
  this kind has.

- **`lm-provision machine list --provider <name>`** (repeatable) says
  what a platform is running and changes nothing. One JSON document on
  stdout, one row per machine: its id, what it is called, the platform,
  the `expires_at` read off the machine's own name, and whether it
  carried a lease stamp at all — so a machine this tool never named is
  reported rather than invisible, and never released on that evidence.
  A platform that could not be asked lands in `failed` and costs the
  zero exit, because a listing that read as an empty account is the one
  way this could do harm. Listing needs the platform's credential: the
  key buys the question.

- **MCP tool `lm_machine_list(provider)`** — the same document, from
  the same function, over MCP (10 §Tool set; backing surface 08
  §Acquisitions and sweep, the listing half).

### Changed

- **The machine subcommands moved under `machine`.** `acquire` /
  `release` / `sweep` are now `lm-provision machine acquire` /
  `machine release` / `machine sweep`, beside the new `machine list`.
  Their flags are unchanged, including the `--dry-run true` defaults on
  the two that spend or destroy. These four are the only subcommands
  that talk to a platform about a machine, and typing one's way into a
  group is the cheapest boundary there is between "provision this pod"
  and "delete these machines".

- **The pod-side binary is `lm-provisioner`.** The package
  (`lm-provision`) has described itself as a "static on-pod
  provisioner" all along, and the binary now carries that name — so the
  command an operator types and the program that runs as root on a pod
  are no longer the same word on one `PATH`. The release archive is
  unchanged (`dist` names it after the package): still
  `lm-provision-x86_64-unknown-linux-musl.tar.xz`, with
  `lm-provisioner` inside it.

  **Older releases still work.** Every archive up to v0.9.0 holds the
  entry under the old name, so the resolver accepts either — and writes
  what it finds into the cache as `lm-provisioner` regardless, leaving
  one name for everything downstream. The visible cost is one re-fetch:
  a cache entry from before this version sits under the old file name
  and is a miss, so the next `apply` downloads and verifies the archive
  once more. The cache directory layout is unchanged.

  **Install in this order when upgrading**: `lm-provision` first, then
  `lm-provision-cli`. Until 0.9.0 the `lm-provision` package owned the
  `lm-provision` binary *name*; now `lm-provision-cli` does. Installing
  the CLI first is refused because the name is taken, and forcing past
  that only defers the problem — upgrading `lm-provision` afterwards
  removes the binaries it has stopped producing, and that list now
  includes `lm-provision`, so it deletes the CLI. Upgrading
  `lm-provision` first frees the name by the same mechanism, and the
  CLI installs onto it cleanly. (Recovering from the wrong order is one
  `cargo install lm-provision-cli`; nothing else is damaged.)

  **`--skip-install` against a pod last provisioned by ≤0.9.0 fails at
  step 2.** That pod holds `<remote-dir>/lm-provision`, and the session
  derives the remote path from the binary's name, so step 2 invokes
  `<remote-dir>/lm-provisioner hash` — a file that is not there. It
  surfaces as "remote hash invocation failed", which is exactly what
  that error is for: the gated-off step's postcondition is not met (08
  §Error surface). One `apply` without `--skip-install` pushes the
  provisioner under the new name and the gate closes again. The old
  file stays where it is at `<remote-dir>/lm-provision`; nothing
  deletes it for you.

- **`lm-provision-host` spawns `lm-provision machine sweep`.** The
  `--driver` default is now `lm-provision`. A host upgraded without its
  CLI reports the tick as failed — "could not run" — rather than
  silently enforcing nothing.

  **A host upgraded before the CLI is reinstalled reports exit 2 every
  tick.** If the old `lm-provision` binary is still on `PATH` — the
  pre-rename provisioner, which has no `machine` subcommand — the
  daemon spawns it successfully and it exits 2 on `machine sweep`
  (clap's usage-error class). The health endpoint says `ok: false` with
  "`lm-provision machine sweep` exited with exit status: 2" until the
  CLI is installed, and no machine is released in the meantime.

### Deprecated

### Removed

- **The `lm-provision-driver` and `lm-provision-mcp` binaries.** Both
  crates remain, as libraries, under the same names and with the same
  public API; what they no longer ship is a `[[bin]]`. `lm-provision
  apply` / `machine …` is the first one's surface, `lm-provision mcp`
  the second's.

### Fixed

### Security

## [0.9.0] - 2026-09-08

### Changed

- **The provisioner pushed to a pod now comes from CI, not from your
  machine.** `apply` required `--artifact <path>`, which put a `cargo
  build --target x86_64-unknown-linux-musl` in front of every
  provision and made what runs as root on a pod a property of whoever
  ran the driver: some working tree, some toolchain, some day, under a
  version number nothing recorded. The release workflow has been
  building that target on every tag all along
  (`dist-workspace.toml` §targets) and publishing the archive beside a
  `.sha256`; nothing consumed it. Now `apply` resolves a *version* —
  by default the driver's own — to that release asset, downloads it
  once, verifies the published digest before unpacking, and caches the
  binary under `$XDG_CACHE_HOME/lm-provision/provisioner/<version>/`.
  A cache hit needs no network. Provisioning a pod needs neither a
  musl toolchain nor a checkout.

  `--provisioner-version <ver>` pins another release.
  `--provisioner-path <file>` pushes a local build instead — the
  override for developing the provisioner itself, unverified because
  naming the file is the authorization. This is the `fetch-release`
  ensure-binary strategy spec 08 §Session steps had reserved and
  deferred "distribution surface not published yet"; the surface is
  published, so it is the default and `push-local-artifact` is the
  override.

- **The MCP server stopped requiring a binary of its own.**
  `LM_PROVISION_BINARY` was mandatory: a server started without it
  refused to start, so every deployment of `lm-provision-mcp` carried
  the same local-build dependence `apply` just shed. It is now
  optional and takes two forms — an **`https://` archive URL**,
  verified against the `.sha256` published beside it and cached (a
  fork's release, a mirror inside a network that cannot reach
  github.com, an asset uploaded by hand), or a **local path**, used as
  given. Unset resolves the release the server's own version was built
  alongside. The reasoning that made it mandatory — "guessing at one
  would silently point the driver at the wrong artifact" — was right
  about guessing, and the release built by CI from this source, with
  its digest checked before anything is pushed, is not a guess. A
  scheme that is neither is refused rather than read as a filename, so
  a mistyped `http://` says so instead of reporting a missing file.

- **Named the pod-side binary.** It is **the provisioner** — the word
  this workspace was already using for it (`crates/lm-provision`'s own
  package description, spec 08 §Inputs "The provisioner binary
  artifact") and the word Packer uses for the thing that installs and
  configures a machine. Not an *agent*: `agentless` is the industry's
  term for installing nothing on the managed node, so calling a
  one-shot binary an agent makes a reader's first question — is it
  still running, does it need stopping — the wrong one. *Artifact* was
  free to keep its existing meaning here: what a profile declares and
  an apply pulls back off the pod (`--artifacts-dir`). Accordingly
  `--artifact` is now spelled `--provisioner-path`, after the
  convention every tool that names its remote-side counterpart follows
  (`--rsync-path`, borg's `--remote-path`, git's `--upload-pack`).
  **The old spellings `--artifact` and `--artifact-version` keep
  working** as aliases: they shipped in 0.8.0.

## [0.8.0] - 2026-09-01

### Changed

- **The lease now rides on the machine, and the platform's own list is
  what a sweep works from.** Enforcement used to depend on a file: if
  `~/.lm-provision/acquisitions.jsonl` was lost, or the machine was
  bought on one host and swept from another, the row was gone and the
  machine billed forever with nothing looking for it. Every reaper that
  has run at scale inverts that — Netflix's Janitor Monkey, `aws-nuke`,
  `cloud-nuke`, the AWS Instance Scheduler, the Kubernetes TTL
  controllers all enumerate from the provider's API and read the policy
  off the resource's own tag. So does this now. `acquire` writes the
  expiry into the field each platform gives an operator for naming a
  resource — a pod's `name`, an instance's `--label` — as
  `lmp-exp-20260902T063000Z` (colon-free: those fields are constrained
  differently everywhere, and a colon is the likeliest character to be
  refused). `sweep --provider runpod --provider vast` then lists the
  account, reads the stamp off each machine, and releases the expired
  ones through the same release gate as before. Nothing has to be kept
  in step with anything: a sweeper holding the account's key is
  sufficient.

  A machine carrying **no** stamp is reported under a new `unknown`
  field in the sweep artifact and never released on the listing's
  evidence — this tool did not name it, and deleting what it does not
  recognise is the accident, not the enforcement. (The record half may
  still release such a machine when a recorded lease names its id;
  that is how a pre-stamp machine expires, and it then appears as both
  `unknown` and `released`.) A platform that could not be listed lands
  in `failed` under its own name and costs the sweep its zero exit,
  since that account may be billing for anything — and so does a
  listing whose shape could not be read as a fleet: absence from a
  listing retires recorded rows, so a shape change that silently read
  as an empty account would retire the whole record while everything
  on it kept billing. Idempotency is by convergence rather than by
  reading the platform CLI's error text: a machine already gone is
  simply absent from the next listing, so nothing here depends on the
  spelling of somebody else's "not found".

  **The acquisitions record is demoted to the audit trail** — who
  bought what, when, for which profile, and how it was given back. It
  is still written exactly as before, still read by a sweep run with no
  `--provider` (which is what reaches machines created before the stamp
  existed), and an outstanding row whose machine is absent from its
  platform's list now gets a correction appended: the bill has ended
  and the file should say so. What it no longer is, is the thing
  correctness depends on. The daemon takes the same `--provider` flag
  (specs 08 §Acquisitions and sweep, 09 §Acquisitions record).

### Added

- **A daemon that sweeps without being asked
  (`lm-provision-host`).** `sweep` gives back every machine whose lease
  has run out, but only when somebody runs it — which is the
  forgotten-machine problem one level up, since the host has nothing
  that keeps running between driver invocations. The AGPL control-plane
  crate is now that something: every `--interval-secs` (default 300,
  against hour-grained leases) it runs `lm-provision-driver sweep`,
  relays what the driver said with the driver's name in front of it,
  and logs what came back. **It runs the driver as a child process
  rather than linking it** — the CLI is the contract the specs
  normalise, and exec leaves the AGPL crate depending on nothing
  permissive at all, which is the cleanest the license boundary can be.
  One sweep runs at startup, because an operator restarting the daemon
  after a week with the laptop closed wants enforcement now. A tick
  that fails — driver missing, non-zero exit, stdout that is not the
  artifact — is recorded with its reason and the daemon waits for the
  next one; a TTL enforcer that dies on the first bad tick protects
  nothing for the rest of the week.

  **`--dry-run` defaults to `false` here, the opposite of the CLI's
  default, on purpose.** On the CLI, an operator asking which machines
  would be released must not find out by them being gone; installing a
  long-lived TTL-enforcement service is the opposite act — it is the
  consent to release expired machines, and a daemon that defaulted to
  observing would be the forgotten-machine problem wearing a uniform.
  `--dry-run true` is the observation mode, and the release gate inside
  sweep refuses uncollected work either way.

  One endpoint comes with it, on `--bind` (default `127.0.0.1:7909`):
  any request gets one JSON document — whether the last sweep worked,
  when it ran, how many have run, and the sweep's own artifact
  verbatim, kept even on a failed tick when the sweep still wrote one:
  an exit-1 sweep's `failed` field names the machines still billing,
  which is exactly what the reader of `ok: false` needs next. Hand-rolled HTTP/1.1 over a raw socket, since a web
  framework would buy nothing over thirty lines for one consumer asking
  one question (spec 08 §Acquisitions and sweep).

- **A machine you acquired is now written down, and `sweep` gives back
  the ones whose lease ran out.** `acquire` created a billable machine
  and left its id in one place — the run's stdout. Close the terminal
  and the machine kept running with nothing on the host that knew it
  was there. Every real acquire now appends a row to
  `~/.lm-provision/acquisitions.jsonl` (`--acquisitions` to move it):
  the id, the platform, the profile hash, the release argv verbatim,
  and a lease — `--ttl-hours`, default 24, with no opt-out, because an
  unleased machine is one nothing ever comes back for. A release
  appends a correction row naming the same id; rows are never
  rewritten, so "what is still running" is an id-join over the file
  rather than a flag somebody has to keep current. `sweep` reads it,
  takes the expired machines, and puts each one through the same
  release gate `release` applies before deleting it — no `--force`
  here, since a scheduled sweep is the least informed thing in the
  system about whether the work still on a machine may go with it.
  `--dry-run` defaults to true, as `acquire`'s does. A gate refusal is
  not a sweep failure; a machine that expired and could not be
  released is, because it is still billing — and a ledger the gate
  could not read fails the machine rather than refusing it, since a
  corrupt ledger read as a refusal would hold every expired machine
  behind a zero exit forever. The row schema lives in
  `lm-provision-protocol` beside the ledger's — the control plane will
  read the same file (specs 08 §Acquisitions and sweep, 09
  §Acquisitions record).

- **The license boundary, cut before the code that needs it.** The
  coming control plane (a daemon that outlives a driver run: TTL
  enforcement, ledger custody) is AGPL-3.0-or-later, and the engine is
  MIT / Apache-2.0 and stays that way. Relicensing is a decision one
  can only make alone before outside contributions arrive, so the split
  is in place while both new crates are still empty or unchanged:
  `lm-provision-host` (AGPL-3.0-or-later, `publish = false`, an empty
  scaffold whose one test asserts no permissive manifest names it), and
  `lm-provision-protocol` (MIT / Apache-2.0), the neutral crate holding
  what both sides read and write. The `ledger` module moved there
  verbatim; `lm-provision-driver` re-exports it, so every
  `lm_provision_driver::ledger::*` path still resolves and no caller
  changes.

  **Release order: `lm-provision-protocol` publishes to crates.io
  before `lm-provision-driver`.** The driver now depends on it by
  version, and a version that is not on the registry yet does not
  resolve.

## [0.7.0] - 2026-08-30

### Added

- **A second platform: the vast.ai marketplace (`--provider vast`).**
  The hardware there is already listed as offers, so selection happens
  before create: the acquisition now carries an optional *discovery* —
  a `search offers` query built from the profile's requirements in the
  marketplace's own filter words (`num_gpus>=`, `gpu_ram>=`,
  `disk_space>=`), pinned to verified hosts, sorted by ascending
  price — and the first row is the machine. The query is the whole
  selection policy, and a dry-run prints it. No catalogue: the
  marketplace answers memory in the device's own figures, and the
  filter takes the floor in the profile's own unit. Raw TCP only (no
  managed HTTPS proxy), one disk (a persistent level is refused, not
  mapped), and authentication stays with the service's own CLI — it
  holds its key in the file `vastai set api-key` writes, so the driver
  requires no variable and a missing key is that CLI's own error.
  `acquire` / `release` / `check` all take `--provider` (default
  `runpod`; where to buy is the operator's call at acquisition time,
  not the profile's).
- **The image's registry is asked before a machine exists to pull it
  and fail.** A marketplace host accepts a create naming a manifest
  that is not there, then retries `manifest unknown` forever — on
  billing (found live: the create succeeded and the host logged the
  missing manifest once a minute). `acquire` now asks the registry's
  own manifest endpoint first, through `curl` with the spec's
  anonymous-pull token dance; a definitive "not there" refuses at
  exit 3 while the bill is still zero, and anything unanswerable
  (private auth, no network) is noted and stepped past rather than
  refused over.

- **cargo-dist release pipeline.** Pushing a version tag now builds
  all three binaries for six targets — including
  `x86_64-unknown-linux-musl`, the pod-side artifact `driver apply`
  pushes (spec 08's static-binary baseline) — and uploads archives,
  checksums, and shell/powershell installers to the GitHub Release.
  Configuration lives in `dist-workspace.toml`; the workflow is
  `dist generate`d, not hand-written. Homebrew / APT / Docker targets
  are deliberately not configured: each needs operator-side
  infrastructure (a tap repository, signing keys, registry
  credentials) that is a separate decision.

### Changed

- **GPU selection sorts by price, not by memory.** The catalogue now
  carries each model's published secure-cloud on-demand rate, and
  `acquire` asks for the cheapest device that clears the profile's
  VRAM floor (the rest remain fallbacks, as before). Memory was the
  old proxy for price and it lied: at a 24 GB floor it led with the
  RTX 4090 (74¢/hr) when the RTX A5000 (27¢/hr) also cleared it —
  2.7× the price for the same clearance.
- **`requires_image` is gone; the image is a `provider` key.**
  (Breaking, DSL surface.) An image name is one platform's vocabulary
  — the same workload is a docker tag on a pod service and no image at
  all on a bare-VM service — so a neutral slot for it was really the
  first platform's slot wearing a neutral name. Profiles write
  `provider."runpod.imageName"` instead, and `acquire` refuses without
  it as it always did (the refusal now names the provider key).
  Profiles that never declared an image keep their hash; the two
  shipped profiles that did are re-issued as `machine-verify-0.2.0`
  and `qwen-vllm-serve-0.2.0` with new pins in `index.json`.

## [0.6.0] - 2026-08-12

### Added

- **A profile can say what the machine must be.** Until now a profile
  described what to do to a machine that already existed and said
  nothing about the machine itself, so the one part nobody could write
  down was the part that had to be arranged by hand every time. Four
  slots now carry it — `requires_ports`, `requires_gpu`, `requires_disk`,
  `requires_image` — in the workload's own terms: how much memory the
  weights need, how many devices, which storage survives a restart, and
  whether a port has to be reachable over public HTTP or only as a raw
  socket. Omitting a slot is not asking for zero; a profile that does not
  care leaves it out and the target's own default applies.
- **Requirements are matched against a target that answers for itself.**
  A target says what it can provide (`Infra::capability`), what it can
  select on, and — separately — what it cannot decide. That third answer
  is the load-bearing one: a container runtime can pass a device count
  through but has no way to ask for a memory size, and neither "yes" nor
  "no" describes that. `admit` refuses before anything exists, `observe`
  settles the rest by looking at the machine that does, and each
  requirement produces a finding rather than being silently dropped.
- **`acquire` / `release` / `check` on the driver.** Acquisition is a
  subcommand of its own rather than a flag on `apply`, so obtaining a
  machine is always something asked for; `--dry-run` defaults to on and
  renders the request without sending it. `check` judges a machine that
  already exists against a profile, requirement by requirement, creating
  and destroying nothing.
- **Two adapters, deliberately.** A managed pod service is the one this
  provisions; a container runtime is here to keep the vocabulary honest,
  because a requirement language designed against a single platform
  records that platform's shape and calls it universal. The second is
  what proves the refusal path is real: it is the one that cannot provide
  public HTTP.
- **`provider`** — a namespaced slot for the values one target has and
  another has no word for (a pre-created network volume, a template).
  Keys reach the adapter that owns the namespace verbatim; keys for a
  target that is not this one are reported as unexamined rather than
  dropped.
- **The driver resolves its target's credential.** A tool that starts
  machines owns the means of starting them, and there was no resolution
  order at all — the environment still had to be arranged, by whoever
  happened to be running the driver. Adapters now declare the variables
  their target's tooling reads, by name, and the driver fills the
  environment from an ordered search: what the process already has, then
  `$LM_PROVISION_ENV_FILE`, `~/.config/lm-provision/.env`, `./.env`.
  First writer wins. A missing one is refused before anything spends,
  naming the variable and every place consulted — and distinguishing a
  file that is absent from one that was read and did not define it. No
  value is ever bound, formatted or logged.

### Changed

- **Device memory is read in the unit devices report it in.** A part sold
  as 48 GB answers 46068 MiB — 48.3 decimal GB, 45.0 GiB — because ECC
  reserves about 6.25% of a GDDR6 framebuffer and because MiB is not GB.
  Two quantities in two units were both called GB and compared to each
  other. Machine state now carries mebibytes; a profile keeps writing the
  vendor's decimal figure, because when a floor is read no machine exists
  and a published number is all there is to match against. The two meet
  once, in a conversion that reads the published label as decimal on
  purpose: that is the smaller of the two readings, so a selection can
  only under-estimate what a device carries.
- **`MachineState.gpu_vram_gb` is now `gpu_vram_mib`.** Breaking, and the
  point of the change above.
- **`Infra` gained `credentials()`.** Breaking for any implementor
  outside this crate.
- **The catalog's size is stated in three places, not eight.** A number a
  reader cannot act on was being hand-synchronised across doc comments
  and specs; a test now names the three that remain and fails when a kind
  is added.

### Fixed

- **A requirement the target could not meet used to reach the request
  anyway.** A memory floor above every catalogued device dropped the
  model selection and produced a body that looked well-formed — device
  count present, selection absent — and exited zero, so the machine would
  have been created without the thing that was asked for. The request is
  now built from the adapter's answers rather than alongside them, which
  closes the same hole on the storage axis before it had a case.
- **A profile that declared no ports asked for none.** An empty list is a
  claim that nothing should be exposed, and a profile that said nothing
  never made it.
- **What the service says once is no longer thrown away.** The managed
  pod service names the attached device model in its create response and
  then returns an empty `machine` object from every read-back afterwards.
  Inspect replaced the description wholesale, so the memory a profile
  asked for came back `NotChecked` on every real machine while the tests
  passed — their fixture had been written from a create response, a shape
  no read-back has. Inspect now fills only what the fresh description
  declines to say.
- **stdout carries exactly one machine-readable artifact again.**
  `release` ran the service CLI with inherited stdout, so a release
  printed the service's empty body and then its own JSON; `acquire`
  printed the new machine's identifier and then the verdict. What the
  service says now goes to stderr as `runpod-cli: <line>` — the GNU form,
  naming the program that spoke — and says nothing when it has nothing to
  say. The identifier still goes out the moment the machine exists,
  because one whose identifier was never printed is a bill nobody can
  stop; it goes to stderr, as the trace it is.

### Deprecated

### Removed

### Security

## [0.5.0] - 2026-08-11

### Added

- **A completion condition per lifecycle step, and one vocabulary for
  writing it.** Every kind used to answer "is this finished?" in its own
  shape, or not at all: six ad-hoc forms across payload fields and host
  Rust. There is now one `Assert` — an expression over predicates,
  folding to four answers (`Satisfied` / `Unsatisfied` / `NotChecked` /
  `CheckFailed`) rather than a boolean, because "I did not look" and
  "I looked and could not tell" are different things to a reader of a
  plan. Four entity types derive their own: `ModelFile` (present, and
  matching a declared digest), `Checkout` (a repository is there and
  holds the named ref), `Service` (the recorded process is alive and was
  launched with exactly these arguments), `Venv` (there is an
  interpreter in it).
- **A second apply converges instead of repeating.** A model file that
  is already there is not fetched again, a clone that exists is not
  attempted again, a server already running with these arguments is not
  relaunched, a venv that exists is not recreated. Each skip names the
  part of the condition that held, so the report says what was true
  rather than only that something was skipped.
- **`toolchain.python`** (23rd catalog kind). Creates the virtual
  environment ComfyUI runs in and installs a declared `requirements.txt`
  into it. Inherits the host interpreter's packages unless the profile
  sets `isolated` — a GPU pod's torch is built against its own driver,
  and a venv that cannot see it makes pip fetch a wheel whose CUDA does
  not match, which surfaces only as a launch that never becomes ready.
- **Resources: `produces` / `requires` / `assumes`.** A phase can only
  reach a path something created. `comfyui.install` produces
  `comfyui_root` (its `install_dir`, defaulting to `/workspace/ComfyUI`),
  `toolchain.python` produces `venv` under it, and the phases that
  consume them require them back. `Spec.assumes` is where a profile
  states that something is already present. Validate rejects a profile
  whose requirement nothing binds — by resource name, before any effect
  runs. The check is a scope check over the canonical phase order, not a
  dependency graph: nothing is reordered.
- **Every ComfyUI-relative path derives from one declared root.** The
  models root, the custom-nodes root, the entry point and the venv were
  six constants in host code that a profile could not see or point
  elsewhere; they are now derivations of `comfyui_root`, and moving it
  moves what `paths` must cover.
- **Independent transfers in one `models` phase run at the same time.**
  Independence is decided over the composed steps — transfers to
  distinct destinations may overlap and nothing else may — so a phase
  whose steps are not independent keeps its order.
- **Byte-level progress while a transfer is still running.** A
  `net.transfer.progress` event every fifteen seconds plus the first
  chunk and the last, carrying bytes / total / percent / elapsed. No
  rate and no estimate: an ETA asserts the next minutes look like the
  last, and nothing here has looked at the network to say so.
- **`sync.pull` converges too.** A second apply no longer re-downloads a
  file that is already there. Its condition is the same `ModelFile` a
  `models` entry without a declared digest carries — the kinds are
  spelled differently and that was never a reason for one to skip and
  the other to fetch the same bytes again.
  - All three of its routes, including the `hf` one where `dst` names a
    *directory* and the file lands at `<dst>/<path_in_repo>`. That
    asymmetry nearly cost the route its condition; composing the landed
    path was cheaper than living with one kind that converges and its
    neighbour that does not.
  - A CLI-routed step can now carry a completion condition while its
    install guard keeps its own, so a converged pod skips both: the
    install because the tool is on `PATH`, the download because the file
    is there.
- **A large download is fetched in parallel ranges, by the provisioner
  itself.** Sixteen requests of 10 MiB at a time, assembled with
  positioned writes into a preallocated file. Nothing is installed on
  the pod and no external process is involved; the first request is the
  probe, so a supplier that does not serve ranges costs no extra round
  trip and takes the single-stream path it always would have.
  - **Every chunk requests the URL the profile named and follows its own
    redirect.** That is the whole design. HuggingFace signs its redirect
    target for *one byte range* and documents that requesting outside it
    fails authorization, so a downloader that resolves once and splits
    against the result — `aria2c`, and `hf_transfer` too — has every
    range after the first refused. Re-resolving per chunk is what their
    own protocol asks for.
  - Both constants are HuggingFace's own: 16 is the default of
    `HF_XET_NUM_CONCURRENT_RANGE_GETS`, 10 MiB is `DOWNLOAD_CHUNK_SIZE`.
    There is no documented limit on concurrent connections to the Hub —
    the published quotas are request counts per five-minute window — so
    these are matched to the supplier's own client rather than tuned.
  - A chunk that fails is retried five times with backoff, because
    sixteen connections held across a multi-gigabyte transfer will drop
    one, and without the retry that single drop discards every other
    chunk's work. Measured: the first run without retries died 2 minutes
    into a 32-chunk fetch.
  - Verified end to end against **both** suppliers these profiles name,
    each time by comparing the assembled file's sha256 against the hash
    the supplier publishes for it: HuggingFace, 335 MB over 32 chunks;
    CivitAI, 37 MB over 4. That check is the one that matters when
    sixteen writers share one file.
  - Range-scoped signing is **HuggingFace's**, not everyone's. CivitAI
    signs only the host, so one resolved URL there serves any range —
    but this route re-resolves anyway rather than keeping a list of
    hosts trusted to serve a second range, which would be a list to
    maintain and to be wrong about. It is not merely affordable: on a
    2.13 GB CivitAI model, alternating runs on one pod, this route took
    22 / 23 / 26 s against 35 / 36 / 50 s for a resolve-once downloader
    with the same connection count, the two ranges not overlapping.
  - **The step is the same step.** Same condition, so a re-applied
    profile still skips a finished download; `sha256` still verified by
    that condition reading the file; `net.transfer.progress` unchanged
    in shape, cadence and ordering, because the cadence is decided by
    the transcript rather than by the transfer. A consumer cannot tell
    from the event stream which mechanism ran.
  - Which one ran is said once, by a new `net.transfer.route` event.
    Falling back to the single stream is allowed; falling back
    *quietly* is not, because a slow run must not look like one that
    was always going to be slow.

### Changed

- **Breaking (a profile that consumes ComfyUI must produce or assume
  it).** A `models`, `custom_nodes`, `comfyui.restart` or venv-scoped
  `python.deps` phase with no `comfyui.install` and no `assumes` entry
  is now rejected at validate and at apply. The shape is real — a pod
  that already carries ComfyUI — and the fix is one `assumes` line. It
  used to compose a path under a root nothing had made and fail on the
  pod with `no such file`.
- **A checkout implies a venv, the way it already implied a launch.**
  When `comfyui.install` is present, an undeclared `toolchain.python` is
  inserted alongside the restart and health poll that were already being
  inserted, installing the checkout's own `requirements.txt`. Inserting
  a launch while withholding what it runs would have rejected a profile
  consisting of nothing but `comfyui.install`, over a phase its author
  never wrote.
- **Every `requirements.txt` is filtered before pip sees it.** Lines
  pinning the torch family are stripped, for ComfyUI's own requirements
  and for each custom node's, through one shared pattern. A pin that
  reaches pip replaces the pod's driver-matched torch inside the venv,
  and the only symptom is `torch.cuda.is_available()` answering false at
  launch. The custom-node install previously applied no filter at all.
- **The venv is `.venv`**, matching the reference implementation. The
  earlier `venv` spelling pointed at a directory nothing had ever
  created.
- **`net.transfer` carries a real model weight.** The 16 MiB cap is
  gone, redirects are followed, and a read that stalls fails on a
  deadline instead of hanging.
- **`net.http_get` / `net.http_post` moved onto `Call`**, and dry-run
  answers each step's condition rather than restating the step.
- dsl-kit 0.10, then 0.11; the AST projection is no longer hand-built.

### Fixed

- **The venv's pip is brought current before anything is installed
  through it.** The reference implementation does this between creating
  the venv and its first install; porting that script left the line
  behind. ComfyUI at `master` would not finish installing its
  requirements in an hour, twice, on two pods; with pip upgraded first
  the same profile finished in nine minutes and the pod went on to
  produce an image. The comparison is not fully isolated — the fast run
  also had a faster link — and the code comment says so.
- **A cancelled transfer takes its partial file with it**, so a
  destination is either absent or complete and the next apply's
  condition is answering about a whole file.
- **A CLI-routed step puts its CLI on `PATH` first.** `sync.pull`,
  `staging.push` and `llm_models` route to `b2` / `hf` when the source
  scheme and a credential `env` say so, and reached for a tool the pod
  need not have: `command not found`, on a binary the profile never
  named. Each routed step now composes an install ahead of the
  invocation, skipped when the tool resolves. No new kind and nothing
  to declare — which CLI is needed follows from the route, and the
  route is already derived from the payload.
- **`Assert::CommandOnPath` and the `Cli` entity.** The fifth predicate
  and the fourth entity: a name resolves on `PATH`. It is what makes
  the install above a *conditioned* step rather than a `command -v … ||`
  written inside the shell, where the report cannot see it. Evaluated
  in dry-run too — a `PATH` lookup is a read, and cheaper than the git
  predicate that already runs in both modes.
- **A transfer creates the directory it is about to write into.** Under
  the built-in root this never showed — a ComfyUI checkout ships a
  `models/` tree — but a root a profile declares for itself ships
  nothing, and even a checkout has no `models/lora`. The failure was
  `No such file or directory` on a path the author never wrote. The
  destination has already passed the `paths` policy by then, so nothing
  is created outside a declared root.

### Deprecated

### Removed

### Security

## [0.4.0] - 2026-08-06

### Added

- **Pod target registry (`lm-provision-mcp`).** `LM_PROVISION_TARGETS`
  points at a JSON file naming every pod the server may provision, and
  `lm_apply` resolves its `pod_id` against it. Entries are an array —
  a `pod_id`-keyed object would let a duplicate key resolve last-wins,
  which is the unchecked-destination shape the registry exists to
  remove. Two kinds: `ssh` (the connection fields mirror spec 08
  §Session contract's `ConnectionSpec`) and `local-exec`. `port` is
  mandatory and non-zero, `key_path` is mandatory (spec 08 refuses to
  fall back to a default key), `user` defaults to `root` and
  `remote_dir` to `/root`; unknown fields are rejected so a misspelled
  `keypath` cannot leave a documented default silently in force. Paths
  are literal — neither `~` nor environment variables are expanded.
- **`DEFAULT_SSH_USER` / `DEFAULT_REMOTE_DIR` (`lm-provision-driver`).**
  The two ConnectionSpec defaults are now named constants the CLI and
  the registry both read.

### Changed

- **Breaking (`lm_apply` resolves `pod_id` before it runs anything).**
  `pod_id` used to select nothing: every call ran against the same
  local staging directory while the ledger stamped whatever pod the
  caller named, so a row recorded an unchecked claim rather than an
  observed destination (spec 09 §Ledger). A `pod_id` with no registry
  entry is now a precondition error — no effect runs and no ledger row
  is written. **Deployments must supply `LM_PROVISION_TARGETS`**: with
  it unset the registry is empty and every apply fails. A path that is
  set but unreadable or malformed fails startup instead of degrading to
  "every pod is unknown".
- **Breaking (`lm_apply` runs the session contract).** The MCP path
  moved from the 2026-07 three-step middle onto `session::run` (spec 08
  §Session steps 0-5). The profile is now validated before the first
  transport call, so a profile that loads but fails validation is a
  precondition error rather than a pod-side report.
- **Breaking (a failed ledger append no longer discards the apply).**
  `SessionOutput` carries `ledger_warning` and the session returns the
  collected report either way; spec 09 §Error surface asks that the
  record not be swallowed, not that the outcome be thrown away. The
  duty to surface it moved to the caller: `lm-provision-driver` prints
  the warning to stderr and exits 1 even on an ok report, and the MCP
  server keeps returning `ledger_appended: false` alongside it.
- **MCP error messages no longer carry connection details.** A failure
  that crosses to the client keeps its class, the `pod_id`, and this
  server's own values (the local digest, a missing secret's name, a
  validation message) and drops what the pod or `ssh` authored. The
  full text is logged at ERROR on the server instead. The CLI is
  unchanged — the operator who wrote the registry still gets the raw
  `ssh` / `scp` diagnostic.

### Deprecated

### Removed

### Fixed

- **The MCP server no longer executes the provisioner binary.** Hashing
  the profile used to spawn the uploaded artifact locally, but that
  artifact is the `x86_64-unknown-linux-musl` build meant for the pod
  (spec 08 §Inputs) — a macOS server cannot run it, so the path could
  not work outside a test that substituted a host-native build. The
  session contract's in-process hash replaces it.
- **A repeated key inside one registry entry is rejected.** Entries
  were held as `serde_json::Value`, and building a `Value` builds a
  map, so a second `"host"` in the same entry collapsed last-wins
  before the entry was ever validated. Entries now keep their undecoded
  JSON text, and the repeat is a `duplicate field` decode error naming
  the entry.

### Security

## [0.3.0] - 2026-08-05

### Added

- **`net.transfer` bridge** now resolves public `hf://` sources to their
  `https://huggingface.co/<owner>/<repo>/resolve/<rev>/<path>` URL (default
  revision `main`, URL-carried `@<rev>` wins over `opts.revision`) and
  implements HTTP PUT uploads to `https://` destinations. Public `b2://`
  sources stay unsupported by design — the deployment's download endpoint
  is cluster- and account-specific and no profile field declares one; the
  error names the gap and points at the credential `env` route that does
  work (spec 04 §`net.transfer`).
- **validate check 8** — a second `service.ready` under the same
  `service.start` is rejected. Both would carry `11_service_<N>_ready`,
  and that number is what tells two services apart (spec 02 §Canonical
  phase ordering).
- **validate check 9 (`declared ⊇ derived`)** — the compiler walks the
  normalized plan and asserts that every `capabilities` / `paths` /
  `http_allowlist` entry the run will need appears in the corresponding
  declared list. Implicitly inserted steps count: a profile that writes
  only `comfyui.install` still has to declare the health poll's
  `net.http_get` and its URL. Built-in path constants count too:
  `models` writes under `/workspace/ComfyUI/models/...` even though the
  author never spells that path out (spec 00 §Capability derivation,
  spec 03 §validate).

### Changed

- **Breaking (canonical order becomes an execution contract, not a plan
  one).** The ordering / implicit-insertion / suppression rules now
  rewrite the AST once (`crate::normalize`) and both `plan` and `apply`
  consume the result. `apply` used to drive the authored phase list
  directly, so the three rules only affected the plan artifact; a
  `comfyui.install` alone would not spawn its restart / health poll on
  apply, and a `python.version_check` asserting the default would still
  run. Both are now fixed. The profile as *written* is what `hash` /
  `canonical` see, so an inserted step does not change a profile's hash
  (spec 02 §Canonical phase ordering).
- **Breaking (capability gate reads the resolved route).** A lifecycle
  op's demand comes from the steps its payload expands to, not from its
  kind: a credential-`env` `sync.pull` and every `staging.push` route to
  the native CLI, so they demand `sh.exec`. A profile that granted only
  `net.transfer` used to run a shell under it; it is now denied at the
  L4 gate (spec 02 §Dispatch routing "What the L4 gate sees").
- **Breaking (bridge policies see every write).** A lifecycle-composed
  transfer or HTTP poll answers to the same `paths` / `http_allowlist`
  a direct op would — the check runs on the resolved step, so an
  `hf://` source is gated as its `https://huggingface.co` URL. Profiles
  that used to reach undeclared paths / hosts through `sync.pull` /
  `models` / `comfyui.health` / `service.ready` now need those targets
  in the corresponding declared list (spec 05 §L3).
- **Breaking (`env.ref` becomes a reachable capability).** A phase
  carrying an `EnvRef` value node — in `fs.write` content, in an `env`
  keyed slot, in a header map, in a POST body — now demands `env.ref`
  on top of whatever its kind requires. Dereferencing a `Spec.env`
  entry is an effect of its own, so profiles that read one need
  `env.ref` in `capabilities` (spec 02 §Shared vocabulary).
- **Breaking (`net.transfer` direction is a validate-stage decision).**
  A remote scheme on `src` is a download, one on `dst` is an upload;
  a scheme on both sides or on neither is rejected at validate rather
  than surfaced mid-apply. `models` gains the same treatment: an
  element with neither `dst` nor `name` has nowhere to write to and is
  now a precondition error (spec 02 §Catalog kinds / §Error surface).
- **`service.ready` orphans get their own service index.** A resume
  profile that polls a server an earlier apply started no longer
  inherits `_0_` from the first declared service — it opens the next
  free index. The two never collide on `11_service_0_ready` again
  (spec 02 §Canonical phase ordering).
- **spec 02 phase catalog respec.** The 34-finding DeepReview pass
  landed as point fixes to `docs/spec/02-phase-catalog.md`:
  direct-op / `zz_unknown` no-op semantics narrowed to unrecognized
  kinds only; implicit-insertion guard restated per phase (not "neither
  declared"); `platform.kind` documented as a free string with a note
  step for unknown values; ids are slot labels rather than sort keys;
  `dst | name` / `subdir | kind` precedence stated; ollama's argv
  ignores `model` / `port`; secret-shaped and sensitive-key sets
  collapsed to one set with two consumer chapters; case-insensitivity
  and byte-equality split into separate claims; `<KindName>` ↔ dotted
  label mapping tabulated (`comfyui` → `ComfyUi`, `hooks.post_install`
  → `PostInstall`).

## [0.2.0] - 2026-08-05

### Changed

- **Breaking (profile capabilities):** `comfyui.health` and `service.ready`
  now require `net.http_get` instead of `sh.exec`. Both kinds expand into a
  single HTTP poll, so they are gated on the capability of the effect they
  perform (spec 02 §Catalog kinds, 03 §dispatch, 05 §L4); the pid file the
  poll re-reads between attempts is a provisioner-internal file read, not a
  bridge operation. A profile that declares only `sh.exec` and uses either
  kind must add `net.http_get` to its `capabilities`.

## [0.1.0] - 2026-08-03

### Added

- Typed profile AST pipeline: JSON / canonical-text frontend, validate,
  deterministic canonical encoding + SHA-256 profile hash, plan, and the
  effectful apply engine (`lm-provision` lib + CLI with `validate` /
  `hash` / `plan` / `apply --dry-run` subcommands).
- 22-kind phase catalog covering system packages, Python toolchain,
  ComfyUI install / restart / health, generic service start / readiness,
  model prefetch (`hf` CLI), sync pull / push (`https` / `hf://` / `b2://`),
  staging push, filesystem writes, shell steps, bind mounts, hooks, and
  first-class HTTP access (`net.http_get` / `net.http_post` with headers,
  body, `body_json`, and per-step `timeout_sec`).
- Secret handling: `EnvSecret` / `EnvRef` declaration-derived env policy.
  Secret values are delivered via environment or SSH stdin script only —
  never in process argv, reports, transcripts, or the ledger; audit lines
  carry names and byte lengths with `[REDACTED]` markers.
- Readiness probing with fail-fast posture: per-kind poll deadlines
  (ComfyUI health 180s, service ready 300s, overridable per step via
  `timeout_sec`) and died-during-wait detection (pid-file + settle check +
  armed liveness poll) that fails in seconds instead of burning the full
  timeout when the supervised process crashes during startup.
- Push driver (`lm-provision-driver`): one-shot session contract over SSH —
  ensure-binary (SHA-256 idempotent push of the static musl artifact),
  profile placement, apply, report / transcript collection, and an
  append-only apply ledger. Secrets travel by stdin script; keys are
  explicit (no default-key fallback).
- MCP server (`lm-provision-mcp`): `lm_validate` / `lm_hash` / `lm_plan`
  and apply-ledger inspection (`lm_ledger_list` / `lm_ledger_get`) exposed
  as MCP tools.
- External interface specifications in `docs/spec/` (00-10): profile DSL
  surface, phase catalog, pipeline stage artifacts, bridge, sandbox layer
  contract, secret handling, CLI, push-driver protocol, apply report and
  ledger, MCP.

[Unreleased]: https://github.com/ynishi/lm-provision/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/ynishi/lm-provision/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ynishi/lm-provision/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ynishi/lm-provision/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ynishi/lm-provision/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ynishi/lm-provision/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ynishi/lm-provision/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ynishi/lm-provision/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ynishi/lm-provision/releases/tag/v0.1.0
