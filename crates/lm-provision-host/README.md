# lm-provision-host

The continuously-running side of lm-provision. `lm-provision machine
sweep` gives back every machine whose recorded lease has run out, but
only when somebody runs it — which is the forgotten-machine problem one
level up. This daemon runs it on a timer and answers one question about
itself over HTTP.

It is **AGPL-3.0-or-later**, not the workspace's MIT / Apache-2.0: a
control plane is a service one can host for others, and the AGPL is
what keeps a hosted modification of it available to the people using
it. The boundary is the crate boundary — nothing here depends on the
engine crates, and nothing there may depend on this one (a test in
`src/lib.rs` fails if a permissive manifest ever names it).

## Running it

```sh
lm-provision-host --interval-secs 300 --bind 127.0.0.1:7909
```

The daemon runs the **operator CLI**, it does not link the driver's
code: the CLI is the contract, and exec is what keeps the AGPL side
free of any dependency on the permissive one. So
`lm-provision` has to be on `PATH` (or named with `--driver`),
and it needs whatever credentials a release requires — a sweep that
cannot authenticate reports the machine as failed and leaves it
running.

## It enforces by default

`--dry-run` defaults to **false** here. On the CLI it defaults to
*true*, because an operator asking which machines would be released
must not find out by them being gone. Installing a long-lived
TTL-enforcement service is the opposite act: it is the consent to
release expired machines, and a daemon that defaulted to observing
would be the forgotten-machine problem wearing a uniform.

`--dry-run true` is the observation mode — every sweep names what it
would release and releases nothing, and the daemon logs a warning at
startup saying it is not enforcing anything. Either way the release
gate inside `sweep` still refuses to delete a machine whose declared
artifacts were never collected; there is no `--force` on this path.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--interval-secs <secs>` | `300` | Seconds between sweeps. Leases are hour-grained, so minutes-grained checking is already tight against them. Zero is refused: a timer with no period is a loop spawning the driver as fast as it can exit. |
| `--driver <path>` | `lm-provision` | The binary to run — the operator CLI, invoked as `machine sweep`. A bare name is looked up on `PATH`. |
| `--provider <name>` | none | A platform each sweep asks what it is running (`runpod`, `vast`), judging those machines by the lease stamped on each one rather than by the record. Repeatable. Without it a sweep can only act on the acquisitions record — a file, which can be lost or written on another host while the machine keeps billing. Listing needs that platform's credential even in `--dry-run true`; machines carrying no `lmp-exp-` stamp are reported and never released. |
| `--acquisitions <path>` | driver's default | The acquisitions record to sweep, passed through verbatim. Unset means the driver's own default — the file this host's `acquire` runs already wrote to. |
| `--ledger <path>` | driver's default | The ledger the release gate reads, passed through verbatim. |
| `--dry-run <bool>` | `false` | See above. |
| `--bind <addr>` | `127.0.0.1:7909` | Where the health endpoint listens. Loopback, because the document names machines and says whether enforcement is working. |

A sweep is run immediately at startup and then every interval: an
operator restarting the daemon after a week with the laptop closed
wants enforcement now, not at the top of the next interval. A tick that
fails — the driver missing, a non-zero exit, stdout that is not the
artifact — is logged and recorded, and the daemon waits for the next
one. A TTL enforcer that dies on the first bad tick protects nothing
for the rest of the week.

## The health endpoint

Any request on the socket gets the same document. There is no routing
and no method parsing: there is one consumer asking one question — "is
this daemon still enforcing?" — and a 404 table would only give it new
ways to be told nothing.

```console
$ curl -s localhost:7909
```

```json
{
  "ok": true,
  "dry_run": false,
  "interval_secs": 300,
  "started_at": "2026-09-01T09:12:03.114Z",
  "ticks": 4,
  "last_tick_at": "2026-09-01T09:27:03.402Z",
  "last_tick_ok": true,
  "last_artifact": {
    "dry_run": false,
    "expired": 1,
    "failed": [],
    "refused": [],
    "released": ["pod-abc123"],
    "unknown": []
  }
}
```

- `ok` — whether the newest sweep produced an artifact. True before the
  first sweep finishes; `ticks: 0` beside it says which of the two it
  is.
- `last_tick_error` — why the newest sweep did not. **Absent**, not
  null, when there is nothing to read.
- `last_artifact` — the sweep's own document, carried through
  unchanged (08 §Acquisitions and sweep). Absent after a failed tick,
  so a stale copy never sits under a fresh timestamp claiming a sweep
  happened.

Ctrl-C stops the daemon; machines already released stay released.
