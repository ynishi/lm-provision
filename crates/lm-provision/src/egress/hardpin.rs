//! Hard enforcement layer for the sh.exec egress pin (Linux only).
//!
//! The soft layer ([`super::proxy`]) captures every subprocess that honours
//! `HTTPS_PROXY`. A subprocess that *ignores* the proxy env and opens its own
//! socket to an off-host address would slip past it. This layer closes that:
//! a subprocess is spawned under a seccomp user-notify filter, and a supervisor
//! in the parent inspects the destination of each address-carrying network
//! syscall and refuses anything that is not the proxy endpoint or a configured
//! DNS resolver.
//!
//! Why that allowset is the whole enforcement: when the proxy is self-hosted on
//! `127.0.0.1`, a cooperative CLI's only connect is to the proxy (loopback) —
//! the proxy does the real DNS + outbound connect on its behalf. A CLI that
//! bypasses the proxy tries to reach the external IP directly, which is neither
//! the proxy nor a resolver, and is denied at the syscall.
//!
//! # Which syscalls are trapped, and why `connect` alone is not enough
//!
//! Pinning `connect(2)` only leaves a subprocess an off-host channel with
//! zero `connect` calls: `sendto(2)` carries its own destination
//! (`sendto(fd, buf, len, flags, dest, addrlen)`), so unconnected UDP —
//! arbitrary exfil, DNS-over-UDP to any resolver — never touches
//! `connect`, and even TCP can dial out via `sendto(..., MSG_FASTOPEN,
//! dest, ...)`. `sendmsg(2)` / `sendmmsg(2)` carry a destination inside
//! their `struct msghdr` the same way. So the filter traps **`connect`,
//! `sendto`, `sendmsg`, and `sendmmsg`**, and the supervisor reads the
//! destination out of whichever argument slot the syscall uses (the
//! `nr`-keyed switch in [`supported::is_notif_allowed`]). A syscall whose
//! destination argument is NULL means "use the socket's connected peer",
//! which was already judged at `connect` time — that is the allowed
//! [`supported::Dest::NotInet`] case.
//!
//! # io_uring is denied outright
//!
//! `io_uring` submits operations — including `IORING_OP_CONNECT` and
//! `IORING_OP_SEND` — through `io_uring_enter(2)`, not as the distinct
//! syscalls this filter traps, so a ring is a hole seccomp cannot see
//! into. The filter closes it at the root: `io_uring_setup(2)` is
//! refused (`EPERM`), so the confined child cannot create a ring in the
//! first place and every network operation it can still issue is a
//! syscall the filter does see. This denies `io_uring` **entirely** to
//! the `sh.exec` subprocess — the fail-closed choice, and a cheap one
//! here: the child reaches the network through the proxy env and normal
//! socket syscalls, never through a ring. `EPERM` (rather than
//! `RET_KILL_PROCESS`) so a runtime that merely *probes* `io_uring` and
//! falls back to ordinary sockets keeps working; the fallback path is
//! itself trapped, so the denial loses nothing.
//!
//! # The allowset: the proxy endpoint and configured resolvers
//!
//! The pin allows exactly two kinds of destination, not "any loopback
//! service" (which would leave a Docker API on `:2375`, a local
//! database, or any other loopback listener reachable):
//!
//! - **the proxy's own listen address** — the `SocketAddr` the proxy
//!   bound, threaded in from the supply that started it (the same address
//!   that goes into the child's `HTTPS_PROXY`, [`super::EgressSupply`]).
//!   That is the one endpoint a cooperative subprocess dials.
//! - **the host's configured DNS resolvers on port 53** — read once from
//!   `/etc/resolv.conf` before the child is spawned ([`read_nameservers`]),
//!   so a subprocess that resolves names itself before proxying keeps
//!   working. This admits a loopback stub (`127.0.0.53` for
//!   systemd-resolved, `127.0.0.11` for Docker's embedded DNS) **and** a
//!   real off-host nameserver a container is pointed at (`10.x`, a public
//!   resolver) — a resolver is trusted for `:53` by *being in
//!   resolv.conf*, not by being loopback. Port 53 to an address that is
//!   not a configured resolver is refused: `connect(2)` does not know a
//!   protocol, so "any IP on port 53" would be an unrestricted TCP
//!   channel to an attacker-numbered host, the very thing the pin exists
//!   to refuse.
//!
//! If `/etc/resolv.conf` cannot be read, the allowset falls back to
//! loopback addresses on port 53 only — enough for the common stub-resolver
//! case, and fail-closed for everything else.
//!
//! # Unix-domain sockets are out of scope
//!
//! The pin does not cover `AF_UNIX` (a Docker socket, D-Bus, an nss
//! resolver socket): local IPC is not network egress, and spec 05 §L3
//! scopes `sh_egress` to network egress. An `AF_UNIX` destination is the
//! [`supported::Dest::NotInet`] allow case.
//!
//! # What the supervisor's authorization is worth
//!
//! The supervisor answers each notification by reading the destination
//! out of the tracee's memory (`/proc/<pid>/mem`), then — the order
//! `seccomp_unotify(2)` prescribes — asking
//! `SECCOMP_IOCTL_NOTIF_ID_VALID` whether the notification it read for
//! is still live, and only then responding. That step is what keeps a
//! response from landing on a *different* syscall: without it, a target
//! that died between the receive and the response could have its
//! notification id reused by a later one, and this supervisor would be
//! answering a question it never inspected.
//!
//! ID_VALID does not, on its own, close the re-read race inherent to a
//! `CONTINUE` response — and so the supervisor does not answer an
//! address-carrying syscall with `CONTINUE`. `CONTINUE` tells the kernel
//! to run the real `connect(2)`, and the kernel then re-reads the
//! `sockaddr` from the tracee's own pointer, so a second thread in the
//! tracee can rewrite that memory after the supervisor read it and
//! before the syscall resumes — making the connect that happens a
//! different one from the connect that was authorized.
//! `seccomp_unotify(2)` §NOTES states the rule: the notifier must not be
//! used for a security policy that depends on the *contents* of pointer
//! arguments unless the supervisor performs the operation itself.
//!
//! So it does (§the re-read TOCTOU closure, [`supported::plan`] /
//! [`supported::emulate`]). For a permitted destination the supervisor
//! lifts a duplicate of the tracee's own socket out with
//! `pidfd_getfd(2)` — a fd to the **same open file description**, so
//! operating on it operates on the tracee's real socket — performs the
//! `connect` / `send` there against **its own copy** of the sockaddr,
//! and answers with the syscall's result value rather than `CONTINUE`.
//! The kernel does not re-execute, so the pointer is never re-read and
//! there is no window to race. A `CONTINUE` is left only where the
//! decision rests on a **register** argument, fixed at the trap and
//! beyond a sibling thread's reach — never on re-readable memory:
//! `connect` with a NULL `addr` register; `sendto` with a NULL
//! destination register (`args[4]`, a connected-peer send — the peer was
//! fixed at the emulated connect); `sendmsg` with a NULL `msghdr` pointer
//! register (`args[1]`); and `sendmmsg` with a NULL base or zero `vlen`
//! register. A non-NULL `sendmsg` / `sendmmsg` never `CONTINUE`s even
//! when its `msg_name` reads NULL: `msg_name` lives *inside* a re-readable
//! `struct msghdr`, so the supervisor performs the send itself (a NULL
//! destination standing for the connected peer).
//!
//! The supervisor is a single thread draining the notifications serially,
//! so an emulated syscall runs on it. Every wait it can do on a tracee
//! socket is bounded ([`supported::wait_writable`]) and every send is
//! `MSG_DONTWAIT`, so no one emulated `connect`/`send` can park the thread
//! (and thus every other tracee thread's egress) indefinitely — the
//! emulated destinations are the loopback proxy and configured resolvers,
//! where the waits are short in any case.
//!
//! Two things still bound the pin, and neither is affected by the
//! closure above:
//!
//! - The soft layer ([`super::proxy`]) is where cooperative traffic
//!   goes. This filter only ever sees a subprocess that already left
//!   the proxy env behind.
//! - Spec 05 §L3's **best-effort** register is about *availability*, not
//!   this race: a profile cannot know the pod kernel supports the pin,
//!   and an unsupported arch has no pin at all (§Unsupported arches), so
//!   containment in general still comes from the pod boundary. Where the
//!   pin *is* in force, the destination it enforces is now sound — the
//!   re-read hole this section used to concede is closed.
//!
//! # Arch check
//!
//! The BPF program compares `seccomp_data.arch` against the native
//! `AUDIT_ARCH_*` for the build target **before** it looks at
//! `seccomp_data.nr`. A 32-bit compat entry (e.g. `int 0x80` on
//! `x86_64`) or any other foreign ABI presents a different `arch` and
//! a `nr` from a different syscall table — without this check the
//! foreign `nr` would fail to equal `SYS_connect` and fall through to
//! `SECCOMP_RET_ALLOW`, bypassing the pin. A mismatch takes the
//! `SECCOMP_RET_KILL_PROCESS` branch instead: the filter's coverage of
//! `connect(2)` is native-ABI-only, so a foreign ABI has silently lost
//! it, and either the process is compromised or it is trying to
//! bypass. Fail closed. (Standard seccomp practice — see
//! `Documentation/userspace-api/seccomp_filter.rst` on `arch` /
//! `seccomp_data`.)
//!
//! The arch check alone is **not** enough on `x86_64`. The x32 ABI
//! shares `AUDIT_ARCH_X86_64` with the native ABI but sets
//! `__X32_SYSCALL_BIT` (`0x40000000`) in `nr` — so an x32 `connect`
//! presents `arch == AUDIT_ARCH_X86_64`, passes the arch JEQ, and
//! carries `nr = 0x4000002A`, which fails the JEQ against 64-bit
//! `SYS_connect` (0x2A) and falls through to `SECCOMP_RET_ALLOW`. The
//! bypass is identical to the compat `int 0x80` path the arch check
//! closes. To seal it, the x86_64 program adds a second guard between
//! the `nr` load and the `SYS_connect` compare: a `BPF_JGE` against
//! `X32_SYSCALL_BIT` sending any `nr` with the bit set to the same
//! `RET_KILL_PROCESS` sentinel. Same rationale as the foreign-arch
//! branch — the filter has no coverage of the x32 syscall table, and
//! standard practice (libseccomp, Docker's default profile,
//! `Documentation/userspace-api/seccomp_filter.rst`) is to deny any
//! `nr` with the x32 bit set when filtering the x86_64 ABI. aarch64
//! has no x32 equivalent and its filter carries no such guard.
//!
//! # Unsupported arches
//!
//! The BPF program is architecture-specific: it hard-codes the native
//! `AUDIT_ARCH_*` and (on x86_64) `__X32_SYSCALL_BIT`. Implementations
//! exist for `x86_64` and `aarch64` — the two Linux arches this crate
//! ships binaries for. Other Linux targets (`riscv64`, `ppc64le`,
//! `s390x`, `i686`, …) still compile the crate (it is a published
//! library and consumers select their own target); on those,
//! [`run_pinned`] returns an `io::Error` naming the unsupported
//! `target_arch` rather than either (a) failing to compile the crate
//! or (b) falling back to an arch-blind filter — the second option
//! would re-open exactly the foreign-ABI / x32 bypasses the guards
//! above close. The caller ([`crate::exec::effects::sh_exec`]) wraps
//! that error as `ExecError::EffectFailed`; the subprocess never
//! spawns and the step's report says why. **Fail closed** — a profile
//! whose `sh_egress` pin cannot be honoured on this host refuses to
//! run rather than running unrouted. Operators on unsupported arches
//! reach off-host through [`super::EgressSupply::External`]
//! (`LM_EGRESS_PROXY` pointing at an external gateway), which does
//! not consult this layer.
//!
//! Both behaviours were probed on a real host before being relied on
//! here: the user-notify install under Docker's default seccomp, and
//! the v4+v6 gating of a real CLI (an IPv4-only filter is bypassed
//! over IPv6, so both families are gated here).
//!
//! # `pidfd_getfd` gates the mode: full pin, or connect-only fallback
//!
//! Two things want `pidfd_getfd(2)`: the listener hand-off lifts the
//! child's seccomp listener into the supervisor with it
//! ([`supported::lift_listener`]), and the emulated syscalls
//! ([`supported::emulate`]) operate on a `pidfd_getfd` duplicate of the
//! tracee's socket. The hand-off cannot instead use `SCM_RIGHTS` *while
//! sends are trapped* — `SCM_RIGHTS` is a `sendmsg`, which the full filter
//! traps the instant it is armed, before the supervisor has a listener to
//! answer with (a deadlock; see [`supported::install_and_signal`]) — so
//! the full pin is bound to `pidfd_getfd`.
//!
//! A container seccomp policy can refuse `pidfd_getfd`: Docker's default
//! profile does on some platforms — **measured: a RunPod pod under
//! `Seccomp:2`, 2026-09-01, `pidfd_getfd` → `EPERM`**. Rather than refuse
//! to run there, the pin falls back to a **connect-only** mode
//! ([`supported::Mode`]): its filter traps `connect` alone, so `sendmsg`
//! is no longer trapped and the listener hands off by `SCM_RIGHTS`
//! ([`supported::send_fd`] / [`supported::recv_listener`]) with no
//! `pidfd_getfd`; the supervisor answers `connect` with `CONTINUE` (allow)
//! / `EPERM` (deny), so a non-cooperative subprocess's off-host TCP
//! `connect` is still refused at the syscall. The cost, stated plainly:
//! the send families (`sendto` / `sendmsg` / `sendmmsg`, and the
//! `AF_UNSPEC` UDP exfil vector) are **not** pinned in this mode, and the
//! `CONTINUE` re-read race is not closed — both are the accepted
//! best-effort limitation of a host that cannot run the full pin. For full
//! off-host enforcement on such a host, reach off-host through
//! [`super::EgressSupply::External`] (`LM_EGRESS_PROXY`), which does not
//! use this layer.
//!
//! [`supported::run_pinned`] chooses the mode once, before the fork, from
//! [`supported::pidfd_getfd_available`]. A second guard backs it up:
//! [`supported::install_and_signal`] closes the child's inherited copy of
//! the parent socketpair end, so a hand-off failure becomes a clean EOF on
//! the child's ack read rather than the hang it was before — the forked
//! child otherwise kept that end open and never saw EOF (**measured: the
//! same RunPod pod, any pinned `sh.exec` hung until killed**, before the
//! fallback and this close existed).
//!
//! Applies only to a **self-hosted** (loopback) proxy. An external gateway
//! ([`super::EgressSupply::External`]) is off-host, so a loopback-only pin
//! would break it; there the gateway owns enforcement and this layer is off.

#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Output};

/// The endpoints the pin admits for one run (§The allowset).
///
/// Built once, before the child is spawned, and held for the run:
/// [`PinConfig::for_proxy`] pairs the proxy's bound address with the
/// host's configured resolvers, reading `/etc/resolv.conf` a single time
/// (the man-page discipline is that a security decision must not depend
/// on a file re-read per notification). The supervisor then answers
/// every trapped syscall against this fixed set.
#[derive(Debug, Clone)]
pub struct PinConfig {
    /// The proxy's own listen address — the one endpoint a cooperative
    /// subprocess dials (its `HTTPS_PROXY`).
    proxy: SocketAddr,
    /// The host's configured DNS resolvers (`nameserver` lines of
    /// `/etc/resolv.conf`), each admitted on port 53 only.
    resolvers: Vec<IpAddr>,
    /// `/etc/resolv.conf` could not be read; fall back to allowing any
    /// loopback address on port 53 (the stub-resolver case) and nothing
    /// else.
    dns_loopback_fallback: bool,
}

impl PinConfig {
    /// Pair `proxy` with the resolvers read from `/etc/resolv.conf`.
    pub fn for_proxy(proxy: SocketAddr) -> Self {
        match read_nameservers() {
            Some(resolvers) => Self {
                proxy,
                resolvers,
                dns_loopback_fallback: false,
            },
            None => Self {
                proxy,
                resolvers: Vec::new(),
                dns_loopback_fallback: true,
            },
        }
    }

    /// Whether a `connect` / `sendto` / `sendmsg` destination `(ip,
    /// port)` is one of the two endpoints the pin exists for.
    fn permits(&self, ip: IpAddr, port: u16) -> bool {
        if SocketAddr::new(ip, port) == self.proxy {
            return true;
        }
        if port == 53 {
            if self.resolvers.contains(&ip) {
                return true;
            }
            if self.dns_loopback_fallback && ip.is_loopback() {
                return true;
            }
        }
        false
    }

    /// A config with an explicit resolver set, for tests — the file read
    /// [`for_proxy`](Self::for_proxy) does is not deterministic across
    /// hosts.
    #[cfg(test)]
    pub(crate) fn for_test(
        proxy: SocketAddr,
        resolvers: Vec<IpAddr>,
        dns_loopback_fallback: bool,
    ) -> Self {
        Self {
            proxy,
            resolvers,
            dns_loopback_fallback,
        }
    }
}

/// The `nameserver` addresses in `/etc/resolv.conf`, or `None` when the
/// file cannot be read (the fallback signal, §The allowset).
///
/// A readable file with no `nameserver` line returns `Some(vec![])` —
/// distinct from unreadable: the host stated its resolvers and named
/// none, so the pin admits none rather than opening the loopback
/// fallback. Only the first token after `nameserver` is read, and only
/// when it parses as an IP; anything else is skipped, never guessed at.
fn read_nameservers() -> Option<Vec<IpAddr>> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    Some(parse_nameservers(&text))
}

/// Parse the `nameserver` lines out of `resolv.conf` text. Split from
/// [`read_nameservers`] so the parse is testable without a file: the
/// keyword must be its own token, and only a following token that parses
/// as an IP is kept.
///
/// A `%zone` suffix on a link-local address (`fe80::1%eth0`) is stripped
/// before parsing — the pin compares the address, and the zone is a
/// routing detail the decoded `sockaddr` does not carry into the 16-byte
/// address field. Without the strip, a host whose only nameserver is
/// scoped would parse to an empty resolver set and every DNS lookup
/// would `EPERM`.
fn parse_nameservers(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() == Some("nameserver") {
            if let Some(ip) = tokens
                .next()
                .map(|token| token.split('%').next().unwrap_or(token))
                .and_then(|addr| addr.parse::<IpAddr>().ok())
            {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// `nameserver` lines parse; keyword must be its own token; a
    /// following token that is not an IP is skipped, not guessed at.
    #[test]
    fn parse_nameservers_reads_only_well_formed_nameserver_lines() {
        let text = "\
# a comment\n\
nameserver 127.0.0.53\n\
nameserver 10.0.0.1\n\
options edns0\n\
nameserverfoo 1.2.3.4\n\
nameserver not-an-ip\n\
nameserver 2001:4860:4860::8888\n";
        let got = parse_nameservers(text);
        assert_eq!(
            got,
            vec![
                "127.0.0.53".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ],
            "`nameserverfoo` and `not-an-ip` must not be read"
        );
    }

    /// **A scoped (zoned) link-local resolver keeps its address** (finding
    /// 5). `fe80::1%eth0` must yield `fe80::1` — dropping the whole line
    /// left a host with only a scoped nameserver unable to resolve (empty
    /// set → :53 denied → every lookup EPERMs).
    #[test]
    fn parse_nameservers_strips_the_zone_from_a_scoped_resolver() {
        let got = parse_nameservers("nameserver fe80::1%eth0\nnameserver fe80::2%1\n");
        assert_eq!(
            got,
            vec![
                "fe80::1".parse::<IpAddr>().unwrap(),
                "fe80::2".parse().unwrap(),
            ]
        );
    }

    /// **The allowset is the proxy endpoint plus configured resolvers,
    /// not any loopback service.** A local Docker API on `127.0.0.1:2375`
    /// or a database on `127.0.0.1:5432` is refused; only the proxy's own
    /// `SocketAddr` is allowed off port 53.
    #[test]
    fn permits_only_the_proxy_endpoint_and_configured_resolvers() {
        let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let resolver: IpAddr = "10.0.0.53".parse().unwrap();
        let cfg = PinConfig::for_test(proxy, vec![resolver], false);

        // The proxy endpoint, exactly.
        assert!(cfg.permits(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        // Another loopback port is not the proxy — Docker API, a DB, …
        assert!(!cfg.permits(IpAddr::V4(Ipv4Addr::LOCALHOST), 2375));
        assert!(!cfg.permits(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432));

        // The configured resolver, on port 53 only — even though it is
        // off-host (the round-4 regression: a real `10.x` nameserver
        // must resolve).
        assert!(cfg.permits(resolver, 53));
        assert!(!cfg.permits(resolver, 443));
        // An off-host address on 53 that is not the resolver is refused.
        assert!(!cfg.permits("8.8.8.8".parse().unwrap(), 53));
        // A loopback stub is not admitted unless it is in resolv.conf.
        assert!(!cfg.permits("127.0.0.53".parse().unwrap(), 53));
    }

    /// When `/etc/resolv.conf` is unreadable the fallback admits loopback
    /// on port 53 only — the stub-resolver case — and nothing off-host.
    #[test]
    fn the_dns_loopback_fallback_admits_only_loopback_on_port_53() {
        let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let cfg = PinConfig::for_test(proxy, Vec::new(), true);
        assert!(cfg.permits("127.0.0.53".parse().unwrap(), 53));
        assert!(cfg.permits(IpAddr::V4(Ipv4Addr::LOCALHOST), 53));
        assert!(!cfg.permits("8.8.8.8".parse().unwrap(), 53));
        assert!(!cfg.permits(IpAddr::V4(Ipv4Addr::LOCALHOST), 2375));
    }
}

/// Run `command` under the egress hard pin, returning its collected
/// output.
///
/// On the supported arches (`x86_64`, `aarch64`) this delegates to
/// [`supported::run_pinned`], which installs the seccomp user-notify
/// filter, supervises each address-carrying network syscall from a
/// parent thread against `config`, and collects output the way
/// [`Command::output`] does. `command`'s stdio must already be
/// configured by the caller.
///
/// On other Linux arches — see §Unsupported arches — this returns an
/// `io::Error` naming the target and pointing at
/// [`super::EgressSupply::External`] as the workaround.
pub fn run_pinned(command: Command, config: PinConfig) -> io::Result<Output> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        supported::run_pinned(command, config)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (command, config);
        Err(io::Error::other(format!(
            "sh_egress hard pin has no implementation for target_arch={} — \
             the seccomp BPF program is architecture-specific and only \
             x86_64 / aarch64 are implemented today; set LM_EGRESS_PROXY \
             to route through an external gateway, or omit sh_egress",
            std::env::consts::ARCH,
        )))
    }
}

/// The seccomp / BPF machinery lives in this submodule so its
/// arch-specific constants and struct definitions do not leak into
/// the outer scope of unsupported-arch builds. The outer [`run_pinned`]
/// above is the only entry point on any arch.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod supported {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // --- seccomp / ioctl constants (uapi/linux/seccomp.h) -------------------

    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    /// Terminate the whole process. Chosen for the arch-mismatch branch
    /// below because that branch means "the caller issued a syscall via a
    /// syscall-entry ABI this filter was not built to recognise" — the
    /// filter's whole coverage of `connect(2)` is native-ABI-only, so a
    /// foreign ABI has silently lost that coverage. A live process that
    /// reached this branch is either (a) itself compromised or (b) trying
    /// to bypass the pin; either way, letting it continue would be exactly
    /// the fall-through-to-`ALLOW` the arch check exists to close.
    /// (`RET_KILL_PROCESS` needs kernel 4.14+; `USER_NOTIF` — already
    /// required by this module — needs 5.0+, so the version bar is set by
    /// the notify path, not here.)
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    /// Return an errno to the caller without running the syscall. The low
    /// 16 bits carry the errno. Used for `io_uring_setup` (§io_uring is
    /// denied outright): the child gets `EPERM` and falls back to
    /// ordinary sockets, which the filter does trap — a graceful deny,
    /// unlike `RET_KILL_PROCESS`, which would kill a runtime that merely
    /// probes `io_uring` and handles the refusal.
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    /// `io_uring_setup` denied with this errno (`EPERM`, low 16 bits).
    const SECCOMP_RET_ERRNO_EPERM: u32 = SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0x0000_ffff);
    const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

    /// The `audit_arch` field the kernel writes into `seccomp_data.arch`
    /// for a native-ABI syscall on the current build target
    /// (`asm/audit.h`, mirrored in `linux-raw-sys::*::ptrace`). Compared
    /// against `seccomp_data.arch` as the first BPF check so a 32-bit
    /// compat entry (e.g. `int 0x80` on x86_64) is caught before it can
    /// present a foreign `nr` and slip past the `SYS_connect` compare.
    #[cfg(target_arch = "x86_64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

    /// `asm/unistd.h` `__X32_SYSCALL_BIT`. On x86_64 the x32 ABI shares
    /// `AUDIT_ARCH_X86_64` with native but sets this bit in every `nr`.
    /// A JGE against this value on the native path routes every x32
    /// syscall to `RET_KILL_PROCESS`; see the module doc §Arch check
    /// for the bypass this closes. aarch64 has no x32 equivalent and
    /// does not carry the constant.
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    // Classic-BPF opcodes for the connect-trapping filter.
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    /// Unsigned `>=`. Used on x86_64 to catch any `nr` carrying
    /// `X32_SYSCALL_BIT` (all x32 numbers are `>= 0x40000000`; no
    /// native x86_64 `nr` reaches that far).
    #[cfg(target_arch = "x86_64")]
    const BPF_JGE: u16 = 0x30;
    const BPF_RET: u16 = 0x06;
    const BPF_K: u16 = 0x00;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    #[repr(C)]
    struct SeccompData {
        nr: i32,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }
    #[repr(C)]
    struct SeccompNotif {
        id: u64,
        pid: u32,
        flags: u32,
        data: SeccompData,
    }
    #[repr(C)]
    struct SeccompNotifResp {
        id: u64,
        val: i64,
        error: i32,
        flags: u32,
    }

    // `_IOC(dir, type, nr, size)` for the asm-generic layout (all our targets):
    // NR[0..8] TYPE[8..16] SIZE[16..30] DIR[30..32], DIR = READ|WRITE = 3.
    const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
        ((dir << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
    }
    fn notif_recv_ioctl() -> libc::c_ulong {
        ioc(
            3,
            b'!' as u32,
            0,
            std::mem::size_of::<SeccompNotif>() as u32,
        )
    }
    fn notif_send_ioctl() -> libc::c_ulong {
        ioc(
            3,
            b'!' as u32,
            1,
            std::mem::size_of::<SeccompNotifResp>() as u32,
        )
    }
    /// `SECCOMP_IOCTL_NOTIF_ID_VALID` = `SECCOMP_IOW(2, __u64)`. The
    /// direction is *write* (dir 1: the id travels userspace → kernel),
    /// not the `IOWR` of the recv / send pair above — the id is an input
    /// and the answer comes back as the ioctl's own return. Kernels 5.0
    /// through 5.3 defined this number with the read direction instead;
    /// the fix (`seccomp: Fix ioctl number for SECCOMP_IOCTL_NOTIF_ID_VALID`)
    /// kept the old number working as an alias, so the corrected value
    /// here is understood by every kernel that has user-notify at all.
    fn notif_id_valid_ioctl() -> libc::c_ulong {
        ioc(1, b'!' as u32, 2, std::mem::size_of::<u64>() as u32)
    }

    /// What the supervisor was able to learn about one `connect`'s
    /// destination ([`read_dest`]).
    ///
    /// Three outcomes, because two of them used to be one `None` — and
    /// collapsing them made the security boundary fail *open*: "this is
    /// an `AF_UNIX` socket" and "the tracee's memory would not read"
    /// were answered with the same value, and that value meant allow.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Dest {
        /// An `AF_INET` / `AF_INET6` destination, fully decoded.
        Inet(IpAddr, u16),
        /// The `sockaddr` was read and names a family that is neither:
        /// `AF_UNIX` (nss, a resolver's local socket), `AF_NETLINK`,
        /// and friends. Local IPC is not egress.
        NotInet,
        /// The `sockaddr` could not be read out of the tracee, or was
        /// read but is too short to decode for the family it claims.
        Unreadable,
    }

    /// Whether one extracted destination is permitted by the hard pin.
    ///
    /// The inet rule is [`super::PinConfig::permits`]: the proxy's own
    /// endpoint, or a configured resolver on port 53 (§The allowset).
    /// Everything else off the two endpoints — including port 53 to an
    /// address that is not a configured resolver — is refused, because
    /// `connect(2)` does not know a protocol and a port number is not
    /// evidence of one.
    fn is_allowed(dest: Dest, config: &super::PinConfig) -> bool {
        match dest {
            // A non-inet family (AF_UNIX, AF_NETLINK) cannot carry
            // off-host egress, and a NULL destination means "the socket's
            // connected peer", already judged at connect time. Refusing
            // either would break local IPC / name resolution.
            //
            // Treating every non-inet family as harmless is safe only
            // because the child ran `PR_SET_NO_NEW_PRIVS` (see
            // `install_and_signal`): it cannot acquire `CAP_NET_RAW` it
            // does not already hold, so an unprivileged `sh.exec` child
            // cannot open an `AF_PACKET` / raw socket to reach off-host
            // outside the inet families this pin decodes. (`AF_UNSPEC` on
            // a send is decoded as `AF_INET`, not treated as non-inet —
            // see [`is_notif_allowed`].)
            Dest::NotInet => true,
            // Fail closed. Every input to the read that just failed is
            // under the tracee's influence — the pointer, the length,
            // and the timing of an `munmap` between the notification
            // and the read — so "I could not tell" must not answer
            // "go ahead" at a security boundary. This is not a
            // transient class: see [`read_sockaddr`] on the stopped
            // tracee.
            Dest::Unreadable => false,
            Dest::Inet(ip, port) => config.permits(ip, port),
        }
    }

    /// Whether the trapped syscall in `notif` is permitted, reading its
    /// destination out of whichever argument slot the syscall uses.
    ///
    /// The switch is keyed on `notif.data.nr` explicitly, and an `nr`
    /// this function does not recognise is **denied** rather than parsed
    /// against the connect layout by default (defence in depth): the BPF
    /// program above traps exactly these four syscalls, so a mismatch
    /// here would mean the filter and this reader had drifted apart, and
    /// the safe reading of that is "refuse", not "guess".
    ///
    /// - `connect(fd, addr, addrlen)` — `addr` at args[1], len args[2].
    /// - `sendto(fd, buf, len, flags, dest, addrlen)` — `dest` at
    ///   args[4], len args[5].
    /// - `sendmsg(fd, msg, flags)` — args[1] is a `struct msghdr*`; the
    ///   destination is its `msg_name` / `msg_namelen`.
    /// - `sendmmsg(fd, msgvec, vlen, flags)` — args[1] is an array of
    ///   `struct mmsghdr`; **every** entry's `msg_name` is checked
    ///   ([`mmsg_allowed`]), because the kernel sends the whole array on
    ///   one syscall.
    ///
    /// **`AF_UNSPEC` differs by syscall.** For the *send* family, Linux's
    /// `udp_sendmsg` treats `sin_family == AF_UNSPEC` as `AF_INET`, so a
    /// zero-family `sockaddr` with a real off-host address is a valid UDP
    /// datagram to that host — it must be decoded with the `AF_INET`
    /// layout and judged, not waved through. For `connect(2)`, `AF_UNSPEC`
    /// means "dissolve the socket's association" (no egress), so it stays
    /// the allowed non-inet case. The `unspec_is_inet` flag (true for the
    /// send family, false for connect) carries that distinction into the
    /// decoder.
    ///
    /// The tracee's memory is opened **once** here and threaded down to
    /// every reader (a `sendmmsg` with a large `vlen` would otherwise
    /// re-open `/proc/<pid>/mem` thousands of times on the blocked-
    /// supervisor path). An open that cannot be completed — even after
    /// [`open_proc_mem`]'s bounded retry — is fail-closed: deny.
    fn is_notif_allowed(notif: &SeccompNotif, config: &super::PinConfig) -> bool {
        let pid = notif.pid;
        let Ok(mem) = open_proc_mem(&format!("/proc/{pid}/mem")) else {
            return false;
        };
        let args = &notif.data.args;
        match notif.data.nr as libc::c_long {
            n if n == libc::SYS_connect => {
                is_allowed(dest_of(&mem, args[1], args[2] as usize, false), config)
            }
            n if n == libc::SYS_sendto => {
                is_allowed(dest_of(&mem, args[4], args[5] as usize, true), config)
            }
            n if n == libc::SYS_sendmsg => is_allowed(msghdr_dest(&mem, args[1], true), config),
            n if n == libc::SYS_sendmmsg => mmsg_allowed(&mem, args[1], args[2], config),
            _ => false,
        }
    }

    // --- the re-read TOCTOU closure: perform the syscall in the supervisor ---
    //
    // `is_notif_allowed` above is the *judgment* (is this destination
    // permitted). Answering a permitted syscall with
    // `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is what leaves the re-read race
    // (§What the supervisor's authorization is worth): the kernel re-runs
    // the real syscall and re-reads the `sockaddr` from the tracee's
    // pointer, so a sibling thread that rewrites that memory after this
    // supervisor read it makes the connect/send that happens a different
    // one from the connect/send that was authorized.
    //
    // The closure is the one `seccomp_unotify(2)` §NOTES prescribes:
    // *perform the operation in the supervisor* on a duplicate of the
    // tracee's own socket fd (`pidfd_getfd`, which returns a fd to the
    // **same open file description**, so the connect lands on the tracee's
    // real socket and the tracee's later sends use it), then answer with a
    // plain result value — **not** `CONTINUE`. The kernel returns that
    // value without re-executing, so the pointer is never re-read.
    //
    // Only a **NULL** address pointer stays a `CONTINUE` (`Plan::Continue`):
    // its NULL-ness is a register argument, fixed at the trap and beyond a
    // sibling thread's reach, so there is nothing to re-read. Every
    // non-NULL address is performed here — a permitted inet destination
    // with a canonical sockaddr rebuilt from the judged `(ip, port)`, and a
    // non-inet destination (`AF_UNIX`, `AF_UNSPEC`-on-connect) with the
    // bytes as read: local IPC is not policed, but performing it still
    // denies the race the chance to turn it into off-host egress. A
    // permitted destination whose payload cannot be copied fails closed
    // (`Plan::Deny`): the supervisor cannot perform a send it cannot read.

    /// The largest datagram payload the supervisor will copy to perform a
    /// send on the tracee's behalf. A single UDP datagram maxes at 64 KiB;
    /// the only address-carrying sends that reach an *allowed* destination
    /// are a musl DNS query to a resolver and the odd fast-open — all far
    /// under this. A larger claimed length denies the send rather than
    /// copying it (a cheap fail-closed bound, not a real limit on
    /// anything legitimate).
    const MAX_SEND_PAYLOAD: usize = 64 * 1024;

    /// The largest `sockaddr` the supervisor copies to perform a non-inet
    /// destination as-read. `sockaddr_un` is 110 bytes (2 family + 108
    /// path); 128 covers every real family with room to spare. An inet
    /// destination is not copied through here — it is rebuilt canonically
    /// from the judged `(ip, port)` ([`serialize_inet`]).
    const MAX_ADDR_COPY: usize = 128;

    /// `UIO_MAXIOV` — the kernel's own cap on `msg_iovlen`. A `sendmsg`
    /// claiming more scatter/gather segments than this is malformed; the
    /// gather denies rather than walking it.
    const IOV_MAX: u64 = 1024;

    /// What the supervisor must do to answer one permitted notification
    /// without a re-readable `CONTINUE`.
    enum Plan {
        /// The judgment did not depend on re-readable pointer contents (a
        /// NULL destination / connected-peer send). `CONTINUE` is safe —
        /// there is nothing a sibling thread can rewrite.
        Continue,
        /// Refuse with `EPERM`: either the destination is not permitted, or
        /// it is but the supervisor could not read what it needs to perform
        /// the syscall itself (fail closed).
        Deny,
        /// Perform `op` on a `pidfd_getfd` duplicate of the tracee's `fd`,
        /// then answer with the result value.
        Emulate { fd: i32, op: EmOp },
    }

    /// The syscall the supervisor performs on the tracee's socket.
    enum EmOp {
        /// `connect(fd, &addr, addr.len())` with the supervisor's own copy
        /// of the sockaddr.
        Connect(Vec<u8>),
        /// A single `sendto`/`sendmsg`: `addr` is `None` for a
        /// connected-peer send (which does not reach here — it is
        /// `Plan::Continue`), `Some` for an explicit destination.
        Send {
            addr: Option<Vec<u8>>,
            payload: Vec<u8>,
            flags: i32,
        },
        /// A `sendmmsg`: each datagram performed in turn; the answer is the
        /// count of datagrams sent, matching the syscall's own return. The
        /// per-message `msg_len` the kernel writes back into each `mmsghdr`
        /// is **not** written back here — the supervisor does not write the
        /// tracee's memory. A caller reading `msg_len[i]` would see it
        /// unchanged. This only affects an address-carrying `sendmmsg` to an
        /// allowed destination (glibc's parallel-DNS `sendmmsg` is on a
        /// connected socket → NULL `msg_name` → `Plan::Continue`, unaffected),
        /// which is rare and not security-relevant (the destinations are
        /// allowed either way).
        SendMulti { dgrams: Vec<Dgram>, flags: i32 },
    }

    /// One datagram of a `sendmmsg` — the same shape as [`EmOp::Send`]'s
    /// fields, minus the per-call `flags` (shared across the array).
    struct Dgram {
        addr: Option<Vec<u8>>,
        payload: Vec<u8>,
    }

    /// Build the [`Plan`] for a permitted notification: what the supervisor
    /// must perform, keyed on the syscall the same way [`is_notif_allowed`]
    /// judges it. Reads the tracee's memory once through `mem`; a read it
    /// needs but cannot complete is [`Plan::Deny`] (fail closed).
    ///
    /// `plan` re-judges the destination itself rather than trusting the
    /// earlier [`is_notif_allowed`] pass: the two reads bracket a window in
    /// which a sibling thread could rewrite the address, so `plan` performs
    /// only what *it* read and judged. If that read now shows an off-host
    /// address, `plan` denies — the combination can only ever be more
    /// restrictive than the gate, never less.
    fn plan(mem: &std::fs::File, notif: &SeccompNotif, config: &super::PinConfig) -> Plan {
        let args = &notif.data.args;
        let fd = args[0] as i32;
        match notif.data.nr as libc::c_long {
            n if n == libc::SYS_connect => plan_connect(mem, fd, args[1], args[2] as usize, config),
            n if n == libc::SYS_sendto => plan_sendto(mem, fd, args, config),
            n if n == libc::SYS_sendmsg => plan_sendmsg(mem, fd, args[1], args[2] as i32, config),
            n if n == libc::SYS_sendmmsg => {
                plan_sendmmsg(mem, fd, args[1], args[2], args[3] as i32, config)
            }
            _ => Plan::Deny,
        }
    }

    /// Resolve a permitted destination pointer into the sockaddr bytes the
    /// supervisor will pass to the syscall.
    ///
    /// `Ok(None)` — a NULL pointer: the caller turns this into
    /// [`Plan::Continue`] (connect) or the connected-peer case (send).
    /// `Ok(Some(bytes))` — the sockaddr to perform: an inet destination
    /// rebuilt canonically from the judged `(ip, port)` (stripping any
    /// trailing bytes the tracee chose), a non-inet destination as read.
    /// `Err(())` — deny: unreadable, or an inet address not in the
    /// allowset.
    #[allow(clippy::result_unit_err)]
    fn resolve_addr(
        mem: &std::fs::File,
        ptr: u64,
        len: usize,
        unspec_is_inet: bool,
        config: &super::PinConfig,
    ) -> Result<Option<Vec<u8>>, ()> {
        if ptr == 0 {
            return Ok(None);
        }
        let Some(raw) = read_addr_copy(mem, ptr, len) else {
            return Err(());
        };
        match classify(&raw, unspec_is_inet) {
            Dest::Unreadable => Err(()),
            Dest::Inet(ip, port) => {
                if config.permits(ip, port) {
                    Ok(Some(serialize_inet(ip, port)))
                } else {
                    Err(())
                }
            }
            // AF_UNIX / AF_UNSPEC-on-connect: not egress, not policed, but
            // performed here (with the bytes as read) so the re-read race
            // cannot turn it into an inet destination.
            Dest::NotInet => Ok(Some(raw)),
        }
    }

    fn plan_connect(
        mem: &std::fs::File,
        fd: i32,
        ptr: u64,
        len: usize,
        config: &super::PinConfig,
    ) -> Plan {
        match resolve_addr(mem, ptr, len, false, config) {
            // A NULL sockaddr on connect is invalid (the kernel EFAULTs);
            // let CONTINUE carry it there rather than inventing an errno.
            Ok(None) => Plan::Continue,
            Ok(Some(addr)) => Plan::Emulate {
                fd,
                op: EmOp::Connect(addr),
            },
            Err(()) => Plan::Deny,
        }
    }

    fn plan_sendto(
        mem: &std::fs::File,
        fd: i32,
        args: &[u64; 6],
        config: &super::PinConfig,
    ) -> Plan {
        // sendto(fd, buf, len, flags, dest_addr, addrlen).
        let addr = match resolve_addr(mem, args[4], args[5] as usize, true, config) {
            Ok(None) => return Plan::Continue, // connected-peer send
            Ok(Some(a)) => Some(a),
            Err(()) => return Plan::Deny,
        };
        let Some(payload) = read_payload(mem, args[1], args[2] as usize) else {
            return Plan::Deny;
        };
        Plan::Emulate {
            fd,
            op: EmOp::Send {
                addr,
                payload,
                flags: args[3] as i32,
            },
        }
    }

    fn plan_sendmsg(
        mem: &std::fs::File,
        fd: i32,
        msghdr_ptr: u64,
        flags: i32,
        config: &super::PinConfig,
    ) -> Plan {
        if msghdr_ptr == 0 {
            // The msghdr pointer itself is a register argument, fixed at
            // the trap; a NULL one the kernel EFAULTs, nothing to send.
            return Plan::Continue;
        }
        let Some((name_ptr, name_len, iov_ptr, iov_len)) = read_msghdr(mem, msghdr_ptr) else {
            return Plan::Deny;
        };
        // `msg_name` lives *inside* the msghdr, in re-readable tracee
        // memory — unlike `connect`/`sendto`, whose destination pointer is
        // a register argument. So even a NULL `msg_name` cannot be answered
        // with `CONTINUE` (a sibling could set it before the kernel
        // re-reads): the supervisor always performs the send itself, with a
        // NULL destination for the connected-peer case.
        let addr = match resolve_addr(mem, name_ptr, name_len, true, config) {
            Ok(None) => None,
            Ok(Some(a)) => Some(a),
            Err(()) => return Plan::Deny,
        };
        let Some(payload) = gather_iov(mem, iov_ptr, iov_len) else {
            return Plan::Deny;
        };
        Plan::Emulate {
            fd,
            op: EmOp::Send {
                addr,
                payload,
                flags,
            },
        }
    }

    fn plan_sendmmsg(
        mem: &std::fs::File,
        fd: i32,
        base: u64,
        vlen: u64,
        flags: i32,
        config: &super::PinConfig,
    ) -> Plan {
        if base == 0 || vlen == 0 {
            // `base` and `vlen` are register arguments — a NULL / zero
            // array is fixed at the trap; nothing to send.
            return Plan::Continue;
        }
        if vlen > MMSG_MAX_ENTRIES as u64 {
            return Plan::Deny; // cannot inspect them all → fail closed
        }
        // Each entry's `msg_name` is inside the re-readable array, so — as
        // for `sendmsg` — the supervisor always performs the whole call
        // rather than `CONTINUE`, even when every entry is a connected-peer
        // send.
        let mut dgrams = Vec::new();
        for i in 0..vlen {
            let hdr_ptr = base.saturating_add(i * MMSGHDR_SIZE);
            let Some((name_ptr, name_len, iov_ptr, iov_len)) = read_msghdr(mem, hdr_ptr) else {
                return Plan::Deny;
            };
            let addr = match resolve_addr(mem, name_ptr, name_len, true, config) {
                Ok(None) => None,
                Ok(Some(a)) => Some(a),
                Err(()) => return Plan::Deny,
            };
            let Some(payload) = gather_iov(mem, iov_ptr, iov_len) else {
                return Plan::Deny;
            };
            dgrams.push(Dgram { addr, payload });
        }
        Plan::Emulate {
            fd,
            op: EmOp::SendMulti { dgrams, flags },
        }
    }

    /// The four fields of a `struct msghdr` (LP64) the supervisor needs:
    /// `(msg_name, msg_namelen, msg_iov, msg_iovlen)`. Offsets: `msg_name`
    /// at 0, `msg_namelen` at 8 (a `socklen_t`, 4 bytes), `msg_iov` at 16,
    /// `msg_iovlen` at 24 (a `size_t`). `None` if the header cannot be read.
    ///
    /// `msg_control` (ancillary data) is deliberately not read: an
    /// allowset destination (a DNS query, the proxy) carries none, and an
    /// off-host send is denied before it reaches here — so the emulated
    /// send omits control data rather than copying and replaying it. A
    /// send that depended on cmsg to an *allowed* endpoint would lose it;
    /// none in the cooperative egress path does.
    fn read_msghdr(mem: &std::fs::File, ptr: u64) -> Option<(u64, usize, u64, u64)> {
        let mut head = [0u8; 32];
        let read = read_mem(mem, ptr, &mut head).ok()?;
        if read < 32 {
            return None;
        }
        let name = u64::from_ne_bytes(head[0..8].try_into().expect("8 bytes"));
        let namelen = u32::from_ne_bytes(head[8..12].try_into().expect("4 bytes")) as usize;
        let iov = u64::from_ne_bytes(head[16..24].try_into().expect("8 bytes"));
        let iovlen = u64::from_ne_bytes(head[24..32].try_into().expect("8 bytes"));
        Some((name, namelen, iov, iovlen))
    }

    /// Read a `sockaddr` copy for the supervisor to perform, bounded by
    /// [`MAX_ADDR_COPY`]. Non-NULL only (callers handle NULL first).
    fn read_addr_copy(mem: &std::fs::File, ptr: u64, len: usize) -> Option<Vec<u8>> {
        let n = len.min(MAX_ADDR_COPY);
        if n == 0 {
            return Some(Vec::new());
        }
        let mut buf = vec![0u8; n];
        let read = read_mem(mem, ptr, &mut buf).ok()?;
        buf.truncate(read);
        Some(buf)
    }

    /// Read a contiguous send payload (`sendto`'s `buf`/`len`), bounded by
    /// [`MAX_SEND_PAYLOAD`]. A length past the bound, or a non-NULL read
    /// that fails, is `None` → the caller denies.
    fn read_payload(mem: &std::fs::File, ptr: u64, len: usize) -> Option<Vec<u8>> {
        if len > MAX_SEND_PAYLOAD {
            return None;
        }
        if len == 0 {
            return Some(Vec::new());
        }
        if ptr == 0 {
            return None; // a non-zero length from a NULL buffer cannot be read
        }
        let mut buf = vec![0u8; len];
        let read = read_mem(mem, ptr, &mut buf).ok()?;
        buf.truncate(read);
        Some(buf)
    }

    /// Gather a `struct iovec` array (a `sendmsg`'s scatter/gather list)
    /// into one contiguous buffer — the datagram the kernel would build.
    /// Each `iovec` is `{ base: *const, len: usize }` (16 bytes, LP64).
    /// `iov_len` past [`IOV_MAX`], or a running total past
    /// [`MAX_SEND_PAYLOAD`], or any unreadable segment, is `None` → deny.
    fn gather_iov(mem: &std::fs::File, iov_ptr: u64, iov_len: u64) -> Option<Vec<u8>> {
        if iov_len == 0 || iov_ptr == 0 {
            return Some(Vec::new());
        }
        if iov_len > IOV_MAX {
            return None;
        }
        let mut out = Vec::new();
        for i in 0..iov_len {
            let entry = iov_ptr.checked_add(i.checked_mul(16)?)?;
            let mut hdr = [0u8; 16];
            let read = read_mem(mem, entry, &mut hdr).ok()?;
            if read < 16 {
                return None;
            }
            let base = u64::from_ne_bytes(hdr[0..8].try_into().expect("8 bytes"));
            let seg = u64::from_ne_bytes(hdr[8..16].try_into().expect("8 bytes")) as usize;
            if out.len().checked_add(seg)? > MAX_SEND_PAYLOAD {
                return None;
            }
            if seg > 0 {
                if base == 0 {
                    return None;
                }
                let mut chunk = vec![0u8; seg];
                let rc = read_mem(mem, base, &mut chunk).ok()?;
                chunk.truncate(rc);
                out.extend_from_slice(&chunk);
            }
        }
        Some(out)
    }

    /// A canonical `sockaddr_in` / `sockaddr_in6` for a judged `(ip, port)`.
    /// Built from the decoded address rather than copied from the tracee,
    /// so the bytes the supervisor connects to are exactly the ones it
    /// judged — no trailing tracee-chosen bytes ride along.
    fn serialize_inet(ip: IpAddr, port: u16) -> Vec<u8> {
        fn bytes_of<T>(value: &T) -> Vec<u8> {
            // SAFETY: `T` is a `#[repr(C)]` libc sockaddr POD; reading its
            // own bytes is sound and the slice does not outlive `value`.
            unsafe {
                std::slice::from_raw_parts(
                    (value as *const T) as *const u8,
                    std::mem::size_of::<T>(),
                )
                .to_vec()
            }
        }
        match ip {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: port.to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                bytes_of(&sa)
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                bytes_of(&sa)
            }
        }
    }

    /// The thread-group id of tracee thread `tid`, read from
    /// `/proc/<tid>/status` `Tgid:`.
    ///
    /// `seccomp_notif.pid` is the tracee **thread's** tid, and
    /// `pidfd_open(2)` on a non-thread-group-leader fails `EINVAL` before
    /// Linux 6.9's `PIDFD_THREAD`, so the supervisor resolves the tid to
    /// its tgid before opening a pidfd. `None` — the status file could not
    /// be read or carried no `Tgid:` — fails the emulation closed.
    fn resolve_tgid(tid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Tgid:") {
                return rest.trim().parse::<u32>().ok();
            }
        }
        None
    }

    /// Perform `op` on a `pidfd_getfd` duplicate of the tracee's socket and
    /// return `(val, errno)` for the notification response: `errno == 0`
    /// means success and `val` is the syscall's return; a non-zero `errno`
    /// is the error to hand back (the caller negates it into
    /// `SeccompNotifResp::error`).
    ///
    /// The duplicate shares the tracee's open file description
    /// ([`pidfd_getfd(2)`]), so a `connect` on it connects the tracee's own
    /// socket and the tracee's later sends use that connection. Any step
    /// that cannot complete — tgid unresolved, pidfd/getfd refused (the
    /// tracee died, or Yama denies the attach) — fails closed with `EPERM`;
    /// the tracee's syscall never reached the network either way.
    ///
    /// A concurrent `close(fd)` in a sibling thread cannot turn this into
    /// an off-host bypass: `pidfd_getfd` would then fail, or duplicate a
    /// recycled fd — and the supervisor only ever performs an *allowed*
    /// destination, so the worst case is an allowset connect on the wrong
    /// socket, never an off-host one.
    fn emulate(fd: i32, op: EmOp, tid: u32) -> (i64, i32) {
        let Some(tgid) = resolve_tgid(tid) else {
            return (0, libc::EPERM);
        };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tgid, 0) };
        if pidfd < 0 {
            return (0, libc::EPERM);
        }
        let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) };
        unsafe { libc::close(pidfd as RawFd) };
        if dup < 0 {
            return (0, libc::EPERM);
        }
        let dup = dup as RawFd;
        let result = match op {
            EmOp::Connect(addr) => do_connect(dup, &addr),
            EmOp::Send {
                addr,
                payload,
                flags,
            } => do_send(dup, addr.as_deref(), &payload, flags),
            EmOp::SendMulti { dgrams, flags } => {
                let mut sent: i64 = 0;
                let mut errno = 0;
                for d in &dgrams {
                    let (_, e) = do_send(dup, d.addr.as_deref(), &d.payload, flags);
                    if e != 0 {
                        // sendmmsg returns the count sent so far; the error
                        // surfaces only if nothing went out at all.
                        errno = if sent == 0 { e } else { 0 };
                        break;
                    }
                    sent += 1;
                }
                (sent, errno)
            }
        };
        unsafe { libc::close(dup) };
        result
    }

    /// Whether `fd` is in non-blocking mode (`O_NONBLOCK`), read through
    /// the shared open file description so it reflects the tracee's own
    /// setting.
    fn is_nonblocking(fd: RawFd) -> bool {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        flags >= 0 && (flags & libc::O_NONBLOCK) != 0
    }

    /// `connect(2)` the tracee's socket to the authorized `addr`.
    ///
    /// Returns `(0, 0)` on success. A non-blocking socket that returns
    /// `EINPROGRESS` relays `EINPROGRESS` unchanged (`(0, EINPROGRESS)`) —
    /// the tracee expects to poll its own fd, which works because it is the
    /// same open file description. A blocking socket, or an `EINTR`
    /// (§`connect(2)` proceeds asynchronously after a signal), is driven to
    /// completion with a bounded `poll` + `SO_ERROR`. Every emulated
    /// `connect` targets an allowset destination — the loopback proxy or a
    /// configured resolver — so the wait is short in practice; the bound
    /// only caps a pathological case.
    fn do_connect(fd: RawFd, addr: &[u8]) -> (i64, i32) {
        let r = unsafe {
            libc::connect(
                fd,
                addr.as_ptr() as *const libc::sockaddr,
                addr.len() as libc::socklen_t,
            )
        };
        if r == 0 {
            return (0, 0);
        }
        let e = errno();
        if e == libc::EINPROGRESS {
            if is_nonblocking(fd) {
                return (0, libc::EINPROGRESS);
            }
            return finish_connect(fd);
        }
        if e == libc::EINTR {
            return finish_connect(fd);
        }
        (0, e)
    }

    /// Wait for a backgrounded `connect` to settle (bounded `poll` for
    /// writability, then `SO_ERROR`). `(0, 0)` on success, `(0, errno)`
    /// otherwise — a `poll` timeout is reported as `ETIMEDOUT`.
    fn finish_connect(fd: RawFd) -> (i64, i32) {
        if !wait_writable(fd, 5_000) {
            return (0, libc::ETIMEDOUT);
        }
        let mut so_error: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return (0, errno());
        }
        if so_error == 0 {
            (0, 0)
        } else {
            (0, so_error)
        }
    }

    /// `sendto(2)` the copied payload to the authorized destination (or the
    /// connected peer, `addr == None`) on the tracee's socket. Returns
    /// `(bytes_sent, 0)` or `(0, errno)`.
    ///
    /// The send is issued with `MSG_DONTWAIT` so it never blocks the single
    /// supervisor thread (which drains every tracee thread's notifications
    /// serially — a blocked send here would stall them all). If it would
    /// block (`EAGAIN`): a non-blocking tracee socket gets the `EAGAIN`
    /// relayed (it expects to retry); a blocking one is given a **bounded**
    /// `poll` for buffer space and one retry, so a blocking-socket send
    /// keeps its blocking semantics up to the cap rather than failing
    /// spuriously or hanging forever. `EINTR` retries.
    fn do_send(fd: RawFd, addr: Option<&[u8]>, payload: &[u8], flags: i32) -> (i64, i32) {
        let (aptr, alen) = match addr {
            Some(a) => (
                a.as_ptr() as *const libc::sockaddr,
                a.len() as libc::socklen_t,
            ),
            None => (std::ptr::null(), 0),
        };
        let send_once = || unsafe {
            libc::sendto(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                flags | libc::MSG_DONTWAIT,
                aptr,
                alen,
            )
        };
        loop {
            let n = send_once();
            if n >= 0 {
                return (n as i64, 0);
            }
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                if is_nonblocking(fd) {
                    return (0, e); // relay to a tracee that expects to poll
                }
                // Blocking socket: wait bounded for send-buffer space, then
                // try once more. A timeout reports ETIMEDOUT rather than
                // stalling the supervisor.
                if !wait_writable(fd, 5_000) {
                    return (0, libc::ETIMEDOUT);
                }
                let n2 = send_once();
                return if n2 >= 0 {
                    (n2 as i64, 0)
                } else {
                    (0, errno())
                };
            }
            return (0, e);
        }
    }

    /// `poll` `fd` for `POLLOUT` up to `timeout_ms`; `true` if it became
    /// writable, `false` on timeout or error. Bounds every wait the
    /// supervisor does on a tracee socket so no single emulated syscall can
    /// park the shared supervisor thread indefinitely.
    fn wait_writable(fd: RawFd, timeout_ms: libc::c_int) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            let pr = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if pr < 0 && errno() == libc::EINTR {
                continue;
            }
            return pr > 0 && (pfd.revents & libc::POLLOUT) != 0;
        }
    }

    /// The current thread's `errno`.
    fn errno() -> i32 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }

    // --- child side: install the filter, hand the listener to the parent ----

    /// Install the user-notify filter and hand its listener fd to the parent —
    /// **without a trapped syscall**.
    ///
    /// The mechanism depends on the [`Mode`]. In `Emulated` the obvious way
    /// to pass the listener — `SCM_RIGHTS` over the socketpair — is a
    /// `sendmsg`, which the full filter traps the instant `seccomp` returns,
    /// before the parent has the listener to answer the trap with. That
    /// deadlocks: the child blocks in the fd-passing `sendmsg`, the parent
    /// blocks waiting to receive it, and the supervisor that would allow it
    /// has no listener yet. So in `Emulated` the fd travels differently: the
    /// child `write`s its own pid and listener fd *number* to `sync_sock` (a
    /// plain `write`, not trapped), then blocks in a `read` for a one-byte
    /// ack. While it is blocked — alive, fd table stable — a parent **helper
    /// thread** lifts the listener out of the child with `pidfd_getfd(2)`
    /// ([`run_pinned`]), acks, and the child then closes its own copy (so an
    /// adversarial child cannot answer its own notifications, and the fd does
    /// not leak across the exec) and proceeds.
    ///
    /// In `ConnectOnly` (the host refused `pidfd_getfd`) the filter traps
    /// `connect` alone, so `sendmsg` is *not* trapped and `SCM_RIGHTS` works:
    /// the child sends the listener fd directly ([`send_fd`]) over
    /// `sync_sock`, waits the same ack, and closes its copy. `write` / `read`
    /// / `sendmsg`(ConnectOnly) / `close` are all `RET_ALLOW` in their mode,
    /// so nothing here traps.
    ///
    /// The helper thread is load-bearing: `Command::spawn` does not return
    /// until the child `exec`s, and the child cannot `exec` until it is
    /// acked — so the ack cannot come from the same thread that calls `spawn`.
    ///
    /// Runs in the **child**, inside `pre_exec`, so it must stay to raw
    /// syscalls (no allocation): a fork child sharing the parent's address
    /// space cannot safely run arbitrary code.
    ///
    /// Which enforcement the pin runs, chosen once by [`run_pinned`] from
    /// whether `pidfd_getfd(2)` is permitted on this host.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// `pidfd_getfd` available: trap the full address-carrying set
        /// (connect + sendto + sendmsg + sendmmsg), hand the listener off by
        /// `pidfd_getfd`, and perform authorized syscalls in the supervisor
        /// (the re-read TOCTOU closure).
        Emulated,
        /// `pidfd_getfd` refused by the host's seccomp (e.g. RunPod under
        /// Docker `Seccomp:2`): trap `connect` alone. `sendmsg` is then not
        /// trapped, so the listener hands off by `SCM_RIGHTS`, and the
        /// supervisor answers `connect` with `CONTINUE` (allow) / `EPERM`
        /// (deny) — no emulation. A best-effort connect pin: a
        /// non-cooperative subprocess's off-host TCP `connect` is still
        /// refused at the syscall, but the send families (UDP / `sendto`)
        /// are unpinned and the CONTINUE re-read race is not closed.
        ConnectOnly,
    }

    /// # Safety
    /// Called only from `pre_exec` on a freshly forked child.
    unsafe fn install_and_signal(
        sync_sock: RawFd,
        parent_end: RawFd,
        mode: Mode,
    ) -> io::Result<()> {
        // Close the fork-inherited copy of the *parent's* socketpair end
        // before blocking on the ack. Both ends were created `SOCK_CLOEXEC`,
        // but close-on-exec has not fired yet — this child has not exec'd,
        // it is about to block in `read_exact` for the ack — so without this
        // the child still holds `parent_end` open, and the peer of
        // `sync_sock` never reaches zero writers. If the parent's handshake
        // then fails (e.g. `pidfd_getfd` is refused by the host's seccomp)
        // and closes *its* `parent_end`, the child's ack read would not see
        // EOF and would block forever — deadlocking `Command::spawn` and
        // hanging the whole step. Closing it here makes that failure a clean
        // EOF → the child errors out → `spawn` returns and the pin fails
        // closed instead of hanging. [measured: 2026-09-01, RunPod pod under
        // Docker Seccomp:2 refusing `pidfd_getfd`, sh.exec hung until killed.]
        libc::close(parent_end);
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        // Two BPF programs, chosen by `mode`. Both open with the arch
        // (+ x32 on x86_64) guards (§Arch check) and the io_uring_setup
        // denial (§io_uring is denied outright); they differ only in which
        // network syscalls reach the supervisor:
        //
        // - `Emulated` traps the full address-carrying set (connect +
        //   sendto + sendmsg + sendmmsg). `sendmsg` being trapped is why the
        //   listener hand-off cannot use `SCM_RIGHTS` and uses `pidfd_getfd`.
        // - `ConnectOnly` traps `connect` alone (§`pidfd_getfd` fallback).
        //   `sendmsg` is left `ALLOW`, so the hand-off *can* use `SCM_RIGHTS`
        //   here — the whole reason this mode exists on a host that refuses
        //   `pidfd_getfd`. Jump offsets are counted from the instruction
        //   after the jump, so the two programs have different targets and
        //   are written out in full rather than edited from one another.
        #[cfg(target_arch = "x86_64")]
        let full = [
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 10,
                k: NATIVE_AUDIT_ARCH,
            },
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP | BPF_JGE | BPF_K,
                jt: 8,
                jf: 0,
                k: X32_SYSCALL_BIT,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 6,
                jf: 0,
                k: libc::SYS_io_uring_setup as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 4,
                jf: 0,
                k: libc::SYS_connect as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 3,
                jf: 0,
                k: libc::SYS_sendto as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: libc::SYS_sendmsg as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: libc::SYS_sendmmsg as u32,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO_EPERM,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
        ];
        // x86_64 connect-only — 10 instructions.
        //   0: A=arch; 1: JEQ NATIVE jf 7→KILL(9); 2: A=nr;
        //   3: JGE X32 jt 5→KILL(9); 4: JEQ io_uring jt 3→EPERM(8);
        //   5: JEQ connect jt 1→NOTIFY(7); 6: ALLOW; 7: NOTIFY; 8: EPERM; 9: KILL
        #[cfg(target_arch = "x86_64")]
        let connect_only = [
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 7,
                k: NATIVE_AUDIT_ARCH,
            },
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP | BPF_JGE | BPF_K,
                jt: 5,
                jf: 0,
                k: X32_SYSCALL_BIT,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 3,
                jf: 0,
                k: libc::SYS_io_uring_setup as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: libc::SYS_connect as u32,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO_EPERM,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
        ];
        // aarch64 full — 12 instructions, no x32 guard.
        #[cfg(target_arch = "aarch64")]
        let full = [
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 9,
                k: NATIVE_AUDIT_ARCH,
            },
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 6,
                jf: 0,
                k: libc::SYS_io_uring_setup as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 4,
                jf: 0,
                k: libc::SYS_connect as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 3,
                jf: 0,
                k: libc::SYS_sendto as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: libc::SYS_sendmsg as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: libc::SYS_sendmmsg as u32,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO_EPERM,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
        ];
        // aarch64 connect-only — 9 instructions.
        //   0: A=arch; 1: JEQ NATIVE jf 6→KILL(8); 2: A=nr;
        //   3: JEQ io_uring jt 3→EPERM(7); 4: JEQ connect jt 1→NOTIFY(6);
        //   5: ALLOW; 6: NOTIFY; 7: EPERM; 8: KILL
        #[cfg(target_arch = "aarch64")]
        let connect_only = [
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 6,
                k: NATIVE_AUDIT_ARCH,
            },
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 3,
                jf: 0,
                k: libc::SYS_io_uring_setup as u32,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: libc::SYS_connect as u32,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO_EPERM,
            },
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
        ];
        let filter: &[SockFilter] = match mode {
            Mode::Emulated => &full,
            Mode::ConnectOnly => &connect_only,
        };
        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        let listener = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            &prog as *const SockFprog as libc::c_long,
        );
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = listener as RawFd;
        // Hand the listener to the parent, then wait for the ack that says it
        // has it. The mechanism depends on the mode (see this function's doc
        // and [`Mode`]).
        match mode {
            Mode::Emulated => {
                // `sendmsg` is trapped, so SCM_RIGHTS would deadlock — write
                // our pid + the listener fd *number* (plain `write`, not
                // trapped) for the parent to lift with `pidfd_getfd`.
                let mut msg = [0u8; 8];
                msg[0..4].copy_from_slice(&(libc::getpid() as i32).to_ne_bytes());
                msg[4..8].copy_from_slice(&(listener as i32).to_ne_bytes());
                write_all(sync_sock, &msg)?;
            }
            Mode::ConnectOnly => {
                // `sendmsg` is NOT trapped in this filter, so pass the
                // listener itself by SCM_RIGHTS directly — no `pidfd_getfd`.
                send_fd(sync_sock, listener)?;
            }
        }
        let mut ack = [0u8; 1];
        read_exact(sync_sock, &mut ack)?;
        // The parent holds a dup now; drop our copy so it neither survives the
        // exec into the target program nor lets an adversarial child answer
        // its own notifications.
        libc::close(listener);
        Ok(())
    }

    /// Send `fd` to the peer of `sock` in a one-byte `SCM_RIGHTS` `sendmsg`
    /// (the `ConnectOnly` hand-off). Raw so it is safe in the child's
    /// `pre_exec`; only reached under the connect-only filter, which does
    /// not trap `sendmsg`, so this call is not itself intercepted.
    ///
    /// # Safety
    /// Called only from `pre_exec` on a freshly forked child.
    unsafe fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        // Room for one fd's control message (CMSG_SPACE(4) is 24 on LP64).
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);
        loop {
            let n = libc::sendmsg(sock, &msg, 0);
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(());
        }
    }

    /// `write(2)` all of `buf`, looping over short writes. Raw so it is
    /// safe in the child's `pre_exec`.
    unsafe fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = libc::write(
                fd,
                buf.as_ptr().add(off) as *const libc::c_void,
                buf.len() - off,
            );
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if n == 0 {
                return Err(io::Error::other("write returned 0"));
            }
            off += n as usize;
        }
        Ok(())
    }

    /// `read(2)` exactly `buf.len()` bytes, looping over short reads.
    unsafe fn read_exact(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = libc::read(
                fd,
                buf.as_mut_ptr().add(off) as *mut libc::c_void,
                buf.len() - off,
            );
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if n == 0 {
                return Err(io::Error::other("unexpected EOF on the sync socket"));
            }
            off += n as usize;
        }
        Ok(())
    }

    // --- parent side: the supervisor loop -----------------------------------

    /// Lift the child's notification listener into the parent with
    /// `pidfd_getfd(2)`, acking the child once the fd is ours. Runs on the
    /// **helper thread** (see [`run_pinned`]); consumes `sync_sock`.
    ///
    /// The child has written its pid + listener fd *number* and is blocked
    /// reading for the ack, so its fd table is stable across the
    /// `pidfd_getfd`. Yama restricts `pidfd_getfd` to a `PTRACE_MODE_ATTACH`
    /// target, which a direct child of the same user satisfies; where it does
    /// not, this returns the error and the pin fails closed (the `sh.exec`
    /// step refuses rather than running unrouted).
    fn lift_listener(sync_sock: RawFd) -> io::Result<RawFd> {
        let result = lift_listener_inner(sync_sock);
        // Whatever happened, close our end: on success the fd is grabbed, on
        // failure the close gives the child's ack `read` an EOF so it exits.
        unsafe { libc::close(sync_sock) };
        result
    }

    fn lift_listener_inner(sync_sock: RawFd) -> io::Result<RawFd> {
        let mut msg = [0u8; 8];
        unsafe { read_exact(sync_sock, &mut msg)? };
        let child_pid = i32::from_ne_bytes(msg[0..4].try_into().expect("4 bytes"));
        let child_listener = i32::from_ne_bytes(msg[4..8].try_into().expect("4 bytes"));

        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
        if pidfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let notify_fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, child_listener, 0) };
        let getfd_err = io::Error::last_os_error();
        unsafe { libc::close(pidfd as RawFd) };
        if notify_fd < 0 {
            return Err(getfd_err);
        }
        let notify_fd = notify_fd as RawFd;

        // The fd is ours; ack so the child closes its copy and exec's.
        if let Err(err) = unsafe { write_all(sync_sock, &[1u8]) } {
            unsafe { libc::close(notify_fd) };
            return Err(err);
        }
        Ok(notify_fd)
    }

    /// Receive the child's notification listener over `SCM_RIGHTS` (the
    /// `ConnectOnly` hand-off), acking once it is ours. The sibling of
    /// [`lift_listener`] for a host that refuses `pidfd_getfd`: the child's
    /// connect-only filter leaves `sendmsg` untrapped, so it sends the fd
    /// directly ([`send_fd`]) and this receives it — no `pidfd_getfd`.
    /// Consumes `sync_sock`.
    fn recv_listener(sync_sock: RawFd) -> io::Result<RawFd> {
        let result = recv_listener_inner(sync_sock);
        // Whatever happened, close our end: on failure the close gives the
        // child's ack `read` an EOF so it exits rather than hanging.
        unsafe { libc::close(sync_sock) };
        result
    }

    fn recv_listener_inner(sync_sock: RawFd) -> io::Result<RawFd> {
        let notify_fd = recv_fd(sync_sock)?;
        // The fd is ours; ack so the child closes its copy and exec's.
        if let Err(err) = unsafe { write_all(sync_sock, &[1u8]) } {
            unsafe { libc::close(notify_fd) };
            return Err(err);
        }
        Ok(notify_fd)
    }

    /// Receive one fd from a `SCM_RIGHTS` `sendmsg` on `sock`. The parent
    /// half of [`send_fd`]; runs on the helper thread (not `pre_exec`), so
    /// it may allocate. A message that carries no `SCM_RIGHTS` fd, or an
    /// EOF before one arrives, is an error → the pin fails closed.
    fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len() as _;
        loop {
            let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if n == 0 {
                return Err(io::Error::other(
                    "EOF on the sync socket before the listener fd arrived",
                ));
            }
            break;
        }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null()
            || unsafe { (*cmsg).cmsg_level } != libc::SOL_SOCKET
            || unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS
        {
            return Err(io::Error::other(
                "hand-off message carried no SCM_RIGHTS listener fd",
            ));
        }
        let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd) };
        Ok(fd)
    }

    /// The largest number of `struct mmsghdr` entries the supervisor
    /// will walk for one `sendmmsg`. A `vlen` past this is denied
    /// wholesale rather than partially inspected — the kernel caps
    /// `sendmmsg` at `UIO_MAXIOV` (1024) messages, so this cap is the
    /// kernel's own and a call claiming more is malformed.
    const MMSG_MAX_ENTRIES: usize = 1024;

    /// `size_of::<struct mmsghdr>()` on LP64: a 56-byte `struct msghdr`
    /// plus a 4-byte `msg_len` plus 4 bytes of tail padding. Used to
    /// stride from one entry's `msghdr` to the next in the tracee's
    /// array ([`mmsg_allowed`]).
    const MMSGHDR_SIZE: u64 = 64;

    /// The destination named by a `sockaddr` pointer + length, with a
    /// NULL pointer meaning "the socket's connected peer".
    ///
    /// A NULL `dest_addr` (the ordinary shape of a `sendto` on a
    /// connected socket) is [`Dest::NotInet`] — allowed, because the
    /// peer it will use was already judged when the socket connected.
    /// A non-NULL pointer is read and classified by [`read_sockaddr`].
    /// `unspec_is_inet` decides how an `AF_UNSPEC` family reads (see
    /// [`is_notif_allowed`]).
    fn dest_of(mem: &std::fs::File, ptr: u64, len: usize, unspec_is_inet: bool) -> Dest {
        if ptr == 0 {
            return Dest::NotInet;
        }
        read_sockaddr(mem, ptr, len, unspec_is_inet)
    }

    /// The destination named by a `sendmsg` `struct msghdr` in the
    /// tracee: `msg_name` (a `sockaddr*` at offset 0) with `msg_namelen`
    /// (a `socklen_t` at offset 8 on LP64).
    ///
    /// A NULL `msg_name` is the connected-peer case ([`Dest::NotInet`]).
    /// A `msghdr` that cannot be read is [`Dest::Unreadable`] — the same
    /// fail-closed answer as an unreadable `sockaddr`, for the same
    /// reason: the send names somewhere the supervisor cannot see.
    fn msghdr_dest(mem: &std::fs::File, msghdr_ptr: u64, unspec_is_inet: bool) -> Dest {
        if msghdr_ptr == 0 {
            return Dest::NotInet;
        }
        // The first 16 bytes of `struct msghdr`: msg_name (8) then
        // msg_namelen (4) + 4 padding.
        let mut head = [0u8; 16];
        let Ok(read) = read_mem(mem, msghdr_ptr, &mut head) else {
            return Dest::Unreadable;
        };
        if read < 16 {
            return Dest::Unreadable;
        }
        let msg_name = u64::from_ne_bytes(head[0..8].try_into().expect("8 bytes"));
        let msg_namelen = u32::from_ne_bytes(head[8..12].try_into().expect("4 bytes")) as usize;
        if msg_name == 0 {
            return Dest::NotInet;
        }
        read_sockaddr(mem, msg_name, msg_namelen, unspec_is_inet)
    }

    /// Whether **every** message in a `sendmmsg` array goes somewhere the
    /// pin allows.
    ///
    /// `sendmmsg` transmits the whole `struct mmsghdr` array on a single
    /// syscall, so one authorization covers all of them — checking only
    /// the first would let a caller hide an off-host destination in
    /// entry two. Each entry's `msghdr` is at `base + i * MMSGHDR_SIZE`
    /// (the `msg_len` counter follows the `msghdr` in each element). A
    /// `vlen` past [`MMSG_MAX_ENTRIES`], or any entry that reads
    /// unallowed, denies the whole call. `sendmmsg` is a send, so each
    /// entry's `AF_UNSPEC` reads as `AF_INET` (`unspec_is_inet = true`).
    fn mmsg_allowed(mem: &std::fs::File, base: u64, vlen: u64, config: &super::PinConfig) -> bool {
        if base == 0 || vlen == 0 {
            return true; // nothing addressed → connected-peer sends only
        }
        let vlen = vlen as usize;
        if vlen > MMSG_MAX_ENTRIES {
            return false; // cannot inspect them all → fail closed
        }
        (0..vlen).all(|i| {
            let hdr_ptr = base.saturating_add(i as u64 * MMSGHDR_SIZE);
            is_allowed(msghdr_dest(mem, hdr_ptr, true), config)
        })
    }

    /// Read and classify a `sockaddr` out of the child's memory.
    ///
    /// Where the line between [`Dest::NotInet`] and [`Dest::Unreadable`]
    /// sits, and why it sits there: the family is the **first two bytes
    /// of every `sockaddr`** (`sa_family_t` is a `u16` at offset 0), so
    /// two bytes successfully read are enough to answer "is this an inet
    /// address at all" — an `AF_UNIX` destination answers that question
    /// completely, whatever follows those two bytes. Fewer than two
    /// bytes answers nothing: the `pread` failed outright (an unmapped
    /// pointer, a page dropped between the notification and the read) or
    /// came back short. An inet family whose address bytes are missing —
    /// `AF_INET` under 8 bytes, `AF_INET6` under 24 — is the same case
    /// wearing a destination's clothes: the send names somewhere, and
    /// this supervisor cannot see where. Both are [`Dest::Unreadable`],
    /// which [`is_allowed`] denies.
    ///
    /// Denying a short inet `sockaddr` costs nothing real: the kernel
    /// rejects an `addrlen` below the family's own `sockaddr` size with
    /// `EINVAL`, so that syscall was going to fail either way — it just
    /// fails as `EPERM` now, without this layer having to trust a length
    /// the tracee chose.
    ///
    /// # Why the read is not retried, but the open is
    ///
    /// [`Dest::Unreadable`] denies, and a denial that fired on a passing
    /// hiccup would turn a working `sh.exec` step into an `EPERM` for no
    /// reason. Two failure surfaces are worth distinguishing.
    ///
    /// The **read** ([`read_at`]'s `read_at` call) is not retried, and
    /// does not need to be: it happens against a **stopped** tracee. A
    /// `SECCOMP_RET_USER_NOTIF` thread is blocked inside the kernel at
    /// the syscall trap until this supervisor answers it — the syscall
    /// has not run, the thread is not scheduled, and its address space
    /// is not being torn down underneath the read. A `pread` of a mapped
    /// page does not fail for load: a paged-out page faults in and the
    /// read waits. So the read failures this can see are structural —
    /// the pointer is not mapped (`EIO`), or the process is gone (and
    /// [`id_is_valid`] discards that notification rather than refusing
    /// it, §What the supervisor's authorization is worth). Reading a
    /// stable pointer twice would only return the same answer twice.
    ///
    /// The **open** of `/proc/<pid>/mem` is different, and *is* retried
    /// ([`read_at`]): `File::open` can fail with `EMFILE` / `ENFILE` /
    /// `ENOMEM` / `EINTR` for reasons that have nothing to do with the
    /// tracee — the supervisor's own fd table is full, the machine is
    /// under memory pressure, a signal interrupted the call. Those are
    /// genuinely transient and unrelated to the destination being
    /// judged, so a legitimate `connect` must not be turned into an
    /// `EPERM` by one. A few attempts with a tiny backoff clears them;
    /// a persistent open failure still denies (now genuinely rare).
    fn read_sockaddr(mem: &std::fs::File, ptr: u64, len: usize, unspec_is_inet: bool) -> Dest {
        let mut buf = [0u8; 28]; // max(sockaddr_in=16, sockaddr_in6=28)
        let n = len.min(buf.len());
        let Ok(read) = read_mem(mem, ptr, &mut buf[..n]) else {
            return Dest::Unreadable;
        };
        classify(&buf[..read], unspec_is_inet)
    }

    /// Decode a `sockaddr` already read into `buf` (`read` bytes) into a
    /// [`Dest`]. Split from [`read_sockaddr`] so the same decode serves
    /// both the judgment path (a 28-byte read) and the emulation path,
    /// which reads a larger copy so an `AF_UNIX` path survives; the byte
    /// layout it decodes is identical either way.
    ///
    /// The family / short-read boundaries are [`read_sockaddr`]'s: two
    /// bytes name the family, an inet family missing its address bytes is
    /// [`Dest::Unreadable`], and `AF_UNSPEC` decodes as `AF_INET` only on
    /// a send (`unspec_is_inet`).
    fn classify(buf: &[u8], unspec_is_inet: bool) -> Dest {
        if buf.len() < 2 {
            return Dest::Unreadable;
        }
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        // On a *send*, the kernel's `udp_sendmsg` reads `AF_UNSPEC` as
        // `AF_INET` (the `sin_port` / `sin_addr` at the sockaddr_in
        // offsets are still a real destination), so it is decoded here as
        // one rather than waved through as non-inet (finding 1). On a
        // `connect`, `unspec_is_inet` is false and `AF_UNSPEC` falls to
        // the non-inet arm — a request to dissolve the association, not an
        // egress.
        let decode_as_inet =
            family == libc::AF_INET as u16 || (unspec_is_inet && family == libc::AF_UNSPEC as u16);
        if decode_as_inet {
            if buf.len() < 8 {
                return Dest::Unreadable;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            return Dest::Inet(IpAddr::V4(ip), port);
        }
        if family == libc::AF_INET6 as u16 {
            if buf.len() < 24 {
                return Dest::Unreadable;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            return Dest::Inet(IpAddr::V6(Ipv6Addr::from(octets)), port);
        }
        Dest::NotInet
    }

    /// Whether notification `id` is still live
    /// (`SECCOMP_IOCTL_NOTIF_ID_VALID`).
    ///
    /// Asked **after** the tracee's memory has been read and **before**
    /// the response is sent — the sequence `seccomp_unotify(2)` §NOTES
    /// prescribes. A `false` means the target died or the notification
    /// was cancelled while the supervisor was reading it, and the id may
    /// already belong to a newer notification; responding then would
    /// answer a syscall this loop never looked at.
    ///
    /// `ENOENT` — the kernel's documented "that id is gone" — is the
    /// only error that answers `false`. Any other errno means the
    /// *question* failed rather than the id: on kernels 5.0 through 5.3
    /// this ioctl exists only under the wrong-direction number and this
    /// call gets `ENOTTY`, and treating that as "invalid" would drop
    /// every notification, leaving each `connect` blocked in the kernel
    /// forever with nothing gained. Where the check cannot be asked,
    /// the destination read still decides — the layer is back to what
    /// it was before this check existed, which is a weaker guarantee
    /// and not a hang. (Answering it properly there would mean retrying
    /// under `SECCOMP_IOR(2, __u64)`; those kernels have been end of
    /// life for years and no target this crate ships for runs one.)
    fn id_is_valid(notify_fd: RawFd, request: libc::c_ulong, id: u64) -> bool {
        // The ioctl takes a pointer to the id; the answer is the return.
        if unsafe { libc::ioctl(notify_fd, request as _, &id) } == 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
    }

    /// `pread` from an already-open `/proc/<pid>/mem` handle at an
    /// absolute offset. The handle is opened once per notification
    /// ([`is_notif_allowed`]) and reused for every sockaddr this reads,
    /// so a `sendmmsg` with a large `vlen` does one open, not thousands.
    ///
    /// The read is not retried (§Why the read is not retried, but the
    /// open is); the open it shares was already retried through
    /// [`open_proc_mem`].
    fn read_mem(mem: &std::fs::File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        mem.read_at(buf, offset)
    }

    /// Open `/proc/<pid>/mem`, retrying a small number of times on the
    /// errno set that is transient and unrelated to the tracee —
    /// `EMFILE` / `ENFILE` (fd-table pressure), `ENOMEM` (memory
    /// pressure), `EINTR` (a signal) — with a tiny backoff between
    /// attempts (§Why the read is not retried, but the open is). Any
    /// other errno, or a persistent transient one, returns the error and
    /// the caller denies.
    fn open_proc_mem(path: &str) -> io::Result<std::fs::File> {
        const ATTEMPTS: usize = 4;
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            match std::fs::File::open(path) {
                Ok(file) => return Ok(file),
                Err(err) => {
                    let transient = matches!(
                        err.raw_os_error(),
                        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::EINTR)
                    );
                    if !transient {
                        return Err(err);
                    }
                    last = Some(err);
                    if attempt + 1 < ATTEMPTS {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("open retries exhausted")))
    }

    /// An owned notification listener fd whose `Drop` closes it —
    /// **including on an unwind** (§the supervisor).
    ///
    /// Closing the listener is what makes the child's trapped syscalls
    /// resolve: `seccomp_unotify(2)` returns `ENOSYS` to a target whose
    /// notification listener has been closed. If the supervisor panicked
    /// and left the fd open, that resolution would never come and the
    /// child's next `connect` — and the parent's `wait_with_output`
    /// behind it — would block forever. Wrapping the raw fd in
    /// [`std::os::fd::OwnedFd`] the moment the supervisor takes it means
    /// the close runs on every exit, normal or panicking, so a supervisor
    /// crash fails the step cleanly (`ENOSYS`) instead of hanging it.
    struct NotifyListener(OwnedFd);

    impl NotifyListener {
        /// Take ownership of the raw listener fd.
        ///
        /// # Safety
        /// `fd` must be an open fd this is the sole owner of.
        unsafe fn from_raw(fd: RawFd) -> Self {
            NotifyListener(OwnedFd::from_raw_fd(fd))
        }

        fn as_raw(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    /// Run the supervisor loop until `stop` is set and no notification is
    /// pending. Each trapped syscall is answered against `config`: allowed
    /// → let the kernel run the real syscall (`CONTINUE`); denied → inject
    /// `EPERM`, so the real send/connect never happens.
    ///
    /// `notify_fd` is taken by value into a [`NotifyListener`] so the
    /// listener is closed on **every** exit, including a panic — which is
    /// what lets the child's trapped syscalls resolve to `ENOSYS` rather
    /// than blocking the parent forever (H4).
    fn supervise(notify_fd: RawFd, stop: Arc<AtomicBool>, config: super::PinConfig, mode: Mode) {
        // SAFETY: `run_pinned` handed us the sole copy of this fd.
        let listener = unsafe { NotifyListener::from_raw(notify_fd) };
        let notify_fd = listener.as_raw();
        let recv_ioctl = notif_recv_ioctl();
        let send_ioctl = notif_send_ioctl();
        let id_valid_ioctl = notif_id_valid_ioctl();
        loop {
            let mut pfd = libc::pollfd {
                fd: notify_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
            if pr == 0 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            if pr < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if pfd.revents & libc::POLLHUP != 0 && pfd.revents & libc::POLLIN == 0 {
                break; // child gone, no more notifications
            }
            let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
            // `ioctl`'s request arg is `c_ulong` on glibc, `c_int` on musl — cast
            // to whichever the target expects (the low 32 bits are the request).
            let rc = unsafe { libc::ioctl(notify_fd, recv_ioctl as _, &mut notif) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            // Decide the answer. `is_notif_allowed` is the destination
            // judgment in both modes; how a *permitted* syscall is answered
            // differs:
            //
            // - `Emulated`: turn it into a `Plan` that answers *without* a
            //   re-readable `CONTINUE` — the supervisor performs the syscall
            //   itself (§the re-read TOCTOU closure). A permitted syscall
            //   whose payload cannot be read fails closed (`Plan::Deny`).
            // - `ConnectOnly`: no emulation is possible (the host refused
            //   `pidfd_getfd`), so a permitted `connect` is `CONTINUE`
            //   (the accepted best-effort re-read race) and a denied one is
            //   `EPERM`. Only `connect` is trapped in this mode.
            let plan = match mode {
                Mode::Emulated => {
                    if is_notif_allowed(&notif, &config) {
                        match open_proc_mem(&format!("/proc/{}/mem", notif.pid)) {
                            Ok(mem) => plan(&mem, &notif, &config),
                            Err(_) => Plan::Deny, // cannot read to perform → fail closed
                        }
                    } else {
                        Plan::Deny
                    }
                }
                Mode::ConnectOnly => {
                    if is_notif_allowed(&notif, &config) {
                        Plan::Continue
                    } else {
                        Plan::Deny
                    }
                }
            };
            // Read, then validate the id, then respond (§What the
            // supervisor's authorization is worth). A notification that
            // went invalid while its memory was being read has nothing
            // left to answer — and its id may already belong to a newer
            // one — so drop it and go back to the poll. Validity is
            // checked **before** performing an emulated syscall so the
            // supervisor never acts for a tracee that has gone.
            if !id_is_valid(notify_fd, id_valid_ioctl, notif.id) {
                continue;
            }
            let mut resp: SeccompNotifResp = unsafe { std::mem::zeroed() };
            resp.id = notif.id;
            match plan {
                Plan::Continue => {
                    // NULL destination / connected-peer send: nothing a
                    // sibling thread can rewrite, so re-execution is safe.
                    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                }
                Plan::Deny => {
                    resp.error = -libc::EPERM;
                    tracing::warn!("egress: off-host network syscall denied at the pin");
                }
                Plan::Emulate { fd, op } => {
                    // Perform the syscall here on the tracee's own socket,
                    // then hand back the result — the kernel does not
                    // re-execute, so the sockaddr is never re-read.
                    let (val, err) = emulate(fd, op, notif.pid);
                    if err == 0 {
                        resp.val = val;
                    } else {
                        resp.error = -err;
                    }
                }
            }
            let sc = unsafe { libc::ioctl(notify_fd, send_ioctl as _, &resp) };
            if sc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                // ENOENT = the notification was cancelled (child died mid-syscall);
                // any other error means the listener is unusable — stop.
                break;
            }
        }
        // `listener` drops here (or on an unwind), closing the fd.
    }

    /// Whether `pidfd_getfd(2)` is usable on this host.
    ///
    /// Opens a pidfd on the current process and tries to duplicate a fd it
    /// is certain exists — the pidfd itself — through `pidfd_getfd`. Success
    /// means the host's seccomp policy permits the call (→ [`Mode::Emulated`]);
    /// an `EPERM` / `ENOSYS` (a container profile that filters it, or a kernel
    /// without it) means [`run_pinned`] falls back to [`Mode::ConnectOnly`].
    /// Using the pidfd as its own target keeps the probe from depending on any
    /// other fd being open, so an `EBADF` cannot be mistaken for a policy
    /// refusal.
    fn pidfd_getfd_available() -> bool {
        let pidfd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id() as libc::c_long, 0) };
        if pidfd < 0 {
            return false;
        }
        let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, pidfd, 0) };
        let ok = dup >= 0;
        if ok {
            unsafe { libc::close(dup as RawFd) };
        }
        unsafe { libc::close(pidfd as RawFd) };
        ok
    }

    /// Run `command` with the egress hard pin: install the filter in the
    /// child, hand its notification listener to the parent, supervise its
    /// trapped syscalls against `config` from a parent thread, and collect
    /// its output like [`Command::output`]. `command`'s stdio must already
    /// be configured by the caller. Reached only through the outer
    /// [`super::run_pinned`], which dispatches by target arch.
    ///
    /// [`pidfd_getfd_available`] chooses the [`Mode`]: `Emulated` (full trap,
    /// `pidfd_getfd` hand-off, syscall emulation) where the host permits
    /// `pidfd_getfd`, else `ConnectOnly` (connect-only trap, `SCM_RIGHTS`
    /// hand-off, `CONTINUE`/`EPERM`) as the fallback for a host that refuses
    /// it (§`pidfd_getfd` fallback).
    pub(super) fn run_pinned(mut command: Command, config: super::PinConfig) -> io::Result<Output> {
        // Choose the mode once, before the fork, from whether the host
        // permits `pidfd_getfd(2)`. The full pin (trap sends + emulate)
        // needs it both to hand off the listener and to perform authorized
        // syscalls; a host whose seccomp refuses it (Docker's default
        // profile on some platforms — measured: RunPod pods under
        // `Seccomp:2`, 2026-09-01, `pidfd_getfd` → EPERM) cannot run that,
        // so fall back to the connect-only pin, which hands off by
        // `SCM_RIGHTS` and answers with `CONTINUE`/`EPERM` (§`pidfd_getfd`
        // fallback). It still refuses a non-cooperative subprocess's
        // off-host `connect` at the syscall; it does not pin the send
        // families or close the re-read race.
        let mode = if pidfd_getfd_available() {
            Mode::Emulated
        } else {
            tracing::warn!(
                "egress: pidfd_getfd refused by this host's seccomp; the hard pin \
                 falls back to connect-only (sendto/UDP unpinned, CONTINUE re-read \
                 race not closed). Use LM_EGRESS_PROXY for full off-host enforcement."
            );
            Mode::ConnectOnly
        };
        let mut fds = [0 as libc::c_int; 2];
        // `SOCK_CLOEXEC`: both ends close at the child's `execve`, so
        // neither the sync socket leaks into the exec'd (untrusted)
        // program (finding 6). The child still inherits `child_sock` across
        // the fork and uses it in `install_and_signal` before the exec —
        // close-on-*exec* does not close it before then.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let (parent_sock, child_sock) = (fds[0], fds[1]);

        unsafe {
            command.pre_exec(move || install_and_signal(child_sock, parent_sock, mode));
        }

        // The handshake runs on its own thread because `spawn` blocks until
        // the child `exec`s and the child cannot `exec` until this acks it —
        // so the ack must not be on the spawning thread (see
        // [`install_and_signal`]). The helper owns `parent_sock` and closes it.
        // The hand-off mechanism matches the mode: `pidfd_getfd` for
        // `Emulated`, `SCM_RIGHTS` receive for `ConnectOnly`.
        let handshake = std::thread::spawn(move || match mode {
            Mode::Emulated => lift_listener(parent_sock),
            Mode::ConnectOnly => recv_listener(parent_sock),
        });

        let child = command.spawn();
        // The parent no longer needs the child's end regardless of outcome; on
        // a spawn failure this frees the socketpair so the helper's read sees
        // EOF and returns rather than blocking forever.
        unsafe { libc::close(child_sock) };
        let child = match child {
            Ok(c) => c,
            Err(err) => {
                // `spawn` can fail *after* `pre_exec` ran and the helper
                // already lifted the listener (a bad `argv[0]` fails at the
                // exec, past the ack). In that case the helper returns
                // `Ok(fd)`; close it here or it leaks — repeated spawn
                // failures in the long-lived apply process would march to
                // `EMFILE` (finding 4). The success path hands the fd to
                // `supervise`, which owns and closes it, so this is the
                // only arm that closes it directly — no double close.
                if let Ok(Ok(fd)) = handshake.join() {
                    unsafe { libc::close(fd) };
                }
                return Err(err);
            }
        };

        let notify_fd = match handshake.join() {
            Ok(Ok(fd)) => fd,
            Ok(Err(err)) => {
                // The helper closed `parent_sock`, so the child's ack `read`
                // saw EOF and exited its `pre_exec`; reap it.
                let mut child = child;
                let _ = child.wait();
                return Err(err);
            }
            Err(_) => {
                let mut child = child;
                let _ = child.wait();
                return Err(io::Error::other("hard-pin handshake thread panicked"));
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let supervisor =
            std::thread::spawn(move || supervise(notify_fd, stop_thread, config, mode));

        let output = child.wait_with_output();
        stop.store(true, Ordering::Relaxed);
        let _ = supervisor.join();
        output
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::process::Stdio;

        /// A config whose proxy endpoint is `addr` and whose only DNS
        /// allowance is the loopback fallback — enough for the read /
        /// classify tests, which care about the `Dest` boundary, not the
        /// resolver set.
        fn cfg_proxy(addr: SocketAddr) -> super::super::PinConfig {
            super::super::PinConfig::for_test(addr, Vec::new(), true)
        }

        /// **The allowset is the proxy endpoint, not any loopback.** The
        /// proxy `SocketAddr` is admitted; a different loopback port is
        /// not; an off-host address is not.
        #[test]
        fn is_allowed_admits_the_proxy_endpoint_and_refuses_other_loopback() {
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);
            assert!(is_allowed(
                Dest::Inet(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                &cfg
            ));
            // A local Docker API / DB on another loopback port: refused.
            assert!(!is_allowed(
                Dest::Inet(IpAddr::V4(Ipv4Addr::LOCALHOST), 2375),
                &cfg
            ));
            assert!(!is_allowed(
                Dest::Inet(IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)), 443),
                &cfg
            ));
            assert!(is_allowed(Dest::NotInet, &cfg));
            assert!(!is_allowed(Dest::Unreadable, &cfg));
        }

        /// **A configured off-host resolver is reachable on :53; an
        /// unconfigured off-host address on :53 is not.** This is the
        /// round-4 regression closure — a real `10.x` nameserver must
        /// resolve — paired with the H3 tightening: port 53 alone grants
        /// nothing.
        #[test]
        fn is_allowed_admits_a_configured_resolver_on_port_53_only() {
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let resolver: IpAddr = "10.0.0.53".parse().unwrap();
            let cfg = super::super::PinConfig::for_test(proxy, vec![resolver], false);
            assert!(is_allowed(Dest::Inet(resolver, 53), &cfg));
            assert!(!is_allowed(Dest::Inet(resolver, 443), &cfg));
            assert!(!is_allowed(
                Dest::Inet("8.8.8.8".parse().unwrap(), 53),
                &cfg
            ));
            // A loopback stub is not admitted when resolv.conf named a
            // different resolver (fallback off).
            assert!(!is_allowed(
                Dest::Inet("127.0.0.53".parse().unwrap(), 53),
                &cfg
            ));
        }

        /// Build a notification for syscall `nr` whose args are `args`,
        /// pointing into **this** process's memory. `/proc/self/mem`
        /// reads the same way `/proc/<child>/mem` does, so the readers
        /// can be exercised against real bytes without a child to trace.
        fn notif(nr: libc::c_long, args: [u64; 6]) -> SeccompNotif {
            let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
            notif.pid = std::process::id();
            notif.data.nr = nr as i32;
            notif.data.args = args;
            notif
        }

        /// A `sockaddr_in` for `ip:port`, big-endian port, 16 bytes.
        fn sockaddr_in(ip: Ipv4Addr, port: u16) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            v.extend_from_slice(&port.to_be_bytes());
            v.extend_from_slice(&ip.octets());
            v.extend_from_slice(&[0u8; 8]); // sin_zero
            v
        }

        /// The reader tests read our own memory: `/proc/self/mem` behaves
        /// exactly like the `/proc/<child>/mem` the supervisor opens.
        fn self_mem() -> std::fs::File {
            open_proc_mem("/proc/self/mem").expect("open /proc/self/mem")
        }

        /// **`read_sockaddr` decodes what it can read and admits what it
        /// cannot.** A `sockaddr_in`, an `AF_UNIX` sockaddr, a NULL
        /// pointer, and an `AF_INET` header truncated below its address
        /// bytes — the four outcomes, against real memory.
        #[test]
        fn read_sockaddr_separates_inet_from_non_inet_from_unreadable() {
            let mem = self_mem();
            let v4 = sockaddr_in(Ipv4Addr::new(140, 82, 121, 4), 443);
            assert_eq!(
                read_sockaddr(&mem, v4.as_ptr() as u64, 16, false),
                Dest::Inet(IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)), 443)
            );

            // sockaddr_un: family plus a path. Local IPC, not egress.
            let mut un = Vec::new();
            un.extend_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
            un.extend_from_slice(b"/var/run/nscd/socket\0");
            assert_eq!(
                read_sockaddr(&mem, un.as_ptr() as u64, un.len(), false),
                Dest::NotInet
            );

            // NULL through `dest_of` is the connected-peer case.
            assert_eq!(dest_of(&mem, 0, 16, false), Dest::NotInet);

            // An inet family whose address bytes are not there.
            assert_eq!(
                read_sockaddr(&mem, v4.as_ptr() as u64, 4, false),
                Dest::Unreadable
            );
        }

        /// **`AF_UNSPEC` is an off-host UDP exfil vector on the send
        /// family, and is decoded as `AF_INET` there (finding 1).** Linux
        /// treats a zero-family `sockaddr` on `sendmsg`/`sendto` as
        /// `AF_INET`, so a family-0 sockaddr with an off-host address must
        /// be denied; on `connect`, family 0 is "dissolve the association"
        /// and stays allowed. A send-family family-0 too short for
        /// `sockaddr_in` is `Unreadable` → denied.
        #[test]
        fn af_unspec_is_inet_on_a_send_but_not_on_connect() {
            let mem = self_mem();

            // sockaddr_in bytes but with family 0x0000 (AF_UNSPEC),
            // off-host address and a real port — a valid UDP datagram.
            let mut unspec_off = sockaddr_in(Ipv4Addr::new(203, 0, 113, 1), 53);
            unspec_off[0..2].copy_from_slice(&(libc::AF_UNSPEC as u16).to_ne_bytes());
            // The same shape aimed at the proxy endpoint (allowed on send).
            let mut unspec_proxy = sockaddr_in(Ipv4Addr::LOCALHOST, 8080);
            unspec_proxy[0..2].copy_from_slice(&(libc::AF_UNSPEC as u16).to_ne_bytes());

            // Send family (`unspec_is_inet = true`): decoded as AF_INET.
            assert_eq!(
                read_sockaddr(&mem, unspec_off.as_ptr() as u64, 16, true),
                Dest::Inet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 53)
            );
            assert_eq!(
                read_sockaddr(&mem, unspec_proxy.as_ptr() as u64, 16, true),
                Dest::Inet(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
            );
            // Too short for a sockaddr_in on the send path → Unreadable.
            assert_eq!(
                read_sockaddr(&mem, unspec_off.as_ptr() as u64, 4, true),
                Dest::Unreadable
            );

            // connect (`unspec_is_inet = false`): family 0 is non-inet.
            assert_eq!(
                read_sockaddr(&mem, unspec_off.as_ptr() as u64, 16, false),
                Dest::NotInet
            );
        }

        /// **The end-to-end judgement: a family-0 `sendto` to an off-host
        /// address is DENIED, and `connect` with `AF_UNSPEC` is still
        /// allowed.** This is the closure of the HIGH bypass — the shipped
        /// `sendto` e2e used `('203.0.113.1', 53)`, which Python encodes as
        /// `AF_INET`, so it never exercised the AF_UNSPEC path.
        #[test]
        fn is_notif_allowed_denies_an_af_unspec_send_but_allows_an_af_unspec_connect() {
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);

            let mut unspec_off = sockaddr_in(Ipv4Addr::new(203, 0, 113, 1), 53);
            unspec_off[0..2].copy_from_slice(&(libc::AF_UNSPEC as u16).to_ne_bytes());

            // sendto with family 0 to an off-host address: denied.
            assert!(!is_notif_allowed(
                &notif(
                    libc::SYS_sendto,
                    [3, 0, 1, 0, unspec_off.as_ptr() as u64, 16]
                ),
                &cfg
            ));
            // sendmsg with a family-0 msg_name to an off-host address: denied.
            let hdr = msghdr_for(&unspec_off);
            assert!(!is_notif_allowed(
                &notif(libc::SYS_sendmsg, [3, hdr.as_ptr() as u64, 0, 0, 0, 0]),
                &cfg
            ));
            // connect with AF_UNSPEC: allowed (dissolve association).
            assert!(is_notif_allowed(
                &notif(
                    libc::SYS_connect,
                    [3, unspec_off.as_ptr() as u64, 16, 0, 0, 0]
                ),
                &cfg
            ));
        }

        /// **`is_notif_allowed` reads the destination out of the right
        /// argument slot for each trapped syscall** — the H1 fix. Before
        /// it, only `connect`'s slot (args[1]) was read, so a `sendto`
        /// (dest at args[4]) or a `sendmsg` (dest inside a `msghdr` at
        /// args[1]) reached an off-host address unexamined.
        #[test]
        fn is_notif_allowed_reads_the_destination_slot_of_each_syscall() {
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);

            let off_host = sockaddr_in(Ipv4Addr::new(203, 0, 113, 1), 53);
            let to_proxy = sockaddr_in(Ipv4Addr::LOCALHOST, 8080);

            // connect: sockaddr at args[1], len at args[2].
            assert!(!is_notif_allowed(
                &notif(
                    libc::SYS_connect,
                    [3, off_host.as_ptr() as u64, 16, 0, 0, 0]
                ),
                &cfg
            ));
            assert!(is_notif_allowed(
                &notif(
                    libc::SYS_connect,
                    [3, to_proxy.as_ptr() as u64, 16, 0, 0, 0]
                ),
                &cfg
            ));

            // sendto: dest at args[4], len at args[5]. args[1] deliberately
            // points at the *off-host* buffer to prove the old code (which
            // read args[1]) would have mis-decided.
            assert!(!is_notif_allowed(
                &notif(
                    libc::SYS_sendto,
                    [
                        3,
                        off_host.as_ptr() as u64,
                        1,
                        0,
                        off_host.as_ptr() as u64,
                        16
                    ]
                ),
                &cfg
            ));
            assert!(is_notif_allowed(
                &notif(libc::SYS_sendto, [3, 0, 1, 0, to_proxy.as_ptr() as u64, 16]),
                &cfg
            ));

            // sendto with a NULL dest (connected socket) → allowed.
            assert!(is_notif_allowed(
                &notif(libc::SYS_sendto, [3, off_host.as_ptr() as u64, 1, 0, 0, 0]),
                &cfg
            ));

            // sendmsg: args[1] is a msghdr whose msg_name points at the
            // sockaddr and msg_namelen is its length.
            let off_hdr = msghdr_for(&off_host);
            assert!(!is_notif_allowed(
                &notif(libc::SYS_sendmsg, [3, off_hdr.as_ptr() as u64, 0, 0, 0, 0]),
                &cfg
            ));

            // An unrecognised nr is denied (H6 defence in depth).
            assert!(!is_notif_allowed(&notif(libc::SYS_write, [0; 6]), &cfg));
        }

        /// A `struct msghdr` (LP64) whose `msg_name` points at `addr` and
        /// `msg_namelen` is its length; the rest zero. 56 bytes.
        fn msghdr_for(addr: &[u8]) -> Vec<u8> {
            let mut hdr = vec![0u8; 56];
            hdr[0..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
            hdr[8..12].copy_from_slice(&(addr.len() as u32).to_ne_bytes());
            hdr
        }

        /// **`sendmmsg` checks every entry, not just the first.** The
        /// kernel sends the whole array on one syscall, so an off-host
        /// destination hidden in the second message must deny the call.
        #[test]
        fn is_notif_allowed_checks_every_sendmmsg_entry() {
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);

            let ok = sockaddr_in(Ipv4Addr::LOCALHOST, 8080);
            let bad = sockaddr_in(Ipv4Addr::new(203, 0, 113, 1), 443);

            // Two mmsghdr entries (64 bytes each): entry 0 → proxy (ok),
            // entry 1 → off-host (must sink the whole call).
            let mut arr = [0u8; 128];
            arr[0..56].copy_from_slice(&msghdr_for(&ok));
            arr[64..120].copy_from_slice(&msghdr_for(&bad));
            assert!(!is_notif_allowed(
                &notif(libc::SYS_sendmmsg, [3, arr.as_ptr() as u64, 2, 0, 0, 0]),
                &cfg
            ));

            // Both entries to the proxy → allowed.
            let mut good = [0u8; 128];
            good[0..56].copy_from_slice(&msghdr_for(&ok));
            good[64..120].copy_from_slice(&msghdr_for(&ok));
            assert!(is_notif_allowed(
                &notif(libc::SYS_sendmmsg, [3, good.as_ptr() as u64, 2, 0, 0, 0]),
                &cfg
            ));

            // A vlen past the kernel cap is denied wholesale.
            assert!(!is_notif_allowed(
                &notif(
                    libc::SYS_sendmmsg,
                    [
                        3,
                        good.as_ptr() as u64,
                        (MMSG_MAX_ENTRIES + 1) as u64,
                        0,
                        0,
                        0
                    ]
                ),
                &cfg
            ));
        }

        /// **The notification listener closes on drop** (H4 RAII). A
        /// supervisor panic must not leak the fd — the leaked-open
        /// listener is what would hang the child's next connect. Proven
        /// by wrapping a real fd and asserting it is closed after the
        /// guard drops.
        #[test]
        fn notify_listener_closes_the_fd_on_drop() {
            let mut fds = [0 as libc::c_int; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let (read_fd, write_fd) = (fds[0], fds[1]);
            {
                let listener = unsafe { NotifyListener::from_raw(read_fd) };
                assert_eq!(listener.as_raw(), read_fd);
            }
            // After the guard drops the fd is closed: F_GETFD → EBADF.
            let rc = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
            assert_eq!(rc, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            unsafe { libc::close(write_fd) };
        }

        /// End-to-end: a real subprocess under the pin reaches the proxy
        /// endpoint (allowed) but is refused a direct external connect
        /// (denied at the syscall). The proxy endpoint here is a loopback
        /// listener whose address is threaded into the [`PinConfig`], so
        /// the test exercises the H3 "only the proxy addr" rule, not the
        /// old "any loopback" one.
        #[test]
        fn pinned_subprocess_reaches_the_proxy_but_not_external() {
            use std::io::Read;
            use std::net::TcpListener;

            // Stand in for the proxy: a loopback listener whose addr is
            // the one the pin will admit.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let proxy_addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut _b = [0u8; 1];
                    let _ = s.read(&mut _b);
                }
            });

            // bash /dev/tcp: dial the proxy addr (allowed), then an
            // external TEST-NET-3 address (must be EPERM'd).
            let script = format!(
                "exec 3<>/dev/tcp/127.0.0.1/{port} && echo PROXY_OK; \
                 (exec 4<>/dev/tcp/203.0.113.1/80) 2>/dev/null && echo EXTERNAL_LEAK || echo EXTERNAL_BLOCKED",
                port = proxy_addr.port()
            );
            let mut cmd = Command::new("bash");
            cmd.arg("-c").arg(script);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());

            let out = run_pinned(cmd, cfg_proxy(proxy_addr)).expect("run pinned");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("PROXY_OK"),
                "the proxy endpoint should connect: {stdout}"
            );
            assert!(
                stdout.contains("EXTERNAL_BLOCKED"),
                "external connect must be denied at the syscall: {stdout}"
            );
        }

        /// End-to-end for H1: a subprocess that reaches off-host by
        /// **`sendto`** (unconnected UDP, never a `connect`) is denied at
        /// the syscall. Needs `python3` for a raw `sendto`; skipped when
        /// it is absent (the deterministic `is_notif_allowed` test above
        /// carries the guarantee either way).
        #[test]
        fn pinned_subprocess_cannot_sendto_off_host() {
            let Some(python) = find_python3() else {
                eprintln!("skipping: python3 not found");
                return;
            };
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            // Built with `concat!` so the Python indentation is literal string
            // content — a `\`-continuation would eat the leading spaces and
            // hand Python an `IndentationError`.
            let script = concat!(
                "import socket\n",
                "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
                "try:\n",
                "    s.sendto(b'x', ('203.0.113.1', 53))\n",
                "    print('SENDTO_LEAK')\n",
                "except OSError as e:\n",
                "    print('SENDTO_BLOCKED' if e.errno == 1 else 'SENDTO_ERR%d' % e.errno)\n",
            );
            let mut cmd = Command::new(python);
            cmd.arg("-c").arg(script);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let out = run_pinned(cmd, cfg_proxy(proxy)).expect("run pinned");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stdout.contains("SENDTO_BLOCKED"),
                "an unconnected UDP sendto off-host must be denied: stdout={stdout:?} stderr={stderr:?} status={:?}",
                out.status
            );
        }

        /// **The 2a closure at the plan layer: a permitted inet `connect`
        /// is *performed* by the supervisor (`Plan::Emulate`), never
        /// answered with `CONTINUE`.** Only a NULL pointer — a register
        /// argument, beyond a sibling thread's reach — stays `Continue`;
        /// an `AF_UNIX` destination is performed too (so the re-read race
        /// cannot flip it to an inet address), and a disallowed inet
        /// destination denies.
        #[test]
        fn a_permitted_inet_connect_is_emulated_not_continued() {
            let mem = self_mem();
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);
            let to_proxy = sockaddr_in(Ipv4Addr::LOCALHOST, 8080);

            match plan(
                &mem,
                &notif(
                    libc::SYS_connect,
                    [3, to_proxy.as_ptr() as u64, 16, 0, 0, 0],
                ),
                &cfg,
            ) {
                Plan::Emulate {
                    fd: 3,
                    op: EmOp::Connect(addr),
                } => {
                    // The performed sockaddr is the canonical one, decoding
                    // back to exactly the judged endpoint.
                    assert_eq!(
                        classify(&addr, false),
                        Dest::Inet(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
                    );
                }
                _ => panic!("a permitted inet connect must emulate, not CONTINUE"),
            }

            // NULL addr: register-based, nothing to re-read → Continue.
            assert!(matches!(
                plan(&mem, &notif(libc::SYS_connect, [3, 0, 16, 0, 0, 0]), &cfg),
                Plan::Continue
            ));

            // Disallowed inet destination → Deny.
            let off = sockaddr_in(Ipv4Addr::new(203, 0, 113, 1), 80);
            assert!(matches!(
                plan(
                    &mem,
                    &notif(libc::SYS_connect, [3, off.as_ptr() as u64, 16, 0, 0, 0]),
                    &cfg
                ),
                Plan::Deny
            ));

            // AF_UNIX: performed (local IPC, not policed) — Emulate, never
            // Continue, so the race cannot turn it into inet egress.
            let mut un = Vec::new();
            un.extend_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
            un.extend_from_slice(b"/run/nscd/socket\0");
            assert!(matches!(
                plan(
                    &mem,
                    &notif(
                        libc::SYS_connect,
                        [3, un.as_ptr() as u64, un.len() as u64, 0, 0, 0]
                    ),
                    &cfg
                ),
                Plan::Emulate {
                    op: EmOp::Connect(_),
                    ..
                }
            ));
        }

        /// **A connected-peer send stays `Continue`; an explicit permitted
        /// destination is emulated with the payload copied out of the
        /// tracee.** The copy is what lets the supervisor send it itself
        /// rather than let the kernel re-read (and a sibling thread rewrite)
        /// the destination.
        #[test]
        fn a_send_to_a_permitted_destination_copies_the_payload() {
            let mem = self_mem();
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);
            let to_proxy = sockaddr_in(Ipv4Addr::LOCALHOST, 8080);
            let payload = b"hello dns";

            match plan(
                &mem,
                &notif(
                    libc::SYS_sendto,
                    [
                        3,
                        payload.as_ptr() as u64,
                        payload.len() as u64,
                        0,
                        to_proxy.as_ptr() as u64,
                        16,
                    ],
                ),
                &cfg,
            ) {
                Plan::Emulate {
                    op:
                        EmOp::Send {
                            addr: Some(_),
                            payload: got,
                            flags: 0,
                        },
                    ..
                } => assert_eq!(got, payload),
                _ => panic!("a permitted sendto must emulate with the copied payload"),
            }

            // sendto NULL dest = connected-peer send → Continue is safe:
            // the destination register (args[4]) is fixed at the trap.
            assert!(matches!(
                plan(
                    &mem,
                    &notif(
                        libc::SYS_sendto,
                        [3, payload.as_ptr() as u64, payload.len() as u64, 0, 0, 0]
                    ),
                    &cfg
                ),
                Plan::Continue
            ));
        }

        /// **`sendmsg` / `sendmmsg` never `CONTINUE`, even for a NULL
        /// `msg_name`** — the destination lives inside a re-readable
        /// `struct msghdr`, so a sibling could set it after the judgment.
        /// The supervisor performs the send itself (a NULL destination
        /// stands for the connected peer).
        #[test]
        fn a_sendmsg_with_a_null_name_is_emulated_not_continued() {
            let mem = self_mem();
            let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let cfg = cfg_proxy(proxy);
            let payload = b"query";

            // A msghdr with msg_name == NULL but a real iov payload.
            let mut hdr = [0u8; 32];
            // msg_name (0..8) left zero; msg_namelen (8..12) zero.
            let iov = {
                let mut v = Vec::new();
                v.extend_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
                v.extend_from_slice(&(payload.len() as u64).to_ne_bytes());
                v
            };
            hdr[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            hdr[24..32].copy_from_slice(&1u64.to_ne_bytes());

            match plan(
                &mem,
                &notif(libc::SYS_sendmsg, [3, hdr.as_ptr() as u64, 0, 0, 0, 0]),
                &cfg,
            ) {
                Plan::Emulate {
                    op:
                        EmOp::Send {
                            addr: None,
                            payload: got,
                            ..
                        },
                    ..
                } => assert_eq!(got, payload),
                _ => panic!("a NULL-name sendmsg must emulate a connected-peer send, not CONTINUE"),
            }

            // Only a NULL msghdr *pointer* (a register) stays Continue.
            assert!(matches!(
                plan(&mem, &notif(libc::SYS_sendmsg, [3, 0, 0, 0, 0, 0]), &cfg),
                Plan::Continue
            ));
        }

        /// **`gather_iov` concatenates the scatter/gather segments into the
        /// one datagram the kernel would build, and refuses an oversized
        /// `iov_len`.**
        #[test]
        fn gather_iov_concatenates_and_bounds() {
            let mem = self_mem();
            let a = b"AAAA";
            let b = b"BBBBBB";
            let mut iov = Vec::new();
            iov.extend_from_slice(&(a.as_ptr() as u64).to_ne_bytes());
            iov.extend_from_slice(&(a.len() as u64).to_ne_bytes());
            iov.extend_from_slice(&(b.as_ptr() as u64).to_ne_bytes());
            iov.extend_from_slice(&(b.len() as u64).to_ne_bytes());

            assert_eq!(
                gather_iov(&mem, iov.as_ptr() as u64, 2).expect("gather"),
                b"AAAABBBBBB"
            );
            // Past the kernel's iovec cap → deny.
            assert!(gather_iov(&mem, iov.as_ptr() as u64, IOV_MAX + 1).is_none());
            // No segments → empty datagram.
            assert_eq!(
                gather_iov(&mem, iov.as_ptr() as u64, 0).unwrap(),
                Vec::<u8>::new()
            );
        }

        /// **`serialize_inet` round-trips through `classify`** for v4 and
        /// v6 — the canonical bytes the supervisor connects to decode back
        /// to exactly the judged endpoint, with no tracee-chosen tail.
        #[test]
        fn serialize_inet_round_trips() {
            let v4 = "140.82.121.4".parse::<IpAddr>().unwrap();
            assert_eq!(
                classify(&serialize_inet(v4, 443), false),
                Dest::Inet(v4, 443)
            );
            let v6 = "2001:4860:4860::8888".parse::<IpAddr>().unwrap();
            assert_eq!(classify(&serialize_inet(v6, 53), false), Dest::Inet(v6, 53));
        }

        /// **`read_msghdr` reads `msg_iov` / `msg_iovlen` from the LP64
        /// layout**, the fields the send-family emulation needs and the
        /// judgment-only `msghdr_dest` never read (it stopped at
        /// `msg_namelen`).
        #[test]
        fn read_msghdr_reads_name_and_iov_fields() {
            let addr = sockaddr_in(Ipv4Addr::LOCALHOST, 8080);
            let iov_marker = 0xdead_beef_u64;
            let mut hdr = [0u8; 32];
            hdr[0..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
            hdr[8..12].copy_from_slice(&(addr.len() as u32).to_ne_bytes());
            hdr[16..24].copy_from_slice(&iov_marker.to_ne_bytes());
            hdr[24..32].copy_from_slice(&3u64.to_ne_bytes());
            let mem = self_mem();
            let (name, namelen, iov, iovlen) =
                read_msghdr(&mem, hdr.as_ptr() as u64).expect("read msghdr");
            assert_eq!(name, addr.as_ptr() as u64);
            assert_eq!(namelen, addr.len());
            assert_eq!(iov, iov_marker);
            assert_eq!(iovlen, 3);
        }

        /// **End-to-end: send-family emulation actually delivers the
        /// payload.** A permitted `sendto` is not re-executed — the
        /// supervisor copies the datagram and sends it on the tracee's own
        /// socket. Proven by binding a real UDP socket as the allowed
        /// endpoint and asserting the bytes arrive. Needs `python3`;
        /// skipped when absent.
        #[test]
        fn emulated_sendto_delivers_the_payload_to_the_allowed_endpoint() {
            use std::net::UdpSocket;
            let Some(python) = find_python3() else {
                eprintln!("skipping: python3 not found");
                return;
            };
            // The allowed endpoint is a real UDP socket; its address is the
            // pin's proxy, so a sendto to it is permitted and emulated.
            let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
            recv.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let addr = recv.local_addr().unwrap();
            let script = format!(
                concat!(
                    "import socket\n",
                    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
                    "n = s.sendto(b'EMULATED_OK', ('127.0.0.1', {port}))\n",
                    "print('SENT%d' % n)\n",
                ),
                port = addr.port()
            );
            let mut cmd = Command::new(python);
            cmd.arg("-c").arg(script);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let out = run_pinned(cmd, cfg_proxy(addr)).expect("run pinned");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("SENT11"),
                "the emulated sendto should report 11 bytes: stdout={stdout:?} stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            let mut buf = [0u8; 64];
            let (n, _) = recv
                .recv_from(&mut buf)
                .expect("the emulated datagram must arrive at the allowed endpoint");
            assert_eq!(
                &buf[..n],
                b"EMULATED_OK",
                "the supervisor must deliver the copied payload"
            );
        }

        /// **`pidfd_getfd` is available on the test host**, so the probe
        /// [`run_pinned`] gates on returns true here and the pin runs. On a
        /// host whose seccomp refuses `pidfd_getfd` (a Docker container under
        /// the default profile — measured on RunPod, 2026-09-01) the probe
        /// returns false and `run_pinned` fails closed with a message
        /// pointing at the external gateway, rather than deadlocking the
        /// listener hand-off. The refusal path itself is not unit-testable
        /// here (it needs a restricting seccomp policy this test process is
        /// not under), but the probe is the single point that decides it.
        #[test]
        fn pidfd_getfd_probe_is_true_on_an_unrestricted_host() {
            assert!(
                pidfd_getfd_available(),
                "the dev/CI host must permit pidfd_getfd; if this fails the \
                 host's seccomp is refusing it and the pin would fail closed"
            );
        }

        /// Locate `python3` on `PATH`, for the optional `sendto` e2e.
        fn find_python3() -> Option<std::path::PathBuf> {
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .map(|dir| dir.join("python3"))
                .find(|candidate| candidate.is_file())
        }
    }
}

#[cfg(all(test, not(any(target_arch = "x86_64", target_arch = "aarch64")),))]
mod tests_unsupported {
    use super::*;
    use std::process::Command;

    /// On an unsupported Linux arch the entry point returns an
    /// `io::Error` naming the target rather than falling back to an
    /// arch-blind filter (§Unsupported arches).
    #[test]
    fn run_pinned_refuses_on_unsupported_arch() {
        let cmd = Command::new("/bin/true");
        let config = super::PinConfig::for_proxy("127.0.0.1:8080".parse().unwrap());
        let err = run_pinned(cmd, config).expect_err("run_pinned must refuse on unsupported arch");
        let msg = err.to_string();
        assert!(msg.contains("target_arch="), "{msg}");
        assert!(msg.contains(std::env::consts::ARCH), "{msg}");
    }
}
