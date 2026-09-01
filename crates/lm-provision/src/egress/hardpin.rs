//! Hard enforcement layer for the sh.exec egress pin (Linux only).
//!
//! The soft layer ([`super::proxy`]) captures every subprocess that honours
//! `HTTPS_PROXY`. A subprocess that *ignores* the proxy env and opens its own
//! socket to an off-host address would slip past it. This layer closes that:
//! a subprocess is spawned under a seccomp `connect(2)` user-notify filter, and
//! a supervisor in the parent inspects each `connect` destination and refuses
//! anything that is not loopback (the self-hosted proxy) or DNS.
//!
//! Why that allowset is the whole enforcement: when the proxy is self-hosted on
//! `127.0.0.1`, a cooperative CLI's only connect is to the proxy (loopback) —
//! the proxy does the real DNS + outbound connect on its behalf. A CLI that
//! bypasses the proxy tries to connect straight to the external IP, which is
//! neither loopback nor port 53, and is denied at the syscall. Port 53 stays
//! open so a tool that resolves names before proxying keeps working; the
//! residual that leaves (DNS tunnelling) is a narrower channel than open
//! egress and is noted in the design doc.
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
//! This mirrors two probes recorded in `workspace/tasks/sh-exec-egress-pin/`:
//! the user-notify install under Docker's default seccomp, and the v4+v6
//! gating of a real CLI (an IPv4-only filter is bypassed over IPv6, so both
//! families are gated here).
//!
//! Applies only to a **self-hosted** (loopback) proxy. An external gateway
//! ([`super::EgressSupply::External`]) is off-host, so a loopback-only pin
//! would break it; there the gateway owns enforcement and this layer is off.

#![cfg(target_os = "linux")]

use std::io;
use std::process::{Command, Output};

/// Run `command` under the connect hard pin, returning its collected
/// output.
///
/// On the supported arches (`x86_64`, `aarch64`) this delegates to
/// [`supported::run_pinned`], which installs the seccomp user-notify
/// filter, supervises each `connect` from a parent thread, and
/// collects output the way [`Command::output`] does. `command`'s
/// stdio must already be configured by the caller.
///
/// On other Linux arches — see §Unsupported arches — this returns an
/// `io::Error` naming the target and pointing at
/// [`super::EgressSupply::External`] as the workaround.
pub fn run_pinned(command: Command) -> io::Result<Output> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        supported::run_pinned(command)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = command;
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
    use std::os::fd::RawFd;
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
        ioc(3, b'!' as u32, 0, std::mem::size_of::<SeccompNotif>() as u32)
    }
    fn notif_send_ioctl() -> libc::c_ulong {
        ioc(3, b'!' as u32, 1, std::mem::size_of::<SeccompNotifResp>() as u32)
    }

    /// Whether a `connect` to this destination is permitted by the hard pin.
    ///
    /// Loopback (v4 `127.0.0.0/8`, v6 `::1`) is the self-hosted proxy; port 53 is
    /// DNS. Everything else — a direct off-host connect that bypassed the proxy —
    /// is refused. A non-inet family (AF_UNIX for nss, etc.) is allowed: it cannot
    /// carry off-host egress and blocking it would break local name resolution.
    fn is_allowed(dest: Option<(IpAddr, u16)>) -> bool {
        match dest {
            None => true, // non-inet or unreadable → not an egress channel
            Some((_, 53)) => true,
            Some((IpAddr::V4(ip), _)) => ip.is_loopback(),
            Some((IpAddr::V6(ip), _)) => ip.is_loopback(),
        }
    }

    // --- child side: install the filter, hand the listener to the parent ----

    /// Install the connect user-notify filter and send its listener fd to the
    /// parent over `send_sock`. Runs in the **child**, inside `pre_exec`, so it
    /// must stay to raw syscalls (no allocation): a fork child sharing the
    /// parent's address space cannot safely run arbitrary code.
    ///
    /// # Safety
    /// Called only from `pre_exec` on a freshly forked child.
    unsafe fn install_and_send(send_sock: RawFd) -> io::Result<()> {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        // x86_64 BPF program — 8 instructions, with the x32 guard
        // between the nr load and the SYS_connect compare. Jump offsets
        // are counted from the instruction *after* the jump.
        //   0: A = seccomp_data.arch (offset 4)
        //   1: if A == NATIVE_AUDIT_ARCH: fall to 2 (native path)
        //      else: skip 5 to reach 7 (kill on foreign ABI — §Arch check)
        //   2: A = seccomp_data.nr (offset 0)
        //   3: if A >= X32_SYSCALL_BIT: skip 3 to reach 7 (kill on x32)
        //      else: fall to 4 (native nr — §Arch check on x32)
        //   4: if A == SYS_connect: fall to 5 (notify supervisor)
        //      else: skip 1 to reach 6 (allow every other native syscall)
        //   5: RET_USER_NOTIF — supervisor answers connect destinations
        //   6: RET_ALLOW      — every other native-ABI syscall is fine
        //   7: RET_KILL_PROCESS — foreign ABI or x32 → no filter coverage
        #[cfg(target_arch = "x86_64")]
        let filter = [
            SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 4 },
            SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 5, k: NATIVE_AUDIT_ARCH },
            SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 },
            SockFilter { code: BPF_JMP | BPF_JGE | BPF_K, jt: 3, jf: 0, k: X32_SYSCALL_BIT },
            SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 1, k: libc::SYS_connect as u32 },
            SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF },
            SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
            SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS },
        ];
        // aarch64 BPF program — 7 instructions, no x32 guard (the ABI
        // has no x32 equivalent). Offsets shift down by one accordingly.
        //   0: A = seccomp_data.arch (offset 4)
        //   1: if A == NATIVE_AUDIT_ARCH: fall to 2 (native path)
        //      else: skip 4 to reach 6 (kill on foreign ABI — §Arch check)
        //   2: A = seccomp_data.nr (offset 0)
        //   3: if A == SYS_connect: fall to 4 (notify supervisor)
        //      else: skip 1 to reach 5 (allow every other native syscall)
        //   4: RET_USER_NOTIF — supervisor answers connect destinations
        //   5: RET_ALLOW      — every other native-ABI syscall is fine
        //   6: RET_KILL_PROCESS — foreign ABI → the pin has no coverage
        #[cfg(target_arch = "aarch64")]
        let filter = [
            SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 4 },
            SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 4, k: NATIVE_AUDIT_ARCH },
            SockFilter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 },
            SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 1, k: libc::SYS_connect as u32 },
            SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF },
            SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
            SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS },
        ];
        let prog = SockFprog { len: filter.len() as u16, filter: filter.as_ptr() };
        let listener = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            &prog as *const SockFprog as libc::c_long,
        );
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        send_fd(send_sock, listener as RawFd)?;
        Ok(())
    }

    /// Send one fd over a connected unix socket via SCM_RIGHTS.
    unsafe fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
        let mut dummy: u8 = b'x';
        let mut iov = libc::iovec {
            iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cbuf = [0u8; 32]; // >= CMSG_SPACE(sizeof(int))
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _ };
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<libc::c_int>(),
        );
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive one fd sent by [`send_fd`]. Runs in the parent.
    fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
        unsafe {
            let mut dummy: u8 = 0;
            let mut iov = libc::iovec {
                iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
                iov_len: 1,
            };
            let mut cbuf = [0u8; 32];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
            if libc::recvmsg(sock, &mut msg, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(io::Error::other("no SCM_RIGHTS cmsg"));
            }
            let mut fd: libc::c_int = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut fd as *mut libc::c_int as *mut u8,
                std::mem::size_of::<libc::c_int>(),
            );
            Ok(fd as RawFd)
        }
    }

    // --- parent side: the supervisor loop -----------------------------------

    /// Read the `connect` destination out of the child's memory for one
    /// notification. Returns `None` for a non-inet family or an unreadable
    /// pointer (both allowed by [`is_allowed`]).
    fn read_dest(notif: &SeccompNotif) -> Option<(IpAddr, u16)> {
        // connect(fd, addr: *const sockaddr, addrlen) — args[1] is the pointer.
        let addr_ptr = notif.data.args[1];
        let addr_len = notif.data.args[2] as usize;
        let mut buf = [0u8; 28]; // max(sockaddr_in=16, sockaddr_in6=28)
        let n = addr_len.min(buf.len());
        let path = format!("/proc/{}/mem", notif.pid);
        let read = read_at(&path, addr_ptr, &mut buf[..n]).ok()?;
        if read < 2 {
            return None;
        }
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        match family as libc::c_int {
            libc::AF_INET if read >= 8 => {
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                Some((IpAddr::V4(ip), port))
            }
            libc::AF_INET6 if read >= 24 => {
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[8..24]);
                Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
            }
            _ => None,
        }
    }

    /// `pread` from a path at an absolute offset. Isolates the one unsafe read of
    /// another process's memory.
    fn read_at(path: &str, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let file = std::fs::File::open(path)?;
        file.read_at(buf, offset)
    }

    /// Run the supervisor loop until `stop` is set and no notification is pending.
    /// Each `connect` is answered: allowed → let the kernel run the real syscall
    /// (`CONTINUE`); denied → inject `EPERM`, so the real connect never happens.
    fn supervise(notify_fd: RawFd, stop: Arc<AtomicBool>) {
        let recv_ioctl = notif_recv_ioctl();
        let send_ioctl = notif_send_ioctl();
        loop {
            let mut pfd = libc::pollfd { fd: notify_fd, events: libc::POLLIN, revents: 0 };
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
            let allow = is_allowed(read_dest(&notif));
            let mut resp: SeccompNotifResp = unsafe { std::mem::zeroed() };
            resp.id = notif.id;
            if allow {
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            } else {
                resp.error = -libc::EPERM;
                tracing::warn!("egress: connect denied at syscall (bypassed proxy)");
            }
            let sc = unsafe { libc::ioctl(notify_fd, send_ioctl as _, &resp) };
            if sc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                // ENOENT = the notification was cancelled (child died mid-connect);
                // any other error means the listener is unusable — stop.
                break;
            }
        }
        unsafe { libc::close(notify_fd) };
    }

    /// Run `command` with the connect hard pin: install the filter in the child,
    /// supervise its connects from a parent thread, and collect its output like
    /// [`Command::output`]. `command`'s stdio must already be configured
    /// (stdin/stdout/stderr) by the caller. Reached only through the outer
    /// [`super::run_pinned`], which dispatches by target arch.
    pub(super) fn run_pinned(mut command: Command) -> io::Result<Output> {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (parent_sock, child_sock) = (fds[0], fds[1]);

        unsafe {
            command.pre_exec(move || install_and_send(child_sock));
        }
        let child = command.spawn();
        // The parent no longer needs the child's end regardless of spawn outcome.
        unsafe { libc::close(child_sock) };
        let child = match child {
            Ok(c) => c,
            Err(err) => {
                unsafe { libc::close(parent_sock) };
                return Err(err);
            }
        };

        let notify_fd = recv_fd(parent_sock);
        unsafe { libc::close(parent_sock) };
        let notify_fd = notify_fd?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let supervisor = std::thread::spawn(move || supervise(notify_fd, stop_thread));

        let output = child.wait_with_output();
        stop.store(true, Ordering::Relaxed);
        let _ = supervisor.join();
        output
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::process::Stdio;

        #[test]
        fn allowset_permits_loopback_and_dns_only() {
            assert!(is_allowed(Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 443))));
            assert!(is_allowed(Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 443))));
            assert!(is_allowed(Some((IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)))); // DNS
            assert!(is_allowed(None)); // non-inet
            assert!(!is_allowed(Some((IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)), 443))));
            assert!(!is_allowed(Some((
                IpAddr::V6("2600:9000:2751:1200::1".parse().unwrap()),
                443
            ))));
        }

        /// End-to-end: a real subprocess under the pin reaches a loopback listener
        /// (allowed) but is refused a direct external connect (denied at syscall).
        /// Uses `sh -c` with a tiny connect helper via `/dev/tcp`.
        #[test]
        fn pinned_subprocess_reaches_loopback_but_not_external() {
            use std::io::Read;
            use std::net::TcpListener;

            // A loopback listener that the child is allowed to reach.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut _b = [0u8; 1];
                    let _ = s.read(&mut _b);
                }
            });

            // bash /dev/tcp: connect loopback (should succeed), then an external
            // TEST-NET-3 address 203.0.113.1 (should be EPERM'd → non-zero).
            let script = format!(
                "exec 3<>/dev/tcp/127.0.0.1/{port} && echo LOOPBACK_OK; \
                 (exec 4<>/dev/tcp/203.0.113.1/80) 2>/dev/null && echo EXTERNAL_LEAK || echo EXTERNAL_BLOCKED",
                port = port
            );
            let mut cmd = Command::new("bash");
            cmd.arg("-c").arg(script);
            cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());

            let out = run_pinned(cmd).expect("run pinned");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("LOOPBACK_OK"), "loopback should connect: {stdout}");
            assert!(
                stdout.contains("EXTERNAL_BLOCKED"),
                "external connect must be denied at the syscall: {stdout}"
            );
        }
    }
}

#[cfg(all(
    test,
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
))]
mod tests_unsupported {
    use super::*;
    use std::process::Command;

    /// On an unsupported Linux arch the entry point returns an
    /// `io::Error` naming the target rather than falling back to an
    /// arch-blind filter (§Unsupported arches).
    #[test]
    fn run_pinned_refuses_on_unsupported_arch() {
        let cmd = Command::new("/bin/true");
        let err = run_pinned(cmd).expect_err("run_pinned must refuse on unsupported arch");
        let msg = err.to_string();
        assert!(msg.contains("target_arch="), "{msg}");
        assert!(msg.contains(std::env::consts::ARCH), "{msg}");
    }
}
