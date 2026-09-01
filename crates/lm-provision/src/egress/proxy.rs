//! In-process CONNECT egress proxy (the soft enforcement layer).
//!
//! `sh.exec` subprocesses are routed here through `HTTPS_PROXY` / `HTTP_PROXY`
//! (see [`super::proxy_env`]). The proxy accepts an HTTP `CONNECT host:port`,
//! checks the host against the [`EgressPolicy`], peeks the TLS ClientHello to
//! reject a fronted SNI, and otherwise opens an opaque tunnel — TLS is never
//! decoded. It is a `127.0.0.1` listener bound before the subprocess steps run
//! and torn down when apply ends; a single static binary supplies its own
//! proxy with no extra process or infrastructure (the ephemeral-pod case).
//!
//! This is *soft* enforcement: it captures every subprocess that honours the
//! proxy env (pip / git / curl / hf / b2 all do). A subprocess that ignores
//! the env is a matter for the hard layer (a seccomp `connect` pin, see
//! [`super::hardpin`]); the register here is "route + refuse by declaration",
//! not "containment" — the same honesty spec 05 keeps for the `paths` policy.
//!
//! # SNI peek: read the whole ClientHello before parsing
//!
//! A ClientHello can — and, with 4 KB TLS 1.3 `key_share` payloads,
//! sometimes does — arrive across more than one TCP segment. A single
//! `read()` off the client socket then hands [`super::sni::extract_sni`]
//! a truncated buffer, which returns `None` and looks the same as
//! "well-formed hello without SNI".
//!
//! It can also arrive across more than one **TLS record**: a handshake
//! message may be fragmented over several records (RFC 8446 §5.1), and
//! a hello whose `server_name` extension lands in record 2 reads as a
//! hello without SNI when only record 1 is parsed — the "nothing
//! contradicts the CONNECT host, allow" branch, which is a fronted
//! tunnel forwarded. Segment reassembly alone does not see it: each
//! record is perfectly well-formed.
//!
//! So the peek reassembles the **handshake message**, not the first
//! record. It reads the 5-byte record header (`content_type(1)` +
//! `version(2)` + `length(2)`), buffers that record's body, reads the
//! handshake header (`msg_type(1)` + `length(3)`) off the front of it,
//! and keeps pulling records — appending their bodies — until the
//! declared handshake length is in hand, all under one byte cap and one
//! deadline ([`SNI_PEEK_MAX_BYTES`], [`SNI_PEEK_DEADLINE`]). The
//! reassembled handshake is re-framed as a single record for
//! [`extract_sni`](super::sni::extract_sni), which walks record →
//! handshake → extensions and neither knows nor cares how many records
//! the bytes crossed. **What is forwarded upstream is the raw wire
//! bytes, verbatim and in order** — never the re-framed copy.
//!
//! The peek starts from whatever [`read_head`] read past the CONNECT
//! terminator. A client is free to put `CONNECT …\r\n\r\n` and the
//! first bytes of its hello in one segment; those bytes belong to the
//! tunnel, and the head read hands them on rather than dropping them.
//!
//! Policy for what a peek's outcome means:
//!
//! - **First byte is not `0x16`** — the payload is not a TLS record.
//!   Forward it: the CONNECT host was already checked against the
//!   [`EgressPolicy`], non-TLS traffic on 443 (a health probe, an
//!   opaque protocol) carries no SNI to contradict it, and refusing
//!   would break the shape of the tunnel.
//! - **Full ClientHello, SNI extracted, matches CONNECT host** — allow,
//!   and forward the peeked bytes. The two names are compared after the
//!   DNS normalisation the allowlist itself applies
//!   ([`super::host_match::normalise`]): a trailing dot is not a
//!   difference, so `CONNECT huggingface.co.:443` with an SNI of
//!   `huggingface.co` is one host, not a fronting attempt.
//! - **Full ClientHello, SNI extracted, differs from CONNECT host** — a
//!   domain-fronted hello: refuse. Nothing is forwarded upstream and
//!   the tunnel is dropped (spec 05 §L3 sh_egress: "checks each CONNECT
//!   host — and the TLS ClientHello's SNI, to refuse a fronted name").
//! - **Full ClientHello, no SNI extension present** — allow: there is
//!   nothing to contradict the CONNECT host. Modern clients almost
//!   always send SNI, but a hello without one is not a fronting signal
//!   on its own. This branch is only reachable now that the *whole*
//!   handshake has been assembled — an SNI in a later record no longer
//!   arrives here dressed as an absent one.
//! - **Byte cap or deadline hit before the ClientHello is complete, or
//!   a non-handshake record turns up inside it** — refuse. A TLS
//!   ClientHello is a KB-scale message dispatched immediately after the
//!   CONNECT ack; a peer that takes seconds to send one, claims a
//!   length beyond the cap, or interleaves something else mid-handshake
//!   is either broken or attempting to slip past the check while it
//!   ticks. Fail closed rather than forward what we could not inspect.
//!
//! # What the fronting refusal does not catch
//!
//! The SNI check reads the **plaintext outer `server_name`** only, and
//! that is all it can see without decoding TLS (which this layer never
//! does — spec 05 §L3, best-effort, not containment):
//!
//! - **Encrypted ClientHello (ECH).** ECH puts the real name in an
//!   encrypted inner hello; the outer `server_name` carries only the
//!   public/cover name. A fronted request under ECH shows a benign outer
//!   SNI, and this check passes it.
//! - **Host / `:authority` fronting inside the tunnel.** Once the tunnel
//!   is open the proxy forwards opaque bytes; a client can send an HTTP
//!   `Host:` (or HTTP/2 `:authority`) header for a different site than the
//!   SNI named, and that header is inside the TLS session the proxy does
//!   not read. The check is inspect-once at handshake, not per-request
//!   enforcement.
//!
//! Both are within the "best-effort, not a containment claim" register.
//! The backstop for them is the hard pin's **endpoint pinning**
//! ([`super::hardpin`]): a cooperative subprocess reaches the network only
//! through the proxy, and a subprocess that bypasses the proxy to reach an
//! off-host address directly is refused at the syscall regardless of what
//! name it would have fronted.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::policy::EgressPolicy;
use super::sni::{extract_sni, Sni};

/// Maximum bytes the SNI peek will buffer before giving up. A single
/// TLS record's `length` field is 16 bits — the record body cannot
/// legally exceed 2^14 (16 KiB) per RFC 8446 §5.1 — so 20 KiB leaves
/// room for the 5-byte header plus a bit of slack, and refuses a peer
/// declaring a header length beyond the spec's ceiling before we
/// allocate for it.
const SNI_PEEK_MAX_BYTES: usize = 20 * 1024;

/// How long the SNI peek will wait for the full first TLS record. A
/// real ClientHello is dispatched immediately after the CONNECT ack;
/// this budget is orders of magnitude above the round-trip a
/// cooperative client needs and well under any patience an operator
/// has for a stuck tunnel.
const SNI_PEEK_DEADLINE: Duration = Duration::from_secs(5);

/// How long [`read_head`] will wait for the whole CONNECT request head
/// (`CONNECT …\r\n\r\n`). Without a bound the head read is an open
/// `read` loop, and a subprocess can hold a serve task open indefinitely
/// by dribbling one byte at a time — a slowloris, multiplied by every
/// connection it opens (S1). The head is a few hundred bytes a
/// cooperative client sends at once; this is generous for that and still
/// drops a stall long before an apply's own patience runs out.
const CONNECT_HEAD_DEADLINE: Duration = Duration::from_secs(10);

/// A running in-process proxy: where to point subprocesses, and the task
/// serving them. Dropping the handle aborts the serve loop.
pub struct Proxy {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Proxy {
    /// `http://127.0.0.1:<port>` — the value for `HTTPS_PROXY` / `HTTP_PROXY`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The bound address, for tests and diagnostics.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind a proxy on an ephemeral `127.0.0.1` port and start serving.
///
/// Must be called with a tokio runtime current (apply already runs on one).
/// Returns once the listener is bound, so the address is ready to inject
/// before any subprocess starts.
pub async fn serve(policy: EgressPolicy) -> std::io::Result<Proxy> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let policy = Arc::new(policy);
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((client, _)) => {
                    let policy = policy.clone();
                    tokio::spawn(handle(client, policy));
                }
                Err(_) => continue,
            }
        }
    });
    Ok(Proxy { addr, task })
}

/// Read the CONNECT request line + headers, up to the blank line, and
/// hand back **whatever followed the terminator in the same read**.
///
/// A client may coalesce `CONNECT …\r\n\r\n` and the first bytes of its
/// ClientHello into one segment. Those bytes are the tunnel's, not the
/// head's: dropping them left the SNI peek reading a stream that begins
/// mid-hello, whose first byte is not `0x16`, which parses as "not TLS"
/// and forwards the whole fronted handshake unexamined. They come back
/// as the second half of the pair so the peek can start from them.
///
/// Each pass searches only the bytes this read could have completed a
/// terminator in, not the whole buffer: re-scanning everything after
/// every read is quadratic in the head's length, and a client that
/// dribbles a 16 KiB head out in small writes is the one who decides
/// how many passes that is. Backing the cursor up **3 bytes** from the
/// previous end is what keeps a `\r\n\r\n` split across a read boundary
/// findable — the terminator is 4 bytes, so at most its first 3 can
/// already have been scanned.
async fn read_head(client: &mut TcpStream, budget: Duration) -> Option<(String, Vec<u8>)> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        // Bound the whole head read (S1): a client that dribbles the head
        // out one byte at a time is dropped when the budget runs out,
        // rather than holding a serve task until the apply ends.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let n = match tokio::time::timeout(remaining, client.read(&mut tmp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => return None,
        };
        if n == 0 {
            return None;
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&tmp[..n]);
        if let Some(at) = buf[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let pipelined = buf.split_off(scan_from + at + 4);
            return Some((String::from_utf8_lossy(&buf).into_owned(), pipelined));
        }
        if buf.len() > 16384 {
            // No terminator inside the cap. A valid CONNECT request line
            // followed by oversized headers would otherwise open a tunnel
            // and *discard* the un-terminated tail — which may hold the
            // start of the ClientHello, corrupting the handshake. Fail
            // closed: drop the connection rather than serve it (S3/finding
            // 3).
            return None;
        }
    }
}

async fn refuse(client: &mut TcpStream, line: &str) {
    let _ = client.write_all(line.as_bytes()).await;
}

async fn handle(mut client: TcpStream, policy: Arc<EgressPolicy>) {
    let (head, pipelined) = match read_head(&mut client, CONNECT_HEAD_DEADLINE).await {
        Some(pair) => pair,
        None => return,
    };
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "CONNECT" {
        // Plain-HTTP forwarding is not offered: the CLIs this gates all use
        // HTTPS (CONNECT). A bare GET through the proxy is refused rather
        // than silently allowed.
        refuse(&mut client, "HTTP/1.1 405 Method Not Allowed\r\n\r\n").await;
        return;
    }
    let host = connect_host(target).to_string();
    if !policy.allows(&host) {
        tracing::warn!(host = %host, "egress: CONNECT denied (not in sh_egress)");
        refuse(&mut client, "HTTP/1.1 403 Forbidden\r\nX-Egress: denied\r\n\r\n").await;
        return;
    }
    // Dial the host that was just allowlisted, not the raw target string
    // (S5). A target with no usable port is a malformed authority.
    let Some(port) = connect_port(target) else {
        tracing::warn!(target = %target, "egress: CONNECT target has no valid port");
        refuse(&mut client, "HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return;
    };
    let dial = reconstruct_dial(&host, port);
    let mut upstream = match TcpStream::connect(&dial).await {
        Ok(s) => s,
        Err(err) => {
            tracing::debug!(host = %host, %err, "egress: upstream connect failed");
            refuse(&mut client, "HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    // Split the client only for the peek (it reads the client half); the
    // upstream stays whole. Whichever path the peek takes, `peeked` is
    // what gets forwarded first — the peek never consumes bytes the tunnel
    // would otherwise carry.
    let (mut cr, cw) = client.into_split();
    let peeked = match peek_client_hello(&mut cr, pipelined).await {
        PeekOutcome::ClientHello { forward, hello } => {
            match extract_sni(&hello) {
                Sni::Found(server_name) => {
                    if !same_host(&server_name, &host) {
                        tracing::warn!(
                            connect = %host, sni = %server_name,
                            "egress: SNI mismatch (domain fronting) refused"
                        );
                        return; // drop the tunnel; nothing forwarded upstream
                    }
                    forward
                }
                // A well-formed hello with no server_name extension: nothing
                // contradicts the CONNECT host, allow.
                Sni::None => forward,
                // The handshake was assembled to its declared length but does
                // not parse as a ClientHello — fail closed rather than treat
                // an unreadable hello as a hello without SNI (S4).
                Sni::Unparseable => {
                    tracing::warn!(
                        connect = %host,
                        "egress: assembled ClientHello did not parse — refusing"
                    );
                    return;
                }
            }
        }
        PeekOutcome::NotTls(bytes) => {
            // Non-TLS payload on the CONNECT tunnel. The CONNECT host was
            // already checked; forward the bytes as-is (spec's SNI check
            // is a fronting refusal, not a TLS-only gate).
            bytes
        }
        PeekOutcome::Refuse(reason) => {
            tracing::warn!(
                connect = %host, %reason,
                "egress: SNI peek could not complete a full ClientHello — refusing"
            );
            return;
        }
        PeekOutcome::Eof => Vec::new(),
    };
    // Reunite the client halves so the tunnel is two whole duplex streams:
    // `copy_bidirectional` shuts each side's write half down when its
    // reader hits EOF, so a TCP half-close on one end is propagated to the
    // other instead of the tunnel hanging until an idle timeout (finding
    // 2). Two independent `copy` under `join!` never call `poll_shutdown`.
    let mut client = match cr.reunite(cw) {
        Ok(stream) => stream,
        Err(_) => return, // both halves are this connection's — unreachable
    };
    if !peeked.is_empty() && upstream.write_all(&peeked).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// The host half of a CONNECT target's authority, without the brackets
/// an IPv6 literal wears.
///
/// CONNECT's target is `host:port` (RFC 9110 §9.3.6) and an IPv6
/// literal in an authority is bracketed (RFC 3986 §3.2.2), so
/// `[2606:50c0::153]:443` carries four colons before the port one.
/// Splitting at the *first* colon returns `[2606` — a string no
/// allowlist pattern matches and no `server_name` equals, so the proxy
/// refused every v6-literal CONNECT for a reason that had nothing to do
/// with the declaration, and an operator who declared the literal had
/// no way to make it work.
///
/// Bracketed authorities yield what is inside the brackets; everything
/// else splits at the **last** colon, which is the port separator for a
/// DNS name or a v4 literal. An unterminated bracket is not an
/// authority this function will invent a host out of: the raw target
/// comes back, the allowlist does not match it, and the CONNECT is
/// refused.
///
/// The bare form is what both consumers want. [`EgressPolicy`] compares
/// it against the declared patterns — a v6 literal will not match a
/// DNS-name pattern, which is correct, and an operator who declares the
/// literal itself gets a literal-to-literal comparison
/// ([`super::host_match`] lowercases and trims a trailing dot; neither
/// changes a hex literal). The SNI check compares it against the
/// ClientHello's `server_name`, which is where the bare form matters
/// again: a bracket in one side and not the other would read as a
/// mismatch.
fn connect_host(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((inside, _)) => inside,
            None => target,
        };
    }
    match target.rsplit_once(':') {
        // A host part that still contains a `:` is a **bare** IPv6 literal
        // (`2606:50c0::153`), not `host:port` — splitting it would invent a
        // host (`2606:50c0:`) inconsistent with the unterminated-bracket
        // branch above (S2). Hand the raw target back so the allowlist
        // refuses it rather than matching a fabrication.
        Some((host, _)) if !host.contains(':') => host,
        _ => target,
    }
}

/// The port half of a CONNECT target's authority, or `None` when the
/// authority is not `host:port` (a bare host, a bare IPv6 literal, a
/// non-numeric or out-of-range port).
///
/// Parsed the same bracket-aware way as [`connect_host`] so the two never
/// disagree about where the host ends and the port begins.
fn connect_port(target: &str) -> Option<u16> {
    if let Some(rest) = target.strip_prefix('[') {
        // `[v6]:port` — the port is whatever follows the closing bracket.
        let after = rest.split_once(']')?.1;
        return after.strip_prefix(':')?.parse().ok();
    }
    let (host, port) = target.rsplit_once(':')?;
    if host.contains(':') {
        return None; // bare IPv6 literal, no port
    }
    port.parse().ok()
}

/// Rebuild a dial string from the **validated** host and the parsed port,
/// re-bracketing an IPv6 literal so `ToSocketAddrs` reads it back the same
/// way (S5).
///
/// The proxy allowlisted `host`; dialing the raw CONNECT target instead
/// would hand `TcpStream::connect` a string this code never validated, so
/// a future `ToSocketAddrs` quirk could reach an address the allowlist
/// never saw. Reconstructing from the pieces keeps the dialed authority
/// identical to the checked one.
fn reconstruct_dial(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Whether a ClientHello's `server_name` names the host the CONNECT
/// asked for.
///
/// Both sides go through [`super::host_match::normalise`] — the same
/// trailing-dot trim and lowercase [`EgressPolicy::allows`] just applied
/// to this host. Comparing raw made the proxy contradict itself:
/// `CONNECT huggingface.co.:443` satisfied a `huggingface.co` pattern
/// (the policy trimmed the dot) and was then refused as fronting
/// against an SNI of `huggingface.co`, over a difference RFC 1035 §3.1
/// says is not one. A fronted name is still a fronted name after
/// normalising — that is the whole content of the check.
fn same_host(server_name: &str, connect_host: &str) -> bool {
    super::host_match::normalise(server_name) == super::host_match::normalise(connect_host)
}

/// What [`peek_client_hello`] observed on the client socket. The
/// caller decides forwarding + tunnel-drop from the variant.
enum PeekOutcome {
    /// A complete ClientHello, however many records it took.
    ClientHello {
        /// Every byte read off the wire, verbatim and in order — this
        /// is what the tunnel carries.
        forward: Vec<u8>,
        /// The same handshake re-framed as one record for
        /// [`extract_sni`]. Parsed, never sent.
        hello: Vec<u8>,
    },
    /// The peeked bytes are not a TLS record (first byte != `0x16`).
    /// Forward as-is; the CONNECT host was already checked.
    NotTls(Vec<u8>),
    /// The client closed before sending any bytes. Nothing to check
    /// and nothing to forward.
    Eof,
    /// The peek ran out of time or budget before the ClientHello was
    /// complete, a declared length is beyond the cap, or a
    /// non-handshake record turned up inside the handshake. Fail
    /// closed.
    Refuse(&'static str),
}

/// How one [`fill_to`] attempt ended.
enum Fill {
    /// The buffer holds at least the requested byte count.
    Done,
    /// The peer closed before it did. The caller decides what a close
    /// means at that point in the parse — it is `Eof` before any bytes,
    /// a non-TLS payload mid-first-header, and a refusal once a record
    /// has been promised.
    Closed,
    /// The deadline passed or the socket errored; the string is the
    /// refusal reason.
    Stopped(&'static str),
}

/// Read from `cr` until `buf` holds `target` bytes, the deadline
/// passes, or the peer closes.
///
/// Never reads past `target`. The peek window is a budget, and a peer
/// with a large buffered stream must not be able to spend more of it
/// than the record in hand needs — the bytes beyond belong to the
/// tunnel, and reading them here would mean holding bytes the forward
/// path then has to account for.
async fn fill_to(
    cr: &mut tokio::net::tcp::OwnedReadHalf,
    buf: &mut Vec<u8>,
    target: usize,
    deadline: tokio::time::Instant,
) -> Fill {
    // One stack buffer, reused across iterations, sized to a typical
    // short read — a fragmented hello must not allocate per iteration
    // on the hot path.
    let mut tmp = [0u8; 4096];
    while buf.len() < target {
        let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if budget.is_zero() {
            return Fill::Stopped("deadline hit before the ClientHello was complete");
        }
        let want = (target - buf.len()).min(tmp.len());
        match tokio::time::timeout(budget, cr.read(&mut tmp[..want])).await {
            Ok(Ok(0)) => return Fill::Closed,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(_)) => return Fill::Stopped("socket read error"),
            Err(_) => return Fill::Stopped("deadline hit before the ClientHello was complete"),
        }
    }
    Fill::Done
}

/// Re-frame reassembled handshake bytes as one TLS record — the shape
/// [`extract_sni`] parses.
///
/// The record version is cosmetic to that parser (it reads the content
/// type and the length, then walks the handshake), so the legacy
/// `0x0301` every real ClientHello record carries goes in. The length
/// always fits its 16-bit field: [`SNI_PEEK_MAX_BYTES`] is well under
/// the field's range and a handshake past the cap was refused before
/// reaching here.
fn reframe(handshake: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(handshake);
    record
}

/// Read the client's first handshake message off `cr` — across as many
/// TLS records as it takes — or decide fail-closed / pass-through per
/// the module doc.
///
/// `pipelined` is whatever [`read_head`] read past the CONNECT
/// terminator; the peek starts from it. Never buffers more than
/// [`SNI_PEEK_MAX_BYTES`] and never blocks longer than
/// [`SNI_PEEK_DEADLINE`].
async fn peek_client_hello(
    cr: &mut tokio::net::tcp::OwnedReadHalf,
    pipelined: Vec<u8>,
) -> PeekOutcome {
    let deadline = tokio::time::Instant::now() + SNI_PEEK_DEADLINE;
    let mut buf = pipelined;
    // The first byte decides TLS vs not, and it may already be in hand
    // from the head read.
    if buf.is_empty() {
        match fill_to(cr, &mut buf, 1, deadline).await {
            Fill::Done => {}
            Fill::Closed => return PeekOutcome::Eof,
            Fill::Stopped(reason) => return PeekOutcome::Refuse(reason),
        }
    }
    if buf[0] != 0x16 {
        // Non-TLS: the CONNECT host was already checked and there is no
        // hello here to contradict it. Forward what we hold and let the
        // copy loops carry on.
        return PeekOutcome::NotTls(buf);
    }

    // Records, until the handshake message they carry is complete.
    // `consumed` is how much of `buf` has been attributed to a record
    // already; `handshake` is the record bodies concatenated, which is
    // the handshake byte stream TLS defines them to carry.
    let mut handshake: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    loop {
        match fill_to(cr, &mut buf, consumed + 5, deadline).await {
            Fill::Done => {}
            Fill::Closed => {
                // The first byte was `0x16` (checked before the loop), so a
                // close here is a handshake record whose header never
                // completed — a TLS-looking stub the SNI check could not
                // read. Fail closed rather than forward it down the "not
                // TLS" path unexamined (S3).
                return PeekOutcome::Refuse("client closed inside the record header");
            }
            Fill::Stopped(reason) => return PeekOutcome::Refuse(reason),
        }
        if buf[consumed] != 0x16 {
            // Something that is not a handshake record, in the middle of
            // a handshake. Nothing legitimate does this before the
            // ClientHello is even finished, and the bytes it hides are
            // exactly the ones this peek exists to read.
            return PeekOutcome::Refuse("non-handshake record inside the ClientHello");
        }
        let body_len = u16::from_be_bytes([buf[consumed + 3], buf[consumed + 4]]) as usize;
        let record_end = consumed + 5 + body_len;
        if record_end > SNI_PEEK_MAX_BYTES {
            return PeekOutcome::Refuse("record length exceeds peek cap");
        }
        match fill_to(cr, &mut buf, record_end, deadline).await {
            Fill::Done => {}
            Fill::Closed => return PeekOutcome::Refuse("client closed mid-record"),
            Fill::Stopped(reason) => return PeekOutcome::Refuse(reason),
        }
        handshake.extend_from_slice(&buf[consumed + 5..record_end]);
        consumed = record_end;

        // The handshake header — msg_type(1) + length(3) — names the
        // whole message's length, however many records it spans. That
        // is the number this loop is reading toward.
        if handshake.len() >= 4 {
            let declared =
                u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            let needed = 4 + declared;
            if needed + 5 > SNI_PEEK_MAX_BYTES {
                return PeekOutcome::Refuse("handshake length exceeds peek cap");
            }
            if handshake.len() >= needed {
                // Anything past the declared length belongs to the next
                // handshake message, not this one.
                handshake.truncate(needed);
                return PeekOutcome::ClientHello {
                    hello: reframe(&handshake),
                    forward: buf,
                };
            }
        }
        if consumed >= SNI_PEEK_MAX_BYTES {
            return PeekOutcome::Refuse("peek cap reached before the ClientHello was complete");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A CONNECT to a denied host is refused with 403 before any tunnel.
    #[tokio::test]
    async fn connect_to_denied_host_is_refused() {
        let proxy = serve(EgressPolicy::new(["huggingface.co".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(b"CONNECT blocked.example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 64];
        let n = c.read(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp[..n]);
        assert!(s.contains("403"), "expected 403, got: {s}");
    }

    /// A CONNECT to an allowed host opens a tunnel: the proxy answers 200 and
    /// bytes reach a local upstream unchanged. Uses a loopback listener as the
    /// "allowed" upstream so the test needs no network.
    #[tokio::test]
    async fn connect_to_allowed_host_tunnels_bytes() {
        // Stand up a fake upstream on loopback and allow "localhost".
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap(); // echo
        });
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        // CONNECT to localhost:<upstream port> (host "localhost" is allowed).
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(
            String::from_utf8_lossy(&resp).contains("200"),
            "expected 200 Connection Established"
        );
        // Now tunnelled: send 5 non-TLS bytes (first byte != 0x16 →
        // PeekOutcome::NotTls → forwarded) and read the echo back.
        c.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
    }

    /// The fronting comparison answers the way the allowlist did: a
    /// trailing dot is not a difference (RFC 1035 §3.1), case is not a
    /// difference (§2.3.3), and a different name still is one.
    #[test]
    fn the_sni_comparison_normalises_both_sides_the_way_the_allowlist_does() {
        assert!(same_host("huggingface.co", "huggingface.co."));
        assert!(same_host("huggingface.co.", "huggingface.co"));
        assert!(same_host("HuggingFace.CO", "huggingface.co"));
        assert!(!same_host("evil.example", "huggingface.co"));
        assert!(!same_host("cdn.huggingface.co", "huggingface.co"));
    }

    /// The authority parse on its own: bracket-aware for an IPv6
    /// literal, last-colon for a name or a v4 literal, and no host
    /// invented out of a malformed authority.
    #[test]
    fn connect_host_reads_the_authority_bracket_aware() {
        assert_eq!(connect_host("huggingface.co:443"), "huggingface.co");
        assert_eq!(connect_host("huggingface.co"), "huggingface.co");
        assert_eq!(connect_host("140.82.121.4:443"), "140.82.121.4");
        assert_eq!(connect_host("[2606:50c0::153]:443"), "2606:50c0::153");
        assert_eq!(connect_host("[::1]:8080"), "::1");
        assert_eq!(connect_host("[2606:50c0::153]"), "2606:50c0::153");
        // No closing bracket: the raw target comes back, so the
        // allowlist refuses it rather than matching something this
        // function made up out of a malformed authority.
        assert_eq!(connect_host("[2606:50c0::153:443"), "[2606:50c0::153:443");
        // A **bare** (unbracketed) v6 literal is not `host:port`: the raw
        // target comes back rather than the mis-truncated `2606:50c0:` (S2).
        assert_eq!(connect_host("2606:50c0::153"), "2606:50c0::153");
        assert_eq!(connect_host("::1"), "::1");
    }

    /// The port half, parsed the same bracket-aware way, and the dial
    /// string rebuilt from the validated host + port (S5). A bare v6
    /// literal has no port and yields `None`, so the proxy refuses it
    /// rather than dialing an authority it never validated.
    #[test]
    fn connect_port_and_dial_reconstruction_agree_with_the_host_split() {
        assert_eq!(connect_port("huggingface.co:443"), Some(443));
        assert_eq!(connect_port("140.82.121.4:8443"), Some(8443));
        assert_eq!(connect_port("[2606:50c0::153]:443"), Some(443));
        assert_eq!(connect_port("[::1]:8080"), Some(8080));
        // No port / bare literal / bad port → None.
        assert_eq!(connect_port("huggingface.co"), None);
        assert_eq!(connect_port("2606:50c0::153"), None);
        assert_eq!(connect_port("host:notaport"), None);
        assert_eq!(connect_port("host:99999"), None);

        // The dial string is rebuilt from the pieces, re-bracketing v6.
        assert_eq!(
            reconstruct_dial("huggingface.co", 443),
            "huggingface.co:443"
        );
        assert_eq!(reconstruct_dial("::1", 8080), "[::1]:8080");
        assert_eq!(
            reconstruct_dial("2606:50c0::153", 443),
            "[2606:50c0::153]:443"
        );
    }

    /// And the policy answers sanely on the bare literal: an operator
    /// who declares the literal gets a literal-to-literal match, while
    /// a DNS-name pattern does not reach an address (which is the
    /// point — a name pattern says nothing about a numeric host).
    #[test]
    fn a_declared_ipv6_literal_matches_the_bare_host_but_a_name_pattern_does_not() {
        let declared = EgressPolicy::new(["2606:50c0::153".to_string()]);
        assert!(declared.allows(connect_host("[2606:50c0::153]:443")));
        let names = EgressPolicy::new(["*.hf.co".to_string()]);
        assert!(!names.allows(connect_host("[2606:50c0::153]:443")));
    }

    /// **A bracketed IPv6 literal is one authority, not four colons.**
    /// `[::1]:port` must reach the declared literal `::1`: splitting at
    /// the first colon handed the policy `[`, so every v6-literal
    /// CONNECT was refused with a 403 that had nothing to do with what
    /// the profile declared.
    #[tokio::test]
    async fn a_bracketed_ipv6_connect_is_allowed_when_the_literal_is_declared() {
        let upstream = TcpListener::bind(("::1", 0)).await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap(); // echo
        });
        let proxy = serve(EgressPolicy::new(["::1".to_string()])).await.unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT [::1]:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(
            String::from_utf8_lossy(&resp).contains("200"),
            "a declared v6 literal must open the tunnel"
        );
        // Non-TLS bytes (first byte != 0x16) ride through the peek.
        c.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
    }

    /// The other half of the same parse: reaching the tunnel over a
    /// bracketed v6 authority must not cost the fronting check. The
    /// host the SNI is compared against is the bare literal, so a
    /// ClientHello naming someone else is still a mismatch and still
    /// forwards nothing.
    #[tokio::test]
    async fn a_bracketed_ipv6_connect_still_refuses_a_fronted_sni() {
        let upstream = TcpListener::bind(("::1", 0)).await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let upstream_saw = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let saw_clone = upstream_saw.clone();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = upstream.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf).await {
                    saw_clone.lock().await.extend_from_slice(&buf[..n]);
                }
            }
        });
        let proxy = serve(EgressPolicy::new(["::1".to_string()])).await.unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT [::1]:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        c.write_all(&client_hello_with_sni("evil.example"))
            .await
            .unwrap();
        let mut dropped = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(1), c.read(&mut dropped)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            upstream_saw.lock().await.is_empty(),
            "a fronted hello must not reach the upstream: {:?}",
            upstream_saw.lock().await
        );
    }

    /// Build a minimal ClientHello record carrying one SNI host_name.
    /// Same shape as [`crate::egress::sni::tests`]'s fixture — kept
    /// here so the proxy tests do not reach across module boundaries.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut sn = Vec::new();
        sn.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sn.extend_from_slice(host);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(0);
        hs_body.extend_from_slice(&2u16.to_be_bytes());
        hs_body.extend_from_slice(&[0x13, 0x01]);
        hs_body.push(1);
        hs_body.push(0);
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01);
        let l = hs_body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// The same ClientHello, its handshake message fragmented over
    /// **two** TLS records — the split RFC 8446 §5.1 permits.
    ///
    /// The cut is 8 bytes in, so record 1 carries the handshake header
    /// and the start of `client_version` / `random` and nothing else:
    /// `extract_sni` on record 1 alone finds no SNI, which is exactly
    /// the shape that used to reach the "no SNI, allow" branch.
    fn two_record_client_hello(host: &str) -> Vec<u8> {
        let single = client_hello_with_sni(host);
        let handshake = &single[5..];
        let cut = 8;
        let mut out = Vec::new();
        for part in [&handshake[..cut], &handshake[cut..]] {
            out.push(0x16);
            out.extend_from_slice(&[0x03, 0x01]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Stand up a loopback upstream that drains whatever the proxy
    /// forwards, and return its address plus the shared buffer it
    /// drains into. Several tests below assert on "what reached the
    /// upstream", and they all want the same listener.
    async fn draining_upstream() -> (SocketAddr, std::sync::Arc<tokio::sync::Mutex<Vec<u8>>>) {
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let saw = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let saw_clone = saw.clone();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = upstream.accept().await {
                let mut buf = vec![0u8; 4096];
                loop {
                    match tokio::time::timeout(Duration::from_millis(300), s.read(&mut buf)).await {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => saw_clone.lock().await.extend_from_slice(&buf[..n]),
                        Ok(Err(_)) => break,
                    }
                }
            }
        });
        (addr, saw)
    }

    /// The two-record fixture is only a regression guard if its first
    /// record really hides the SNI. Record 1 alone is a truncated
    /// handshake, so it is `Unparseable` — never a clean `None`, which
    /// would have driven the "allow" branch — and the reassembled whole
    /// does find the name, which is what the peek hands to [`extract_sni`].
    #[test]
    fn the_two_record_fixture_hides_the_sni_in_its_second_record() {
        let two = two_record_client_hello("evil.example");
        let first_record = 5 + u16::from_be_bytes([two[3], two[4]]) as usize;
        assert_eq!(
            extract_sni(&two[..first_record]),
            Sni::Unparseable,
            "record 1 alone is a truncated handshake, not a hello without SNI"
        );

        let single = client_hello_with_sni("evil.example");
        assert_eq!(
            extract_sni(&reframe(&single[5..])),
            Sni::Found("evil.example".to_string()),
            "the re-framed handshake is what the parser reads"
        );
    }

    /// **A ClientHello fragmented across two TLS records still gets its
    /// SNI read.** Record 1 is a well-formed handshake record with no
    /// extensions in it at all, so a peek that stopped at the first
    /// record found no SNI, took the "nothing contradicts the CONNECT
    /// host" branch, and forwarded a fronted tunnel. The peek now
    /// reassembles the handshake message across records before parsing.
    #[tokio::test]
    async fn a_client_hello_split_across_two_tls_records_is_still_checked_for_fronting() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        c.write_all(&two_record_client_hello("evil.example"))
            .await
            .unwrap();
        let mut dropped = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(1), c.read(&mut dropped)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            upstream_saw.lock().await.is_empty(),
            "a hello fronted in its second record must not reach the upstream: {:?}",
            upstream_saw.lock().await
        );
    }

    /// The other half: a matching SNI split the same way is allowed,
    /// and **both records reach the upstream verbatim**. The re-framed
    /// copy the SNI parse runs on is never what gets forwarded — a
    /// tunnel that delivered a rewritten handshake would break the
    /// TLS transcript hash it is about to be checked against.
    #[tokio::test]
    async fn a_two_record_hello_with_a_matching_sni_is_forwarded_record_for_record() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        let hello = two_record_client_hello("localhost");
        c.write_all(&hello).await.unwrap();
        drop(c);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            upstream_saw.lock().await.clone(),
            hello,
            "the upstream must see the wire bytes, both records, unaltered"
        );
    }

    /// **A client may put the CONNECT and the start of its hello in one
    /// segment.** The head read consumes up to `\r\n\r\n`; the bytes
    /// after it are the tunnel's. Dropping them left the peek reading a
    /// stream that begins mid-hello — first byte not `0x16`, therefore
    /// "not TLS", therefore forwarded without an SNI check, which is
    /// what this fronted hello would have exercised.
    #[tokio::test]
    async fn a_connect_coalesced_with_the_client_hello_still_gets_its_sni_checked() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();

        // The terminator and the first three hello bytes share one
        // write; the rest of the hello follows separately. That split
        // is what makes this test discriminating: dropping the
        // pipelined prefix leaves the peek starting at a record-length
        // byte, which is not `0x16`, so the remainder was forwarded as
        // "not TLS" and reached the upstream unexamined.
        let hello = client_hello_with_sni("evil.example");
        let mut coalesced =
            format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).into_bytes();
        coalesced.extend_from_slice(&hello[..3]);
        c.write_all(&coalesced).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        c.write_all(&hello[3..]).await.unwrap();

        let mut dropped = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_secs(1), c.read(&mut dropped)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            upstream_saw.lock().await.is_empty(),
            "a hello pipelined behind the CONNECT must still be inspected: {:?}",
            upstream_saw.lock().await
        );
    }

    /// And the matching case of the same coalescing: the pipelined
    /// bytes are forwarded, once, in order. Losing them would stall the
    /// handshake; forwarding them twice would corrupt it.
    #[tokio::test]
    async fn a_coalesced_hello_that_matches_is_forwarded_exactly_once() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();

        let hello = client_hello_with_sni("localhost");
        let mut coalesced =
            format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).into_bytes();
        coalesced.extend_from_slice(&hello);
        c.write_all(&coalesced).await.unwrap();
        // Read the tunnel greeting so the proxy's write does not block,
        // then close so the upstream drain loop finishes.
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));
        drop(c);

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(upstream_saw.lock().await.clone(), hello);
    }

    /// **A trailing dot is not domain fronting.** `huggingface.co.` and
    /// `huggingface.co` are one name (RFC 1035 §3.1), and the allowlist
    /// already treats them so — the CONNECT passes. The SNI comparison
    /// used to be raw, so the tunnel was then dropped as fronted
    /// against a hello naming the same host without the dot.
    #[tokio::test]
    async fn a_trailing_dot_on_the_connect_host_is_not_a_fronted_sni() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost.:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(
            String::from_utf8_lossy(&resp).contains("200"),
            "the allowlist trims the trailing dot, so the CONNECT is allowed"
        );

        let hello = client_hello_with_sni("localhost");
        c.write_all(&hello).await.unwrap();
        drop(c);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            upstream_saw.lock().await.clone(),
            hello,
            "an SNI equal to the CONNECT host modulo the trailing dot must be forwarded"
        );
    }

    /// **A CONNECT head that never completes is dropped at the deadline
    /// (S1).** Driven against `read_head` directly with a short budget so
    /// the slowloris bound is exercised in milliseconds: a client that
    /// sends a partial request line and then goes silent must have the
    /// read return `None` at the deadline, not block forever.
    #[tokio::test]
    async fn a_connect_that_stalls_mid_head_is_dropped_at_the_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            // A partial request line, no terminator, then hold the
            // connection open sending nothing more.
            c.write_all(b"CONNECT huggingface").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(c);
        });
        let (mut server, _) = listener.accept().await.unwrap();

        let started = std::time::Instant::now();
        let head = read_head(&mut server, Duration::from_millis(200)).await;
        assert!(head.is_none(), "a stalled head must be dropped, not served");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the drop must happen at the deadline, not when the client eventually closes"
        );
        client.abort();
    }

    /// **An unterminated over-cap head is refused, not tunneled (finding
    /// 3).** A valid CONNECT request line followed by more than 16 KiB of
    /// headers with no `\r\n\r\n` used to be returned as a successful
    /// head — opening a tunnel and discarding the un-terminated tail (the
    /// start of the ClientHello). `read_head` must now return `None`.
    #[tokio::test]
    async fn an_unterminated_over_cap_head_is_refused_not_tunneled() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            // A valid request line, then oversized headers, never a blank
            // line — the whole thing pushed past the 16 KiB cap.
            c.write_all(b"CONNECT huggingface.co:443 HTTP/1.1\r\n")
                .await
                .unwrap();
            let filler = vec![b'x'; 20 * 1024];
            let _ = c.write_all(&filler).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(c);
        });
        let (mut server, _) = listener.accept().await.unwrap();

        let head = read_head(&mut server, Duration::from_secs(5)).await;
        assert!(
            head.is_none(),
            "an over-cap head with no terminator must be refused, not served as a head"
        );
        client.abort();
    }

    /// **A TCP half-close on one side of the tunnel is propagated to the
    /// other (finding 2).** With `copy_bidirectional`, when the client
    /// shuts down its write half after sending a request, the upstream
    /// sees EOF on its read half and its own writer is shut down, so a
    /// one-shot request/response completes instead of hanging until an
    /// idle timeout. The upstream here replies and then closes; the
    /// client must observe that reply and a clean EOF.
    #[tokio::test]
    async fn a_client_half_close_is_propagated_through_the_tunnel() {
        // An upstream that reads until the client half-closes (EOF), then
        // replies and closes — the shape that hangs under two independent
        // `copy`s because the request side's EOF is never forwarded.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut got = Vec::new();
            // Reads return 0 only once the client's write half is shut.
            let _ = s.read_to_end(&mut got).await;
            let _ = s.write_all(b"REPLY").await;
            // Drop closes the upstream, sending EOF back to the client.
        });
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        // Non-TLS bytes ride the tunnel (first byte != 0x16), then the
        // client half-closes its write side — which must reach the
        // upstream as EOF so it replies.
        c.write_all(b"hello").await.unwrap();
        c.shutdown().await.unwrap();

        let mut reply = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut reply)).await;
        assert!(
            read.is_ok(),
            "the tunnel must complete after the half-close, not hang"
        );
        assert_eq!(
            &reply, b"REPLY",
            "the upstream's reply must reach the client"
        );
    }

    /// **A `0x16`-prefixed stub that never completes its record header is
    /// refused, not forwarded (S3).** A single handshake-content byte
    /// followed by a close used to fall through the "client closed
    /// mid-header → treat as non-TLS" path and forward TLS-looking bytes
    /// with no SNI check; now the tunnel is dropped and the upstream sees
    /// nothing.
    #[tokio::test]
    async fn a_truncated_tls_record_stub_is_refused_not_forwarded() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        // A handshake record header that never completes: two bytes, then
        // close.
        c.write_all(&[0x16, 0x03]).await.unwrap();
        drop(c);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            upstream_saw.lock().await.is_empty(),
            "a truncated TLS stub must not be forwarded: {:?}",
            upstream_saw.lock().await
        );
    }

    /// **An assembled ClientHello that does not parse is refused, not
    /// forwarded as "no SNII" (S4).** The record below is complete to its
    /// declared handshake length, so the peek assembles it and hands it to
    /// `extract_sni`, which cannot walk it (a `session_id` length that
    /// overshoots) — `Sni::Unparseable`. That must drop the tunnel, not
    /// take the `Sni::None` allow branch.
    #[tokio::test]
    async fn an_assembled_but_unparseable_hello_is_refused() {
        let (up_addr, upstream_saw) = draining_upstream().await;
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        // A handshake header claiming a length it fills, whose body is a
        // ClientHello the parser cannot walk (session_id length = 255 with
        // no bytes behind it). extract_sni → Unparseable.
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(0xFF); // session_id length overshoots the buffer
        let mut hs = vec![0x01u8];
        let l = hs_body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);
        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        c.write_all(&rec).await.unwrap();
        drop(c);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            upstream_saw.lock().await.is_empty(),
            "an unparseable hello must be refused, not forwarded: {:?}",
            upstream_saw.lock().await
        );
    }

    /// A ClientHello arrives in **two** writes, split across the TLS
    /// record header/body boundary. The peek loop must reassemble the
    /// full record before parsing — a single-read peek returned `None`
    /// for the split hello and forwarded it, letting a fronted SNI slip.
    /// Now the mismatch is caught and the tunnel is dropped.
    #[tokio::test]
    async fn split_client_hello_still_catches_a_domain_fronted_sni() {
        // Stand up a fake "upstream" that would echo bytes; if the
        // proxy forwards anything past the tunnel greeting the test
        // will see it, but the mismatched-SNI path must forward zero.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let upstream_saw = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let saw_clone = upstream_saw.clone();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = upstream.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf).await {
                    saw_clone.lock().await.extend_from_slice(&buf[..n]);
                }
            }
        });
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        // Fronted hello: CONNECT says `localhost`, SNI says `evil.example`.
        let hello = client_hello_with_sni("evil.example");
        // Split at the 3-byte mark: the peek's first read cannot even
        // fill the 5-byte record header, forcing the loop to run.
        c.write_all(&hello[..3]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        c.write_all(&hello[3..]).await.unwrap();

        // The proxy must have dropped the tunnel without forwarding
        // any of the hello (previous single-read code forwarded it).
        // Wait for the drop by attempting a read on the client end.
        let mut dropped = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(1), c.read(&mut dropped)).await;

        // Give the upstream reader task a beat to have read whatever it
        // was going to read (which should be nothing).
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            upstream_saw.lock().await.is_empty(),
            "fronted hello must not reach the upstream: {:?}",
            upstream_saw.lock().await
        );
    }

    /// The matching-SNI split-hello path forwards the whole reassembled
    /// record to the upstream (no bytes dropped, no bytes duplicated).
    /// A previous single-read peek forwarded only the first segment
    /// and stalled the handshake.
    #[tokio::test]
    async fn split_client_hello_with_matching_sni_is_reassembled_and_forwarded() {
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let upstream_saw = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let saw_clone = upstream_saw.clone();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = upstream.accept().await {
                let mut buf = vec![0u8; 4096];
                // Loop to drain until the client closes or a short lull.
                loop {
                    match tokio::time::timeout(Duration::from_millis(300), s.read(&mut buf)).await {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => saw_clone.lock().await.extend_from_slice(&buf[..n]),
                        Ok(Err(_)) => break,
                    }
                }
            }
        });
        let proxy = serve(EgressPolicy::new(["localhost".to_string()]))
            .await
            .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
        c.write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200"));

        let hello = client_hello_with_sni("localhost");
        // Split across the record header/body boundary to force the loop.
        c.write_all(&hello[..3]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        c.write_all(&hello[3..]).await.unwrap();
        // Close so the upstream reader exits its drain loop.
        drop(c);

        // Wait for the upstream drain task to finish.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let saw = upstream_saw.lock().await.clone();
        assert_eq!(
            saw, hello,
            "upstream must see the full reassembled ClientHello, not a partial segment"
        );
    }
}
