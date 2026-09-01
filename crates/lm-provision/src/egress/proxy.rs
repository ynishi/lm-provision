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
//! # SNI peek: read one full TLS record before parsing
//!
//! A ClientHello can — and, with 4 KB TLS 1.3 `key_share` payloads,
//! sometimes does — arrive across more than one TCP segment. A single
//! `read()` off the client socket then hands [`super::sni::extract_sni`]
//! a truncated buffer, which returns `None` and looks the same as
//! "well-formed hello without SNI". The peek here therefore reads the
//! **5-byte TLS record header first** (`content_type(1)` +
//! `version(2)` + `length(2)`) and then loop-reads until the full first
//! record body has been buffered, under a byte cap and a deadline
//! ([`SNI_PEEK_MAX_BYTES`], [`SNI_PEEK_DEADLINE`]). Only then does
//! [`extract_sni`](super::sni::extract_sni) run.
//!
//! Policy for what a peek's outcome means:
//!
//! - **First byte is not `0x16`** — the payload is not a TLS record.
//!   Forward it: the CONNECT host was already checked against the
//!   [`EgressPolicy`], non-TLS traffic on 443 (a health probe, an
//!   opaque protocol) carries no SNI to contradict it, and refusing
//!   would break the shape of the tunnel.
//! - **Full record, SNI extracted, matches CONNECT host** — allow, and
//!   forward the peeked bytes.
//! - **Full record, SNI extracted, differs from CONNECT host** — a
//!   domain-fronted hello: refuse. Nothing is forwarded upstream and
//!   the tunnel is dropped (spec 05 §L3 sh_egress: "checks each CONNECT
//!   host — and the TLS ClientHello's SNI, to refuse a fronted name").
//! - **Full record, no SNI extension present** — allow: there is
//!   nothing to contradict the CONNECT host. Modern clients almost
//!   always send SNI, but a hello without one is not a fronting signal
//!   on its own.
//! - **Byte cap or deadline hit before the full record has been read**
//!   — refuse. A TLS ClientHello is a KB-scale message dispatched
//!   immediately after the CONNECT ack; a peer that takes seconds to
//!   send one, or claims a header length that would exceed the cap, is
//!   either broken or attempting to slip past the check while it
//!   ticks. Fail closed rather than forward what we could not inspect.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::policy::EgressPolicy;
use super::sni::extract_sni;

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

/// Read the CONNECT request line + headers, up to the blank line.
async fn read_head(client: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = client.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
            break;
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

async fn refuse(client: &mut TcpStream, line: &str) {
    let _ = client.write_all(line.as_bytes()).await;
}

async fn handle(mut client: TcpStream, policy: Arc<EgressPolicy>) {
    let head = match read_head(&mut client).await {
        Some(h) => h,
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
    let host = target.split(':').next().unwrap_or("").to_string();
    if !policy.allows(&host) {
        tracing::warn!(host = %host, "egress: CONNECT denied (not in sh_egress)");
        refuse(&mut client, "HTTP/1.1 403 Forbidden\r\nX-Egress: denied\r\n\r\n").await;
        return;
    }
    let upstream = match TcpStream::connect(target).await {
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
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    // Peek the first client bytes so we can check SNI before tunnelling.
    // Whichever path we take, `peeked` is what gets forwarded first —
    // the peek never consumes bytes the tunnel would otherwise carry.
    let peeked = match peek_first_tls_record(&mut cr).await {
        PeekOutcome::TlsRecord(bytes) => {
            if let Some(server_name) = extract_sni(&bytes) {
                if !server_name.eq_ignore_ascii_case(&host) {
                    tracing::warn!(
                        connect = %host, sni = %server_name,
                        "egress: SNI mismatch (domain fronting) refused"
                    );
                    return; // drop the tunnel; nothing forwarded upstream
                }
            }
            // No SNI extension: nothing to contradict CONNECT host, allow.
            bytes
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
    if !peeked.is_empty() && uw.write_all(&peeked).await.is_err() {
        return;
    }
    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);
    let _ = tokio::join!(c2u, u2c);
}

/// What [`peek_first_tls_record`] observed on the client socket. The
/// caller decides forwarding + tunnel-drop from the variant.
enum PeekOutcome {
    /// A full first TLS record ready for [`extract_sni`].
    TlsRecord(Vec<u8>),
    /// The peeked bytes are not a TLS record (first byte != `0x16`).
    /// Forward as-is; the CONNECT host was already checked.
    NotTls(Vec<u8>),
    /// The client closed before sending any bytes. Nothing to check
    /// and nothing to forward.
    Eof,
    /// The peek ran out of time or budget before the full record
    /// arrived, or the record's declared length is beyond the cap.
    /// Fail closed.
    Refuse(&'static str),
}

/// Read one full TLS record body from `cr`, or decide fail-closed /
/// pass-through per the module doc. Never allocates more than
/// [`SNI_PEEK_MAX_BYTES`] and never blocks longer than
/// [`SNI_PEEK_DEADLINE`].
async fn peek_first_tls_record(cr: &mut tokio::net::tcp::OwnedReadHalf) -> PeekOutcome {
    let deadline = tokio::time::Instant::now() + SNI_PEEK_DEADLINE;
    // Reserve room for header + a comfortable full record.
    let mut buf = Vec::with_capacity(5 + 1024);
    // First: fill the 5-byte record header so we know the body length.
    // Bail early if the first byte is not a handshake record (0x16).
    while buf.len() < 5 {
        let read_deadline = deadline.saturating_duration_since(tokio::time::Instant::now());
        if read_deadline.is_zero() {
            return PeekOutcome::Refuse("deadline hit before record header");
        }
        let mut tmp = [0u8; 512];
        let n = match tokio::time::timeout(read_deadline, cr.read(&mut tmp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return PeekOutcome::Refuse("socket read error"),
            Err(_) => return PeekOutcome::Refuse("deadline hit before record header"),
        };
        if n == 0 {
            return if buf.is_empty() {
                PeekOutcome::Eof
            } else {
                // Client closed mid-header — treat as non-TLS (allow the
                // partial bytes through so the tunnel semantics hold).
                PeekOutcome::NotTls(buf)
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        // Once we have any bytes, we can decide TLS vs non-TLS on
        // the first byte without waiting for the rest of the header.
        if buf[0] != 0x16 {
            // Non-TLS: keep reading up to what we already got — the
            // caller forwards it and lets the copy loops carry on.
            return PeekOutcome::NotTls(buf);
        }
    }
    // Header is present; the length field is the third and fourth
    // bytes of the header (positions 3 and 4, big-endian).
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total_needed = 5 + record_len;
    if total_needed > SNI_PEEK_MAX_BYTES {
        return PeekOutcome::Refuse("record length exceeds peek cap");
    }
    // Loop-read until the record body is complete or we hit the
    // deadline. One stack buffer, sized to a typical short read, is
    // reused for every iteration — the header loop above uses the
    // same shape ([u8; 512]); mirror it here so a fragmented TLS
    // record does not allocate per-iteration on the hot path.
    let mut tmp = [0u8; 4096];
    while buf.len() < total_needed {
        let read_deadline = deadline.saturating_duration_since(tokio::time::Instant::now());
        if read_deadline.is_zero() {
            return PeekOutcome::Refuse("deadline hit before full record");
        }
        // Cap this read at what we still need so a peer that sends a
        // larger buffered stream cannot overrun the peek window.
        let remaining = total_needed - buf.len();
        let chunk = remaining.min(tmp.len());
        let n = match tokio::time::timeout(read_deadline, cr.read(&mut tmp[..chunk])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return PeekOutcome::Refuse("socket read error"),
            Err(_) => return PeekOutcome::Refuse("deadline hit before full record"),
        };
        if n == 0 {
            return PeekOutcome::Refuse("client closed mid-record");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    PeekOutcome::TlsRecord(buf)
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
