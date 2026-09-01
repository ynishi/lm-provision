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
//! the env is a matter for the hard layer (a seccomp `connect` pin), a later
//! slice; the register here is "route + refuse by declaration", not
//! "containment" — the same honesty spec 05 keeps for the `paths` policy.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::policy::EgressPolicy;
use super::sni::extract_sni;

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
        refuse(
            &mut client,
            "HTTP/1.1 403 Forbidden\r\nX-Egress: denied\r\n\r\n",
        )
        .await;
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
    // SNI-peek: read the ClientHello before tunnelling, refuse a fronted SNI,
    // then forward the peeked bytes untouched.
    let mut hello = vec![0u8; 4096];
    let hn = cr.read(&mut hello).await.unwrap_or(0);
    if hn > 0 {
        if let Some(server_name) = extract_sni(&hello[..hn]) {
            if !server_name.eq_ignore_ascii_case(&host) {
                tracing::warn!(
                    connect = %host, sni = %server_name,
                    "egress: SNI mismatch (domain fronting) refused"
                );
                return; // drop the tunnel; nothing forwarded upstream
            }
        }
        if uw.write_all(&hello[..hn]).await.is_err() {
            return;
        }
    }
    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);
    let _ = tokio::join!(c2u, u2c);
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
        // Now tunnelled: send 5 non-TLS bytes (no ClientHello → SNI None → allowed)
        // and read the echo back.
        c.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
    }
}
