//! Pure-Rust effect implementations (no mlua dependency).
//!
//! Ported from the old `src/bridge/*` mlua bridges with the Lua layer
//! (table decode / `SecretRef` resolution / audit lines / policy checks)
//! stripped away — those concerns are re-homed elsewhere or deferred
//! (see the parent module doc). What remains here is the effect itself:
//! spawn a process, make an HTTP request, write a file, (un)mount a bind
//! mount.
//!
//! MVP scope (see plan.md §KNOWN LIMITATION):
//! - `sh_exec` runs `std::process::Command`; a non-zero exit is returned
//!   as `Ok(outcome)`, not an error — the caller decides.
//! - `http_get` / `http_post` use `reqwest` (async, rustls) with
//!   redirect following disabled, reporting the raw status. Both take an
//!   [`HttpOpts`] carrying the caller-resolved request headers and an
//!   optional deadline override (default 30 s).
//! - `transfer` implements only `https://` download. `b2://` / `hf://`
//!   downloads and uploads that carry credentials are routed to the
//!   native CLIs over `sh.exec` one layer up (see [`super::lifecycle`],
//!   spec 02 §Dispatch routing), so they never reach here; a `b2://` /
//!   `hf://` source or a URL destination that *does* reach `transfer` is
//!   the public `net.transfer`-bridge scheme resolution (chapter 04),
//!   which is not implemented yet and returns [`ExecError::Unsupported`].
//! - `mount_bind` / `umount` are Linux-only; elsewhere they are
//!   [`ExecError::Unsupported`].
//!
//! ## Caps and deadlines: five HTTP routes, three settings
//!
//! | route | body cap | whole-request timeout | read timeout |
//! |---|---|---|---|
//! | [`http_get`] | 16 MiB | `HttpOpts::timeout` (30 s default) | — |
//! | [`http_post`] | 16 MiB | `HttpOpts::timeout` (30 s default) | — |
//! | [`transfer`] download | — | — | [`TRANSFER_READ_TIMEOUT_SEC`] |
//! | [`transfer`] upload | — | — | [`TRANSFER_READ_TIMEOUT_SEC`] |
//! | `HttpPoll` probe (via [`http_get`]) | 16 MiB | 30 s | — |
//!
//! The three routes that keep the cap **buffer the body in memory**, so
//! a cap is the right shape for them; the two that drop it stream to (or
//! from) a file, where a 4 GiB weight is the normal case and a cap is
//! simply a broken download.
//!
//! A *whole-request* deadline cannot serve a transfer at all: a value
//! large enough not to kill a 4 GiB download is far too large to detect
//! a supplier that stopped answering. What a transfer needs is a
//! deadline that applies to **each read and resets on success**, which
//! is `reqwest`'s `read_timeout` — and the reason this module is async
//! (no blocking HTTP client exposes that primitive).
//!
//! [`TRANSFER_READ_TIMEOUT_SEC`] is not derived from any measurement; it
//! is a value between "detects a stalled supplier" and "does not kill a
//! slow CDN". It is a host-side constant, not a profile field.
//!
//! ## The synchronous seam
//!
//! `dsl_kit::Op::apply` is a synchronous trait method, so an op cannot
//! await. [`block_on_effect`] is the single place the async effects
//! below are driven from that seam; see its doc for the runtime it
//! requires.
//!
//! It is a **residue**, not the design. dsl-kit's own answer is that
//! "effects belong in `Call` children" (`dsl_kit::Op`) and that the host
//! resolves them through an `AsyncEffectResolver`; the three
//! single-effect network phases (`net.transfer` / `net.http_get` /
//! `net.http_post`) have that route now (see [`super::registry`]'s
//! module doc and [`crate::apply`]), and so does **every lifecycle
//! step** ([`super::steps`]). All of them reach [`transfer`] /
//! [`http_get`] / [`sh_exec`] by `await`, not through here.
//!
//! **The four call sites left all belong to the synchronous engine
//! driver**, which is the thing that cannot await — not to any
//! particular phase:
//!
//! - three are the routed network phases' legacy
//!   [`super::registry::EffectRoute::Op`] branches, kept on purpose so
//!   the two-routes-agree regression still has a route to compare;
//! - one is a lifecycle step run from `ProfileOp::run_lifecycle`, which
//!   is what `crate::profile_ast::create_profile_engine` reaches: that
//!   engine is driven by a synchronous `Stepper` (the MCP debugger host,
//!   the exec integration tests), and a synchronous stepper cannot
//!   resolve a `Call`, so a lifecycle phase stays an `Apply` there.
//!
//! The count therefore tracks **how much still runs on the synchronous
//! driver**, and goes to zero when that driver does — not when any
//! individual phase moves.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::ExecError;

/// Per-stream capture tail cap (4 KiB).
const TAIL_LIMIT: usize = 4 * 1024;
/// In-memory HTTP response body cap (16 MiB) — bodies larger than this
/// are an error rather than being buffered unbounded. It applies to the
/// three routes that hold the body in memory, never to the two that
/// stream a file (see the module doc's table).
const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Default request timeout.
const DEFAULT_TIMEOUT_SEC: f64 = 30.0;
/// Per-read deadline on a [`transfer`], reset by every successful read.
///
/// Deliberately *not* a whole-request deadline: a transfer's total time
/// is a function of the file's size and the link's speed, neither of
/// which the host knows, while "nothing arrived for a minute" means the
/// same thing for a 30 MiB LoRA and a 4 GiB checkpoint.
const TRANSFER_READ_TIMEOUT_SEC: u64 = 60;

/// Options for [`sh_exec`]. Carries the resolved env-injection map
/// (spec 06 §Resolution: the caller resolves `env.ref` / literal slots
/// into `name → value` and hands them here). `cwd` / `timeout` remain
/// deferred; the struct shape lets those be added without a signature
/// change.
///
/// The [`std::fmt::Debug`] impl is deliberately hand-written to redact
/// the resolved values — a `ShOpts` printed with `{:?}` shows only the
/// env *keys*, never the secret values (spec 06 opacity: resolved values
/// are never logged).
#[derive(Default, Clone)]
pub struct ShOpts {
    /// Resolved `name → value` env injected into the child process.
    env: BTreeMap<String, String>,
}

impl ShOpts {
    /// Build options carrying the resolved env-injection map.
    pub fn new(env: BTreeMap<String, String>) -> Self {
        Self { env }
    }
}

impl std::fmt::Debug for ShOpts {
    /// Redacts values: only the env key names are rendered so that a
    /// stray `{:?}` of a `ShOpts` can never leak a resolved secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShOpts")
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Result of a [`sh_exec`] call.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// Process exit code (`-1` when terminated by signal / unknown).
    pub exit_code: i32,
    /// Last `TAIL_LIMIT` bytes of stdout, lossily decoded.
    pub stdout_tail: String,
    /// Last `TAIL_LIMIT` bytes of stderr, lossily decoded.
    pub stderr_tail: String,
}

/// Options for [`http_get`] / [`http_post`]. Carries the resolved
/// request headers (spec 06 §Resolution: the caller resolves the
/// `headers` keyed slot into `name → value` and hands them here) and an
/// optional per-request deadline overriding `DEFAULT_TIMEOUT_SEC`.
///
/// The [`std::fmt::Debug`] impl is deliberately hand-written to redact
/// the values — an `HttpOpts` printed with `{:?}` shows only the header
/// *names*, never a resolved secret (spec 06 opacity, spec 09 §Audit
/// log "header names are logged, header values never"), mirroring
/// [`ShOpts`].
#[derive(Default, Clone)]
pub struct HttpOpts {
    /// Resolved `name → value` headers sent with the request.
    headers: BTreeMap<String, String>,
    /// Request deadline in seconds; [`DEFAULT_TIMEOUT_SEC`] when `None`.
    timeout_sec: Option<u16>,
}

impl HttpOpts {
    /// Build options carrying the resolved headers and an optional
    /// deadline override.
    pub fn new(headers: BTreeMap<String, String>, timeout_sec: Option<u16>) -> Self {
        Self {
            headers,
            timeout_sec,
        }
    }

    /// The effective request deadline.
    fn timeout(&self) -> Duration {
        match self.timeout_sec {
            Some(secs) => Duration::from_secs(u64::from(secs)),
            None => Duration::from_secs_f64(DEFAULT_TIMEOUT_SEC),
        }
    }

    /// Whether the declared headers already carry `content-type`
    /// (matched case-insensitively, as HTTP field names are). When they
    /// do, the caller's derived content type is dropped: an explicit
    /// header wins (spec 04 §`net.http_post`).
    fn declares_content_type(&self) -> bool {
        self.headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-type"))
    }
}

impl std::fmt::Debug for HttpOpts {
    /// Redacts values: only the header names are rendered so that a
    /// stray `{:?}` of an `HttpOpts` can never leak a resolved secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOpts")
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("timeout_sec", &self.timeout_sec)
            .finish()
    }
}

/// Result of an [`http_get`] / [`http_post`] call.
#[derive(Debug, Clone)]
pub struct HttpOutcome {
    /// Raw HTTP status code (redirects are reported, not followed).
    pub status: u16,
    /// Last `TAIL_LIMIT` bytes of the response body, lossily decoded.
    pub body_tail: String,
}

/// Result of a [`transfer`] download.
#[derive(Debug, Clone)]
pub struct TransferOutcome {
    /// Bytes written to the destination.
    pub bytes: u64,
    /// Destination path written to.
    pub dst: String,
}

/// Last `TAIL_LIMIT` bytes of `bytes`, lossily decoded to UTF-8.
fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(TAIL_LIMIT);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// Run `argv` as a child process and capture stdout/stderr.
///
/// A non-zero exit is returned as `Ok(outcome)` (the caller judges it);
/// only a spawn failure or an empty `argv` is an [`ExecError`].
pub fn sh_exec(argv: &[String], opts: &ShOpts) -> Result<ExecOutcome, ExecError> {
    if argv.is_empty() {
        return Err(ExecError::EffectFailed {
            op: "sh_exec".to_string(),
            message: "argv must be a non-empty list of strings".to_string(),
        });
    }

    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .envs(&opts.env)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| ExecError::EffectFailed {
            op: "sh_exec".to_string(),
            message: format!("failed to start '{}': {err}", argv[0]),
        })?;

    Ok(ExecOutcome {
        exit_code: output.status.code().unwrap_or(-1),
        stdout_tail: tail(&output.stdout),
        stderr_tail: tail(&output.stderr),
    })
}

/// Drive one async effect from the engine's synchronous `Op::apply`.
///
/// `dsl_kit::Op::apply` is a `fn`, not an `async fn`, so an op cannot
/// await. Rather than spread that seam over every call site, it lives
/// here: the four remaining callers — the `net_http_get` /
/// `net_http_post` / `net_transfer` ops in [`super::registry`] (the
/// legacy [`super::registry::EffectRoute::Op`] branch of three phases
/// that also have a `Call` route), and one per lifecycle step in
/// `ProfileOp::run_lifecycle` — hand their future to this function. All
/// four are the synchronous engine driver; see the module doc.
///
/// **A caller with more than one thing to await hands over one future
/// covering all of it**, rather than calling this once per await. The
/// transfer step is the example: evaluating its completion condition
/// and performing the transfer are both async, and both live inside the
/// single future it passes here. Counting call sites is therefore a
/// meaningful measure of how far the synchronous seam has spread.
///
/// Nothing on the `Call` route comes through here: a suspended effect is
/// awaited by the host resolver ([`crate::apply`]) on the runtime that
/// is already driving `drive_async`.
///
/// **A multi-threaded tokio runtime must be current.** Production gets
/// one from the CLI entry point ([`crate::cli`] builds it and
/// `block_on`s [`crate::apply::run_apply_ast`]); a test that drives an
/// effect needs `#[tokio::test(flavor = "multi_thread")]`.
/// `block_in_place` hands this worker's queued tasks to a sibling thread
/// before blocking, which the current-thread flavour has no sibling to
/// do — so both "no runtime" and "the wrong flavour" are reported as an
/// [`ExecError`] naming the requirement, rather than left to tokio's own
/// panic.
pub(super) fn block_on_effect<T, E>(
    op: &str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: From<ExecError>,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Err(ExecError::EffectFailed {
            op: op.to_string(),
            message: "no tokio runtime is running: apply drives async effects and must be \
                      called from inside a multi-threaded tokio runtime"
                .to_string(),
        }
        .into());
    };
    if !matches!(
        handle.runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    ) {
        return Err(ExecError::EffectFailed {
            op: op.to_string(),
            message: "the current tokio runtime is single-threaded: apply blocks the calling \
                      thread on each effect and must be called from inside a multi-threaded \
                      tokio runtime"
                .to_string(),
        }
        .into());
    }
    tokio::task::block_in_place(|| handle.block_on(future))
}

/// Render `err` with its whole source chain.
///
/// `reqwest::Error`'s own `Display` is a category ("error sending
/// request"); everything that identifies the failure — connection
/// refused, a fired read timeout, a TLS rejection — is in the sources.
/// Dropping them would turn every network failure into the same line.
fn render(err: &reqwest::Error) -> String {
    let mut out = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        out.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    out
}

/// Build a one-request [`reqwest::Client`], applying `configure` on top
/// of the defaults.
fn client(
    op: &str,
    configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<reqwest::Client, ExecError> {
    configure(reqwest::Client::builder())
        .build()
        .map_err(|err| ExecError::EffectFailed {
            op: op.to_string(),
            message: format!("failed building the HTTP client: {}", render(&err)),
        })
}

/// HTTP GET `url` with `opts`' resolved headers, reporting the raw
/// status (redirects disabled).
pub async fn http_get(url: &str, opts: &HttpOpts) -> Result<HttpOutcome, ExecError> {
    let client = client("net_http_get", |builder| {
        builder
            .redirect(reqwest::redirect::Policy::none())
            .timeout(opts.timeout())
    })?;
    let mut request = client.get(url);
    for (name, value) in &opts.headers {
        request = request.header(name, value);
    }

    match request.send().await {
        Ok(response) => http_outcome(response).await,
        Err(err) => Err(ExecError::EffectFailed {
            op: "net_http_get".to_string(),
            message: render(&err),
        }),
    }
}

/// HTTP POST `body` to `url` with `content_type` and `opts`' resolved
/// headers, reporting the raw status (redirects disabled).
///
/// `content_type` is the caller's derived value (spec 04
/// §`net.http_post`: `application/json` for the `body_json` form,
/// `application/octet-stream` otherwise). It is applied **only** when
/// `opts` declares no `content-type` header of its own — `header`
/// appends rather than replaces, so an explicit header must suppress the
/// derived one instead of racing it.
pub async fn http_post(
    url: &str,
    body: &[u8],
    content_type: &str,
    opts: &HttpOpts,
) -> Result<HttpOutcome, ExecError> {
    let client = client("net_http_post", |builder| {
        builder
            .redirect(reqwest::redirect::Policy::none())
            .timeout(opts.timeout())
    })?;
    let mut request = client.post(url);
    if !opts.declares_content_type() {
        request = request.header("content-type", content_type);
    }
    for (name, value) in &opts.headers {
        request = request.header(name, value);
    }

    match request.body(body.to_vec()).send().await {
        Ok(response) => http_outcome(response).await,
        Err(err) => Err(ExecError::EffectFailed {
            op: "net_http_post".to_string(),
            message: render(&err),
        }),
    }
}

/// Read the status + body tail off a completed HTTP response.
async fn http_outcome(response: reqwest::Response) -> Result<HttpOutcome, ExecError> {
    let status = response.status().as_u16();
    let bytes =
        read_capped(response, MAX_BYTES)
            .await
            .map_err(|message| ExecError::EffectFailed {
                op: "net_http".to_string(),
                message,
            })?;
    Ok(HttpOutcome {
        status,
        body_tail: tail(&bytes),
    })
}

/// Transfer `src` to `dst`.
///
/// The direction and the URL come from [`super::scheme::resolve`]: a
/// scheme on `src` is a download (`https://` verbatim, `hf://`
/// rewritten to its public resolve URL), a scheme on `dst` is an
/// upload. Credential-carrying transfers never reach here — those route
/// to the native CLIs over `sh.exec` one layer up (see
/// [`super::lifecycle`], spec 02 §Dispatch routing) — and a `b2://`
/// source fails with an error naming the endpoint no profile field
/// declares, rather than a guessed host.
pub async fn transfer(src: &str, dst: &str) -> Result<TransferOutcome, ExecError> {
    transfer_in(src, dst, Duration::from_secs(TRANSFER_READ_TIMEOUT_SEC)).await
}

/// [`transfer`] with the per-read deadline injected, so a test can prove
/// a stalled supplier is detected without spending
/// [`TRANSFER_READ_TIMEOUT_SEC`] doing it.
async fn transfer_in(
    src: &str,
    dst: &str,
    read_timeout: Duration,
) -> Result<TransferOutcome, ExecError> {
    match super::scheme::resolve("net_transfer", src, dst)? {
        super::scheme::Transfer::Download { url } => download(&url, dst, read_timeout).await,
        super::scheme::Transfer::Upload { url } => upload(src, &url, read_timeout).await,
    }
}

/// GET `url`, streaming the body into the local `dst` path.
///
/// **Redirects are followed** (`reqwest`'s default limit of 10). A
/// public weight is routinely served as a `3xx` to a CDN — HuggingFace
/// resolves every LFS object that way — so a download that stops at the
/// redirect writes the redirect's own body to `dst` and reports success.
/// Following makes the success range `200..300` rather than `200..400`:
/// once redirects are followed there is no route by which a `3xx` is the
/// final status, so accepting one could only mean the entity was missed.
async fn download(
    url: &str,
    dst: &str,
    read_timeout: Duration,
) -> Result<TransferOutcome, ExecError> {
    let client = client("net_transfer", |builder| builder.read_timeout(read_timeout))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: render(&err),
        })?;

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: format!("download responded with status {status}"),
        });
    }

    let bytes = stream_to_file(response, dst)
        .await
        .map_err(|message| ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message,
        })?;

    Ok(TransferOutcome {
        bytes,
        dst: dst.to_string(),
    })
}

/// PUT the local `src` file to `url`.
///
/// The file is **streamed**, not buffered: an upload's whole point is a
/// weight, and reading one into memory to hand it over would cap the op
/// at whatever the provisioner can hold. `Content-Length` is taken from
/// the file's metadata so the request stays length-delimited rather than
/// chunked. `content_type` is deferred (chapter 04 §`net.transfer`), so
/// the request carries the octet-stream default.
async fn upload(
    src: &str,
    url: &str,
    read_timeout: Duration,
) -> Result<TransferOutcome, ExecError> {
    let file = tokio::fs::File::open(src)
        .await
        .map_err(|err| ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: format!("open '{src}': {err}"),
        })?;
    let bytes = file
        .metadata()
        .await
        .map_err(|err| ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: format!("stat '{src}': {err}"),
        })?
        .len();

    let client = client("net_transfer", |builder| {
        builder
            .redirect(reqwest::redirect::Policy::none())
            .read_timeout(read_timeout)
    })?;
    let response = client
        .put(url)
        .header("content-type", "application/octet-stream")
        .header(reqwest::header::CONTENT_LENGTH, bytes)
        .body(reqwest::Body::from(file))
        .send()
        .await
        .map_err(|err| ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: render(&err),
        })?;

    let status = response.status().as_u16();
    if !(200..400).contains(&status) {
        return Err(ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: format!("upload responded with status {status}"),
        });
    }

    Ok(TransferOutcome {
        bytes,
        dst: url.to_string(),
    })
}

/// Write `content` to `path`, truncating/creating. The parent directory
/// is not created — a missing parent is an error. Returns the byte count.
pub fn fs_write(path: &str, content: &[u8]) -> Result<usize, ExecError> {
    let mut file = std::fs::File::create(path).map_err(|err| ExecError::EffectFailed {
        op: "fs_write".to_string(),
        message: format!("failed opening '{path}': {err}"),
    })?;
    file.write_all(content)
        .map_err(|err| ExecError::EffectFailed {
            op: "fs_write".to_string(),
            message: format!("failed writing '{path}': {err}"),
        })?;
    Ok(content.len())
}

/// Bind-mount `src` at `dst` (Linux only).
#[cfg(target_os = "linux")]
pub fn mount_bind(src: &str, dst: &str) -> Result<(), ExecError> {
    use nix::mount::{mount, MsFlags};

    mount(Some(src), dst, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|err| {
        ExecError::EffectFailed {
            op: "mount_bind".to_string(),
            message: err.to_string(),
        }
    })
}

/// Non-Linux stub: bind mount is unsupported.
#[cfg(not(target_os = "linux"))]
pub fn mount_bind(_src: &str, _dst: &str) -> Result<(), ExecError> {
    Err(ExecError::Unsupported(
        "mount.bind: not supported on this platform (mount requires Linux)".to_string(),
    ))
}

/// Unmount `path` (Linux only).
#[cfg(target_os = "linux")]
pub fn umount(path: &str) -> Result<(), ExecError> {
    nix::mount::umount(path).map_err(|err| ExecError::EffectFailed {
        op: "mount_umount".to_string(),
        message: err.to_string(),
    })
}

/// Non-Linux stub: umount is unsupported.
#[cfg(not(target_os = "linux"))]
pub fn umount(_path: &str) -> Result<(), ExecError> {
    Err(ExecError::Unsupported(
        "mount.umount: not supported on this platform (mount requires Linux)".to_string(),
    ))
}

/// Buffer `response`'s body, rejecting one that would exceed
/// `max_bytes`. Errors are returned as a message string.
///
/// The cap is checked *before* each chunk is appended, so an oversized
/// body is refused rather than held and then complained about.
async fn read_capped(mut response: reqwest::Response, max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|err| format!("failed reading response body: {}", render(&err)))?;
        let Some(chunk) = chunk else { break };
        if buf.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err(format!("response body exceeds max_bytes ({max_bytes})"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Stream `response`'s body to `dst_path`, removing the partial file on
/// any failure. Errors are returned as a message string.
///
/// **No cap.** This is the path a model weight travels; the size that
/// would have to be refused is the size that is normal here. What
/// bounds the stream instead is the client's `read_timeout` — a supplier
/// that stops sending fails, a supplier that keeps sending is allowed to
/// finish.
async fn stream_to_file(mut response: reqwest::Response, dst_path: &str) -> Result<u64, String> {
    let mut file = tokio::fs::File::create(dst_path)
        .await
        .map_err(|err| format!("failed creating '{dst_path}': {err}"))?;

    let mut total: u64 = 0;
    let result: Result<u64, String> = loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if let Err(err) = file.write_all(&chunk).await {
                    break Err(format!("failed writing '{dst_path}': {err}"));
                }
                total += chunk.len() as u64;
            }
            // The body ended. `tokio::fs::File` buffers, so the last
            // write is only on disk once it is flushed — a destination
            // reported as complete while its tail is still in memory
            // would be a silently truncated weight.
            Ok(None) => match file.flush().await {
                Ok(()) => break Ok(total),
                Err(err) => break Err(format!("failed writing '{dst_path}': {err}")),
            },
            Err(err) => break Err(format!("failed reading response body: {}", render(&err))),
        }
    };

    match result {
        Ok(total) => Ok(total),
        Err(err) => {
            let _ = tokio::fs::remove_file(dst_path).await;
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    }

    #[test]
    fn sh_exec_runs_echo_and_captures_stdout() {
        let outcome = sh_exec(
            &["echo".to_string(), "hello".to_string()],
            &ShOpts::default(),
        )
        .expect("echo should run");
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout_tail.contains("hello"));
    }

    #[test]
    fn sh_exec_injects_the_resolved_env_into_the_child_process() {
        let key = format!("LM_EXEC_INJECT_{}", std::process::id());
        let mut env = BTreeMap::new();
        env.insert(key.clone(), "injected-value".to_string());
        // `printf %s "$KEY"` echoes the injected value on stdout iff the
        // child process actually received it in its environment.
        let outcome = sh_exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                format!("printf %s \"${key}\""),
            ],
            &ShOpts::new(env),
        )
        .expect("sh should run");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout_tail, "injected-value");
    }

    #[test]
    fn sh_opts_debug_redacts_the_env_values() {
        let mut env = BTreeMap::new();
        env.insert("HF_TOKEN".to_string(), "super-secret-value".to_string());
        let rendered = format!("{:?}", ShOpts::new(env));
        assert!(rendered.contains("HF_TOKEN"), "keys are shown: {rendered}");
        assert!(
            !rendered.contains("super-secret-value"),
            "values must be redacted: {rendered}"
        );
    }

    #[test]
    fn sh_exec_reports_a_non_zero_exit_as_ok() {
        let outcome = sh_exec(
            &["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
            &ShOpts::default(),
        )
        .expect("a non-zero exit is not an error, it is an outcome");
        assert_eq!(outcome.exit_code, 7);
    }

    #[test]
    fn sh_exec_rejects_empty_argv() {
        let err = sh_exec(&[], &ShOpts::default()).expect_err("empty argv must be an error");
        assert!(err.to_string().contains("argv"));
    }

    #[test]
    fn fs_write_creates_a_file_and_reports_the_byte_count() {
        let dir = std::env::temp_dir().join(format!(
            "lm-exec-fs-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("out.txt");
        let path_str = path.to_string_lossy().into_owned();

        let n = fs_write(&path_str, b"hello world").expect("write should succeed");
        assert_eq!(n, 11);
        assert_eq!(std::fs::read(&path).expect("read back"), b"hello world");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fs_write_fails_when_the_parent_directory_is_missing() {
        let missing = std::env::temp_dir().join(format!(
            "lm-exec-missing-{}-{}/out.txt",
            std::process::id(),
            unique_suffix()
        ));
        let err = fs_write(&missing.to_string_lossy(), b"x")
            .expect_err("a missing parent directory must be an error");
        assert!(err.to_string().contains("fs_write"));
    }

    #[tokio::test]
    async fn http_get_reports_the_status_from_a_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = "pong";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        let url = format!("http://{addr}/");
        let outcome = http_get(&url, &HttpOpts::default())
            .await
            .expect("http_get should succeed");
        assert_eq!(outcome.status, 200);
        assert!(outcome.body_tail.contains("pong"));

        handle.join().expect("server thread joins");
    }

    /// Spawn a one-shot local HTTP server. Returns the URL to call and a
    /// join handle yielding the **raw request text** (request line +
    /// headers + body), so a test can assert on exactly what went over
    /// the wire.
    fn one_shot_server() -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let request = read_request(&mut stream);
            let body = "ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            request
        });
        (format!("http://{addr}/"), handle)
    }

    /// Read one whole HTTP request (headers plus a `Content-Length`
    /// body, when declared) off `stream`.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).expect("read request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let want = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if buf.len() - (head_end + 4) >= want {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn http_get_sends_the_declared_headers() {
        let (url, handle) = one_shot_server();
        let headers = BTreeMap::from([
            ("X-Demo".to_string(), "demo-value".to_string()),
            ("Authorization".to_string(), "Bearer tok".to_string()),
        ]);

        let outcome = http_get(&url, &HttpOpts::new(headers, None))
            .await
            .expect("http_get should succeed");
        assert_eq!(outcome.status, 200);

        let request = handle.join().expect("server thread joins").to_lowercase();
        assert!(
            request.contains("x-demo: demo-value"),
            "declared header must reach the wire: {request}"
        );
        assert!(
            request.contains("authorization: bearer tok"),
            "declared header must reach the wire: {request}"
        );
    }

    #[tokio::test]
    async fn http_post_sends_the_body_with_the_derived_content_type() {
        let (url, handle) = one_shot_server();
        let outcome = http_post(
            &url,
            br#"{"prompt":"hi"}"#,
            "application/json",
            &HttpOpts::default(),
        )
        .await
        .expect("http_post should succeed");
        assert_eq!(outcome.status, 200);

        let request = handle.join().expect("server thread joins");
        assert!(
            request
                .to_lowercase()
                .contains("content-type: application/json"),
            "the derived content type must reach the wire: {request}"
        );
        assert!(
            request.contains(r#"{"prompt":"hi"}"#),
            "the body must reach the wire: {request}"
        );
    }

    /// `header` appends rather than replaces, so a `content-type`
    /// declared in `headers` must *suppress* the derived one — not race
    /// it into a duplicated field (spec 04 §`net.http_post`: an explicit
    /// header wins).
    #[tokio::test]
    async fn an_explicit_content_type_header_replaces_the_derived_one() {
        let (url, handle) = one_shot_server();
        let headers = BTreeMap::from([(
            // Deliberately cased differently from the derived header's
            // name: HTTP field names are case-insensitive.
            "Content-Type".to_string(),
            "text/plain".to_string(),
        )]);
        http_post(
            &url,
            b"raw",
            "application/json",
            &HttpOpts::new(headers, None),
        )
        .await
        .expect("http_post should succeed");

        let request = handle.join().expect("server thread joins").to_lowercase();
        assert!(
            request.contains("content-type: text/plain"),
            "the explicit header must win: {request}"
        );
        assert!(
            !request.contains("content-type: application/json"),
            "the derived content type must be suppressed, not appended: {request}"
        );
        assert_eq!(
            request.matches("content-type:").count(),
            1,
            "exactly one content-type field: {request}"
        );
    }

    #[test]
    fn http_opts_debug_redacts_the_header_values() {
        let headers = BTreeMap::from([(
            "Authorization".to_string(),
            "Bearer super-secret-value".to_string(),
        )]);
        let rendered = format!("{:?}", HttpOpts::new(headers, Some(5)));
        assert!(
            rendered.contains("Authorization"),
            "names are shown: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-value"),
            "values must be redacted: {rendered}"
        );
    }

    /// A one-shot local server that answers the first request with a
    /// `302` pointing at `/final`, and the second with `payload`.
    ///
    /// The redirect carries a body of its own, which is what a client
    /// that does not follow redirects would write to the destination —
    /// so the fixture distinguishes "followed the redirect" from
    /// "reported the 3xx as a success".
    fn redirecting_server(payload: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the first request");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let decoy = "redirect-body-that-must-never-be-written";
            let redirect = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{addr}/final\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                decoy.len(),
                decoy
            );
            stream
                .write_all(redirect.as_bytes())
                .expect("write the redirect");
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept the redirected request");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            stream
                .write_all(response.as_bytes())
                .expect("write the payload");
        });
        (format!("http://{addr}/start"), handle)
    }

    /// A 3xx supplier must yield the *entity*, not the redirect.
    ///
    /// HuggingFace serves an LFS weight as a `302` to its CDN, so a
    /// download that reports the redirect as a success writes the
    /// redirect's own body to the destination and calls it a model file.
    #[tokio::test]
    async fn a_download_follows_a_redirect_and_writes_the_final_body() {
        let payload = "the-entity-behind-the-redirect";
        let (url, handle) = redirecting_server(payload);
        let dst = std::env::temp_dir().join(format!(
            "lm-exec-redirect-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let dst_str = dst.to_string_lossy().into_owned();

        let outcome = transfer(&url, &dst_str)
            .await
            .expect("a 302 supplier must still deliver");

        assert_eq!(
            std::fs::read_to_string(&dst).expect("the destination was written"),
            payload,
            "the redirect's own body must never reach the destination"
        );
        assert_eq!(outcome.bytes, payload.len() as u64);

        std::fs::remove_file(&dst).ok();
        handle.join().expect("server thread joins");
    }

    /// A public `b2://` source still cannot resolve — but the failure
    /// now names the missing piece (the deployment's download endpoint)
    /// and the way around it, instead of reading as a blanket
    /// "not implemented" (chapter 04 §net.transfer).
    #[tokio::test]
    async fn transfer_names_what_a_public_b2_source_is_missing() {
        let err = transfer("b2://bucket/model.safetensors", "/tmp/model.safetensors")
            .await
            .expect_err("b2:// source must be unsupported");
        let message = err.to_string();
        assert!(
            message.contains("download endpoint") && message.contains("b2 CLI route"),
            "expected the endpoint-gap message, got: {message}"
        );
    }

    /// A `b2://` / `hf://` upload destination is CLI-routed by the
    /// lifecycle layer, so one arriving here is a routing bug and says
    /// so rather than attempting a PUT.
    #[tokio::test]
    async fn transfer_rejects_a_cli_routed_upload_destination() {
        let err = transfer("/workspace/out.bin", "hf://owner/repo/out.bin")
            .await
            .expect_err("hf:// destination must not reach the bridge");
        assert!(err.to_string().contains("CLI-routed"), "{err}");
    }

    // -----------------------------------------------------------------
    // Caps: what the two streaming routes dropped, and what the three
    // in-memory ones kept.
    // -----------------------------------------------------------------

    /// A size no in-memory route would accept: one byte past the 16 MiB
    /// cap the three buffering routes still enforce.
    const OVER_CAP: usize = 16 * 1024 * 1024 + 1;

    /// A body of `len` bytes with a recognisable, position-dependent
    /// fill, so a truncated or reordered transfer cannot pass by having
    /// the right length.
    fn payload_of(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Serve `body` once, with a `Content-Length`.
    fn serving_server(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).expect("write head");
            stream.write_all(&body).expect("write body");
        });
        (format!("http://{addr}/"), handle)
    }

    /// A download must not be capped: the file the provisioner exists to
    /// fetch is larger than any buffer it would be sane to hold, and the
    /// old 16 MiB limit meant a real weight failed *and* took its
    /// partial file with it.
    #[tokio::test]
    async fn a_download_past_the_in_memory_cap_completes_with_every_byte() {
        let body = payload_of(20 * 1024 * 1024);
        let (url, handle) = serving_server(body.clone());
        let dst = std::env::temp_dir().join(format!(
            "lm-exec-big-download-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let dst_str = dst.to_string_lossy().into_owned();

        let outcome = transfer(&url, &dst_str)
            .await
            .expect("a 20 MiB download must succeed");

        assert_eq!(outcome.bytes, body.len() as u64);
        assert_eq!(
            std::fs::read(&dst).expect("the destination was written"),
            body,
            "every byte, in order"
        );

        std::fs::remove_file(&dst).ok();
        handle.join().expect("server thread joins");
    }

    /// The counterpart: `http_get` buffers its body, so its cap stays.
    /// Lifting it there would let a mistyped URL pull an arbitrarily
    /// large response into the provisioner's memory.
    #[tokio::test]
    async fn http_get_still_refuses_a_body_past_the_in_memory_cap() {
        let (url, handle) = serving_server(payload_of(OVER_CAP));

        let err = http_get(&url, &HttpOpts::default())
            .await
            .expect_err("a body past the cap must be an error, not a buffer");
        assert!(
            err.to_string().contains("max_bytes"),
            "the failure names the cap: {err}"
        );

        handle.join().expect("server thread joins");
    }

    /// An upload streams the file, so it is not capped either — the same
    /// weight has to be able to travel back out.
    #[tokio::test]
    async fn an_upload_past_the_in_memory_cap_sends_every_byte() {
        let body = payload_of(20 * 1024 * 1024);
        let src = std::env::temp_dir().join(format!(
            "lm-exec-big-upload-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::write(&src, &body).expect("write the source file");
        let src_str = src.to_string_lossy().into_owned();

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let expected = body.clone();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let received = read_request_body(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("write response");
            assert_eq!(received, expected, "the whole file must reach the wire");
        });

        let outcome = transfer(&src_str, &format!("http://{addr}/put"))
            .await
            .expect("a 20 MiB upload must succeed");
        assert_eq!(outcome.bytes, body.len() as u64);

        std::fs::remove_file(&src).ok();
        handle.join().expect("server thread joins");
    }

    /// Read one request off `stream` and return its `Content-Length`
    /// body.
    fn read_request_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        let mut want: Option<usize> = None;
        let mut head_end = 0usize;
        loop {
            let n = stream.read(&mut chunk).expect("read request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if want.is_none() {
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                head_end = end + 4;
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                want = Some(
                    head.lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0),
                );
            }
            if buf.len() - head_end >= want.unwrap_or(0) {
                break;
            }
        }
        buf[head_end..].to_vec()
    }

    // -----------------------------------------------------------------
    // The per-read deadline
    // -----------------------------------------------------------------

    /// A supplier that accepts the connection, promises a body and then
    /// sends nothing must fail on the per-read deadline rather than hang
    /// until something else gives up.
    ///
    /// The deadline is injected (1 s) instead of spending the real
    /// [`TRANSFER_READ_TIMEOUT_SEC`] proving the same thing; what the
    /// assertion pins is that the *injected* value is what ended the
    /// wait, from both sides — no earlier (so it is not some other
    /// deadline firing) and not much later (so it fired at all).
    #[tokio::test]
    async fn a_supplier_that_stops_sending_fails_on_the_read_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            // Headers promising a body that never arrives. The
            // connection is held open, so nothing but the read deadline
            // can end the client's wait.
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
                .expect("write head");
            while !server_stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let dst = std::env::temp_dir().join(format!(
            "lm-exec-stalled-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let dst_str = dst.to_string_lossy().into_owned();

        let read_timeout = Duration::from_secs(1);
        let started = std::time::Instant::now();
        let err = transfer_in(&format!("http://{addr}/"), &dst_str, read_timeout)
            .await
            .expect_err("a supplier that stops sending must fail");
        let elapsed = started.elapsed();

        assert!(
            elapsed >= read_timeout,
            "the deadline must not fire early ({elapsed:?}): {err}"
        );
        assert!(
            elapsed < read_timeout * 5,
            "the deadline must fire, not be waited out ({elapsed:?}): {err}"
        );
        assert!(
            !dst.exists(),
            "a failed transfer leaves no partial file behind"
        );

        stop.store(true, Ordering::Relaxed);
        handle.join().expect("server thread joins");
    }

    // -----------------------------------------------------------------
    // The synchronous seam
    // -----------------------------------------------------------------

    /// The seam reports a missing runtime as a step failure naming the
    /// requirement. Left to tokio it would be a panic from inside
    /// `Op::apply`, which the engine has no way to turn into a report
    /// entry.
    #[test]
    fn the_effect_bridge_reports_a_missing_runtime_instead_of_panicking() {
        let err: ExecError = block_on_effect("net_transfer", async {
            Err::<(), ExecError>(ExecError::Unsupported("unreached".to_string()))
        })
        .expect_err("no runtime is running here");
        let message = err.to_string();
        assert!(
            message.contains("no tokio runtime is running"),
            "the failure names what is missing: {message}"
        );
    }

    /// …and the same for a runtime of the wrong flavour: the seam blocks
    /// its thread, which a current-thread runtime has no sibling worker
    /// to cover for.
    #[tokio::test]
    async fn the_effect_bridge_reports_a_single_threaded_runtime_instead_of_panicking() {
        let err: ExecError = block_on_effect("net_transfer", async {
            Err::<(), ExecError>(ExecError::Unsupported("unreached".to_string()))
        })
        .expect_err("the default #[tokio::test] runtime is single-threaded");
        let message = err.to_string();
        assert!(
            message.contains("single-threaded"),
            "the failure names the flavour: {message}"
        );
    }

    /// Under the flavour the seam does require, the future runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_effect_bridge_drives_the_future_on_a_multi_threaded_runtime() {
        let (url, handle) = one_shot_server();
        let outcome = block_on_effect("net_http_get", http_get(&url, &HttpOpts::default()))
            .expect("a multi-threaded runtime is what the seam asks for");
        assert_eq!(outcome.status, 200);
        handle.join().expect("server thread joins");
    }
}
