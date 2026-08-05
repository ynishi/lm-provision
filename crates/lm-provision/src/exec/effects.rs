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
//! - `http_get` / `http_post` use `ureq` (sync, rustls) with redirect
//!   following disabled, reporting the raw status. Both take an
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

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::ExecError;

/// Per-stream capture tail cap (4 KiB).
const TAIL_LIMIT: usize = 4 * 1024;
/// HTTP response body cap (16 MiB) — bodies larger than this are an
/// error rather than being buffered unbounded.
const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Read/download chunk size.
const CHUNK_SIZE: usize = 64 * 1024;
/// Default request timeout.
const DEFAULT_TIMEOUT_SEC: f64 = 30.0;

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

/// HTTP GET `url` with `opts`' resolved headers, reporting the raw
/// status (redirects disabled).
pub fn http_get(url: &str, opts: &HttpOpts) -> Result<HttpOutcome, ExecError> {
    let mut builder = ureq::get(url);
    for (name, value) in &opts.headers {
        builder = builder.header(name, value);
    }
    let request = builder
        .config()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(opts.timeout()))
        .build();

    match request.call() {
        Ok(response) => http_outcome(response),
        Err(err) => Err(ExecError::EffectFailed {
            op: "net_http_get".to_string(),
            message: err.to_string(),
        }),
    }
}

/// HTTP POST `body` to `url` with `content_type` and `opts`' resolved
/// headers, reporting the raw status (redirects disabled).
///
/// `content_type` is the caller's derived value (spec 04
/// §`net.http_post`: `application/json` for the `body_json` form,
/// `application/octet-stream` otherwise). It is applied **only** when
/// `opts` declares no `content-type` header of its own — `ureq`'s
/// `header` appends rather than replaces, so an explicit header must
/// suppress the derived one instead of racing it.
pub fn http_post(
    url: &str,
    body: &[u8],
    content_type: &str,
    opts: &HttpOpts,
) -> Result<HttpOutcome, ExecError> {
    let mut builder = ureq::post(url);
    if !opts.declares_content_type() {
        builder = builder.header("content-type", content_type);
    }
    for (name, value) in &opts.headers {
        builder = builder.header(name, value);
    }
    let request = builder
        .config()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(opts.timeout()))
        .build();

    match request.send(body) {
        Ok(response) => http_outcome(response),
        Err(err) => Err(ExecError::EffectFailed {
            op: "net_http_post".to_string(),
            message: err.to_string(),
        }),
    }
}

/// Read the status + body tail off a completed HTTP response.
fn http_outcome(response: ureq::http::Response<ureq::Body>) -> Result<HttpOutcome, ExecError> {
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let reader = body.as_reader();
    let bytes = read_capped(reader, MAX_BYTES).map_err(|message| ExecError::EffectFailed {
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
pub fn transfer(src: &str, dst: &str) -> Result<TransferOutcome, ExecError> {
    match super::scheme::resolve("net_transfer", src, dst)? {
        super::scheme::Transfer::Download { url } => download(&url, dst),
        super::scheme::Transfer::Upload { url } => upload(src, &url),
    }
}

/// GET `url`, streaming the body into the local `dst` path.
fn download(url: &str, dst: &str) -> Result<TransferOutcome, ExecError> {
    let request = ureq::get(url)
        .config()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs_f64(DEFAULT_TIMEOUT_SEC)))
        .build();

    let response = request.call().map_err(|err| ExecError::EffectFailed {
        op: "net_transfer".to_string(),
        message: err.to_string(),
    })?;

    let status = response.status().as_u16();
    if !(200..400).contains(&status) {
        return Err(ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: format!("download responded with status {status}"),
        });
    }

    let mut body = response.into_body();
    let reader = body.as_reader();
    let bytes =
        stream_to_file(reader, dst, MAX_BYTES).map_err(|message| ExecError::EffectFailed {
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
/// The body is read into memory under the same 16 MiB cap the download
/// path streams against: `ureq`'s `send` takes the bytes, and a capped
/// read keeps a mistyped `src` from pulling an arbitrarily large file
/// into the provisioner. `content_type` is deferred (chapter 04
/// §`net.transfer`), so the request carries the octet-stream default.
fn upload(src: &str, url: &str) -> Result<TransferOutcome, ExecError> {
    let file = std::fs::File::open(src).map_err(|err| ExecError::EffectFailed {
        op: "net_transfer".to_string(),
        message: format!("open '{src}': {err}"),
    })?;
    let body = read_capped(file, MAX_BYTES).map_err(|message| ExecError::EffectFailed {
        op: "net_transfer".to_string(),
        message,
    })?;

    let request = ureq::put(url)
        .header("content-type", "application/octet-stream")
        .config()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs_f64(DEFAULT_TIMEOUT_SEC)))
        .build();

    let response = request
        .send(&body[..])
        .map_err(|err| ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: err.to_string(),
        })?;

    let status = response.status().as_u16();
    if !(200..400).contains(&status) {
        return Err(ExecError::EffectFailed {
            op: "net_transfer".to_string(),
            message: format!("upload responded with status {status}"),
        });
    }

    Ok(TransferOutcome {
        bytes: body.len() as u64,
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

/// Read `reader` to EOF in [`CHUNK_SIZE`] chunks, rejecting a body that
/// would exceed `max_bytes`. Errors are returned as a message string.
fn read_capped(mut reader: impl Read, max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; CHUNK_SIZE];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|err| format!("failed reading response body: {err}"))?;
        if n == 0 {
            break;
        }
        if buf.len() as u64 + n as u64 > max_bytes {
            return Err(format!("response body exceeds max_bytes ({max_bytes})"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Stream `reader` to `dst_path` in [`CHUNK_SIZE`] chunks, removing the
/// partial file on any failure and rejecting a body over `max_bytes`.
/// Errors are returned as a message string.
fn stream_to_file(mut reader: impl Read, dst_path: &str, max_bytes: u64) -> Result<u64, String> {
    let mut file = std::fs::File::create(dst_path)
        .map_err(|err| format!("failed creating '{dst_path}': {err}"))?;
    let mut total: u64 = 0;
    let mut chunk = [0u8; CHUNK_SIZE];

    let result: Result<u64, String> = (|| {
        loop {
            let n = reader
                .read(&mut chunk)
                .map_err(|err| format!("failed reading response body: {err}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max_bytes {
                return Err(format!("response body exceeds max_bytes ({max_bytes})"));
            }
            file.write_all(&chunk[..n])
                .map_err(|err| format!("failed writing '{dst_path}': {err}"))?;
        }
        Ok(total)
    })();

    match result {
        Ok(total) => Ok(total),
        Err(err) => {
            let _ = std::fs::remove_file(dst_path);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

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

    #[test]
    fn http_get_reports_the_status_from_a_local_server() {
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
        let outcome = http_get(&url, &HttpOpts::default()).expect("http_get should succeed");
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

    #[test]
    fn http_get_sends_the_declared_headers() {
        let (url, handle) = one_shot_server();
        let headers = BTreeMap::from([
            ("X-Demo".to_string(), "demo-value".to_string()),
            ("Authorization".to_string(), "Bearer tok".to_string()),
        ]);

        let outcome =
            http_get(&url, &HttpOpts::new(headers, None)).expect("http_get should succeed");
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

    #[test]
    fn http_post_sends_the_body_with_the_derived_content_type() {
        let (url, handle) = one_shot_server();
        let outcome = http_post(
            &url,
            br#"{"prompt":"hi"}"#,
            "application/json",
            &HttpOpts::default(),
        )
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

    /// `ureq`'s `header` appends rather than replaces, so a
    /// `content-type` declared in `headers` must *suppress* the derived
    /// one — not race it into a duplicated field (spec 04
    /// §`net.http_post`: an explicit header wins).
    #[test]
    fn an_explicit_content_type_header_replaces_the_derived_one() {
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

    /// A public `b2://` source still cannot resolve — but the failure
    /// now names the missing piece (the deployment's download endpoint)
    /// and the way around it, instead of reading as a blanket
    /// "not implemented" (chapter 04 §net.transfer).
    #[test]
    fn transfer_names_what_a_public_b2_source_is_missing() {
        let err = transfer("b2://bucket/model.safetensors", "/tmp/model.safetensors")
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
    #[test]
    fn transfer_rejects_a_cli_routed_upload_destination() {
        let err = transfer("/workspace/out.bin", "hf://owner/repo/out.bin")
            .expect_err("hf:// destination must not reach the bridge");
        assert!(err.to_string().contains("CLI-routed"), "{err}");
    }
}
