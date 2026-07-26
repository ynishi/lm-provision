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
//!   following disabled, reporting the raw status.
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
    /// Last [`TAIL_LIMIT`] bytes of stdout, lossily decoded.
    pub stdout_tail: String,
    /// Last [`TAIL_LIMIT`] bytes of stderr, lossily decoded.
    pub stderr_tail: String,
}

/// Result of an [`http_get`] / [`http_post`] call.
#[derive(Debug, Clone)]
pub struct HttpOutcome {
    /// Raw HTTP status code (redirects are reported, not followed).
    pub status: u16,
    /// Last [`TAIL_LIMIT`] bytes of the response body, lossily decoded.
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

/// HTTP GET `url`, reporting the raw status (redirects disabled).
pub fn http_get(url: &str) -> Result<HttpOutcome, ExecError> {
    let request = ureq::get(url)
        .config()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs_f64(DEFAULT_TIMEOUT_SEC)))
        .build();

    match request.call() {
        Ok(response) => http_outcome(response),
        Err(err) => Err(ExecError::EffectFailed {
            op: "net_http_get".to_string(),
            message: err.to_string(),
        }),
    }
}

/// HTTP POST `body` to `url` with `content_type`, reporting the raw
/// status (redirects disabled).
pub fn http_post(url: &str, body: &[u8], content_type: &str) -> Result<HttpOutcome, ExecError> {
    let request = ureq::post(url)
        .header("content-type", content_type)
        .config()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs_f64(DEFAULT_TIMEOUT_SEC)))
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
/// MVP: `https://` (or `http://`) source → GET and stream to the `dst`
/// path. Credential-carrying `b2://` / `hf://` downloads and uploads are
/// routed to the native CLIs over `sh.exec` one layer up (see
/// [`super::lifecycle`], spec 02 §Dispatch routing) and never reach
/// here. A `b2://` / `hf://` source or a URL destination that *does*
/// reach `transfer` is the public `net.transfer`-bridge scheme
/// resolution (chapter 04), which is not implemented yet, so it returns
/// [`ExecError::Unsupported`].
pub fn transfer(src: &str, dst: &str) -> Result<TransferOutcome, ExecError> {
    if src.starts_with("b2://") || src.starts_with("hf://") {
        return Err(ExecError::Unsupported(format!(
            "net.transfer '{src}': public b2:// / hf:// download over the \
             net.transfer bridge (chapter 04 scheme resolution) is not implemented"
        )));
    }
    if dst.contains("://") {
        return Err(ExecError::Unsupported(format!(
            "net.transfer to '{dst}': upload over the net.transfer bridge \
             (HTTP PUT) is not implemented"
        )));
    }
    if !(src.starts_with("https://") || src.starts_with("http://")) {
        return Err(ExecError::Unsupported(format!(
            "net.transfer '{src}': only https:// download is implemented"
        )));
    }

    let request = ureq::get(src)
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
        let outcome = http_get(&url).expect("http_get should succeed");
        assert_eq!(outcome.status, 200);
        assert!(outcome.body_tail.contains("pong"));

        handle.join().expect("server thread joins");
    }

    #[test]
    fn transfer_rejects_a_b2_source_with_the_known_limitation_message() {
        let err = transfer("b2://bucket/model.safetensors", "/tmp/model.safetensors")
            .expect_err("b2:// source must be unsupported");
        let message = err.to_string();
        assert!(
            message.contains("net.transfer bridge") && message.contains("not implemented"),
            "expected the public-bridge KNOWN LIMITATION message, got: {message}"
        );
    }

    #[test]
    fn transfer_rejects_a_url_destination_as_an_unsupported_upload() {
        let err = transfer("/workspace/out.bin", "https://example.com/upload")
            .expect_err("URL destination (upload) must be unsupported");
        assert!(err.to_string().contains("upload"));
    }
}
