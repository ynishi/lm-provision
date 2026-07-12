//! `net.http_get` / `net.http_post` / `net.transfer` bridges
//! (04-bridge.md §Outputs; milestone M3-3).
//!
//! Three Lua-visible operations, three separate `KNOWN_CAPABILITIES`
//! entries (`net.http_get`, `net.http_post`, `net.transfer` —
//! 05-sandbox-layer-contract.md §L4), so
//! [`crate::sandbox::wire_sandboxed_profile`] registers each with its own
//! [`crate::sandbox::capgate::register_if_granted`] call (registration
//! order step 8) rather than gating them as one unit — a profile that
//! declares `net.http_get` but not `net.transfer` sees `net.http_get`
//! callable and `net.transfer` nil, exactly like the register-skip
//! guarantee for every other capability.
//!
//! HTTP transport is [`ureq`] (sync, `rustls` feature only — no
//! `native-tls`, keeping the musl static binary free of an OpenSSL
//! dependency, 08-push-driver-protocol.md §Inputs "static binary").
//! Every call disables `ureq`'s default "non-2xx is an error" behaviour
//! (`http_status_as_error(false)`) so `net.http_get` / `net.http_post`
//! can report a 4xx/5xx response the same way as any other status —
//! `ok = (200 ≤ status < 400)` (04 §Outputs) — reserving `ureq::Error`
//! (an `Err` from `.call()` / `.send()`) for genuine transport failure
//! (DNS, connection refused, TLS, timeout), which is exactly 04 §Common
//! conventions' "effect failures ... transport failure" bucket.
//!
//! `opts.body_json`'s table → JSON encoding reuses `lm.canonical.encode`
//! (required through the same sandboxed VM the call runs on) rather than
//! writing a second Lua-table-to-JSON walker on the Rust side — the same
//! rationale [`crate::cli::plan_pipeline`]'s doc comment already records
//! for the `plan` subcommand: a table can carry a `SecretRef` userdata,
//! and `lm.canonical` is the one place that already knows how to encode
//! that opaquely as `{"__secret":"NAME"}` (03-pipeline-stage-artifacts.md
//! §canonical) instead of leaking a userdata's raw representation.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::time::Duration;

use mlua::{Function, Lua, Table, Value};
use sha2::{Digest, Sha256};

use crate::sandbox::capgate::CapabilityGate;
use crate::sandbox::policy::{HttpPolicy, PathPolicy};
use crate::secret::SecretRef;

/// The capability name `net.http_get` installs under
/// (05-sandbox-layer-contract.md §L4 `KNOWN_CAPABILITIES`).
pub const CAPABILITY_HTTP_GET: &str = "net.http_get";
/// The capability name `net.http_post` installs under.
pub const CAPABILITY_HTTP_POST: &str = "net.http_post";
/// The capability name `net.transfer` installs under.
pub const CAPABILITY_TRANSFER: &str = "net.transfer";

/// `opts.timeout_sec` default (04-bridge.md §Outputs `net.http_get` /
/// `net.http_post` / `net.transfer`: "default 30").
const DEFAULT_TIMEOUT_SEC: f64 = 30.0;
/// `opts.max_bytes` default (04 §Outputs: "default 16 MiB").
const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Read/write chunk size for the capped-read loops below — bounds how
/// much any single iteration can over-read past `max_bytes` before the
/// cap is checked, so a response is "never buffered unbounded" (04
/// §Outputs `net.http_get` / `net.http_post`) without needing to know
/// the body length up front.
const CHUNK_SIZE: usize = 64 * 1024;

/// Host deployment config for the `b2://` scheme's cluster prefix (04
/// §Outputs `net.transfer`: "the `f<NNN>` cluster prefix is
/// deployment-configured"; plan.md's unresolved item #9). This is a
/// host-level deployment value, not a profile-declared name — it is
/// read directly from the process environment, not routed through
/// [`crate::sandbox::policy::EnvPolicy`] or the `env_secrets` allowlist
/// (neither of which govern host configuration a profile author never
/// names). Unset: `net.transfer` returns a Lua error naming this
/// variable rather than guessing a default (04 §Stability marks the
/// scheme-resolution URL templates "provisional" precisely because
/// "endpoint churn upstream may force a revision" — the same reasoning
/// argues against baking in *any* literal cluster id as a fallback).
const B2_CLUSTER_ENV: &str = "LM_PROVISION_B2_CLUSTER";

// ---------------------------------------------------------------------
// Registration (04 §Registration order step 8)
// ---------------------------------------------------------------------

/// Get-or-create the profile-visible `net` global table. All three
/// operations share one table, so whichever of the three installs first
/// (declaration order is a `HashSet` iteration in
/// [`crate::sandbox::wire_sandboxed_profile`], so no operation can rely
/// on installing before another) must not clobber a sibling that already
/// created it.
fn net_table(lua: &Lua) -> mlua::Result<Table> {
    match lua.globals().get::<Option<Table>>("net")? {
        Some(table) => Ok(table),
        None => {
            let table = lua.create_table()?;
            lua.globals().set("net", table.clone())?;
            Ok(table)
        }
    }
}

/// Register `net.http_get` on `lua`'s `net` global table.
///
/// Callers are expected to reach this only through
/// [`crate::sandbox::capgate::register_if_granted`] (04 §Registration
/// order step 8's register-skip half) — `gate` is re-checked on every
/// call anyway, as defence in depth over the register skip (04 §Common
/// conventions), the same convention [`crate::bridge::sh::install`]
/// documents.
pub fn install_http_get(
    lua: &Lua,
    gate: CapabilityGate,
    http_policy: HttpPolicy,
) -> mlua::Result<()> {
    let http_get_fn = lua.create_function(
        move |lua, (url, opts): (String, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY_HTTP_GET).map_err(cap_error)?;
            http_get_entry(lua, &url, opts, &http_policy)
        },
    )?;
    net_table(lua)?.set("http_get", http_get_fn)?;
    Ok(())
}

/// Register `net.http_post` on `lua`'s `net` global table (see
/// [`install_http_get`] for the registration-order contract).
pub fn install_http_post(
    lua: &Lua,
    gate: CapabilityGate,
    http_policy: HttpPolicy,
) -> mlua::Result<()> {
    let http_post_fn = lua.create_function(
        move |lua, (url, opts): (String, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY_HTTP_POST).map_err(cap_error)?;
            http_post_entry(lua, &url, opts, &http_policy)
        },
    )?;
    net_table(lua)?.set("http_post", http_post_fn)?;
    Ok(())
}

/// Register `net.transfer` on `lua`'s `net` global table (see
/// [`install_http_get`] for the registration-order contract).
///
/// `env_secrets` is the profile's declared `env_secrets` allowlist
/// ([`crate::vm::eval::Declarations::env_secrets`]) — the set
/// `opts.auth_bearer` `SecretRef` values are checked against before
/// host-thread resolution (06-secret-handling.md §Inputs "Consumption
/// points").
pub fn install_transfer(
    lua: &Lua,
    gate: CapabilityGate,
    http_policy: HttpPolicy,
    path_policy: PathPolicy,
    env_secrets: Vec<String>,
) -> mlua::Result<()> {
    let env_secrets: HashSet<String> = env_secrets.into_iter().collect();
    let transfer_fn = lua.create_function(
        move |lua, (src, dst, opts): (String, String, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY_TRANSFER).map_err(cap_error)?;
            transfer_entry(
                lua,
                &src,
                &dst,
                opts,
                &http_policy,
                &path_policy,
                &env_secrets,
            )
        },
    )?;
    net_table(lua)?.set("transfer", transfer_fn)?;
    Ok(())
}

/// Map any `Display`-able error (`CapGateError`, `HttpPolicyError`,
/// `PathPolicyError`) onto the Lua-error convention 04-bridge.md §Common
/// conventions requires for "usage, policy, and secret errors".
fn cap_error(err: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(err.to_string())
}

/// `require(module)` via the profile's sandboxed VM — the same
/// single-line pattern [`crate::sandbox::catalog::read_string_list`] and
/// [`crate::cli::require_module`] each already use, rather than a shared
/// cross-module helper (no `pub(crate)` accessor for it exists yet, and
/// three call sites do not justify inventing one).
fn require_module(lua: &Lua, module: &str) -> mlua::Result<Table> {
    let require_fn: Function = lua.globals().get("require")?;
    require_fn.call(module)
}

// ---------------------------------------------------------------------
// Shared opts decoding
// ---------------------------------------------------------------------

/// Decoded `opts` common to `net.http_get` and `net.http_post`
/// (04-bridge.md §Outputs "Common `opts`").
struct HttpOpts {
    headers: Vec<(String, String)>,
    timeout_sec: f64,
    max_bytes: u64,
    dry_run: bool,
}

fn decode_headers(headers_table: Option<Table>) -> mlua::Result<Vec<(String, String)>> {
    let Some(headers_table) = headers_table else {
        return Ok(Vec::new());
    };
    let mut headers = Vec::with_capacity(headers_table.raw_len());
    for pair in headers_table.pairs::<String, String>() {
        headers.push(pair?);
    }
    Ok(headers)
}

/// Case-insensitive header-name membership check — used both to decide
/// whether a `body_json` / `body_form` / upload `content_type` default
/// should apply ("unless caller provided one", 04 §Outputs
/// `net.http_get` / `net.http_post`) and whether an `auth_bearer`
/// default `Authorization` header should apply ("unless the caller
/// already set one", 04 §Outputs `net.transfer`).
fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

fn decode_http_opts(opts: &Option<Table>) -> mlua::Result<HttpOpts> {
    let Some(opts) = opts else {
        return Ok(HttpOpts {
            headers: Vec::new(),
            timeout_sec: DEFAULT_TIMEOUT_SEC,
            max_bytes: DEFAULT_MAX_BYTES,
            dry_run: false,
        });
    };
    let headers = decode_headers(opts.get("headers")?)?;
    let timeout_sec = opts
        .get::<Option<f64>>("timeout_sec")?
        .map(|secs| secs.max(0.0))
        .unwrap_or(DEFAULT_TIMEOUT_SEC);
    let max_bytes = opts
        .get::<Option<i64>>("max_bytes")?
        .map(|bytes| bytes.max(0) as u64)
        .unwrap_or(DEFAULT_MAX_BYTES);
    let dry_run = opts.get::<Option<bool>>("dry_run")?.unwrap_or(false);
    Ok(HttpOpts {
        headers,
        timeout_sec,
        max_bytes,
        dry_run,
    })
}

/// One of `opts.body` / `opts.body_json` / `opts.body_form` — decoded
/// and, for `body_json`, already encoded to bytes (04-bridge.md §Outputs
/// `net.http_post`: "exactly one of ... Supplying more than one is a Lua
/// error").
enum PostBody {
    None,
    /// `opts.body` — verbatim.
    Plain(Vec<u8>),
    /// `opts.body_json`, already run through `lm.canonical.encode`.
    Json(String),
    /// `opts.body_form`, already `application/x-www-form-urlencoded`.
    Form(String),
}

impl PostBody {
    /// The `Content-Type` this body kind implies "unless caller provided
    /// one" (04 §Outputs `net.http_post`) — `None` for `body` (verbatim,
    /// no implied type) and for no body at all.
    fn default_content_type(&self) -> Option<&'static str> {
        match self {
            PostBody::Json(_) => Some("application/json"),
            PostBody::Form(_) => Some("application/x-www-form-urlencoded"),
            PostBody::None | PostBody::Plain(_) => None,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self {
            PostBody::None => Vec::new(),
            PostBody::Plain(bytes) => bytes,
            PostBody::Json(text) | PostBody::Form(text) => text.into_bytes(),
        }
    }
}

fn decode_post_body(lua: &Lua, opts: &Option<Table>) -> mlua::Result<PostBody> {
    let Some(opts) = opts else {
        return Ok(PostBody::None);
    };
    let body: Option<String> = opts.get("body")?;
    let body_json: Option<Table> = opts.get("body_json")?;
    let body_form: Option<Table> = opts.get("body_form")?;

    let supplied = [body.is_some(), body_json.is_some(), body_form.is_some()]
        .iter()
        .filter(|is_some| **is_some)
        .count();
    if supplied > 1 {
        // 04 §Outputs `net.http_post`: "Supplying more than one is a Lua
        // error."
        return Err(mlua::Error::RuntimeError(
            "net.http_post: opts.body, opts.body_json, and opts.body_form are mutually exclusive"
                .to_string(),
        ));
    }

    if let Some(body) = body {
        return Ok(PostBody::Plain(body.into_bytes()));
    }
    if let Some(body_json) = body_json {
        let canonical = require_module(lua, "lm.canonical")?;
        let encode_fn: Function = canonical.get("encode")?;
        let json: String = encode_fn.call(body_json)?;
        return Ok(PostBody::Json(json));
    }
    if let Some(body_form) = body_form {
        let mut parts = Vec::new();
        for pair in body_form.pairs::<String, String>() {
            let (key, value) = pair?;
            parts.push(format!(
                "{}={}",
                form_url_encode(&key),
                form_url_encode(&value)
            ));
        }
        return Ok(PostBody::Form(parts.join("&")));
    }
    Ok(PostBody::None)
}

/// `application/x-www-form-urlencoded` percent-encoding: unreserved
/// bytes pass through, space becomes `+`, everything else becomes
/// `%XX`. `opts.body_form` is a plain `table<string,string>` (04
/// §Outputs `net.http_post`), so this is a self-contained utility rather
/// than a dependency on `ureq`'s own (private) form encoder.
fn form_url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------
// net.http_get / net.http_post
// ---------------------------------------------------------------------

/// The audit line shared by `net.http_get` / `net.http_post` (09
/// -apply-report-and-ledger.md §Audit log "HTTP"), emitted once the
/// result table (real or `dry_run`) is built — `status` / `body_bytes`
/// are fields the effect itself produces, so this runs immediately
/// after building `result` rather than strictly before it (see
/// `crate::audit`'s own module doc comment).
fn audit_http_result(
    op: &str,
    url: &str,
    headers: &[(String, String)],
    result: &Table,
) -> mlua::Result<()> {
    let status: i64 = result.get("status")?;
    let body: String = result.get("body")?;
    crate::audit::http(op, url, status, body.len(), headers);
    Ok(())
}

fn http_get_entry(
    lua: &Lua,
    url: &str,
    opts: Option<Table>,
    http_policy: &HttpPolicy,
) -> mlua::Result<Table> {
    http_policy.check(url).map_err(cap_error)?;
    let opts = decode_http_opts(&opts)?;

    let result = if opts.dry_run {
        dry_run_http_result(lua)?
    } else {
        let mut request = ureq::get(url);
        for (name, value) in &opts.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let request = request
            .config()
            .http_status_as_error(false)
            // 04 §Outputs: `ok = (200 ≤ status < 400)` reports a
            // redirect status verbatim — it does not ask the bridge to
            // chase it. ureq's default `max_redirects(10)` would
            // otherwise silently follow a 3xx (and error out on one
            // with no `Location` header, e.g. the ok-boundary status
            // 399) before this function ever sees the status it is
            // supposed to report.
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs_f64(opts.timeout_sec)))
            .build();

        match request.call() {
            Ok(response) => finish_http_response(lua, response, opts.max_bytes, "net.http_get")?,
            Err(err) => http_transport_failure(lua, &err, "net.http_get")?,
        }
    };

    audit_http_result("net.http_get", url, &opts.headers, &result)?;
    Ok(result)
}

fn http_post_entry(
    lua: &Lua,
    url: &str,
    opts: Option<Table>,
    http_policy: &HttpPolicy,
) -> mlua::Result<Table> {
    http_policy.check(url).map_err(cap_error)?;
    let mut common = decode_http_opts(&opts)?;
    // Body-shape decoding (including the XOR check and, for
    // `body_json`, the `lm.canonical.encode` call) runs unconditionally
    // — 04 §Common conventions: "Dry-run therefore still fails on policy
    // violations ... it validates everything except the effect itself."
    let body = decode_post_body(lua, &opts)?;
    if let Some(default_content_type) = body.default_content_type() {
        if !has_header(&common.headers, "content-type") {
            common
                .headers
                .push(("Content-Type".to_string(), default_content_type.to_string()));
        }
    }

    let result = if common.dry_run {
        dry_run_http_result(lua)?
    } else {
        let mut request = ureq::post(url);
        for (name, value) in &common.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let request = request
            .config()
            .http_status_as_error(false)
            // See `http_get_entry`: report a 3xx status rather than
            // chasing it.
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs_f64(common.timeout_sec)))
            .build();

        let body_bytes = body.into_bytes();
        match request.send(body_bytes.as_slice()) {
            Ok(response) => finish_http_response(lua, response, common.max_bytes, "net.http_post")?,
            Err(err) => http_transport_failure(lua, &err, "net.http_post")?,
        }
    };

    audit_http_result("net.http_post", url, &common.headers, &result)?;
    Ok(result)
}

/// `{ ok, status, body, headers, dry_run, error? }` (04-bridge.md
/// §Outputs `net.http_get` / `net.http_post`), reading the response
/// headers before consuming the body so [`read_capped`] can stream the
/// body without ever holding the whole thing in an unbounded buffer.
fn finish_http_response(
    lua: &Lua,
    response: ureq::http::Response<ureq::Body>,
    max_bytes: u64,
    op: &str,
) -> mlua::Result<Table> {
    let status = response.status().as_u16() as i64;
    let response_headers = headers_to_table(lua, response.headers())?;
    let mut response_body = response.into_body();
    let reader = response_body.as_reader();

    match read_capped(reader, max_bytes) {
        Ok(bytes) => {
            let ok = (200..400).contains(&status);
            build_http_result(
                lua,
                ok,
                status,
                String::from_utf8_lossy(&bytes).into_owned(),
                response_headers,
                false,
                None,
            )
        }
        Err(ReadCappedError::Exceeded) => build_http_result(
            lua,
            false,
            -1,
            String::new(),
            lua.create_table()?,
            false,
            Some(format!(
                "{op}: response body exceeds max_bytes ({max_bytes})"
            )),
        ),
        Err(ReadCappedError::Io(err)) => build_http_result(
            lua,
            false,
            -1,
            String::new(),
            lua.create_table()?,
            false,
            Some(format!("{op}: failed reading response body: {err}")),
        ),
    }
}

fn http_transport_failure(lua: &Lua, err: &ureq::Error, op: &str) -> mlua::Result<Table> {
    build_http_result(
        lua,
        false,
        -1,
        String::new(),
        lua.create_table()?,
        false,
        Some(format!("{op}: {err}")),
    )
}

fn dry_run_http_result(lua: &Lua) -> mlua::Result<Table> {
    build_http_result(lua, true, 0, String::new(), lua.create_table()?, true, None)
}

fn build_http_result(
    lua: &Lua,
    ok: bool,
    status: i64,
    body: String,
    headers: Table,
    dry_run: bool,
    error: Option<String>,
) -> mlua::Result<Table> {
    let result = lua.create_table()?;
    result.set("ok", ok)?;
    result.set("status", status)?;
    result.set("body", body)?;
    result.set("headers", headers)?;
    result.set("dry_run", dry_run)?;
    if let Some(error) = error {
        result.set("error", error)?;
    }
    Ok(result)
}

fn headers_to_table(lua: &Lua, headers: &ureq::http::HeaderMap) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for name in headers.keys() {
        let joined = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        table.set(name.as_str(), joined)?;
    }
    Ok(table)
}

// ---------------------------------------------------------------------
// Capped, never-fully-buffered body reading
// ---------------------------------------------------------------------

enum ReadCappedError {
    /// The body would exceed `max_bytes` (04 §Outputs: "larger responses
    /// are rejected, never buffered unbounded").
    Exceeded,
    Io(std::io::Error),
}

/// Read `reader` to EOF in [`CHUNK_SIZE`]-sized chunks, accumulating at
/// most `max_bytes + CHUNK_SIZE` bytes before detecting an overrun — the
/// cap is checked every chunk rather than only after a full read, so an
/// oversized body is never fully accumulated in memory.
fn read_capped(mut reader: impl Read, max_bytes: u64) -> Result<Vec<u8>, ReadCappedError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; CHUNK_SIZE];
    loop {
        let n = reader.read(&mut chunk).map_err(ReadCappedError::Io)?;
        if n == 0 {
            break;
        }
        if buf.len() as u64 + n as u64 > max_bytes {
            return Err(ReadCappedError::Exceeded);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

// ---------------------------------------------------------------------
// net.transfer
// ---------------------------------------------------------------------

/// One resolved side of a `net.transfer(src, dst, opts)` call
/// (04-bridge.md §Outputs `net.transfer` "Scheme resolution").
#[derive(Debug)]
enum ResolvedSide {
    /// Already-or-resolved-to a URL. `special` is `Some` only for a side
    /// that started as `hf://` or `b2://` — it drives the "upload
    /// directly to an hf:// / b2:// dst is rejected" rule, which does
    /// not apply to a plain `https://` URL.
    Url {
        url: String,
        special: Option<SpecialScheme>,
    },
    /// "Anything non-URL is a local path" (04 §Outputs `net.transfer`).
    Path(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecialScheme {
    Hf,
    B2,
}

/// Resolve one `net.transfer` argument before any policy check (04
/// §Outputs `net.transfer`: "Scheme resolution before any policy
/// check").
fn resolve_side(value: &str, b2_cluster_prefix: Option<&str>) -> mlua::Result<ResolvedSide> {
    if let Some(rest) = value.strip_prefix("hf://") {
        return Ok(ResolvedSide::Url {
            url: resolve_hf_url(rest)?,
            special: Some(SpecialScheme::Hf),
        });
    }
    if let Some(rest) = value.strip_prefix("b2://") {
        let prefix = b2_cluster_prefix.ok_or_else(|| {
            mlua::Error::RuntimeError(format!(
                "net.transfer: 'b2://' requires deployment config {B2_CLUSTER_ENV} \
                 (e.g. 'f002') to resolve the cluster prefix"
            ))
        })?;
        return Ok(ResolvedSide::Url {
            url: resolve_b2_url(prefix, rest)?,
            special: Some(SpecialScheme::B2),
        });
    }
    for rejected_scheme in ["gs://", "s3://", "ftp://", "file://"] {
        if value.starts_with(rejected_scheme) {
            // 04 §Outputs `net.transfer`: "gs:// s3:// ftp:// file://
            // are rejected with an explicit unsupported-scheme error."
            return Err(mlua::Error::RuntimeError(format!(
                "net.transfer: unsupported scheme in '{value}' \
                 (gs:// / s3:// / ftp:// / file:// are rejected)"
            )));
        }
    }
    if value.contains("://") {
        return Ok(ResolvedSide::Url {
            url: value.to_string(),
            special: None,
        });
    }
    Ok(ResolvedSide::Path(value.to_string()))
}

/// `hf://<owner>/<repo>/<path>` → `https://huggingface.co/<owner>/<repo>/resolve/main/<path>`
/// (04 §Outputs `net.transfer`).
fn resolve_hf_url(rest: &str) -> mlua::Result<String> {
    let mut parts = rest.splitn(3, '/');
    let owner = parts.next().filter(|s| !s.is_empty());
    let repo = parts.next().filter(|s| !s.is_empty());
    let path = parts.next().filter(|s| !s.is_empty());
    match (owner, repo, path) {
        (Some(owner), Some(repo), Some(path)) => Ok(format!(
            "https://huggingface.co/{owner}/{repo}/resolve/main/{path}"
        )),
        _ => Err(mlua::Error::RuntimeError(
            "net.transfer: malformed 'hf://' URL, expected 'hf://<owner>/<repo>/<path>'"
                .to_string(),
        )),
    }
}

/// `b2://<bucket>/<path>` → `https://f<NNN>.backblazeb2.com/file/<bucket>/<path>`
/// (04 §Outputs `net.transfer`), where `f<NNN>` is `cluster_prefix`
/// ([`B2_CLUSTER_ENV`]).
fn resolve_b2_url(cluster_prefix: &str, rest: &str) -> mlua::Result<String> {
    let mut parts = rest.splitn(2, '/');
    let bucket = parts.next().filter(|s| !s.is_empty());
    let path = parts.next().filter(|s| !s.is_empty());
    match (bucket, path) {
        (Some(bucket), Some(path)) => Ok(format!(
            "https://{cluster_prefix}.backblazeb2.com/file/{bucket}/{path}"
        )),
        _ => Err(mlua::Error::RuntimeError(
            "net.transfer: malformed 'b2://' URL, expected 'b2://<bucket>/<path>'".to_string(),
        )),
    }
}

/// Decoded `net.transfer` `opts` (04-bridge.md §Outputs `net.transfer`).
struct TransferOpts {
    headers: Vec<(String, String)>,
    timeout_sec: f64,
    max_bytes: u64,
    /// Download-only: verify-and-delete-on-mismatch target (04 §Outputs:
    /// "downloads verify and delete the file on mismatch"). 04 does not
    /// define an upload-side meaning for this option, so [`perform_upload`]
    /// never reads it — the upload result's own `sha256` field is always
    /// the freshly computed digest of the file just read, reported
    /// outward rather than verified against anything.
    sha256: Option<String>,
    /// Upload-only default (04 §Outputs: "default
    /// `application/octet-stream` unless a caller header overrides").
    content_type: Option<String>,
    /// Already host-resolved, never handed back to Lua
    /// (06-secret-handling.md §Resolution).
    auth_bearer: Option<String>,
    dry_run: bool,
}

fn decode_transfer_opts(
    opts: &Option<Table>,
    env_secrets: &HashSet<String>,
) -> mlua::Result<TransferOpts> {
    let Some(opts) = opts else {
        return Ok(TransferOpts {
            headers: Vec::new(),
            timeout_sec: DEFAULT_TIMEOUT_SEC,
            max_bytes: DEFAULT_MAX_BYTES,
            sha256: None,
            content_type: None,
            auth_bearer: None,
            dry_run: false,
        });
    };
    let headers = decode_headers(opts.get("headers")?)?;
    let timeout_sec = opts
        .get::<Option<f64>>("timeout_sec")?
        .map(|secs| secs.max(0.0))
        .unwrap_or(DEFAULT_TIMEOUT_SEC);
    let max_bytes = opts
        .get::<Option<i64>>("max_bytes")?
        .map(|bytes| bytes.max(0) as u64)
        .unwrap_or(DEFAULT_MAX_BYTES);
    let sha256 = opts.get::<Option<String>>("sha256")?;
    let content_type = opts.get::<Option<String>>("content_type")?;
    let dry_run = opts.get::<Option<bool>>("dry_run")?.unwrap_or(false);
    let auth_bearer = decode_auth_bearer(opts.get("auth_bearer")?, env_secrets)?;
    Ok(TransferOpts {
        headers,
        timeout_sec,
        max_bytes,
        sha256,
        content_type,
        auth_bearer,
        dry_run,
    })
}

/// `opts.auth_bearer`: `string | SecretRef` (04 §Outputs `net.transfer`),
/// following the same check-then-resolve protocol as `sh.exec`
/// `opts.env` (06-secret-handling.md §Inputs "Consumption points") via
/// the shared [`crate::secret::resolve`].
fn decode_auth_bearer(
    value: Option<Value>,
    env_secrets: &HashSet<String>,
) -> mlua::Result<Option<String>> {
    match value {
        None | Some(Value::Nil) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.to_str()?.to_string())),
        Some(Value::UserData(ud)) if ud.is::<SecretRef>() => {
            let name = ud.borrow::<SecretRef>()?.name().to_string();
            Ok(Some(crate::secret::resolve(&name, env_secrets)?))
        }
        Some(other) => Err(mlua::Error::RuntimeError(format!(
            "net.transfer: opts.auth_bearer must be a string or SecretRef, got {}",
            other.type_name()
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn transfer_entry(
    lua: &Lua,
    src: &str,
    dst: &str,
    opts: Option<Table>,
    http_policy: &HttpPolicy,
    path_policy: &PathPolicy,
    env_secrets: &HashSet<String>,
) -> mlua::Result<Table> {
    let b2_cluster_prefix = std::env::var(B2_CLUSTER_ENV).ok();
    let resolved_src = resolve_side(src, b2_cluster_prefix.as_deref())?;
    let resolved_dst = resolve_side(dst, b2_cluster_prefix.as_deref())?;

    match (resolved_src, resolved_dst) {
        (ResolvedSide::Url { url: src_url, .. }, ResolvedSide::Path(dst_path)) => {
            // Direction: URL→path = download (04 §Outputs `net.transfer`
            // "Direction is inferred after resolution").
            http_policy.check(&src_url).map_err(cap_error)?;
            path_policy.check(&dst_path).map_err(cap_error)?;
            let opts = decode_transfer_opts(&opts, env_secrets)?;
            let result = if opts.dry_run {
                dry_run_transfer_result(lua, "download", &dst_path)?
            } else {
                perform_download(lua, &src_url, &dst_path, &opts)?
            };
            audit_transfer_result("download", &src_url, &dst_path, &result)?;
            Ok(result)
        }
        (
            ResolvedSide::Path(src_path),
            ResolvedSide::Url {
                url: dst_url,
                special,
            },
        ) => {
            if special.is_some() {
                // 04 §Outputs `net.transfer`: "Upload directly to an
                // hf:// / b2:// dst is rejected at this bridge — the
                // dispatch layer routes those to the native CLIs over
                // sh.exec."
                return Err(mlua::Error::RuntimeError(
                    "net.transfer: upload directly to 'hf://' / 'b2://' is rejected; \
                     the dispatch layer routes those through the native CLIs over sh.exec"
                        .to_string(),
                ));
            }
            path_policy.check(&src_path).map_err(cap_error)?;
            http_policy.check(&dst_url).map_err(cap_error)?;
            let opts = decode_transfer_opts(&opts, env_secrets)?;
            let result = if opts.dry_run {
                dry_run_transfer_result(lua, "upload", &src_path)?
            } else {
                perform_upload(lua, &src_path, &dst_url, &opts)?
            };
            audit_transfer_result("upload", &src_path, &dst_url, &result)?;
            Ok(result)
        }
        (ResolvedSide::Url { .. }, ResolvedSide::Url { .. }) => Err(mlua::Error::RuntimeError(
            "net.transfer: URL-to-URL transfer is not supported".to_string(),
        )),
        (ResolvedSide::Path(_), ResolvedSide::Path(_)) => Err(mlua::Error::RuntimeError(
            "net.transfer: path-to-path transfer is not supported; use fs.* instead".to_string(),
        )),
    }
}

/// The `net.transfer` audit line (09-apply-report-and-ledger.md §Audit
/// log "HTTP" extends to `net.transfer` too), emitted once the result
/// table (real or `dry_run`) is built — `bytes` is a field the effect
/// itself produces, so this runs immediately after building `result`
/// rather than strictly before it (see `crate::audit`'s own module doc
/// comment). `src` / `dst` are the caller's own pre-resolution
/// arguments rather than reading them back out of `result` — a
/// `net.transfer` result only echoes back whichever side its resolved
/// direction produced (`dst` on download, `src` on upload,
/// [`build_transfer_result`]), never both.
fn audit_transfer_result(
    direction: &str,
    src: &str,
    dst: &str,
    result: &Table,
) -> mlua::Result<()> {
    let bytes: u64 = result.get("bytes")?;
    crate::audit::net_transfer(direction, src, dst, bytes);
    Ok(())
}

fn dry_run_transfer_result(lua: &Lua, direction: &str, path: &str) -> mlua::Result<Table> {
    build_transfer_result(lua, true, 0, 0, None, direction, path, true, None)
}

#[allow(clippy::too_many_arguments)]
fn build_transfer_result(
    lua: &Lua,
    ok: bool,
    status: i64,
    bytes: u64,
    sha256: Option<String>,
    direction: &str,
    path: &str,
    dry_run: bool,
    error: Option<String>,
) -> mlua::Result<Table> {
    let result = lua.create_table()?;
    result.set("ok", ok)?;
    result.set("status", status)?;
    result.set("bytes", bytes)?;
    if let Some(sha256) = sha256 {
        result.set("sha256", sha256)?;
    }
    result.set("direction", direction)?;
    if direction == "download" {
        result.set("dst", path)?;
    } else {
        result.set("src", path)?;
    }
    result.set("dry_run", dry_run)?;
    if let Some(error) = error {
        result.set("error", error)?;
    }
    Ok(result)
}

fn transfer_transport_failure(
    lua: &Lua,
    err: &ureq::Error,
    direction: &str,
    path: &str,
) -> mlua::Result<Table> {
    build_transfer_result(
        lua,
        false,
        -1,
        0,
        None,
        direction,
        path,
        false,
        Some(format!("net.transfer: {err}")),
    )
}

fn perform_download(
    lua: &Lua,
    src_url: &str,
    dst_path: &str,
    opts: &TransferOpts,
) -> mlua::Result<Table> {
    let mut request = ureq::get(src_url);
    for (name, value) in &opts.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if let Some(bearer) = &opts.auth_bearer {
        if !has_header(&opts.headers, "authorization") {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
    }
    let request = request
        .config()
        .http_status_as_error(false)
        // See `http_get_entry`: report a 3xx status rather than chasing it.
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs_f64(opts.timeout_sec)))
        .build();

    let response = match request.call() {
        Ok(response) => response,
        Err(err) => return transfer_transport_failure(lua, &err, "download", dst_path),
    };

    let status = response.status().as_u16() as i64;
    if !(200..400).contains(&status) {
        return build_transfer_result(
            lua,
            false,
            status,
            0,
            None,
            "download",
            dst_path,
            false,
            Some(format!(
                "net.transfer: download responded with status {status}"
            )),
        );
    }

    let mut response_body = response.into_body();
    let reader = response_body.as_reader();
    match stream_download(reader, dst_path, opts.max_bytes, opts.sha256.as_deref()) {
        Ok((bytes_written, sha256)) => build_transfer_result(
            lua,
            true,
            status,
            bytes_written,
            Some(sha256),
            "download",
            dst_path,
            false,
            None,
        ),
        Err(DownloadError::Exceeded) => build_transfer_result(
            lua,
            false,
            status,
            0,
            None,
            "download",
            dst_path,
            false,
            Some(format!(
                "net.transfer: response body exceeds max_bytes ({})",
                opts.max_bytes
            )),
        ),
        Err(DownloadError::Io(err)) => build_transfer_result(
            lua,
            false,
            status,
            0,
            None,
            "download",
            dst_path,
            false,
            Some(format!("net.transfer: failed writing '{dst_path}': {err}")),
        ),
        Err(DownloadError::ShaMismatch { expected, actual }) => build_transfer_result(
            lua,
            false,
            status,
            0,
            Some(actual.clone()),
            "download",
            dst_path,
            false,
            Some(format!(
                "net.transfer: sha256 mismatch for '{dst_path}': expected {expected}, got {actual}"
            )),
        ),
    }
}

enum DownloadError {
    Exceeded,
    Io(std::io::Error),
    ShaMismatch { expected: String, actual: String },
}

/// Stream `reader` to `dst_path` in [`CHUNK_SIZE`]-sized chunks (04
/// §Outputs `net.transfer`: "Download streams to the destination file
/// (never fully buffered)"), hashing incrementally so the sha256 digest
/// never requires holding the whole body in memory either. On any
/// failure — the cap, an I/O error, or a `sha256` mismatch — the
/// destination file is removed (04 §Outputs: "on any failure the
/// partial file is removed").
fn stream_download(
    mut reader: impl Read,
    dst_path: &str,
    max_bytes: u64,
    expected_sha256: Option<&str>,
) -> Result<(u64, String), DownloadError> {
    let mut file = std::fs::File::create(dst_path).map_err(DownloadError::Io)?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut chunk = [0u8; CHUNK_SIZE];

    let write_result: Result<u64, DownloadError> = (|| {
        loop {
            let n = reader.read(&mut chunk).map_err(DownloadError::Io)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max_bytes {
                return Err(DownloadError::Exceeded);
            }
            file.write_all(&chunk[..n]).map_err(DownloadError::Io)?;
            hasher.update(&chunk[..n]);
        }
        Ok(total)
    })();

    let total = match write_result {
        Ok(total) => total,
        Err(err) => {
            let _ = std::fs::remove_file(dst_path);
            return Err(err);
        }
    };

    let digest = format!("{:x}", hasher.finalize());
    if let Some(expected) = expected_sha256 {
        if digest != expected {
            let _ = std::fs::remove_file(dst_path);
            return Err(DownloadError::ShaMismatch {
                expected: expected.to_string(),
                actual: digest,
            });
        }
    }
    Ok((total, digest))
}

fn perform_upload(
    lua: &Lua,
    src_path: &str,
    dst_url: &str,
    opts: &TransferOpts,
) -> mlua::Result<Table> {
    // 04 §Outputs `net.transfer`: "Upload reads the file, PUTs it" — no
    // streaming requirement for upload, unlike download's "never fully
    // buffered".
    let file_bytes = match std::fs::read(src_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return build_transfer_result(
                lua,
                false,
                -1,
                0,
                None,
                "upload",
                src_path,
                false,
                Some(format!("net.transfer: failed reading '{src_path}': {err}")),
            );
        }
    };
    if file_bytes.len() as u64 > opts.max_bytes {
        return build_transfer_result(
            lua,
            false,
            -1,
            0,
            None,
            "upload",
            src_path,
            false,
            Some(format!(
                "net.transfer: source file exceeds max_bytes ({})",
                opts.max_bytes
            )),
        );
    }
    let sha256 = format!("{:x}", {
        let mut hasher = Sha256::new();
        hasher.update(&file_bytes);
        hasher.finalize()
    });

    let mut request = ureq::put(dst_url);
    for (name, value) in &opts.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if !has_header(&opts.headers, "content-type") {
        let content_type = opts
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        request = request.header("content-type", content_type);
    }
    if let Some(bearer) = &opts.auth_bearer {
        if !has_header(&opts.headers, "authorization") {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
    }
    let request = request
        .config()
        .http_status_as_error(false)
        // See `http_get_entry`: report a 3xx status rather than chasing it.
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs_f64(opts.timeout_sec)))
        .build();

    match request.send(file_bytes.as_slice()) {
        Ok(response) => {
            let status = response.status().as_u16() as i64;
            let ok = (200..400).contains(&status);
            build_transfer_result(
                lua,
                ok,
                status,
                file_bytes.len() as u64,
                Some(sha256),
                "upload",
                src_path,
                false,
                if ok {
                    None
                } else {
                    Some(format!(
                        "net.transfer: upload responded with status {status}"
                    ))
                },
            )
        }
        Err(err) => transfer_transport_failure(lua, &err, "upload", src_path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------
    // scheme resolution (pure, no network)
    // -------------------------------------------------------------

    #[test]
    fn resolve_side_builds_the_hf_resolve_main_url() {
        let resolved =
            resolve_side("hf://owner/repo/path/to/file.bin", None).expect("hf:// should resolve");
        match resolved {
            ResolvedSide::Url { url, special } => {
                assert_eq!(
                    url,
                    "https://huggingface.co/owner/repo/resolve/main/path/to/file.bin"
                );
                assert_eq!(special, Some(SpecialScheme::Hf));
            }
            ResolvedSide::Path(_) => panic!("hf:// must resolve to a URL"),
        }
    }

    #[test]
    fn resolve_side_rejects_a_malformed_hf_url() {
        let err = resolve_side("hf://owner-only", None).expect_err("malformed hf:// must error");
        assert!(err.to_string().contains("malformed 'hf://' URL"));
    }

    #[test]
    fn resolve_side_builds_the_b2_url_using_the_injected_cluster_prefix() {
        let resolved = resolve_side("b2://my-bucket/models/foo.bin", Some("f002"))
            .expect("b2:// should resolve");
        match resolved {
            ResolvedSide::Url { url, special } => {
                assert_eq!(
                    url,
                    "https://f002.backblazeb2.com/file/my-bucket/models/foo.bin"
                );
                assert_eq!(special, Some(SpecialScheme::B2));
            }
            ResolvedSide::Path(_) => panic!("b2:// must resolve to a URL"),
        }
    }

    #[test]
    fn resolve_side_errors_when_b2_cluster_prefix_is_unset() {
        let err = resolve_side("b2://my-bucket/path", None)
            .expect_err("b2:// without a configured cluster prefix must error");
        assert!(err.to_string().contains(B2_CLUSTER_ENV));
    }

    #[test]
    fn resolve_side_rejects_gs_s3_ftp_file_schemes() {
        for rejected in [
            "gs://bucket/x",
            "s3://bucket/x",
            "ftp://host/x",
            "file:///etc/passwd",
        ] {
            let err = resolve_side(rejected, Some("f002"))
                .expect_err(&format!("{rejected} must be rejected"));
            assert!(err.to_string().contains("unsupported scheme"));
        }
    }

    #[test]
    fn resolve_side_passes_through_a_plain_https_url_without_the_special_marker() {
        let resolved =
            resolve_side("https://example.com/path", None).expect("plain https:// should resolve");
        match resolved {
            ResolvedSide::Url { url, special } => {
                assert_eq!(url, "https://example.com/path");
                assert_eq!(special, None);
            }
            ResolvedSide::Path(_) => panic!("https:// must resolve to a URL"),
        }
    }

    #[test]
    fn resolve_side_treats_a_non_url_string_as_a_local_path() {
        let resolved =
            resolve_side("/workspace/models/foo.bin", None).expect("path should resolve");
        assert!(matches!(resolved, ResolvedSide::Path(p) if p == "/workspace/models/foo.bin"));
    }

    // -------------------------------------------------------------
    // header / form helpers (pure)
    // -------------------------------------------------------------

    #[test]
    fn has_header_matches_case_insensitively() {
        let headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
        assert!(has_header(&headers, "content-type"));
        assert!(has_header(&headers, "CONTENT-TYPE"));
        assert!(!has_header(&headers, "authorization"));
    }

    #[test]
    fn form_url_encode_escapes_reserved_bytes_and_maps_space_to_plus() {
        assert_eq!(form_url_encode("hello world"), "hello+world");
        assert_eq!(form_url_encode("a/b=c"), "a%2Fb%3Dc");
        assert_eq!(form_url_encode("safe-._~123"), "safe-._~123");
    }
}
