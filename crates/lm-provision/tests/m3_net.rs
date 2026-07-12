//! M3-3 (`net.http_get` / `net.http_post` / `net.transfer` bridges)
//! regression tests (04-bridge.md §Outputs `net.http_get` /
//! `net.http_post` / `net.transfer`; 06-secret-handling.md §Inputs
//! "Consumption points").
//!
//! Drives the bridges through the same public path a profile author's
//! own `apply`-time code would take:
//! [`lm_provision::vm::eval::evaluate_profile_source`] (registration
//! order steps 1-5) then [`lm_provision::sandbox::wire_sandboxed_profile`]
//! (steps 6-8, which installs the declared `net.*` operations). A tiny
//! one-shot HTTP/1.1 server built on `std::net::TcpListener` stands in
//! for a real endpoint — no HTTP-client/server crate is added as a test
//! dependency (04's own MVP scope keeps the bridge dependency-light, and
//! the fixture only needs to speak enough HTTP/1.1 to answer one
//! request).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use lm_provision::sandbox::wire_sandboxed_profile;
use lm_provision::vm::eval::evaluate_profile_source;
use mlua::{Lua, Table, Value};

// ---------------------------------------------------------------------
// One-shot HTTP/1.1 test server fixture
// ---------------------------------------------------------------------

/// A parsed incoming request, for handlers that want to assert on what
/// the bridge actually sent (method / headers / body).
struct RecordedRequest {
    method: String,
    #[allow(dead_code)]
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct ServerResponse {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl ServerResponse {
    fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }
}

/// Bind to an ephemeral port, accept exactly one connection on a
/// background thread, run `handler` against the parsed request, and
/// write back its response. Returns the server's base URL
/// (`http://127.0.0.1:<port>`).
fn spawn_server<F>(handler: F) -> String
where
    F: Fn(&RecordedRequest) -> ServerResponse + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("test server local_addr");
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            handle_connection(stream, &handler);
        }
    });
    format!("http://{addr}")
}

fn handle_connection(mut stream: TcpStream, handler: &impl Fn(&RecordedRequest) -> ServerResponse) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone test server stream"));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .expect("read test server request body");
    }

    let response = handler(&RecordedRequest {
        method,
        path,
        headers,
        body,
    });

    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        399 => "Unofficial",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", response.status);
    out.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    for (name, value) in &response.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

// ---------------------------------------------------------------------
// sandboxed VM helper (mirrors tests/m3_sh_exec.rs)
// ---------------------------------------------------------------------

fn sandboxed_lua(profile_expr: &str) -> Lua {
    let source = format!(
        r#"
        local profile = require('lm.profile')
        return profile {profile_expr}
        "#
    );
    let extracted =
        evaluate_profile_source(&source, "test-profile").expect("profile should evaluate");
    let sandboxed =
        wire_sandboxed_profile(extracted).expect("sandbox wiring (steps 6-8) should succeed");
    sandboxed.extracted.lua
}

// ---------------------------------------------------------------------
// capability gate (register skip / declared capability)
// ---------------------------------------------------------------------

#[test]
fn net_is_nil_for_a_profile_that_declares_no_net_capability() {
    let lua = sandboxed_lua(r#"{ name = "demo" }"#);
    let value: Value = lua.load("return net").eval().expect("global lookup");
    assert!(
        matches!(value, Value::Nil),
        "05 §L4 register skip: net must not exist when no net.* capability is declared"
    );
}

#[test]
fn http_get_is_nil_when_only_http_post_is_declared() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.http_post" }, http_allowlist = { "https://example.com/" } }"#,
    );
    let http_get: Value = lua
        .load("return net.http_get")
        .eval()
        .expect("net.http_get lookup");
    assert!(
        matches!(http_get, Value::Nil),
        "each net.* operation is its own KNOWN_CAPABILITIES entry (register skip per-op)"
    );
    let http_post: Value = lua
        .load("return net.http_post")
        .eval()
        .expect("net.http_post lookup");
    assert!(!matches!(http_post, Value::Nil));
}

// ---------------------------------------------------------------------
// net.http_get: allowlist / max_bytes / ok boundary
// ---------------------------------------------------------------------

#[test]
fn http_get_rejects_a_url_outside_the_http_allowlist() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.http_get" }, http_allowlist = { "https://allowed.example.com/" } }"#,
    );
    let err = lua
        .load(r#"return net.http_get("https://evil.example.com/")"#)
        .eval::<Value>()
        .expect_err("a url outside http_allowlist must be rejected");
    assert!(err
        .to_string()
        .contains("matches no pattern in profile.http_allowlist"));
}

#[test]
fn http_get_allows_a_url_matching_the_http_allowlist_and_captures_ok_boundary_status_200() {
    let base_url = spawn_server(|_req| ServerResponse::text(200, "hello"));
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_get" }}, http_allowlist = {{ "{base_url}/" }} }}"#
    ));
    let result: Table = lua
        .load(format!(r#"return net.http_get("{base_url}/greet")"#))
        .eval()
        .expect("net.http_get should evaluate for an allowlisted url");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<i64>("status").unwrap(), 200);
    assert_eq!(result.get::<String>("body").unwrap(), "hello");
    assert!(!result.get::<bool>("dry_run").unwrap());
}

#[test]
fn http_get_ok_boundary_status_399_is_ok_and_400_is_not() {
    let base_url_399 = spawn_server(|_req| ServerResponse::text(399, ""));
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_get" }}, http_allowlist = {{ "{base_url_399}/" }} }}"#
    ));
    let result_399: Table = lua
        .load(format!(r#"return net.http_get("{base_url_399}/")"#))
        .eval()
        .expect("status 399 should evaluate");
    assert!(
        result_399.get::<bool>("ok").unwrap(),
        "04 §Outputs: ok = (200 <= status < 400), 399 must be ok"
    );

    let base_url_400 = spawn_server(|_req| ServerResponse::text(400, ""));
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_get" }}, http_allowlist = {{ "{base_url_400}/" }} }}"#
    ));
    let result_400: Table = lua
        .load(format!(r#"return net.http_get("{base_url_400}/")"#))
        .eval()
        .expect("status 400 should evaluate");
    assert!(
        !result_400.get::<bool>("ok").unwrap(),
        "04 §Outputs: ok = (200 <= status < 400), 400 must not be ok"
    );
}

#[test]
fn http_get_rejects_a_response_larger_than_max_bytes_without_raising_a_lua_error() {
    let base_url = spawn_server(|_req| ServerResponse::text(200, "x".repeat(2000)));
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_get" }}, http_allowlist = {{ "{base_url}/" }} }}"#
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.http_get("{base_url}/big", {{ max_bytes = 1000 }})"#
        ))
        .eval()
        .expect("an oversized response is an effect failure, not a Lua error");

    assert!(!result.get::<bool>("ok").unwrap());
    assert!(result
        .get::<String>("error")
        .unwrap()
        .contains("exceeds max_bytes"));
}

#[test]
fn http_get_dry_run_skips_the_network_call_entirely() {
    // No server is spawned at all: if the bridge performed the effect,
    // this test would hang waiting for a connection nothing answers.
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.http_get" }, http_allowlist = { "https://example.com/" } }"#,
    );
    let result: Table = lua
        .load(r#"return net.http_get("https://example.com/x", { dry_run = true })"#)
        .eval()
        .expect("dry_run should skip the effect and evaluate");
    assert!(result.get::<bool>("ok").unwrap());
    assert!(result.get::<bool>("dry_run").unwrap());
}

// ---------------------------------------------------------------------
// net.http_post: body XOR / content-type defaults
// ---------------------------------------------------------------------

#[test]
fn http_post_rejects_supplying_both_body_and_body_json() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.http_post" }, http_allowlist = { "https://example.com/" } }"#,
    );
    let err = lua
        .load(r#"return net.http_post("https://example.com/x", { body = "a", body_json = { x = 1 } })"#)
        .eval::<Value>()
        .expect_err("supplying both body and body_json must be a Lua error");
    assert!(err.to_string().contains("mutually exclusive"));
}

#[test]
fn http_post_sends_body_json_as_canonical_json_with_a_default_content_type() {
    let base_url = spawn_server(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.header("content-type"), Some("application/json"));
        assert_eq!(
            String::from_utf8_lossy(&req.body),
            r#"{"a":1,"b":2}"#,
            "body_json is encoded via lm.canonical.encode (lexicographic key order)"
        );
        ServerResponse::text(200, "ok")
    });
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_post" }}, http_allowlist = {{ "{base_url}/" }} }}"#
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.http_post("{base_url}/create", {{ body_json = {{ b = 2, a = 1 }} }})"#
        ))
        .eval()
        .expect("net.http_post with body_json should evaluate");
    assert!(result.get::<bool>("ok").unwrap());
}

#[test]
fn http_post_sends_body_form_as_urlencoded_with_a_default_content_type() {
    let base_url = spawn_server(|req| {
        assert_eq!(
            req.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(String::from_utf8_lossy(&req.body), "name=martin");
        ServerResponse::text(200, "ok")
    });
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_post" }}, http_allowlist = {{ "{base_url}/" }} }}"#
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.http_post("{base_url}/form", {{ body_form = {{ name = "martin" }} }})"#
        ))
        .eval()
        .expect("net.http_post with body_form should evaluate");
    assert!(result.get::<bool>("ok").unwrap());
}

#[test]
fn http_post_does_not_override_a_caller_supplied_content_type_header() {
    let base_url = spawn_server(|req| {
        assert_eq!(
            req.header("content-type"),
            Some("application/vnd.custom+json")
        );
        ServerResponse::text(200, "ok")
    });
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.http_post" }}, http_allowlist = {{ "{base_url}/" }} }}"#
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.http_post("{base_url}/create", {{
                headers = {{ ["Content-Type"] = "application/vnd.custom+json" }},
                body_json = {{ a = 1 }}
            }})"#
        ))
        .eval()
        .expect("net.http_post should evaluate");
    assert!(result.get::<bool>("ok").unwrap());
}

// ---------------------------------------------------------------------
// net.transfer: scheme resolution / direction / rejection
// ---------------------------------------------------------------------

#[test]
fn transfer_rejects_a_gs_scheme_source_through_the_lua_bridge() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.transfer" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return net.transfer("gs://bucket/x", "/workspace/out.bin")"#)
        .eval::<Value>()
        .expect_err("gs:// must be rejected (04 §Outputs `net.transfer`)");
    assert!(err.to_string().contains("unsupported scheme"));
}

#[test]
fn transfer_rejects_url_to_url() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.transfer" }, http_allowlist = { "https://a.example.com/", "https://b.example.com/" } }"#,
    );
    let err = lua
        .load(r#"return net.transfer("https://a.example.com/x", "https://b.example.com/y")"#)
        .eval::<Value>()
        .expect_err("URL-to-URL must be rejected");
    assert!(err.to_string().contains("URL-to-URL"));
}

#[test]
fn transfer_rejects_path_to_path_and_points_at_fs() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.transfer" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return net.transfer("/workspace/a.bin", "/workspace/b.bin")"#)
        .eval::<Value>()
        .expect_err("path-to-path must be rejected");
    assert!(err.to_string().contains("fs.*"));
}

#[test]
fn transfer_rejects_upload_directly_to_an_hf_dst() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.transfer" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(r#"return net.transfer("/workspace/model.bin", "hf://owner/repo/model.bin")"#)
        .eval::<Value>()
        .expect_err("upload directly to hf:// must be rejected at this bridge");
    assert!(err.to_string().contains("rejected"));
}

#[test]
fn transfer_rejects_a_dst_path_outside_declared_paths() {
    let base_url = spawn_server(|_req| ServerResponse::text(200, "data"));
    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.transfer" }}, http_allowlist = {{ "{base_url}/" }}, paths = {{ "/workspace" }} }}"#
    ));
    let err = lua
        .load(format!(
            r#"return net.transfer("{base_url}/f", "/etc/passwd")"#
        ))
        .eval::<Value>()
        .expect_err("a dst path outside profile.paths must be rejected");
    assert!(err.to_string().contains("profile.paths"));
}

// ---------------------------------------------------------------------
// net.transfer: download + sha256
// ---------------------------------------------------------------------

fn temp_dst_path(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-net-transfer-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("downloaded.bin")
}

#[test]
fn transfer_downloads_to_the_destination_file_and_reports_bytes_and_sha256() {
    let base_url = spawn_server(|_req| ServerResponse::text(200, "the-file-contents"));
    let dst = temp_dst_path("download-ok");
    let dst_str = dst.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.transfer" }}, http_allowlist = {{ "{base_url}/" }}, paths = {{ "{dst_parent}" }} }}"#,
        dst_parent = dst.parent().unwrap().display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.transfer("{base_url}/model.bin", "{dst_str}")"#
        ))
        .eval()
        .expect("download should evaluate");

    assert!(result.get::<bool>("ok").unwrap());
    assert_eq!(result.get::<String>("direction").unwrap(), "download");
    assert_eq!(result.get::<String>("dst").unwrap(), dst_str);
    assert_eq!(result.get::<i64>("bytes").unwrap(), 17);
    let expected_sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"the-file-contents");
        format!("{:x}", hasher.finalize())
    };
    assert_eq!(result.get::<String>("sha256").unwrap(), expected_sha256);
    assert_eq!(
        std::fs::read_to_string(&dst).expect("downloaded file should exist"),
        "the-file-contents"
    );

    std::fs::remove_dir_all(dst.parent().unwrap()).expect("cleanup temp dir");
}

#[test]
fn transfer_verifies_sha256_and_deletes_the_file_on_mismatch() {
    let base_url = spawn_server(|_req| ServerResponse::text(200, "the-file-contents"));
    let dst = temp_dst_path("download-mismatch");
    let dst_str = dst.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.transfer" }}, http_allowlist = {{ "{base_url}/" }}, paths = {{ "{dst_parent}" }} }}"#,
        dst_parent = dst.parent().unwrap().display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.transfer("{base_url}/model.bin", "{dst_str}", {{
                sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
            }})"#
        ))
        .eval()
        .expect("a sha256 mismatch is an effect failure, not a Lua error");

    assert!(!result.get::<bool>("ok").unwrap());
    assert!(result
        .get::<String>("error")
        .unwrap()
        .contains("sha256 mismatch"));
    assert!(
        !dst.exists(),
        "04 §Outputs `net.transfer`: on any failure the partial file is removed"
    );

    std::fs::remove_dir_all(dst.parent().unwrap()).expect("cleanup temp dir");
}

// ---------------------------------------------------------------------
// net.transfer: auth_bearer SecretRef consumption
// ---------------------------------------------------------------------

#[test]
fn transfer_rejects_an_undeclared_auth_bearer_secret_ref() {
    let lua = sandboxed_lua(
        r#"{ name = "demo", capabilities = { "net.transfer" }, http_allowlist = { "https://example.com/" }, paths = { "/workspace" } }"#,
    );
    let err = lua
        .load(
            r#"return net.transfer("https://example.com/x", "/workspace/out.bin", {
                auth_bearer = env.ref("UNDECLARED_SECRET")
            })"#,
        )
        .eval::<Value>()
        .expect_err("an undeclared secret name must be rejected at consumption");
    assert!(err
        .to_string()
        .contains("secret 'UNDECLARED_SECRET' is not declared in profile.env_secrets"));
}

#[test]
fn transfer_fails_fast_when_a_declared_auth_bearer_secret_is_missing_from_the_host_env() {
    let var_name = format!("LM_PROVISION_TEST_TRANSFER_MISSING_{}", std::process::id());
    std::env::remove_var(&var_name);

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.transfer" }}, http_allowlist = {{ "https://example.com/" }}, paths = {{ "/workspace" }}, env_secrets = {{ "{var_name}" }} }}"#
    ));
    let err = lua
        .load(format!(
            r#"return net.transfer("https://example.com/x", "/workspace/out.bin", {{
                auth_bearer = env.ref("{var_name}")
            }})"#
        ))
        .eval::<Value>()
        .expect_err("a declared-but-absent secret must fail fast");
    assert!(err
        .to_string()
        .contains(&format!("secret '{var_name}' missing in host env")));
}

#[test]
fn transfer_dry_run_still_resolves_auth_bearer_and_fails_fast_on_a_missing_secret() {
    let var_name = format!(
        "LM_PROVISION_TEST_TRANSFER_DRYRUN_MISSING_{}",
        std::process::id()
    );
    std::env::remove_var(&var_name);

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.transfer" }}, http_allowlist = {{ "https://example.com/" }}, paths = {{ "/workspace" }}, env_secrets = {{ "{var_name}" }} }}"#
    ));
    let err = lua
        .load(format!(
            r#"return net.transfer("https://example.com/x", "/workspace/out.bin", {{
                dry_run = true,
                auth_bearer = env.ref("{var_name}")
            }})"#
        ))
        .eval::<Value>()
        .expect_err(
            "04 §Common conventions: dry_run still fails on missing secrets, \
             it validates everything except the effect itself",
        );
    assert!(err
        .to_string()
        .contains(&format!("secret '{var_name}' missing in host env")));
}

#[test]
fn transfer_resolves_a_declared_auth_bearer_secret_and_sends_it_as_a_bearer_header() {
    let var_name = format!("LM_PROVISION_TEST_TRANSFER_SECRET_{}", std::process::id());
    std::env::set_var(&var_name, "top-secret-token");

    let base_url = spawn_server(|req| {
        assert_eq!(req.header("authorization"), Some("Bearer top-secret-token"));
        ServerResponse::text(200, "ok")
    });
    let dst = temp_dst_path("auth-bearer");
    let dst_str = dst.display().to_string();

    let lua = sandboxed_lua(&format!(
        r#"{{ name = "demo", capabilities = {{ "net.transfer" }}, http_allowlist = {{ "{base_url}/" }}, paths = {{ "{dst_parent}" }}, env_secrets = {{ "{var_name}" }} }}"#,
        dst_parent = dst.parent().unwrap().display()
    ));
    let result: Table = lua
        .load(format!(
            r#"return net.transfer("{base_url}/x", "{dst_str}", {{
                auth_bearer = env.ref("{var_name}")
            }})"#
        ))
        .eval()
        .expect("net.transfer should evaluate");

    std::env::remove_var(&var_name);
    assert!(result.get::<bool>("ok").unwrap());
    assert!(!result.contains_key("auth_bearer").unwrap());

    std::fs::remove_dir_all(dst.parent().unwrap()).expect("cleanup temp dir");
}
