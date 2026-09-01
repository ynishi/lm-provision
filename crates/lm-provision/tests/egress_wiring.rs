//! Slice 3 wiring: a profile that declares `sh_egress` has its `sh.exec`
//! subprocess routed through the in-process egress proxy — proven end to end
//! through the real apply driver ([`lm_provision::apply::run_apply_ast`]),
//! which is the path that starts the proxy (the sync engine builder used by
//! the other integration tests does not). The subprocess here reaches no
//! network: it only writes its inherited `HTTPS_PROXY` to a marker file, so
//! the test asserts on the *injection*, not on a live connection (the gate's
//! allow/deny behaviour is covered by `egress::proxy`'s unit tests and the
//! on-pod probe recorded in the design doc).

use std::path::PathBuf;

use lm_provision::apply::run_apply_ast;

/// A unique scratch dir under the system temp dir.
fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-egress-wire-{tag}-{}-{}",
        std::process::id(),
        // A monotonic-ish suffix without pulling in a clock dep: the pid +
        // tag already separate concurrent tests; the counter separates the
        // two profiles one test writes.
        tag.len()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Write a profile JSON whose single `sh.exec` records its `HTTPS_PROXY`
/// into `marker`, and return its path. `sh_egress` is included verbatim, so
/// passing `"[]"` exercises the no-pin case and `"[\"example.com\"]"` the pin.
fn write_profile(dir: &std::path::Path, sh_egress_json: &str, marker: &std::path::Path) -> PathBuf {
    let profile = format!(
        r#"{{
  "type": "Spec",
  "name": "egress-wire",
  "version": "0.0.0",
  "capabilities": ["sh.exec"],
  "paths": [],
  "http_allowlist": [],
  "sh_egress": {sh_egress},
  "phases": [
    {{ "type": "ShExec",
       "argv": ["sh", "-c", "printf %s \"${{HTTPS_PROXY:-}}\" > {marker}"] }}
  ]
}}"#,
        sh_egress = sh_egress_json,
        marker = marker.to_string_lossy(),
    );
    let path = dir.join("profile.json");
    std::fs::write(&path, profile).expect("write profile");
    path
}

/// A declared `sh_egress` routes the subprocess: it inherits an
/// `HTTPS_PROXY` pointing at the in-process proxy on loopback.
#[tokio::test(flavor = "multi_thread")]
async fn declared_sh_egress_injects_a_loopback_proxy_into_the_subprocess() {
    let dir = scratch_dir("pinned");
    let marker = dir.join("proxy.txt");
    let _ = std::fs::remove_file(&marker);
    let profile = write_profile(&dir, r#"["example.com"]"#, &marker);

    let report = run_apply_ast(&profile, false).await.expect("apply succeeds");
    assert!(
        report.contains("\"ok\": true") || report.contains("\"ok\":true"),
        "apply report should be ok: {report}"
    );

    let seen = std::fs::read_to_string(&marker).expect("subprocess wrote the marker");
    assert!(
        seen.starts_with("http://127.0.0.1:"),
        "subprocess should inherit a loopback HTTPS_PROXY, got: {seen:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// No `sh_egress` (the opt-in default) starts no proxy and injects nothing:
/// the subprocess sees an empty `HTTPS_PROXY`, exactly as before this feature.
#[tokio::test(flavor = "multi_thread")]
async fn absent_sh_egress_leaves_the_subprocess_unrouted() {
    let dir = scratch_dir("unpinned");
    let marker = dir.join("proxy.txt");
    let _ = std::fs::remove_file(&marker);
    let profile = write_profile(&dir, "[]", &marker);

    run_apply_ast(&profile, false).await.expect("apply succeeds");

    let seen = std::fs::read_to_string(&marker).expect("subprocess wrote the marker");
    assert!(
        seen.is_empty(),
        "an unpinned profile must not inject HTTPS_PROXY, got: {seen:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The hard layer reaches a real subprocess through apply: a declared
/// `sh_egress` pins the address-carrying network syscalls, so a subprocess that
/// ignores the proxy and dials an off-host address directly is refused at the
/// syscall, while a dial of the proxy endpoint itself still succeeds. The
/// subprocess learns the proxy endpoint the way any subprocess does — from its
/// own `HTTPS_PROXY` env — because the pin now admits exactly that endpoint
/// (and configured DNS resolvers), not any loopback service. Linux-only
/// (seccomp); proves the wiring from apply → sh_exec → hardpin::run_pinned,
/// not just the module in isolation.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn declared_sh_egress_hard_pin_blocks_a_direct_offhost_connect() {
    let dir = scratch_dir("hardpin");
    let marker = dir.join("result.txt");
    let _ = std::fs::remove_file(&marker);

    // bash /dev/tcp: parse host:port out of $HTTPS_PROXY and dial the proxy
    // endpoint (allowed — it is what the pin admits), then a direct TEST-NET-3
    // dial (203.0.113.1, off-host → must be EPERM'd at the syscall). Uses bash
    // so /dev/tcp is available; the profile pins egress, so apply binds the
    // proxy, injects its address as HTTPS_PROXY, and runs this under the
    // supervisor.
    let script = format!(
        "hp=${{HTTPS_PROXY#http://}}; h=${{hp%%:*}}; p=${{hp##*:}}; \
         exec 3<>/dev/tcp/$h/$p && echo PROXY_OK >> {m}; \
         (exec 4<>/dev/tcp/203.0.113.1/80) 2>/dev/null \
           && echo EXTERNAL_LEAK >> {m} || echo EXTERNAL_BLOCKED >> {m}",
        m = marker.to_string_lossy(),
    );
    let profile = format!(
        r#"{{
  "type": "Spec",
  "name": "egress-hardpin",
  "version": "0.0.0",
  "capabilities": ["sh.exec"],
  "paths": [],
  "http_allowlist": [],
  "sh_egress": ["example.com"],
  "phases": [
    {{ "type": "ShExec", "argv": ["bash", "-c", {script}] }}
  ]
}}"#,
        script = serde_json_string(&script),
    );
    let path = dir.join("profile.json");
    std::fs::write(&path, profile).expect("write profile");

    run_apply_ast(&path, false).await.expect("apply succeeds");

    let seen = std::fs::read_to_string(&marker).expect("subprocess wrote the marker");
    assert!(
        seen.contains("PROXY_OK"),
        "a dial of the proxy endpoint should be allowed through the pin: {seen:?}"
    );
    assert!(
        seen.contains("EXTERNAL_BLOCKED"),
        "a direct off-host dial must be denied at the syscall: {seen:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Minimal JSON string escaper for embedding a shell script as a JSON argv
/// element — enough for the scripts here (quotes, backslashes, newlines).
#[cfg(target_os = "linux")]
fn serde_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
