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
