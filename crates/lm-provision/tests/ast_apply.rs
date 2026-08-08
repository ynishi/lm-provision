//! End-to-end regression for the `apply` subcommand's AST exec path: all
//! profiles route to [`lm_provision::apply::run_apply_ast`], and a `.lua`
//! profile is rejected at the frontend (the legacy embedded-Lua pipeline
//! is gone).
//!
//! The report envelope (`{ ok, dry_run, profile_name, steps, error? }`)
//! keeps the historical apply-report field names, with the `steps` array
//! carrying the AST exec layer's own step structure — one entry per
//! direct-op phase, one per lifecycle sub-step, with honest `note` steps
//! (see `lm_provision::exec::report`).
//!
//! `run_apply_ast` is `async` and its effect layer blocks the calling
//! thread on the current runtime, so the in-process tests take
//! `#[tokio::test(flavor = "multi_thread")]` — the flavour the CLI entry
//! point builds. The tests that go through the binary instead
//! (`assert_cmd`) exercise that wiring itself and stay synchronous.

use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::{json, Value};

/// A unique temp path stem for this process + call.
fn temp_stem(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lm-provision-ast-apply-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

/// Write `profile` (a serde JSON `Spec`) to a fresh `.json` file and
/// return its path. The `.json` extension is what routes it onto the AST
/// frontend (`is_lua_profile` is false).
fn write_json_profile(label: &str, profile: &Value) -> PathBuf {
    let path = temp_stem(label).with_extension("json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(profile).expect("profile serializes"),
    )
    .expect("write temp profile");
    path
}

fn step_ops(report: &Value) -> Vec<String> {
    report["steps"]
        .as_array()
        .expect("steps is an array")
        .iter()
        .map(|s| s["op"].as_str().expect("op is a string").to_string())
        .collect()
}

fn step_ids(report: &Value) -> Vec<String> {
    report["steps"]
        .as_array()
        .expect("steps is an array")
        .iter()
        .map(|s| s["id"].as_str().expect("id is a string").to_string())
        .collect()
}

/// The `kind` of every step in a plan artifact or an apply report,
/// deduplicated consecutively so a lifecycle phase that expanded into
/// several sub-steps counts once — the two artifacts agree on phases,
/// not on sub-step granularity.
fn step_kinds(artifact: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for step in artifact["steps"].as_array().expect("steps is an array") {
        let kind = step["kind"].as_str().expect("kind is a string").to_string();
        if out.last() != Some(&kind) {
            out.push(kind);
        }
    }
    out
}

// ---------------------------------------------------------------------
// Dry-run report shape (envelope field names + AST step structure).
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_report_has_the_legacy_envelope_and_ast_step_structure() {
    let profile = json!({
        "type": "Spec",
        "name": "ast-apply-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": ["/tmp"],
        "phases": [
            { "type": "SystemApt", "packages": ["git"] },
            { "type": "ShExec", "argv": ["echo", "hi"] },
            { "type": "FsWrite", "path": "/tmp/ast-apply-demo-x", "content": "hello" }
        ]
    });
    let path = write_json_profile("shape", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, true)
        .await
        .expect("dry-run apply over a valid profile should produce a report");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    // Envelope is field-name compatible with lua/lm/report.lua.
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["dry_run"], json!(true));
    assert_eq!(report["profile_name"], json!("ast-apply-demo"));
    assert!(report["steps"].is_array());
    assert!(
        report.get("error").is_none(),
        "an all-ok run carries no error"
    );

    // AST step structure: system.apt expands to one sh Sh sub-step, then
    // the two direct ops in declaration order.
    assert_eq!(
        step_ids(&report),
        vec!["1_system.apt_1", "2_sh.exec", "3_fs.write"]
    );
    assert_eq!(step_ops(&report), vec!["sh.exec", "sh.exec", "fs.write"]);

    let steps = report["steps"].as_array().unwrap();
    for step in steps {
        assert_eq!(step["ok"], json!(true), "step: {step}");
        assert_eq!(step["dry_run"], json!(true), "dry-run marker: {step}");
    }
    // The lifecycle sub-step carries its composed argv (apt-get install).
    assert_eq!(steps[0]["kind"], json!("system.apt"));
    assert_eq!(steps[0]["argv"][0], json!("apt-get"));
    // fs.write reports its target path + byte count even in dry-run.
    assert_eq!(steps[2]["path"], json!("/tmp/ast-apply-demo-x"));
    assert_eq!(steps[2]["bytes"], json!(5));

    std::fs::remove_file(&path).ok();
}

/// A dry-run `models` step reaches the report saying **what would
/// decide whether it is skipped, and that nothing decided it**.
///
/// The two failure modes this pins down are the ones Chef's why-run
/// mode is criticised for and the ones a skip that says nothing
/// produces: claiming the step "would run" when the answer was never
/// looked for, and claiming it was skipped without saying on what.
#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_models_step_reports_its_condition_as_undecided() {
    let digest = "a".repeat(64);
    let profile = json!({
        "type": "Spec",
        "name": "models-dry-run",
        "capabilities": ["net.transfer"],
        "paths": ["/workspace/ComfyUI/models"],
        "http_allowlist": ["https://example.com/"],
        "phases": [{
            "type": "Models",
            "models_json": format!(
                r#"[{{"src":"https://example.com/a.bin","dst":"a.bin","subdir":"lora","sha256":"{digest}"}}]"#
            ),
        }]
    });
    let path = write_json_profile("models-dry-run", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, true)
        .await
        .expect("a dry run touches nothing and reports");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    let steps = report["steps"].as_array().expect("steps is an array");
    assert_eq!(steps.len(), 1);
    let step = &steps[0];
    assert_eq!(step["op"], json!("net.transfer"));
    assert_eq!(step["dry_run"], json!(true));
    assert_eq!(
        step["dst"],
        json!("/workspace/ComfyUI/models/lora/a.bin"),
        "the composed destination, which is also what the condition looks at",
    );

    let note = step["note"]
        .as_str()
        .expect("the condition reaches the report");
    assert!(
        note.starts_with("skip undecided: not evaluated in a dry run"),
        "a dry run must not claim the step would run: {note}",
    );
    assert!(
        note.contains("exists(/workspace/ComfyUI/models/lora/a.bin)") && note.contains(&digest),
        "…and must say what would decide it: {note}",
    );

    std::fs::remove_file(&path).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_note_step_is_honest_never_dispatch_pending() {
    let profile = json!({
        "type": "Spec",
        "name": "note-demo",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "ServiceStart", "name": "llm", "platform_kind": "vllm" }
        ]
    });
    let path = write_json_profile("note", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, true)
        .await
        .expect("dry-run apply should succeed");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    let ops = step_ops(&report);
    assert!(
        ops.contains(&"note".to_string()),
        "an effectless lifecycle sub-step is an honest note step: {ops:?}"
    );
    assert!(
        !ops.contains(&"dispatch_pending".to_string()),
        "the AST path never emits the legacy dispatch_pending skip: {ops:?}"
    );
    let step = &report["steps"][0];
    assert_eq!(step["ok"], json!(true), "a note step is a success");
    assert!(step.get("note").is_some(), "the note text is carried");

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Real-mode end-to-end (harmless effects only).
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn real_mode_runs_sh_exec_and_fs_write_for_real() {
    let dir = temp_stem("real-effects");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("out.txt");
    let target_str = target.to_string_lossy().into_owned();
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "real-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": [dir_str],
        "phases": [
            { "type": "ShExec", "argv": ["true"] },
            { "type": "FsWrite", "path": target_str, "content": "written-for-real" }
        ]
    });
    let path = write_json_profile("real", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("real-mode apply over a harmless profile should succeed");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["dry_run"], json!(false));

    let steps = report["steps"].as_array().unwrap();
    // Real mode carries no dry_run marker on its step entries.
    for step in steps {
        assert!(
            step.get("dry_run").is_none(),
            "real-mode steps omit the dry_run marker: {step}"
        );
    }
    // The sh.exec step captured its (empty) stdout tail structurally.
    assert_eq!(steps[0]["op"], json!("sh.exec"));
    assert!(steps[0].get("stdout").is_some());

    // The effect actually ran.
    assert_eq!(
        std::fs::read_to_string(&target).expect("target file was written"),
        "written-for-real"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// A real-mode **lifecycle** sub-step must carry what it observed —
/// exit status and captured output — not just the argv it was composed
/// from. The exec layer used to keep only the joined trace summary, so
/// these entries were strictly less informative than a direct op's
/// (spec 09 §Apply report: the per-op field table applies to lifecycle
/// sub-steps too).
#[tokio::test(flavor = "multi_thread")]
async fn real_mode_lifecycle_substeps_carry_their_observations() {
    // `hooks.post_install` composes exactly one `sh.exec` sub-step out
    // of the script, so the assertion targets a lifecycle entry rather
    // than a direct op.
    let profile = json!({
        "type": "Spec",
        "name": "lifecycle-observations",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "PostInstall", "script": "echo observed-stdout" }
        ]
    });
    let path = write_json_profile("lifecycle-observations", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("a post_install echo should apply cleanly");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");
    assert_eq!(report["ok"], json!(true));

    let steps = report["steps"].as_array().unwrap();
    assert_eq!(
        steps.len(),
        1,
        "post_install composes one sub-step: {steps:?}"
    );
    let step = &steps[0];

    // Lifecycle sub-step id shape, and the effect it actually ran.
    assert_eq!(step["kind"], json!("hooks.post_install"));
    assert_eq!(step["op"], json!("sh.exec"));
    assert_eq!(step["id"], json!("1_hooks.post_install_1"));

    // The declared input is still there …
    assert_eq!(step["argv"], json!(["sh", "-c", "echo observed-stdout"]));
    // … and now so are the observations.
    assert_eq!(step["status"], json!(0), "exit status: {step}");
    assert!(
        step["stdout"]
            .as_str()
            .expect("stdout tail is recorded")
            .contains("observed-stdout"),
        "captured stdout must reach the report: {step}"
    );
    assert!(step.get("stderr").is_some(), "stderr tail present: {step}");

    std::fs::remove_file(&path).ok();
}

/// The same entries under `--dry-run` carry inputs but **no**
/// observations — nothing ran, so a status/stdout there would be
/// fabricated.
#[tokio::test(flavor = "multi_thread")]
async fn dry_run_lifecycle_substeps_carry_inputs_but_no_observations() {
    let profile = json!({
        "type": "Spec",
        "name": "lifecycle-dry",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "PostInstall", "script": "echo not-executed" }
        ]
    });
    let path = write_json_profile("lifecycle-dry", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, true)
        .await
        .expect("dry-run apply succeeds");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    let step = &report["steps"].as_array().unwrap()[0];
    assert_eq!(step["argv"], json!(["sh", "-c", "echo not-executed"]));
    assert_eq!(step["dry_run"], json!(true));
    assert!(
        step.get("stdout").is_none() && step.get("stderr").is_none(),
        "a dry run observed nothing: {step}"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Fail-fast step collection + the legacy error form.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_step_is_collected_and_stops_the_run() {
    let profile = json!({
        "type": "Spec",
        "name": "fail-demo",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "ShExec", "argv": ["sh", "-c", "exit 3"] },
            { "type": "ShExec", "argv": ["echo", "never-reached"] }
        ]
    });
    let path = write_json_profile("fail", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("a step failure is captured in-report, not returned as Err");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(false));
    let error = report["error"].as_str().expect("error line is present");
    assert!(
        error.starts_with("step 1_sh.exec (sh.exec) failed:"),
        "error uses the legacy `step <id> (<kind>) failed: <reason>` form: {error}"
    );

    // Fail-fast: only the failing step appears; the second never ran.
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1, "fail-fast: later steps are absent");
    assert_eq!(steps[0]["ok"], json!(false));
    assert_eq!(
        steps[0]["status"],
        json!(3),
        "the process exit code is kept"
    );

    std::fs::remove_file(&path).ok();
}

/// A *failing* lifecycle sub-step must be as informative as a failing
/// direct op: the exit code and the captured output that accompanied the
/// failure belong in structured fields, not only quoted inside the
/// `reason` text (spec 09 §Apply report).
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_lifecycle_substep_carries_its_partial_observation() {
    let profile = json!({
        "type": "Spec",
        "name": "lifecycle-fail-observations",
        "capabilities": ["sh.exec"],
        "phases": [
            { "type": "PostInstall",
              "script": "echo out-before-failing; echo err-before-failing 1>&2; exit 7" }
        ]
    });
    let path = write_json_profile("lifecycle-fail-observations", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("a step failure is captured in-report, not returned as Err");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(false));
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1, "fail-fast: {steps:?}");
    let step = &steps[0];

    assert_eq!(step["ok"], json!(false));
    assert_eq!(step["op"], json!("sh.exec"));
    assert_eq!(
        step["status"],
        json!(7),
        "the real exit code survives instead of the pre-effect -1: {step}"
    );
    assert!(
        step["stdout"]
            .as_str()
            .expect("stdout observed before the failure")
            .contains("out-before-failing"),
        "{step}"
    );
    assert!(
        step["stderr"]
            .as_str()
            .expect("stderr observed before the failure")
            .contains("err-before-failing"),
        "{step}"
    );

    std::fs::remove_file(&path).ok();
}

/// `python.version_check` must actually check. Emitting `python3
/// --version` and calling itself advisory let a mismatch pass silently;
/// the assert script fails the step, and the interpreter's real version
/// reaches the report through the captured stderr.
#[tokio::test(flavor = "multi_thread")]
async fn python_version_check_fails_the_run_on_a_mismatch() {
    let profile = json!({
        "type": "Spec",
        "name": "version-mismatch",
        "capabilities": ["sh.exec"],
        "phases": [
            // No interpreter reports 99.99, so this mismatches anywhere.
            { "type": "PythonVersionCheck", "want": "99.99" }
        ]
    });
    let path = write_json_profile("version-mismatch", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("a step failure is captured in-report");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");

    assert_eq!(report["ok"], json!(false), "{report}");
    let step = &report["steps"].as_array().unwrap()[0];
    assert_eq!(step["ok"], json!(false));
    assert_ne!(
        step["status"],
        json!(0),
        "a mismatch exits non-zero: {step}"
    );
    assert!(
        step["stderr"]
            .as_str()
            .expect("stderr reaches the report")
            .contains("python version mismatch"),
        "the assert message names the mismatch: {step}"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// The two routes agree (DC 8), for each moved op.
//
// The point of moving one op at a time onto dsl-kit's `Call` /
// `AsyncEffectResolver` surface is that the move is *checkable*: the same
// profile driven through the legacy op and through the new `Call` route
// has to produce the same report. These are the checks — one pair (real
// + dry-run) per moved op, plus the shared gate check below.
// ---------------------------------------------------------------------

/// Serve `payload` to the first `serves` connections, so two apply runs
/// can hit the **same** URL — a second server would take a second port,
/// and the port is in the report (`steps[].src`).
fn twice_serving_server(
    payload: &'static str,
    serves: usize,
) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        for _ in 0..serves {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn both_net_transfer_routes_produce_the_same_report() {
    use lm_provision::exec::registry::EffectRoute;

    let payload = "the-weight-behind-the-url";
    let (base_url, server) = twice_serving_server(payload, 2);

    let dir = temp_stem("transfer-routes");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("weight.bin");
    let target_str = target.to_string_lossy().into_owned();
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "transfer-routes",
        "capabilities": ["net.transfer"],
        "paths": [dir_str],
        "http_allowlist": [base_url],
        "phases": [
            { "type": "NetTransfer", "src": format!("{base_url}/weight.bin"), "dst": target_str }
        ]
    });
    let path = write_json_profile("transfer-routes", &profile);

    let via_op: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, false, EffectRoute::Op)
            .await
            .expect("the op route produces a report"),
    )
    .expect("report is JSON");
    assert_eq!(via_op["ok"], json!(true), "op route: {via_op}");
    assert_eq!(
        std::fs::read_to_string(&target).expect("the op route wrote the destination"),
        payload
    );
    std::fs::remove_file(&target).ok();

    let via_call: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, false, EffectRoute::Call)
            .await
            .expect("the call route produces a report"),
    )
    .expect("report is JSON");
    assert_eq!(via_call["ok"], json!(true), "call route: {via_call}");
    assert_eq!(
        std::fs::read_to_string(&target).expect("the call route wrote the destination"),
        payload,
        "the resolver ran the effect for real, not a rendering of it"
    );

    assert_eq!(
        via_op, via_call,
        "the two routes must be indistinguishable in the report"
    );
    // …and the report is the one a transfer writes, not an empty run.
    let step = &via_call["steps"].as_array().expect("steps")[0];
    assert_eq!(step["op"], json!("net.transfer"));
    assert_eq!(step["bytes"], json!(payload.len()));

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
    server.join().expect("server thread joins");
}

/// Dry-run agrees too: the `Call` route renders the same trace entry the
/// op does and reaches no effect — the resolver honours [`ExecMode`], it
/// is not "the route that always transfers".
#[tokio::test(flavor = "multi_thread")]
async fn both_net_transfer_routes_agree_under_dry_run_and_reach_no_effect() {
    use lm_provision::exec::registry::EffectRoute;

    let dir = temp_stem("transfer-routes-dry");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("weight.bin");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "transfer-routes-dry",
        "capabilities": ["net.transfer"],
        "paths": [dir_str],
        // Deliberately unreachable: a dry run must not connect.
        "http_allowlist": ["http://127.0.0.1:1"],
        "phases": [
            { "type": "NetTransfer",
              "src": "http://127.0.0.1:1/weight.bin",
              "dst": target.to_string_lossy() }
        ]
    });
    let path = write_json_profile("transfer-routes-dry", &profile);

    let via_op: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, true, EffectRoute::Op)
            .await
            .expect("op route dry run"),
    )
    .expect("report is JSON");
    let via_call: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, true, EffectRoute::Call)
            .await
            .expect("call route dry run"),
    )
    .expect("report is JSON");

    assert_eq!(via_op["ok"], json!(true), "{via_op}");
    assert_eq!(via_op, via_call, "dry-run reports must agree too");
    assert_eq!(via_call["steps"][0]["dry_run"], json!(true));
    assert!(!target.exists(), "a dry run touches no destination");

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn both_net_http_get_routes_produce_the_same_report() {
    use lm_provision::exec::registry::EffectRoute;

    let (base_url, server) = twice_serving_server("pong", 2);
    let url = format!("{base_url}/ping");

    let profile = json!({
        "type": "Spec",
        "name": "http-get-routes",
        "capabilities": ["net.http_get"],
        "http_allowlist": [base_url],
        "phases": [
            {
                "type": "NetHttpGet",
                "url": url,
                // A header the resolver has to resolve for itself: the
                // `Call` route bypasses `Op::apply`, so it carries the
                // header pipe too, not just the request.
                "headers": { "Accept": { "type": "EnvLiteral", "value": "text/plain" } },
                "timeout_sec": 5
            }
        ]
    });
    let path = write_json_profile("http-get-routes", &profile);

    let via_op: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, false, EffectRoute::Op)
            .await
            .expect("the op route produces a report"),
    )
    .expect("report is JSON");
    let via_call: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, false, EffectRoute::Call)
            .await
            .expect("the call route produces a report"),
    )
    .expect("report is JSON");

    assert_eq!(via_op["ok"], json!(true), "op route: {via_op}");
    assert_eq!(via_call["ok"], json!(true), "call route: {via_call}");
    assert_eq!(
        via_op, via_call,
        "the two routes must be indistinguishable in the report"
    );
    // …and the report is the one a request writes, not an empty run: the
    // resolver reached the server and reported its status.
    let step = &via_call["steps"].as_array().expect("steps")[0];
    assert_eq!(step["op"], json!("net.http_get"));
    assert_eq!(step["status"], json!(200));

    std::fs::remove_file(&path).ok();
    server.join().expect("server thread joins");
}

/// Dry-run agrees too, against a deliberately unreachable URL: a run that
/// reports `ok` proves the resolver honours [`ExecMode`] rather than
/// being "the route that always requests".
#[tokio::test(flavor = "multi_thread")]
async fn both_net_http_get_routes_agree_under_dry_run_and_reach_no_effect() {
    use lm_provision::exec::registry::EffectRoute;

    let profile = json!({
        "type": "Spec",
        "name": "http-get-routes-dry",
        "capabilities": ["net.http_get"],
        // Deliberately unreachable: a dry run must not connect.
        "http_allowlist": ["http://127.0.0.1:1"],
        "phases": [
            { "type": "NetHttpGet", "url": "http://127.0.0.1:1/ping" }
        ]
    });
    let path = write_json_profile("http-get-routes-dry", &profile);

    let via_op: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, true, EffectRoute::Op)
            .await
            .expect("op route dry run"),
    )
    .expect("report is JSON");
    let via_call: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, true, EffectRoute::Call)
            .await
            .expect("call route dry run"),
    )
    .expect("report is JSON");

    assert_eq!(
        via_op["ok"],
        json!(true),
        "a dry run reaches no effect, so the unreachable URL is fine: {via_op}"
    );
    assert_eq!(via_op, via_call, "dry-run reports must agree too");
    assert_eq!(via_call["steps"][0]["dry_run"], json!(true));

    std::fs::remove_file(&path).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn both_net_http_post_routes_produce_the_same_report() {
    use lm_provision::exec::registry::EffectRoute;

    let (base_url, server) = twice_serving_server("accepted", 2);
    let url = format!("{base_url}/v1/echo");

    let profile = json!({
        "type": "Spec",
        "name": "http-post-routes",
        "capabilities": ["net.http_post"],
        "http_allowlist": [base_url],
        "phases": [
            {
                "type": "NetHttpPost",
                "url": url,
                "headers": { "Accept": { "type": "EnvLiteral", "value": "text/plain" } },
                // The body form the resolver has to resolve for itself.
                "body_json": "{\"n\":1}",
                "timeout_sec": 5
            }
        ]
    });
    let path = write_json_profile("http-post-routes", &profile);

    let via_op: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, false, EffectRoute::Op)
            .await
            .expect("the op route produces a report"),
    )
    .expect("report is JSON");
    let via_call: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, false, EffectRoute::Call)
            .await
            .expect("the call route produces a report"),
    )
    .expect("report is JSON");

    assert_eq!(via_op["ok"], json!(true), "op route: {via_op}");
    assert_eq!(via_call["ok"], json!(true), "call route: {via_call}");
    assert_eq!(
        via_op, via_call,
        "the two routes must be indistinguishable in the report"
    );
    let step = &via_call["steps"].as_array().expect("steps")[0];
    assert_eq!(step["op"], json!("net.http_post"));
    assert_eq!(step["status"], json!(200));

    std::fs::remove_file(&path).ok();
    server.join().expect("server thread joins");
}

/// The `net.http_post` twin of the GET dry-run check, with the body
/// resolved (and reported by its form, never its content) in both routes.
#[tokio::test(flavor = "multi_thread")]
async fn both_net_http_post_routes_agree_under_dry_run_and_reach_no_effect() {
    use lm_provision::exec::registry::EffectRoute;

    let profile = json!({
        "type": "Spec",
        "name": "http-post-routes-dry",
        "capabilities": ["net.http_post"],
        // Deliberately unreachable: a dry run must not connect.
        "http_allowlist": ["http://127.0.0.1:1"],
        "phases": [
            {
                "type": "NetHttpPost",
                "url": "http://127.0.0.1:1/v1/echo",
                "body": { "type": "EnvLiteral", "value": "payload" }
            }
        ]
    });
    let path = write_json_profile("http-post-routes-dry", &profile);

    let via_op: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, true, EffectRoute::Op)
            .await
            .expect("op route dry run"),
    )
    .expect("report is JSON");
    let via_call: Value = serde_json::from_str(
        &lm_provision::apply::run_apply_ast_routed(&path, true, EffectRoute::Call)
            .await
            .expect("call route dry run"),
    )
    .expect("report is JSON");

    assert_eq!(
        via_op["ok"],
        json!(true),
        "a dry run reaches no effect, so the unreachable URL is fine: {via_op}"
    );
    assert_eq!(via_op, via_call, "dry-run reports must agree too");
    assert_eq!(via_call["steps"][0]["dry_run"], json!(true));

    std::fs::remove_file(&path).ok();
}

/// A capability the profile never declared must be denied on **both**
/// routes. A `Call` bypasses `Op::apply`, so the resolver carries the L4
/// gate and the L3 allowlists itself; without that the new route would be
/// a hole only it has.
#[tokio::test(flavor = "multi_thread")]
async fn the_call_route_is_gated_exactly_as_the_op_route_is() {
    use lm_provision::exec::registry::EffectRoute;

    let dir = temp_stem("transfer-routes-denied");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "transfer-routes-denied",
        // `net.transfer` is *not* declared.
        "capabilities": ["sh.exec"],
        "paths": [dir_str],
        "http_allowlist": ["http://127.0.0.1:1"],
        "phases": [
            { "type": "NetTransfer",
              "src": "http://127.0.0.1:1/weight.bin",
              "dst": dir.join("weight.bin").to_string_lossy() }
        ]
    });
    let path = write_json_profile("transfer-routes-denied", &profile);

    for route in [EffectRoute::Op, EffectRoute::Call] {
        let report: Value = serde_json::from_str(
            &lm_provision::apply::run_apply_ast_routed(&path, false, route)
                .await
                .expect("a denial is captured in-report"),
        )
        .expect("report is JSON");
        assert_eq!(report["ok"], json!(false), "{route:?}: {report}");
        assert!(
            report["error"]
                .as_str()
                .expect("error line")
                .contains("net.transfer"),
            "{route:?} names the undeclared capability: {report}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// The same for the two HTTP ops, on both of their gates: the L4
/// capability the profile never declared, and the L3 `http_allowlist` the
/// URL falls outside of. Both must deny on both routes, in real mode and
/// under dry run (spec 07 "dry-run does policy").
#[tokio::test(flavor = "multi_thread")]
async fn the_call_route_gates_the_http_ops_exactly_as_the_op_route_does() {
    use lm_provision::exec::registry::EffectRoute;

    // (a) `net.http_get` / `net.http_post` undeclared: L4.
    // (b) declared, but the URL is outside `http_allowlist`: L3.
    let cases = [
        (
            "http-get-undeclared",
            json!(["sh.exec"]),
            json!(["http://127.0.0.1:1"]),
            json!({ "type": "NetHttpGet", "url": "http://127.0.0.1:1/ping" }),
            "net.http_get",
        ),
        (
            "http-post-undeclared",
            json!(["sh.exec"]),
            json!(["http://127.0.0.1:1"]),
            json!({ "type": "NetHttpPost", "url": "http://127.0.0.1:1/echo" }),
            "net.http_post",
        ),
        (
            "http-get-off-allowlist",
            json!(["net.http_get"]),
            json!(["http://127.0.0.1:1"]),
            json!({ "type": "NetHttpGet", "url": "http://127.0.0.2:1/ping" }),
            "http://127.0.0.2:1/ping",
        ),
        (
            "http-post-off-allowlist",
            json!(["net.http_post"]),
            json!(["http://127.0.0.1:1"]),
            json!({ "type": "NetHttpPost", "url": "http://127.0.0.2:1/echo" }),
            "http://127.0.0.2:1/echo",
        ),
    ];

    for (label, capabilities, http_allowlist, phase, named) in cases {
        let profile = json!({
            "type": "Spec",
            "name": label,
            "capabilities": capabilities,
            "http_allowlist": http_allowlist,
            "phases": [phase]
        });
        let path = write_json_profile(label, &profile);

        for dry_run in [false, true] {
            for route in [EffectRoute::Op, EffectRoute::Call] {
                let report: Value = serde_json::from_str(
                    &lm_provision::apply::run_apply_ast_routed(&path, dry_run, route)
                        .await
                        .expect("a denial is captured in-report"),
                )
                .expect("report is JSON");
                assert_eq!(
                    report["ok"],
                    json!(false),
                    "{label} {route:?} dry_run={dry_run}: {report}"
                );
                assert!(
                    report["error"]
                        .as_str()
                        .expect("error line")
                        .contains(named),
                    "{label} {route:?} dry_run={dry_run} names {named}: {report}"
                );
            }
        }

        std::fs::remove_file(&path).ok();
    }
}

// ---------------------------------------------------------------------
// CLI wiring: exit codes + stdout/stderr contract through the binary.
// ---------------------------------------------------------------------

fn bin() -> Command {
    Command::cargo_bin("lm-provision").expect("lm-provision binary should build")
}

#[test]
fn cli_apply_routes_a_json_profile_through_the_ast_path_exit_zero() {
    let profile = json!({
        "type": "Spec",
        "name": "cli-ok",
        "capabilities": ["sh.exec"],
        "phases": [ { "type": "ShExec", "argv": ["echo", "ok"] } ]
    });
    let path = write_json_profile("cli-ok", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is the report JSON");
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["profile_name"], json!("cli-ok"));

    std::fs::remove_file(&path).ok();
}

/// `service.start` carries `port` / `tensor_parallel_size` as named
/// `Option<u16>` fields (dsl-kit #1 Layer 2 landed in 0.3.0; the
/// frontend registers a `SyntaxOverrides` value production for
/// `Option<u16>` so the canonical text and JSON front-ends both accept
/// them). `expand_service_start` synthesises `--port` / `--tensor-parallel-size`
/// from the named fields — this test proves the JSON front-end round
/// trip end-to-end (parse → validate → dry-run report carries `port`
/// as an integer in the plan payload).
#[test]
fn cli_apply_named_port_field_synthesises_flag_in_launch_argv() {
    let profile = json!({
        "type": "Spec",
        "name": "cli-named-port",
        "capabilities": ["sh.exec"],
        "phases": [
            {
                "type": "ServiceStart",
                "name": "llm",
                "platform_kind": "vllm",
                "model": "meta-llama/Llama-3-8B",
                "port": 9000,
                "tensor_parallel_size": 4
            }
        ]
    });
    let path = write_json_profile("cli-named-port", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is the report JSON");
    let step = &report["steps"].as_array().unwrap()[0];
    let argv = step["argv"].as_array().expect("argv is an array");
    let joined = argv
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    // The named fields land as their own `--port` / `--tensor-parallel-size`
    // flags in the synthesised launch line.
    assert!(
        joined.contains("--port 9000"),
        "named port must synthesise --port flag: {joined}"
    );
    assert!(
        joined.contains("--tensor-parallel-size 4"),
        "named tensor_parallel_size must synthesise its flag: {joined}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn cli_apply_of_missing_profile_is_exit_one_with_nothing_on_stdout() {
    let missing = temp_stem("cli-missing").with_extension("json");
    let _ = std::fs::remove_file(&missing);
    let output = bin()
        .args(["apply", missing.to_str().unwrap(), "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(output.status.code(), Some(1), "missing profile must exit 1");
    assert!(
        output.stdout.is_empty(),
        "nothing printed on a precondition failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("apply failed: "),
        "stderr carries the failure line: {stderr}"
    );
}

#[test]
fn cli_apply_of_lua_profile_is_rejected() {
    // The extension check precedes any I/O, so the path need not exist.
    let output = bin()
        .args(["apply", "/nonexistent/profile.lua", "--dry-run"])
        .output()
        .expect("process runs");
    assert_eq!(output.status.code(), Some(1), "a .lua profile must exit 1");
    assert!(output.stdout.is_empty(), "nothing printed on failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("apply failed: ")
            && stderr.contains("Lua profiles are no longer supported"),
        "stderr must carry the Lua-unsupported failure line: {stderr}"
    );
}

#[test]
fn cli_apply_ast_step_failure_is_exit_one_with_the_error_on_stderr() {
    let profile = json!({
        "type": "Spec",
        "name": "cli-fail",
        "capabilities": ["sh.exec"],
        "phases": [ { "type": "ShExec", "argv": ["sh", "-c", "exit 5"] } ]
    });
    let path = write_json_profile("cli-fail", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_eq!(output.status.code(), Some(1));
    // The report is still printed to stdout (printed on step failure).
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is the report JSON");
    assert_eq!(report["ok"], json!(false));
    // The final error line is echoed to stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("apply failed: step 1_sh.exec (sh.exec) failed:"),
        "stderr carries the final error line: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

/// A phase-`env` `EnvRef` must resolve to the value node the profile
/// declared in `Spec.env` — a literal to its string, a secret through
/// the same host-env / `env_secrets` pipe an inline reference would go
/// through. The audit transcript still redacts what the corresponding
/// inline node would redact (spec 09).
#[test]
fn env_ref_resolves_through_spec_env_and_redacts_correctly() {
    let dir = temp_stem("env-ref");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("out.txt");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "env-ref-demo",
        // The `sh.exec` phase dereferences two `Spec.env` entries, so
        // `env.ref` joins the effects it declares (spec 02
        // §Shared vocabulary).
        "capabilities": ["sh.exec", "fs.write", "env.ref"],
        "paths": [dir_str],
        "env_secrets": ["ENV_REF_SECRET_TOKEN"],
        "env": {
            // A non-sensitive literal shared across phases.
            "SHARED_MODE": { "type": "EnvLiteral", "value": "must-not-appear-anywhere" },
            // A secret whose logical name is sensitive-shaped, so the
            // audit event redacts *and* the resolved value never leaks.
            "SHARED_TOKEN": { "type": "EnvSecret", "name": "ENV_REF_SECRET_TOKEN" }
        },
        "phases": [
            {
                "type": "ShExec",
                "argv": ["true"],
                "env": {
                    "MODE": { "type": "EnvRef", "name": "SHARED_MODE" },
                    "TOKEN": { "type": "EnvRef", "name": "SHARED_TOKEN" }
                }
            },
            { "type": "FsWrite", "path": target.to_string_lossy(), "content": "written" }
        ]
    });
    let path = write_json_profile("env-ref", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        .env(
            "ENV_REF_SECRET_TOKEN",
            "super-secret-token-value-that-must-not-leak",
        )
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Value on either side of the reference must never leak.
    assert!(
        !stderr.contains("super-secret-token-value-that-must-not-leak"),
        "resolved secret must never appear on the audit transcript: {stderr}"
    );
    assert!(
        !stderr.contains("must-not-appear-anywhere"),
        "no env value ever reaches the transcript, sensitive or not: {stderr}"
    );
    // The redaction marker applies to the *slot* key name in the
    // phase's env: `TOKEN` is sensitive-shaped, `MODE` is not.
    assert!(
        stderr.contains("TOKEN [REDACTED]"),
        "sensitive slot name still marks [REDACTED] even when the value is a reference: {stderr}"
    );
    assert!(
        stderr.contains("MODE"),
        "non-sensitive slot name appears verbatim: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// Validate rejects a phase `EnvRef` whose `name` is not declared in
/// `Spec.env` — the CLI surfaces the rejection before any effect runs.
#[test]
fn env_ref_to_an_undeclared_spec_env_key_is_rejected_at_validate() {
    let profile = json!({
        "type": "Spec",
        "name": "env-ref-bad",
        "capabilities": ["sh.exec"],
        "env": {
            "KNOWN": { "type": "EnvLiteral", "value": "yes" }
        },
        "phases": [
            {
                "type": "ShExec",
                "argv": ["true"],
                "env": {
                    "SLOT": { "type": "EnvRef", "name": "UNKNOWN" }
                }
            }
        ]
    });
    let path = write_json_profile("env-ref-bad", &profile);

    let output = bin()
        .args(["validate", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_ne!(output.status.code(), Some(0), "validate must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("UNKNOWN") && stderr.contains("Spec.env"),
        "validate error names the undeclared reference and its intended lookup surface: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Audit transcript on stderr (spec 09 §Audit log).
// ---------------------------------------------------------------------

/// Every effect invocation must emit one structured audit event on
/// stderr, and the event must never carry a secret value even when
/// the phase's env-injection map resolves one.
#[test]
fn apply_emits_a_stderr_audit_event_per_effect_and_never_a_secret_value() {
    let dir = temp_stem("audit-emit");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("out.txt");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "audit-demo",
        "capabilities": ["sh.exec", "fs.write"],
        "paths": [dir_str],
        "env_secrets": ["AUDIT_SECRET_TOKEN"],
        "phases": [
            // The `AUDIT_SECRET_TOKEN` name matches the sensitive-key
            // set, so it must be logged as `[REDACTED]`.
            { "type": "ShExec", "argv": ["true"],
              "env": {
                  "AUDIT_SECRET_TOKEN": { "type": "EnvSecret", "name": "AUDIT_SECRET_TOKEN" },
                  "MODE": { "type": "EnvLiteral", "value": "audit-mode-value" }
              } },
            { "type": "FsWrite", "path": target.to_string_lossy(), "content": "written" }
        ]
    });
    let path = write_json_profile("audit-emit", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        // The secret value must never appear on stderr. Set it to a
        // literal the test can grep for so a leak is unambiguous.
        .env(
            "AUDIT_SECRET_TOKEN",
            "super-secret-value-that-must-not-leak",
        )
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // (a) One audit event per effect.
    let audit_events: Vec<_> = stderr.lines().filter(|l| l.contains("audit")).collect();
    assert!(
        audit_events.len() >= 2,
        "expected at least one audit event per effect (sh.exec + fs.write), got: {stderr}"
    );
    assert!(
        stderr.contains("op=\"sh.exec\"") || stderr.contains("op=sh.exec"),
        "sh.exec event present: {stderr}"
    );
    assert!(
        stderr.contains("op=\"fs.write\"") || stderr.contains("op=fs.write"),
        "fs.write event present: {stderr}"
    );

    // (b) The secret value must never appear anywhere on stderr.
    assert!(
        !stderr.contains("super-secret-value-that-must-not-leak"),
        "secret value must never reach the audit transcript: {stderr}"
    );
    // Non-sensitive env *values* are redacted too (values are never
    // logged, sensitive or not).
    assert!(
        !stderr.contains("audit-mode-value"),
        "no env value ever reaches the transcript, sensitive or not: {stderr}"
    );

    // (c) Sensitive-named env keys are marked `[REDACTED]`; non-
    // sensitive names appear verbatim.
    assert!(
        stderr.contains("AUDIT_SECRET_TOKEN [REDACTED]"),
        "the sensitive-key marker labels a key whose value was withheld: {stderr}"
    );
    assert!(
        stderr.contains("MODE"),
        "a non-sensitive key name is logged: {stderr}"
    );

    // (d) `fs.write` carries the content_source contract (spec 09).
    assert!(
        stderr.contains("content_source=\"string\"") || stderr.contains("content_source=string"),
        "fs.write event carries content_source: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// `fs.write` `content` as a value node (spec 06 consumption point 3):
/// an `EnvSecret` content resolves from the host env and lands on
/// disk, an `EnvRef` content resolves through `Spec.env` — and the
/// audit transcript names the source (`content_source=secret:<name>` /
/// `env_ref:<name>`) without ever carrying the resolved value.
#[test]
fn fs_write_secret_and_ref_content_resolve_and_never_leak_on_the_transcript() {
    let dir = temp_stem("fs-content");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let secret_target = dir.join("token.txt");
    let ref_target = dir.join("conf.txt");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "fs-content-demo",
        // `env.ref` joins `fs.write` because the second phase's content
        // is an `EnvRef`: reading a host environment variable into the
        // written bytes is its own effect (spec 02 §Catalog kinds).
        "capabilities": ["fs.write", "env.ref"],
        "paths": [dir_str],
        "env_secrets": ["FS_CONTENT_SECRET_TOKEN"],
        "env": {
            "SHARED_CONF": { "type": "EnvLiteral", "value": "conf-value-not-logged" }
        },
        "phases": [
            {
                "type": "FsWrite",
                "path": secret_target.to_string_lossy(),
                "content": { "type": "EnvSecret", "name": "FS_CONTENT_SECRET_TOKEN" }
            },
            {
                "type": "FsWrite",
                "path": ref_target.to_string_lossy(),
                "content": { "type": "EnvRef", "name": "SHARED_CONF" }
            }
        ]
    });
    let path = write_json_profile("fs-content", &profile);

    let output = bin()
        .args(["apply", path.to_str().unwrap()])
        .env(
            "FS_CONTENT_SECRET_TOKEN",
            "fs-secret-value-that-must-not-leak",
        )
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The effects ran with the *resolved* content.
    assert_eq!(
        std::fs::read_to_string(&secret_target).expect("secret-content target was written"),
        "fs-secret-value-that-must-not-leak"
    );
    assert_eq!(
        std::fs::read_to_string(&ref_target).expect("ref-content target was written"),
        "conf-value-not-logged"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The audit event names the source, never the value.
    assert!(
        stderr.contains("content_source=\"secret:FS_CONTENT_SECRET_TOKEN\"")
            || stderr.contains("content_source=secret:FS_CONTENT_SECRET_TOKEN"),
        "secret-content event names its source: {stderr}"
    );
    assert!(
        stderr.contains("content_source=\"env_ref:SHARED_CONF\"")
            || stderr.contains("content_source=env_ref:SHARED_CONF"),
        "ref-content event names its source: {stderr}"
    );
    assert!(
        !stderr.contains("fs-secret-value-that-must-not-leak"),
        "resolved secret content must never reach the transcript: {stderr}"
    );
    assert!(
        !stderr.contains("conf-value-not-logged"),
        "resolved literal content must never reach the transcript either: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// Content resolution follows spec 06 §Resolution "dry-run resolves
/// too": a secret content whose host env var is absent fails the dry
/// run identically to a real run — a passing dry run proves the
/// content plumbing.
#[test]
fn fs_write_secret_content_missing_from_the_host_env_fails_the_dry_run() {
    let dir = temp_stem("fs-content-missing");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let dir_str = dir.to_string_lossy().into_owned();

    let profile = json!({
        "type": "Spec",
        "name": "fs-content-missing-demo",
        "capabilities": ["fs.write"],
        "paths": [dir_str],
        "env_secrets": ["FS_CONTENT_NEVER_SET_SECRET"],
        "phases": [
            {
                "type": "FsWrite",
                "path": dir.join("out.txt").to_string_lossy(),
                "content": { "type": "EnvSecret", "name": "FS_CONTENT_NEVER_SET_SECRET" }
            }
        ]
    });
    let path = write_json_profile("fs-content-missing", &profile);

    let output = bin()
        .args(["apply", "--dry-run", path.to_str().unwrap()])
        .env_remove("FS_CONTENT_NEVER_SET_SECRET")
        .output()
        .expect("process runs");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a dry run must fail on an unresolvable secret content"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FS_CONTENT_NEVER_SET_SECRET"),
        "the failure names the logical secret, nothing else: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&path).ok();
}

/// `net.http_post` `headers` / `body` as secret consumption points
/// (spec 06 point 4): a dry run resolves both, and neither the audit
/// transcript on stderr nor the report on stdout carries a resolved
/// header value or any body content — only header *names* (with the
/// sensitive-key `[REDACTED]` marker) and the body's source form plus
/// byte length.
#[test]
fn http_post_secret_header_and_body_never_leak_on_the_transcript_or_report() {
    let profile = json!({
        "type": "Spec",
        "name": "http-secret-demo",
        "capabilities": ["net.http_post"],
        "http_allowlist": ["https://example.com"],
        "env_secrets": ["HTTP_HEADER_TOKEN", "HTTP_BODY_SECRET"],
        "phases": [
            {
                "type": "NetHttpPost",
                "url": "https://example.com/v1/completions",
                "headers": {
                    "Authorization": { "type": "EnvSecret", "name": "HTTP_HEADER_TOKEN" },
                    "Accept": { "type": "EnvLiteral", "value": "accept-value-not-logged" }
                },
                "body": { "type": "EnvSecret", "name": "HTTP_BODY_SECRET" }
            }
        ]
    });
    let path = write_json_profile("http-secret", &profile);

    // Dry-run: resolution runs, the request does not — so no network is
    // touched while the secret plumbing is still proven end to end.
    let output = bin()
        .args(["apply", "--dry-run", path.to_str().unwrap()])
        .env("HTTP_HEADER_TOKEN", "header-token-that-must-not-leak")
        .env("HTTP_BODY_SECRET", "body-secret-that-must-not-leak")
        .output()
        .expect("process runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // (a) No resolved value on either stream, sensitive or not.
    for leaked in [
        "header-token-that-must-not-leak",
        "body-secret-that-must-not-leak",
        "accept-value-not-logged",
    ] {
        assert!(
            !stderr.contains(leaked),
            "{leaked:?} must never reach the audit transcript: {stderr}"
        );
        assert!(
            !stdout.contains(leaked),
            "{leaked:?} must never reach the report: {stdout}"
        );
    }

    // (b) Header names do appear, with the sensitive-key marker on the
    // one whose name matches the set (`AUTH` ⊂ `Authorization`).
    assert!(
        stderr.contains("Authorization [REDACTED]"),
        "a sensitive header name is marked: {stderr}"
    );
    assert!(
        stderr.contains("Accept"),
        "header names are logged: {stderr}"
    );

    // (c) The body is named by its source form + byte length only.
    assert!(
        stderr.contains("body_source=\"body:secret:HTTP_BODY_SECRET\"")
            || stderr.contains("body_source=body:secret:HTTP_BODY_SECRET"),
        "the post event names the body's source: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "body_bytes={}",
            "body-secret-that-must-not-leak".len()
        )),
        "the post event carries the body's byte length: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

/// Validate rejects a `net.http_post` that declares both body forms —
/// the two name different bodies and different content types, so there
/// is nothing to pick between them (spec 04 §`net.http_post`).
#[test]
fn declaring_both_http_body_forms_is_rejected_at_validate() {
    let profile = json!({
        "type": "Spec",
        "name": "http-both-bodies",
        "capabilities": ["net.http_post"],
        "http_allowlist": ["https://example.com"],
        "phases": [
            {
                "type": "NetHttpPost",
                "url": "https://example.com/post",
                "body": "raw",
                "body_json": "{\"k\":1}"
            }
        ]
    });
    let path = write_json_profile("http-both-bodies", &profile);

    let output = bin()
        .args(["validate", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_ne!(output.status.code(), Some(0), "validate must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("body and body_json are mutually exclusive"),
        "validate names the exclusivity rule: {stderr}"
    );

    std::fs::remove_file(&path).ok();
}

/// The plan artifact describes the run apply performs: same phases, same
/// order, same insertions and suppressions (spec 02 §Canonical phase
/// ordering, via `lm_provision::normalize`).
///
/// The fixture is written in an order no stage uses — a direct op first,
/// then the install, a `python.version_check` asserting the default, and
/// `system.apt` last — so a stage that skipped normalization would show
/// it: declaration order, no inserted restart / health pair, and the
/// suppressed check still present.
#[test]
fn the_plan_artifact_and_the_apply_report_run_the_same_phases_in_the_same_order() {
    let profile = json!({
        "type": "Spec",
        "name": "normalized-demo",
        "capabilities": ["sh.exec", "net.http_get"],
        "http_allowlist": ["http://127.0.0.1:8188"],
        "phases": [
            { "type": "ShExec", "argv": ["echo", "last"] },
            { "type": "ComfyUiInstall", "ref_name": "master" },
            { "type": "PythonVersionCheck", "want": "3.12" },
            { "type": "SystemApt", "packages": ["git"] }
        ]
    });
    let path = write_json_profile("normalized", &profile);

    let plan_out = bin()
        .args(["plan", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_eq!(
        plan_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&plan_out.stderr)
    );
    let plan: Value =
        serde_json::from_slice(&plan_out.stdout).expect("plan stdout is the artifact JSON");

    let apply_out = bin()
        .args(["apply", "--dry-run", path.to_str().unwrap()])
        .output()
        .expect("process runs");
    assert_eq!(
        apply_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&apply_out.stderr)
    );
    let report: Value =
        serde_json::from_slice(&apply_out.stdout).expect("apply stdout is the report JSON");

    let expected = vec![
        "system.apt".to_string(),
        "comfyui.install".to_string(),
        "comfyui.restart".to_string(),
        "comfyui.health".to_string(),
        "sh.exec".to_string(),
    ];
    assert_eq!(step_kinds(&plan), expected, "plan: {plan}");
    assert_eq!(step_kinds(&report), expected, "apply report: {report}");

    std::fs::remove_file(&path).ok();
}
