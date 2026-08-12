//! `comfyui_root` as a declared resource, end to end.
//!
//! **This file exists because two earlier stages could not finish their
//! own Done Criteria.** Stage 1's "a `models` entry that is already
//! there is not transferred again" and stage 5's "an entry skipped in
//! sequence is skipped under the fan-out too" were both proved at the
//! `run_step` level and argued structurally at the phase level, because
//! a `models` phase composed its destination under a `/workspace/ComfyUI`
//! that a test cannot create. Once the root is declared, the same claims
//! can be made against a real apply, into a directory the test owns.
//!
//! What is proved here, and nowhere else:
//!
//! - a declared root moves every ComfyUI-relative path with it;
//! - a `models` entry that is already present is skipped **by a real
//!   apply**, not by a unit test of the condition;
//! - the skip survives the fan-out — one entry skipped and one
//!   transferred, in the same parallel phase;
//! - a phase that consumes ComfyUI without installing or assuming it is
//!   rejected by name, at validate and at apply.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// A local server that answers `GET /<name>` with `body`, `serves` times.
///
/// Bodies rather than empty 200s: these tests are about a file being
/// there on the second apply, so something has to land on the first.
fn serving(serves: usize, body: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        for _ in 0..serves {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    (format!("http://{addr}"), handle)
}

/// A directory this process owns, used as the declared ComfyUI root.
///
/// **Only the root is created — not the `models/lora` beneath it.** A
/// declared root has nobody to ship a `models/` tree the way a ComfyUI
/// checkout does, so the transfer makes its own destination directory;
/// that it does is `a_transfer_makes_its_own_destination_directory`.
/// This helper leaving the subdirectory absent is what keeps every test
/// below exercising that.
fn temp_root(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-comfyui-root-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the declared root");
    dir
}

/// The report of a run that was expected to reach the end.
///
/// `run_apply_ast` answers `Ok` with a report whose `ok` is `false` for a
/// failed step, so a bare `expect` proves nothing about the run.
fn expect_ok(report_json: &str) -> Value {
    let report: Value = serde_json::from_str(report_json).expect("report is JSON");
    assert_eq!(report["ok"], json!(true), "the run must succeed: {report}");
    report
}

fn write_profile(label: &str, profile: &Value) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("lm-provision-{label}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(profile).expect("profile encodes"),
    )
    .expect("write profile");
    path
}

/// A profile whose `models` phase downloads `entries` into a root the
/// test owns.
fn models_into(root: &Path, base_url: &str, entries: &[&str]) -> Value {
    let models: Vec<Value> = entries
        .iter()
        .map(|name| json!({ "src": format!("{base_url}/{name}"), "dst": name, "subdir": "lora" }))
        .collect();
    json!({
        "type": "Spec",
        "name": "declared-root",
        "capabilities": ["net.transfer"],
        "paths": [root.to_string_lossy()],
        "http_allowlist": [base_url],
        "assumes": { "comfyui_root": root.to_string_lossy() },
        "phases": [{
            "type": "Models",
            "models_json": serde_json::to_string(&models).expect("models encode"),
        }]
    })
}

fn steps_of(report: &Value) -> &Vec<Value> {
    report["steps"].as_array().expect("steps is an array")
}

fn note_of(step: &Value) -> String {
    step["note"].as_str().unwrap_or_default().to_string()
}

/// **The claim the built-in constant made untestable.** A declared root
/// is where the weights land — not `/workspace/ComfyUI`.
#[tokio::test(flavor = "multi_thread")]
async fn a_declared_root_is_where_the_weights_land() {
    let root = temp_root("lands");
    let (base, server) = serving(1, b"weights");
    let path = write_profile("root-lands", &models_into(&root, &base, &["a.bin"]));

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("a real apply into a declared root reaches the end");
    let _ = server.join();
    let report = expect_ok(&report_json);

    let landed = root.join("models/lora/a.bin");
    assert!(
        landed.exists(),
        "the entry must land under the declared root, not the built-in one: {report}"
    );
    assert_eq!(
        std::fs::read(&landed).expect("read what landed"),
        b"weights"
    );
    assert_eq!(steps_of(&report).len(), 1, "{report}");
    assert!(
        !Path::new("/workspace/ComfyUI/models/lora/a.bin").exists(),
        "nothing may be written under the built-in root"
    );
}

/// **Stage 1's Done Criterion 3, finally end to end.** The second apply
/// of the same profile does not transfer again — proved by a real apply,
/// and by a server that would fail the test if it were asked twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_apply_does_not_fetch_an_entry_that_is_already_there() {
    let root = temp_root("skip");
    // One serve only. A second request would find nothing accepting and
    // fail the transfer, so a skip that did not happen cannot pass.
    let (base, server) = serving(1, b"weights");
    let path = write_profile("root-skip", &models_into(&root, &base, &["a.bin"]));

    let first = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("the first apply reaches the end");
    let _ = server.join();
    let first = expect_ok(&first);
    assert!(
        note_of(&steps_of(&first)[0]).starts_with("not done: "),
        "the first apply transfers, and says the condition did not hold: {first}"
    );

    let second = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("the second apply reaches the end");
    let second = expect_ok(&second);
    let note = note_of(&steps_of(&second)[0]);
    assert!(
        note.starts_with("skipped, already done: "),
        "the second apply must skip and say why: {second}"
    );
    assert!(
        note.contains("=satisfied"),
        "the note carries which part of the condition held: {note}"
    );
}

/// **Stage 5's Done Criterion 8, finally end to end.** One entry present
/// and one absent, in the same fan-out: the present one is skipped and
/// the absent one is transferred, and the report still lists both in
/// declaration order.
#[tokio::test(flavor = "multi_thread")]
async fn a_skip_survives_the_fan_out() {
    let root = temp_root("fanout");
    let present = root.join("models/lora/a.bin");
    std::fs::create_dir_all(present.parent().expect("parent")).expect("seed the subdir");
    std::fs::write(&present, b"already here").expect("seed the present entry");

    // One serve: only `b.bin` may reach the server.
    let (base, server) = serving(1, b"weights");
    let path = write_profile(
        "root-fanout",
        &models_into(&root, &base, &["a.bin", "b.bin"]),
    );

    let report_json = lm_provision::apply::run_apply_ast(&path, false)
        .await
        .expect("the phase reaches the end with one entry skipped");
    let _ = server.join();
    let report = expect_ok(&report_json);

    let steps = steps_of(&report);
    assert_eq!(steps.len(), 2, "{report}");
    assert_eq!(
        steps
            .iter()
            .map(|s| s["id"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["1_models_1", "1_models_2"],
        "the fan-out reports in declaration order, not completion order: {report}"
    );
    assert!(
        note_of(&steps[0]).starts_with("skipped, already done: "),
        "the present entry is skipped under the fan-out: {report}"
    );
    assert!(
        note_of(&steps[1]).starts_with("not done: "),
        "the absent entry is transferred under the same fan-out: {report}"
    );
    assert_eq!(
        std::fs::read(&present).expect("the skipped entry is untouched"),
        b"already here",
        "a skipped transfer must not overwrite what was already there"
    );
    assert_eq!(
        std::fs::read(root.join("models/lora/b.bin")).expect("the transferred entry"),
        b"weights"
    );
}

/// A profile that consumes ComfyUI without installing or assuming it is
/// rejected **by name**, before any effect runs.
///
/// This is the case that used to fail without being named: the run
/// would previously have composed a destination
/// under a root nothing created and failed on the pod with `no such
/// file`.
#[tokio::test(flavor = "multi_thread")]
async fn consuming_comfyui_without_producing_it_is_rejected_by_name() {
    let (base, _server) = serving(0, b"");
    let profile = json!({
        "type": "Spec",
        "name": "unbound",
        "capabilities": ["net.transfer"],
        "paths": ["/workspace/ComfyUI/models"],
        "http_allowlist": [base],
        "phases": [{
            "type": "Models",
            "models_json": format!(r#"[{{"src":"{base}/a.bin","dst":"a.bin"}}]"#),
        }]
    });
    let path = write_profile("root-unbound", &profile);

    let report_json = lm_provision::apply::run_apply_ast(&path, true)
        .await
        .expect("a failed step still produces a report");
    let report: Value = serde_json::from_str(&report_json).expect("report is JSON");
    assert_eq!(report["ok"], json!(false), "{report}");
    let message = report["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("comfyui_root"),
        "the failure names the resource, not a missing directory: {message}"
    );

    // And validate says the same thing before anything runs, which is
    // where an author meets it.
    let err = lm_provision::cli::ast_validate(&path).expect_err("validate rejects the profile");
    let message = err.to_string();
    assert!(
        message.contains("comfyui_root") && message.contains("models"),
        "validate names the phase and the resource: {message}"
    );
}

/// **A transfer makes the directory it is about to write into.**
///
/// Under the built-in root this never showed: a ComfyUI checkout ships a
/// `models/` tree, so the destination's parent happened to exist. A
/// declared root has nobody to ship one, and a `models` entry naming a
/// subdirectory ComfyUI does not create (`lora` beside the `checkpoints`
/// that is there) has the same gap. Failing would report `No such file
/// or directory` on a path the author never wrote, for a directory that
/// carries no decision — the transfer knows exactly where it is going.
///
/// The path has already been through the L3 path policy by the time it
/// gets here, so this cannot make a directory outside `paths`; that it
/// cannot is `exec_integration`'s policy coverage, not this test's.
#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_makes_its_own_destination_directory() {
    let root = temp_root("mkdir");
    let nested = root.join("models/deeply/nested/subdir");
    assert!(!nested.exists(), "the fixture starts without the tree");

    let (base, server) = serving(1, b"weights");
    let models =
        format!(r#"[{{"src":"{base}/w.bin","dst":"w.bin","subdir":"deeply/nested/subdir"}}]"#);
    let profile = json!({
        "type": "Spec",
        "name": "mkdir-dst",
        "capabilities": ["net.transfer"],
        "paths": [root.to_string_lossy()],
        "http_allowlist": [base],
        "assumes": { "comfyui_root": root.to_string_lossy() },
        "phases": [{ "type": "Models", "models_json": models }]
    });
    let path = write_profile("root-mkdir", &profile);

    let report = expect_ok(
        &lm_provision::apply::run_apply_ast(&path, false)
            .await
            .expect("the apply reaches the end"),
    );
    let _ = server.join();

    assert_eq!(
        std::fs::read(nested.join("w.bin")).expect("the entry landed"),
        b"weights",
        "{report}"
    );
}
