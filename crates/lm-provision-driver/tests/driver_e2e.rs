//! M5-1/M5-2 end-to-end regression: [`LocalExecTransport`] driving the
//! real Phase F `lm-provision` binary through the full upload → hash
//! integrity check → invoke → collect sequence
//! (08-push-driver-protocol.md), followed by an append-only ledger
//! round trip (09-apply-report-and-ledger.md §Ledger).
//!
//! Locating the binary: `CARGO_BIN_EXE_<name>` is only guaranteed by
//! Cargo for a bin target belonging to the *same* package as the
//! integration test being compiled (`lm-provision`, not
//! `lm-provision-driver`); it is checked first anyway as a zero-cost
//! attempt, but the reliable path derives the binary's location from
//! this test binary's own `current_exe()` — every workspace member's
//! build artifacts land under the same `target/<profile>/` directory
//! (one Cargo workspace, 08 §Inputs "Build shape"), so popping the test
//! binary's `deps/` and profile-directory components off finds it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lm_provision_driver::ledger::{self, LedgerRow};
use lm_provision_driver::local_exec::LocalExecTransport;
use lm_provision_driver::{driver, transport::Transport as _};

fn lm_provision_bin() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_lm-provision") {
        return PathBuf::from(path);
    }
    let mut exe = std::env::current_exe().expect("current test executable path");
    exe.pop(); // target/<profile>/deps/
    exe.pop(); // target/<profile>/
    exe.push(if cfg!(windows) {
        "lm-provision.exe"
    } else {
        "lm-provision"
    });
    assert!(
        exe.exists(),
        "expected the lm-provision binary at {}; this test assumes `cargo test --workspace` \
         (or another invocation that builds every workspace member) built it alongside this \
         crate's own tests",
        exe.display()
    );
    exe
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn unique_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lm-provision-driver-e2e-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

fn step_ops(report: &serde_json::Value) -> Vec<&str> {
    report["steps"]
        .as_array()
        .expect("steps should be an array")
        .iter()
        .map(|step| step["op"].as_str().expect("step.op should be a string"))
        .collect()
}

#[test]
fn apply_dry_run_via_local_exec_transport_collects_a_report_with_secret_env_injected() {
    let binary = lm_provision_bin();
    let profile = fixture("apply-secret.lua");

    let local_hash =
        driver::hash_locally(&binary, &profile).expect("local hash subcommand should succeed");
    assert_eq!(local_hash.len(), 64, "sha256 hex digest: {local_hash}");
    assert!(
        local_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "hash: {local_hash}"
    );

    let staging = unique_dir("secret-staging");
    let transport = LocalExecTransport::new(&staging);

    let mut env_secrets = BTreeMap::new();
    env_secrets.insert(
        "DRIVER_TEST_TOKEN".to_string(),
        "super-secret-value".to_string(),
    );

    let collected = driver::run(
        &transport,
        &binary,
        &profile,
        &local_hash,
        &env_secrets,
        true,
    )
    .expect("driver::run should collect a report end to end");

    assert_eq!(collected.profile_hash, local_hash);
    assert_eq!(collected.exit_code, Some(0));
    assert_eq!(collected.report["ok"], serde_json::json!(true));
    assert_eq!(collected.report["dry_run"], serde_json::json!(true));
    assert_eq!(
        collected.report["profile_name"],
        serde_json::json!("demo-driver-apply-secret")
    );
    let ops = step_ops(&collected.report);
    assert!(ops.contains(&"fs.write"), "ops: {ops:?}");
    for step in collected.report["steps"].as_array().unwrap() {
        assert_eq!(
            step["ok"],
            serde_json::json!(true),
            "step failed (likely the exported secret env var was not visible to the child \
             process): {step}"
        );
    }

    // --- ledger round trip (09 §Ledger) ---------------------------------
    let ledger_path = unique_dir("secret-ledger").with_extension("jsonl");
    let first_row = LedgerRow {
        pod_id: "test-pod-1".to_string(),
        profile_hash: collected.profile_hash.clone(),
        report: collected.report.clone(),
        collected_at: collected.collected_at.clone(),
    };
    ledger::append(&ledger_path, &first_row).expect("append should succeed");

    let rows = ledger::list(&ledger_path).expect("list should succeed");
    assert_eq!(rows, vec![first_row.clone()]);

    // A re-apply against the same pod re-appends rather than replacing —
    // 09 §Ledger: "(pod_id, profile_hash) is deliberately not unique".
    let second_row = LedgerRow {
        pod_id: "test-pod-1".to_string(),
        ..first_row.clone()
    };
    ledger::append(&ledger_path, &second_row).expect("re-apply append should succeed");

    let rows = ledger::list(&ledger_path).expect("list should succeed");
    assert_eq!(rows.len(), 2, "re-apply must add a row, not replace one");
    assert_eq!(
        ledger::get(&ledger_path, 0).expect("get 0"),
        Some(second_row),
        "newest row is index 0"
    );
    assert_eq!(
        ledger::get(&ledger_path, 1).expect("get 1"),
        Some(first_row),
        "oldest row is index 1"
    );

    std::fs::remove_dir_all(&staging).ok();
    std::fs::remove_file(&ledger_path).ok();
}

#[test]
fn apply_failing_step_report_is_collected_as_a_richer_signal_not_a_driver_error() {
    let binary = lm_provision_bin();
    let profile = fixture("apply-failing.lua");

    let local_hash =
        driver::hash_locally(&binary, &profile).expect("local hash subcommand should succeed");

    let staging = unique_dir("failing-staging");
    let transport = LocalExecTransport::new(&staging);

    let collected = driver::run(
        &transport,
        &binary,
        &profile,
        &local_hash,
        &BTreeMap::new(),
        true,
    )
    .expect(
        "08 §Error surface: exit 1 + a parseable report is a richer signal than the exit code \
         alone, not a driver-side error",
    );

    assert_eq!(collected.exit_code, Some(1));
    assert_eq!(collected.report["ok"], serde_json::json!(false));
    assert!(
        collected.report["error"]
            .as_str()
            .expect("error field should be a string")
            .contains("sh.exec"),
        "report: {}",
        collected.report
    );

    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn upload_stages_a_real_binary_and_profile_that_can_be_re_hashed_on_the_pod() {
    let binary = lm_provision_bin();
    let profile = fixture("apply-secret.lua");
    let local_hash =
        driver::hash_locally(&binary, &profile).expect("local hash subcommand should succeed");

    let staging = unique_dir("upload-only-staging");
    let transport = LocalExecTransport::new(&staging);
    let paths = transport
        .upload(&binary, &profile)
        .expect("upload should succeed");

    assert!(paths.binary.exists());
    assert!(paths.profile.exists());
    // Re-hashing the staged copy through the staged binary itself must
    // reproduce the same digest (08 §Driver steps: "identical
    // artifacts").
    let staged_hash = driver::hash_locally(&paths.binary, &paths.profile)
        .expect("hash subcommand should succeed against the staged copies");
    assert_eq!(staged_hash, local_hash);

    std::fs::remove_dir_all(&staging).ok();
}
