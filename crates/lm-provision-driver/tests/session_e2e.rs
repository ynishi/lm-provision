//! Session-contract end-to-end regression (08-push-driver-protocol.md
//! §Session steps): [`lm_provision_driver::session::run`] driving the
//! real Phase F binary through [`LocalExecTransport`], exercising the
//! per-step gates, the operator-side secret preflight, the
//! ensure-binary idempotency rule, and the ledger duty.
//!
//! Binary location mirrors `driver_e2e.rs` (same-workspace target dir
//! derivation).

use std::path::PathBuf;

use lm_provision_driver::ledger;
use lm_provision_driver::local_exec::LocalExecTransport;
use lm_provision_driver::session::{self, InvokeMode, SessionError, StepPlan};
use lm_provision_driver::transport::Transport as _;

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
        "expected the lm-provision binary at {} (build the whole workspace)",
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
        "lm-provision-driver-session-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

#[test]
fn session_dry_run_collects_a_report_and_appends_one_ledger_row() {
    let staging = unique_dir("dry-run");
    let ledger_path = staging.join("ledger.jsonl");
    let transport = LocalExecTransport::new(&staging);
    let plan = StepPlan {
        mode: InvokeMode::DryRun,
        ledger: Some(ledger_path.clone()),
        ..StepPlan::default()
    };

    // The fixture consumes DRIVER_TEST_TOKEN (dry-run resolves too).
    std::env::set_var("DRIVER_TEST_TOKEN", "session-e2e-value");
    let output = session::run(
        &transport,
        &plan,
        &lm_provision_bin(),
        &fixture("apply-secret.json"),
        "pod-session-e2e",
    )
    .expect("dry-run session should complete");

    assert_eq!(output.collected.report["ok"], serde_json::json!(true));
    assert_eq!(output.collected.report["dry_run"], serde_json::json!(true));
    assert_eq!(output.collected.exit_code, Some(0));
    assert!(output.ledger_appended);

    let rows = ledger::list(&ledger_path).expect("ledger reads back");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pod_id, "pod-session-e2e");
    assert_eq!(rows[0].profile_hash, output.collected.profile_hash);
    // The resolved secret value never lands in the ledger row.
    let row_json = serde_json::to_string(&rows[0]).expect("row serializes");
    assert!(!row_json.contains("session-e2e-value"));

    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn missing_secret_fails_before_any_transfer() {
    let staging = unique_dir("missing-secret");
    let transport = LocalExecTransport::new(&staging);
    let plan = StepPlan::default(); // Apply mode consumes secrets.

    std::env::remove_var("SESSION_NEVER_SET_TOKEN");
    // A copy of the fixture whose secret name is guaranteed unset (the
    // shared fixture's name is set by the sibling test in-process).
    let profile_dir = unique_dir("missing-secret-profile");
    std::fs::create_dir_all(&profile_dir).expect("profile dir");
    let profile = profile_dir.join("needs-unset-secret.json");
    std::fs::write(
        &profile,
        serde_json::json!({
            "type": "Spec",
            "name": "needs-unset-secret",
            "capabilities": ["sh.exec"],
            "env_secrets": ["SESSION_NEVER_SET_TOKEN"],
            "phases": [
                { "type": "ShExec", "argv": ["true"],
                  "env": { "T": { "type": "EnvSecret", "name": "SESSION_NEVER_SET_TOKEN" } } }
            ]
        })
        .to_string(),
    )
    .expect("write profile");

    let err = session::run(
        &transport,
        &plan,
        &lm_provision_bin(),
        &profile,
        "pod-missing-secret",
    )
    .expect_err("a missing secret must fail the session");
    assert!(matches!(err, SessionError::SecretMissing(name) if name == "SESSION_NEVER_SET_TOKEN"));
    // Preflight fired before any transport call: nothing was staged.
    assert!(
        !staging.exists(),
        "no staging directory should exist after a preflight failure"
    );

    std::fs::remove_dir_all(&profile_dir).ok();
}

#[test]
fn validate_only_consumes_no_secret_and_writes_no_ledger_row() {
    let staging = unique_dir("validate-only");
    let ledger_path = staging.join("ledger.jsonl");
    let transport = LocalExecTransport::new(&staging);
    let plan = StepPlan {
        mode: InvokeMode::ValidateOnly,
        ledger: Some(ledger_path.clone()),
        ..StepPlan::default()
    };

    // The fixture names a secret, but validate-only never consumes it
    // — leave whatever in-process state alone and use a name that is
    // definitely unset in a fresh profile copy.
    let profile_dir = unique_dir("validate-only-profile");
    std::fs::create_dir_all(&profile_dir).expect("profile dir");
    let profile = profile_dir.join("validate-only.json");
    std::fs::write(
        &profile,
        serde_json::json!({
            "type": "Spec",
            "name": "validate-only",
            "capabilities": ["sh.exec"],
            "env_secrets": ["SESSION_VALIDATE_ONLY_UNSET_TOKEN"],
            "phases": [
                { "type": "ShExec", "argv": ["true"],
                  "env": { "T": { "type": "EnvSecret",
                                   "name": "SESSION_VALIDATE_ONLY_UNSET_TOKEN" } } }
            ]
        })
        .to_string(),
    )
    .expect("write profile");
    std::env::remove_var("SESSION_VALIDATE_ONLY_UNSET_TOKEN");

    let output = session::run(
        &transport,
        &plan,
        &lm_provision_bin(),
        &profile,
        "pod-validate-only",
    )
    .expect("validate-only session should complete without the secret");

    assert_eq!(output.collected.report["ok"], serde_json::json!(true));
    assert!(!output.ledger_appended, "validate-only records no apply");
    assert!(!ledger_path.exists());

    std::fs::remove_dir_all(&staging).ok();
    std::fs::remove_dir_all(&profile_dir).ok();
}

#[test]
fn skip_install_without_a_binary_on_the_pod_fails_as_a_precondition() {
    let staging = unique_dir("skip-install");
    let transport = LocalExecTransport::new(&staging);
    let plan = StepPlan {
        skip_install: true,
        mode: InvokeMode::ValidateOnly,
        ledger: None,
        ..StepPlan::default()
    };

    let err = session::run(
        &transport,
        &plan,
        &lm_provision_bin(),
        &fixture("apply-secret.json"),
        "pod-skip-install",
    )
    .expect_err("skip-install with no staged binary must fail, not silently pass");
    // The gate is a declaration, not a promise (08 §Session steps):
    // the missing postcondition surfaces at the first exec against
    // the derived path — as a transport spawn failure on this
    // transport.
    assert!(
        matches!(
            err,
            SessionError::Transport(_) | SessionError::RemoteHash { .. }
        ),
        "expected the missing-binary precondition surface, got: {err:?}"
    );

    std::fs::remove_dir_all(&staging).ok();
}

#[test]
fn ensure_binary_re_run_converges_without_re_transfer_and_repairs_drift() {
    let staging = unique_dir("idempotent");
    let transport = LocalExecTransport::new(&staging);
    let binary = lm_provision_bin();

    let staged = transport.ensure_binary(&binary).expect("first ensure");
    let first_mtime = std::fs::metadata(&staged)
        .expect("staged metadata")
        .modified()
        .expect("mtime");

    // Identical content: the second ensure must be a no-op (08
    // §Session steps: "identical → no-op ... re-convergence, not
    // re-transfer").
    let staged_again = transport.ensure_binary(&binary).expect("second ensure");
    assert_eq!(staged, staged_again);
    let second_mtime = std::fs::metadata(&staged)
        .expect("staged metadata")
        .modified()
        .expect("mtime");
    assert_eq!(first_mtime, second_mtime, "no copy on identical content");

    // Drifted content: ensure repairs it back to the artifact bytes.
    std::fs::write(&staged, b"tampered").expect("tamper staged copy");
    transport.ensure_binary(&binary).expect("repair ensure");
    let repaired = std::fs::read(&staged).expect("read repaired");
    let original = std::fs::read(&binary).expect("read original");
    assert_eq!(repaired, original, "drifted copy must be re-pushed");

    std::fs::remove_dir_all(&staging).ok();
}
