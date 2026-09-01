//! End-to-end for provider-as-truth sweeping (08 §Acquisitions and
//! sweep): the real `lm-provision-driver sweep`, run as a process,
//! against a stub platform CLI that answers `pods list-pods` with a
//! canned fleet and records every argv it is handed.
//!
//! The stub is reached the way the real one is — by name, off `PATH` —
//! so nothing in the driver is overridden for the test. What that
//! covers and no unit test can: that the listing argv the adapter
//! renders is the one that runs, that the lease is read off the
//! machine's own name rather than out of the record, that an unstamped
//! machine survives an enforcing sweep, and that the delete lands on
//! exactly the expired one.
//!
//! Unix-only, like this crate's other end-to-end tests: the workspace
//! has never been built for Windows, and a `#!` script is the shortest
//! stub that is a real process.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use lm_provision_driver::acquisition::{self as record, AcquisitionRow};

/// The driver binary. `CARGO_BIN_EXE_<name>` is guaranteed here: the
/// bin target belongs to this package.
fn driver() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lm-provision-driver"))
}

fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-driver-sweep-e2e-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the temp directory is writable");
    dir
}

/// Far enough either side of any clock this ever runs on that the two
/// leases below need no arithmetic to be over and not over.
const LONG_EXPIRED: &str = "lmp-exp-20200101T000000Z";
const LONG_LIVE: &str = "lmp-exp-20990101T000000Z";

/// What the platform answers a listing with, in the shape this one
/// prints: the rows wrapped in an object, each naming its machine and
/// whatever it is called.
fn fleet(pods: &[(&str, &str)]) -> String {
    let rows: Vec<serde_json::Value> = pods
        .iter()
        .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
        .collect();
    serde_json::json!({ "pods": rows }).to_string()
}

/// Write a stub `runpod-cli` into `dir`: it appends every invocation to
/// `dir/argv`, answers a listing with `fleet`, and says nothing much
/// about anything else — which is what a delete returns.
fn stub_platform_cli(dir: &Path, fleet: &str) {
    let path = dir.join("runpod-cli");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             echo \"$@\" >> {argv}\n\
             for arg in \"$@\"; do\n\
             \x20 if [ \"$arg\" = list-pods ]; then\n\
             \x20   echo '{fleet}'\n\
             \x20   exit 0\n\
             \x20 fi\n\
             done\n\
             echo '\"\"'\n",
            argv = dir.join("argv").display(),
        ),
    )
    .expect("the stub is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub is made executable");
}

/// Every argv the stub was handed, one per line.
fn stub_calls(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("argv")).unwrap_or_default()
}

fn acquired(id: &str, expires_at: &str) -> AcquisitionRow {
    AcquisitionRow {
        id: id.to_string(),
        provider: "runpod".to_string(),
        acquired_at: "2026-09-01T00:00:00Z".to_string(),
        expires_at: expires_at.to_string(),
        profile_hash: "h".repeat(64),
        release: vec![
            "runpod-cli".to_string(),
            "pods".to_string(),
            "delete-pod".to_string(),
            "{id}".to_string(),
        ],
        released_at: None,
    }
}

/// Run `sweep` with the stub ahead of everything on `PATH`.
///
/// `HOME` is moved into the scratch directory so the run cannot read
/// the operator's own record, ledger or `.env`; the credential is
/// exported because listing a platform needs one even under
/// `--dry-run`.
fn sweep(dir: &Path, args: &[&str]) -> serde_json::Value {
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = std::process::Command::new(driver())
        .arg("sweep")
        .args(args)
        .env("PATH", path)
        .env("HOME", dir)
        .env("RUNPOD_API_KEY", "test-key-not-a-real-one")
        .output()
        .expect("the driver binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "the sweep exited {}: {stderr}",
        output.status
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "07 §Stream split gives stdout one machine-readable document: {err}\n\
             stdout: {}\nstderr: {stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// **The platform's list is the inventory, and nothing was written
/// down.** No acquisitions record exists at all here: every machine the
/// sweep judges, it judges from the name the platform reports.
#[test]
fn a_dry_run_judges_the_platforms_own_list_with_no_record_at_all() {
    let dir = unique_dir("dry-run");
    stub_platform_cli(
        &dir,
        &fleet(&[
            ("pod-expired", LONG_EXPIRED),
            ("pod-live", LONG_LIVE),
            ("pod-someone-elses", "jupyter-scratch"),
        ]),
    );

    let artifact = sweep(
        &dir,
        &[
            "--provider",
            "runpod",
            "--dry-run",
            "true",
            "--acquisitions",
            &dir.join("acquisitions.jsonl").display().to_string(),
            "--ledger",
            &dir.join("ledger.jsonl").display().to_string(),
        ],
    );

    assert_eq!(artifact["dry_run"], serde_json::json!(true));
    assert_eq!(artifact["expired"], serde_json::json!(1));
    assert_eq!(artifact["released"], serde_json::json!(["pod-expired"]));
    assert_eq!(
        artifact["unknown"],
        serde_json::json!([{ "id": "pod-someone-elses", "name_or_label": "jupyter-scratch" }]),
        "a machine this tool did not name is reported, never released: {artifact}"
    );
    assert_eq!(artifact["failed"], serde_json::json!([]));

    let calls = stub_calls(&dir);
    assert!(
        calls.contains("pods list-pods -o json"),
        "the adapter's own listing argv is what ran: {calls}"
    );
    assert!(
        !calls.contains("delete-pod"),
        "a dry run names what would go and destroys nothing: {calls}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **The enforcing run**: the expired machine is deleted through the
/// same release argv the record carries, the audit trail catches up
/// with a correction, the live one and the unstamped one are left
/// alone, and an outstanding row for a machine the platform does not
/// list is retired without a release call being spent on it.
#[test]
fn an_enforcing_sweep_deletes_the_expired_machine_and_corrects_the_record() {
    let dir = unique_dir("enforcing");
    stub_platform_cli(
        &dir,
        &fleet(&[
            ("pod-expired", LONG_EXPIRED),
            ("pod-live", LONG_LIVE),
            ("pod-old", "hand-made"),
        ]),
    );

    // Two rows: the machine the platform lists as expired, and one the
    // platform does not list at all.
    let acquisitions = dir.join("acquisitions.jsonl");
    record::append(
        &acquisitions,
        &acquired("pod-expired", "2036-01-01T00:00:00Z"),
    )
    .expect("seed the expired machine's row");
    record::append(&acquisitions, &acquired("pod-gone", "2036-01-01T00:00:00Z"))
        .expect("seed a row for a machine nobody can find");

    let artifact = sweep(
        &dir,
        &[
            "--provider",
            "runpod",
            "--dry-run",
            "false",
            "--acquisitions",
            &acquisitions.display().to_string(),
            "--ledger",
            &dir.join("ledger.jsonl").display().to_string(),
        ],
    );

    assert_eq!(artifact["dry_run"], serde_json::json!(false));
    assert_eq!(
        artifact["released"],
        serde_json::json!(["pod-expired"]),
        "the row's lease says 2036 and the machine's own name says 2020; \
         the machine is what is billing: {artifact}"
    );
    assert_eq!(artifact["failed"], serde_json::json!([]));
    assert_eq!(
        artifact["unknown"],
        serde_json::json!([{ "id": "pod-old", "name_or_label": "hand-made" }])
    );

    let calls = stub_calls(&dir);
    assert!(
        calls.contains("pods delete-pod pod-expired"),
        "the delete lands on the machine whose stamp ran out: {calls}"
    );
    assert!(
        !calls.contains("pod-live") && !calls.contains("pod-old") && !calls.contains("pod-gone"),
        "nothing else was touched: {calls}"
    );

    assert!(
        record::outstanding(&acquisitions)
            .expect("the record reads back")
            .is_empty(),
        "the released machine and the one that was already gone are both retired: {:?}",
        record::list(&acquisitions).expect("the record reads back")
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **A platform that cannot be listed is a failed tick, not a crash.**
/// The sweep still emits its one artifact, the plane appears in
/// `failed` under its own name, and the exit is non-zero because
/// whatever is on that account is billing with nothing able to stop it.
#[test]
fn a_platform_that_cannot_be_listed_is_reported_and_costs_the_zero_exit() {
    let dir = unique_dir("unlistable");
    let path = dir.join("runpod-cli");
    std::fs::write(&path, "#!/bin/sh\necho 'error: unauthorized' >&2\nexit 1\n")
        .expect("the stub is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub is made executable");

    let output = std::process::Command::new(driver())
        .args([
            "sweep",
            "--provider",
            "runpod",
            "--dry-run",
            "false",
            "--acquisitions",
            &dir.join("acquisitions.jsonl").display().to_string(),
            "--ledger",
            &dir.join("ledger.jsonl").display().to_string(),
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", &dir)
        .env("RUNPOD_API_KEY", "test-key-not-a-real-one")
        .output()
        .expect("the driver binary runs");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a plane nobody could read may be billing for anything"
    );
    let artifact: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the artifact is still the one document");
    assert_eq!(artifact["failed"][0]["id"], serde_json::json!("runpod"));
    assert!(
        artifact["failed"][0]["reason"]
            .as_str()
            .is_some_and(|it| it.contains("list-pods")),
        "the reason names what could not be run: {artifact}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
