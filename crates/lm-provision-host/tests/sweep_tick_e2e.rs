//! End-to-end for one tick: a real child process, spawned from a real
//! [`Config`], read back through the health document.
//!
//! The child is a stub `lm-provision` — a shell script that
//! records the argv it was handed, says something on stderr, and
//! prints a canned sweep artifact. Two things are being tested that no
//! unit test can reach: that the daemon's flags survive the trip
//! through an actual `exec`, and that what comes back off the child's
//! stdout is what the health endpoint hands its reader.
//!
//! Unix-only, like the driver's own end-to-end tests: the workspace
//! has never been built for Windows, and a `#!` script is the shortest
//! stub that is a real process.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;

use lm_provision_host::{health_body, Config, SharedStatus, Status};

/// A directory nothing else in this run will pick — the driver's
/// end-to-end tests derive theirs the same way, and for the same
/// reason: tests share `/tmp` with each other and with whatever else
/// is on the machine.
fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-host-e2e-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the temp directory is writable");
    dir
}

/// Write an executable stub driver whose body is `script`, and give
/// back the path the daemon will run it by.
fn stub_driver(dir: &std::path::Path, script: &str) -> PathBuf {
    let path = dir.join("lm-provision");
    std::fs::write(&path, script).expect("the stub is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub is made executable");
    path
}

fn state() -> SharedStatus {
    Arc::new(tokio::sync::Mutex::new(Status::started(
        "2026-09-01T00:00:00Z".to_string(),
    )))
}

/// Held while a test writes a stub driver and then runs it.
///
/// **`ETXTBSY`: the kernel refuses to exec a file some process has
/// open for writing, and a forked child holds its parent's descriptors
/// until it execs.** Every test here writes its stub and spawns it,
/// and cargo runs them on parallel threads of one process — so one
/// test's spawn can inherit another's still-open write descriptor and
/// hold the file busy for exactly as long as it takes to exec. The
/// driver's end-to-end suites lose runs to this; these have not been
/// caught by it, and carry the same lock because they do the same two
/// things [measured: 2026-09-01, `Text file busy` out of `session_e2e`
/// and `driver_e2e`, never yet out of this file].
///
/// A tokio mutex, not a `std` one: the guard is held across the
/// `tick().await` that does the spawning.
static STAGE_AND_RUN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The document the endpoint would return right now, read the way the
/// endpoint reads it.
async fn health_of(config: &Config, state: &SharedStatus) -> serde_json::Value {
    let status = state.lock().await;
    serde_json::from_str(&health_body(config, &status)).expect("the health body is JSON")
}

#[tokio::test]
async fn one_tick_runs_the_driver_and_publishes_what_it_said() {
    let _guard = STAGE_AND_RUN.lock().await;
    let dir = unique_dir("good");
    let argv_log = dir.join("argv");
    let driver = stub_driver(
        &dir,
        &format!(
            "#!/bin/sh\n\
             echo \"$@\" > {argv_log}\n\
             echo 'note: released pod-a' >&2\n\
             echo '{artifact}'\n",
            argv_log = argv_log.display(),
            artifact = r#"{"dry_run":false,"expired":2,"released":["pod-a"],"refused":[{"id":"pod-b","reason":"the newest apply left out.bin on the machine"}],"failed":[]}"#,
        ),
    );

    let config = Config {
        interval_secs: 1,
        driver,
        providers: vec!["runpod".to_string()],
        acquisitions: Some(dir.join("acquisitions.jsonl")),
        ledger: Some(dir.join("ledger.jsonl")),
        dry_run: false,
    };
    let state = state();
    lm_provision_host::tick(&config, &state).await;

    let argv = std::fs::read_to_string(&argv_log).expect("the stub recorded its argv");
    assert_eq!(
        argv.trim(),
        format!(
            "machine sweep --dry-run false --provider runpod --acquisitions {} --ledger {}",
            dir.join("acquisitions.jsonl").display(),
            dir.join("ledger.jsonl").display()
        ),
        "the subcommand, the enforcing default said out loud, the platform to ask, \
         and both paths verbatim"
    );

    let doc = health_of(&config, &state).await;
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["ticks"], 1);
    assert_eq!(doc["dry_run"], false);
    assert_eq!(doc["last_tick_ok"], true);
    assert!(doc.get("last_tick_error").is_none());
    assert_eq!(
        doc["last_artifact"]["expired"], 2,
        "the artifact is the child's own document, carried through whole"
    );
    assert_eq!(doc["last_artifact"]["released"][0], "pod-a");
    assert_eq!(doc["last_artifact"]["refused"][0]["id"], "pod-b");
    assert!(
        doc["last_tick_at"].is_string(),
        "a finished tick is stamped: {doc}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A sweep that exits non-zero is a machine that expired and is still
/// billing. The tick is recorded as failed with the reason, the daemon
/// is still here to try again, and the health document says `ok:
/// false` — which is the whole reason it exists.
#[tokio::test]
async fn a_failing_driver_becomes_a_failed_tick_not_a_dead_daemon() {
    let _guard = STAGE_AND_RUN.lock().await;
    let dir = unique_dir("failing");
    let driver = stub_driver(
        &dir,
        "#!/bin/sh\necho 'error: no credential for pod-a' >&2\nexit 1\n",
    );
    let config = Config {
        interval_secs: 1,
        driver,
        providers: Vec::new(),
        acquisitions: None,
        ledger: None,
        dry_run: false,
    };
    let state = state();
    lm_provision_host::tick(&config, &state).await;

    let doc = health_of(&config, &state).await;
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["ticks"], 1);
    assert_eq!(doc["last_tick_ok"], false);
    assert!(
        doc["last_tick_error"]
            .as_str()
            .is_some_and(|it| it.contains("exited with")),
        "the reason names how the sweep ended: {doc}"
    );
    assert!(
        doc.get("last_artifact").is_none(),
        "a failed sweep leaves no artifact to mistake for a healthy one"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A driver that is not there at all — the misspelled `--driver`, the
/// binary not yet on `PATH`. Same shape: recorded, reported, survived.
#[tokio::test]
async fn a_missing_driver_is_reported_rather_than_fatal() {
    let _guard = STAGE_AND_RUN.lock().await;
    let dir = unique_dir("missing");
    let config = Config {
        interval_secs: 1,
        driver: dir.join("not-installed"),
        providers: Vec::new(),
        acquisitions: None,
        ledger: None,
        dry_run: false,
    };
    let state = state();
    lm_provision_host::tick(&config, &state).await;
    // Twice, because the point is that the first failure did not end
    // the loop the daemon runs this in.
    lm_provision_host::tick(&config, &state).await;

    let doc = health_of(&config, &state).await;
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["ticks"], 2);
    assert!(
        doc["last_tick_error"]
            .as_str()
            .is_some_and(|it| it.contains("could not run")),
        "the reason names the binary that could not be run: {doc}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
