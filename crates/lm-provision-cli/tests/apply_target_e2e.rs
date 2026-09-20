//! End-to-end for the second way an operator names a pod: `--provider
//! <name> --pod-id <id>` instead of an address (08 §Session contract
//! `ConnectionSpec`). The real `lm-provision apply` runs as a process
//! against a stub platform CLI, a stub `ssh` and a stub `scp`, all
//! reached the way the real ones are — by name, off `PATH` — so
//! nothing in the driver is overridden for the test.
//!
//! What that covers and no unit test can: that the address and port
//! the platform reported are the ones `ssh` is dialed with, that the
//! identity file may arrive as an environment variable rather than a
//! flag, that the session's connections are shared, and that a
//! machine with no address yet is refused before anything is dialed.
//!
//! Unix-only, like this crate's other end-to-end tests: the workspace
//! has never been built for Windows, and a `#!` script is the shortest
//! stub that is a real process.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

mod common;

/// The operator CLI, built by cargo for this package.
fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lm-provision"))
}

/// A profile the driver crate's own suites apply — reused rather than
/// re-written, so there is one tiny valid profile in the workspace and
/// not one per test file.
///
/// It declares a secret, which costs this suite nothing: a
/// `--validate-only` session resolves none (08 §Session contract —
/// validate consumes no secrets), so the run needs nothing in its
/// environment that the session's own target resolution did not put
/// there.
fn profile() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lm-provision-driver/tests/fixtures/apply-secret.json")
}

fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-cli-apply-target-e2e-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the temp directory is writable");
    dir
}

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).expect("the stub is writable");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub is made executable");
}

/// A stub `runpod-cli` answering `get-pod` with `described` — the
/// shape a read-back has, which is where the address lives.
fn stub_platform_cli(dir: &Path, described: &str) {
    executable(
        &dir.join("runpod-cli"),
        &format!(
            "#!/bin/sh\n\
             echo \"$@\" >> {argv}\n\
             for arg in \"$@\"; do\n\
             \x20 if [ \"$arg\" = get-pod ]; then\n\
             \x20   echo '{described}'\n\
             \x20   exit 0\n\
             \x20 fi\n\
             done\n\
             echo '\"\"'\n",
            argv = dir.join("platform-argv").display(),
        ),
    );
}

/// Stub `ssh` and `scp`: both record their argv, and `ssh` answers the
/// session's steps the way a pod does — the profile's own hash for
/// step 2 (or the integrity check fails and nothing downstream runs),
/// and a report for the `validate` invocation.
fn stub_transport(dir: &Path, remote_hash: &str) {
    executable(
        &dir.join("ssh"),
        &format!(
            "#!/bin/sh\n\
             echo \"$@\" >> {argv}\n\
             case \"$*\" in\n\
             \x20 *sha256sum*) echo 'deadbeef  /root/lm-provisioner' ;;\n\
             \x20 *\"'hash'\"*) echo '{remote_hash}' ;;\n\
             \x20 *\"'validate'\"*) echo '{{\"ok\":true,\"name\":\"t\"}}' ;;\n\
             esac\n\
             exit 0\n",
            argv = dir.join("ssh-argv").display(),
        ),
    );
    executable(
        &dir.join("scp"),
        &format!(
            "#!/bin/sh\necho \"$@\" >> {argv}\nexit 0\n",
            argv = dir.join("scp-argv").display(),
        ),
    );
}

/// The hash the pod would print for this profile — the number step 2
/// compares against, computed here the way the pod-side binary
/// computes it (spec 11 §Identity).
fn profile_hash() -> String {
    lm_provision::cli::ast_hash(&profile()).expect("the fixture resolves and hashes")
}

/// Every argv a stub recorded, one per line; empty when it was never
/// run at all.
fn recorded(dir: &Path, which: &str) -> String {
    std::fs::read_to_string(dir.join(which)).unwrap_or_default()
}

/// The identity file, which only has to exist — the stub `ssh` never
/// reads it.
fn key_file(dir: &Path) -> PathBuf {
    let path = dir.join("id_test");
    std::fs::write(&path, b"not a real key\n").expect("the temp directory is writable");
    path
}

/// One `apply` run, with the stubs ahead of everything on `PATH`.
///
/// `HOME` and the working directory are moved into the scratch
/// directory so the run cannot read the operator's own `.env`, ledger
/// or caches, and `XDG_RUNTIME_DIR` so the ssh control sockets land
/// there too rather than in the operator's session directory.
fn apply(dir: &Path, args: &[&str], key: Option<&Path>) -> std::process::Output {
    let mut command = std::process::Command::new(cli());
    command
        .arg("apply")
        .args(args)
        .args(["--profile", &profile().display().to_string()])
        .args([
            "--validate-only",
            "--skip-install",
            "--no-ledger",
            "--no-artifacts",
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("RUNPOD_API_KEY", "test-key-not-a-real-one")
        .current_dir(dir);
    match key {
        Some(path) => command.env("LM_PROVISION_SSH_KEY", path),
        None => command.env_remove("LM_PROVISION_SSH_KEY"),
    };
    command.output().expect("the CLI binary runs")
}

/// **The platform says where the machine is, and that is what gets
/// dialed.** No `--ssh` anywhere: the address and the port come out of
/// the read-back's `publicIp` / `portMappings`, the identity file
/// arrives as `LM_PROVISION_SSH_KEY`, and the session's steps share
/// one connection.
#[test]
fn a_provider_and_an_id_are_resolved_into_the_ssh_the_session_dials() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("resolved");
    stub_platform_cli(
        &dir,
        r#"{"id":"pod-1","publicIp":"203.0.113.9","portMappings":{"22":21001},"desiredStatus":"RUNNING"}"#,
    );
    stub_transport(&dir, &profile_hash());
    let key = key_file(&dir);

    let output = apply(
        &dir,
        &["--provider", "runpod", "--pod-id", "pod-1"],
        Some(&key),
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the session ran against the resolved endpoint: {stderr}"
    );

    let platform = recorded(&dir, "platform-argv");
    assert!(
        platform.contains("pods get-pod pod-1"),
        "the machine was read back by its id, through the adapter's own template: {platform}"
    );

    let dialed = recorded(&dir, "ssh-argv");
    assert!(
        dialed.contains("-p 21001"),
        "the port the platform mapped: {dialed}"
    );
    assert!(
        dialed.contains("root@203.0.113.9"),
        "the address the platform reported, as the user it runs workloads as: {dialed}"
    );
    assert!(
        dialed.contains(&format!("-i {}", key.display())),
        "the identity file came from the environment, not a flag: {dialed}"
    );
    assert!(
        dialed.contains("ControlMaster=auto"),
        "the steps of one session share a connection: {dialed}"
    );
    assert!(
        recorded(&dir, "scp-argv").contains("ControlMaster=auto"),
        "including the file transfers, which are most of the handshakes"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **A machine with no address yet is refused, and nothing is
/// dialed.** An empty `publicIp` is what a pod reports while it boots;
/// dialing `":21001"` or waiting on it would turn "ask again in a
/// minute" into a timeout with no explanation in it.
#[test]
fn a_machine_that_reports_no_address_is_refused_before_anything_is_dialed() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("booting");
    stub_platform_cli(
        &dir,
        r#"{"id":"pod-1","publicIp":"","portMappings":{},"desiredStatus":"RUNNING"}"#,
    );
    stub_transport(&dir, &profile_hash());
    let key = key_file(&dir);

    let output = apply(
        &dir,
        &["--provider", "runpod", "--pod-id", "pod-1"],
        Some(&key),
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("no ssh endpoint"),
        "the message says what the machine reported, and what to do: {stderr}"
    );
    assert!(
        stderr.contains("read from the platform: publicIp: empty;"),
        "and which field the projection found wanting: {stderr}"
    );
    assert!(
        !dir.join("ssh-argv").exists(),
        "nothing was dialed: {}",
        recorded(&dir, "ssh-argv")
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **No identity file named anywhere is an input that cannot be
/// used**, and the refusal names both ways to name one — an operator
/// who set neither has no way to guess which they were supposed to.
#[test]
fn no_key_and_no_environment_variable_names_both_ways_to_give_one() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("no-key");
    stub_platform_cli(
        &dir,
        r#"{"id":"pod-1","publicIp":"203.0.113.9","portMappings":{"22":21001}}"#,
    );
    stub_transport(&dir, &profile_hash());

    let output = apply(&dir, &["--provider", "runpod", "--pod-id", "pod-1"], None);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("LM_PROVISION_SSH_KEY") && stderr.contains("--key"),
        "{stderr}"
    );
    assert!(
        !dir.join("platform-argv").exists(),
        "the platform was not even asked: the run could not have connected either way"
    );

    std::fs::remove_dir_all(&dir).ok();
}
