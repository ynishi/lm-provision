//! End-to-end for the three operator verbs — `logs`, `exec`, `cp` —
//! against a stub platform CLI, a stub `ssh` and a stub `scp`, all
//! reached the way the real ones are, by name off `PATH`.
//!
//! What that covers and no unit test can: that the remote command a
//! verb builds is the one `ssh` is actually given, that the address
//! and port come from wherever the target was named, that `cp` puts
//! the `:` side on the right end of the `scp` argv, that an exit code
//! from the pod is the CLI's own exit code, and that a machine with no
//! address yet is refused before anything is dialed.
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

fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lm-provision-cli-pod-verbs-e2e-{name}-{}-{}",
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

/// Stub `ssh` and `scp`: each records its whole argv on one line and
/// exits with `code` — which is how a remote command's status is put
/// in front of the CLI without a pod to run one on.
fn stub_transport(dir: &Path, code: u8) {
    for program in ["ssh", "scp"] {
        executable(
            &dir.join(program),
            &format!(
                "#!/bin/sh\necho \"$@\" >> {argv}\nexit {code}\n",
                argv = dir.join(format!("{program}-argv")).display(),
            ),
        );
    }
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

/// One verb run, with the stubs ahead of everything on `PATH`.
///
/// `HOME` and the working directory are moved into the scratch
/// directory so the run cannot read the operator's own `.env` or
/// caches, and `XDG_RUNTIME_DIR` so the ssh control sockets land there
/// too rather than in the operator's session directory.
fn verb(dir: &Path, args: &[&str], key: Option<&Path>) -> std::process::Output {
    let mut command = std::process::Command::new(cli());
    command
        .args(args)
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

/// A machine the stub platform reports as up, at the address the
/// tests below expect to see dialed.
fn running_pod() -> &'static str {
    r#"{"id":"pod-1","publicIp":"203.0.113.9","portMappings":{"22":21001},"desiredStatus":"RUNNING"}"#
}

/// **`logs` names a service and the pod is told a path.** The count,
/// the follow flag and the log's own location are assembled here; the
/// operator types neither `/tmp` nor `tail`.
#[test]
fn logs_builds_the_tail_the_pod_runs_and_dials_where_the_platform_said() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("logs-tail");
    stub_platform_cli(&dir, running_pod());
    stub_transport(&dir, 0);
    let key = key_file(&dir);

    let output = verb(
        &dir,
        &[
            "logs",
            "--provider",
            "runpod",
            "--pod-id",
            "pod-1",
            "vllm-qwen",
            "--tail",
            "50",
            "--follow",
        ],
        Some(&key),
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    let dialed = recorded(&dir, "ssh-argv");
    assert!(
        dialed
            .trim_end()
            .ends_with("-- tail -n 50 -f '/tmp/vllm-qwen.log'"),
        "the remote command is the last thing ssh is given: {dialed}"
    );
    assert!(
        dialed.contains("-p 21001") && dialed.contains("root@203.0.113.9"),
        "the port and address the platform reported: {dialed}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **Without `--tail`, the whole file** — `kubectl logs`'s own
/// default. And with an address there is no platform to ask: the stub
/// `runpod-cli` is not even on `PATH` here, so a run that tried would
/// fail rather than quietly succeed.
#[test]
fn logs_without_a_tail_prints_the_whole_file_and_an_address_asks_no_platform() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("logs-whole");
    stub_transport(&dir, 0);
    let key = key_file(&dir);

    let output = verb(
        &dir,
        &[
            "logs",
            "--ssh",
            "203.0.113.9:21001",
            "--key",
            &key.display().to_string(),
            "comfyui",
        ],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    let dialed = recorded(&dir, "ssh-argv");
    assert!(
        dialed
            .trim_end()
            .ends_with("-- tail -n +1 '/tmp/comfyui.log'"),
        "from the first line on, and the path is the one a launch writes: {dialed}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **What the operator typed after `--` reaches the pod as they typed
/// it, and what it exits with is what the CLI exits with.** A word
/// with a quote or a space in it is the difference between one
/// argument and three, and an exit code that did not ride back would
/// make the verb useless in a script.
#[test]
fn exec_quotes_the_command_and_passes_the_remote_exit_code_back() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("exec");
    stub_platform_cli(&dir, running_pod());
    stub_transport(&dir, 7);
    let key = key_file(&dir);

    let output = verb(
        &dir,
        &[
            "exec",
            "--provider",
            "runpod",
            "--pod-id",
            "pod-1",
            "--",
            "echo",
            "it's",
            "a b",
        ],
        Some(&key),
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(7),
        "the pod's exit code, not a class of this program's: {stderr}"
    );

    let dialed = recorded(&dir, "ssh-argv");
    assert!(
        dialed.trim_end().ends_with(r#"-- 'echo' 'it'\''s' 'a b'"#),
        "every word quoted for the remote shell: {dialed}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **The `:` says which end of the `scp` argv the pod is on**, in both
/// directions, and a command that names two pod paths or none is an
/// input that cannot be used.
#[test]
fn cp_puts_the_pod_on_the_side_the_colon_names_and_refuses_the_other_spellings() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("cp");
    stub_platform_cli(&dir, running_pod());
    stub_transport(&dir, 0);
    let key = key_file(&dir);
    let target = ["cp", "--provider", "runpod", "--pod-id", "pod-1"];

    let pull = verb(
        &dir,
        &[&target[..], &[":/tmp/x.log", "./out"]].concat(),
        Some(&key),
    );
    assert_eq!(
        pull.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    assert!(
        pull.stdout.is_empty(),
        "nothing is printed on success: {:?}",
        String::from_utf8_lossy(&pull.stdout)
    );
    let copied = recorded(&dir, "scp-argv");
    assert!(
        copied
            .trim_end()
            .ends_with("root@203.0.113.9:/tmp/x.log ./out"),
        "the pod is the source: {copied}"
    );
    assert!(
        copied.starts_with("-r "),
        "recursive, so a directory needs no second spelling: {copied}"
    );

    std::fs::remove_dir_all(&dir).ok();
    let dir = unique_dir("cp-push");
    stub_platform_cli(&dir, running_pod());
    stub_transport(&dir, 0);
    let key = key_file(&dir);
    std::fs::write(dir.join("in"), b"payload\n").expect("the temp directory is writable");

    let push = verb(
        &dir,
        &[&target[..], &["./in", ":/tmp/in"]].concat(),
        Some(&key),
    );
    assert_eq!(
        push.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&push.stderr)
    );
    let copied = recorded(&dir, "scp-argv");
    assert!(
        copied.trim_end().ends_with("./in root@203.0.113.9:/tmp/in"),
        "the pod is the destination: {copied}"
    );

    for operands in [[":/a", ":/b"], ["a", "b"]] {
        let refused = verb(&dir, &[&target[..], &operands[..]].concat(), Some(&key));
        let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert_eq!(refused.status.code(), Some(2), "{operands:?}: {stderr}");
        assert!(
            stderr.contains(':'),
            "the refusal shows the spelling that was missing or doubled: {stderr}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// **A machine with no address yet is refused, and nothing is
/// dialed** — the judgement `apply` makes, made by these verbs too,
/// since they resolve the target the same way.
#[test]
fn a_machine_that_reports_no_address_is_refused_before_anything_is_dialed() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("booting");
    stub_platform_cli(
        &dir,
        r#"{"id":"pod-1","publicIp":"","portMappings":{},"desiredStatus":"RUNNING"}"#,
    );
    stub_transport(&dir, 0);
    let key = key_file(&dir);

    let output = verb(
        &dir,
        &[
            "exec",
            "--provider",
            "runpod",
            "--pod-id",
            "pod-1",
            "--",
            "nvidia-smi",
        ],
        Some(&key),
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no ssh endpoint"), "{stderr}");
    assert!(
        !dir.join("ssh-argv").exists(),
        "nothing was dialed: {}",
        recorded(&dir, "ssh-argv")
    );

    std::fs::remove_dir_all(&dir).ok();
}
