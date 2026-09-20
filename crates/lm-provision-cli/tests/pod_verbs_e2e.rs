//! End-to-end for the operator verbs — `logs`, `exec`, `cp`,
//! `port-forward` — against a stub platform CLI, a stub `ssh` and a
//! stub `scp`, all reached the way the real ones are, by name off
//! `PATH`.
//!
//! What that covers and no unit test can: that the remote command a
//! verb builds is the one `ssh` is actually given, that the address
//! and port come from wherever the target was named, that `cp` puts
//! the `:` side on the right end of the `scp` argv, that an exit code
//! from the pod is the CLI's own exit code, that a detached
//! `port-forward` waits for a port to be listening before it says a
//! pid, and that a machine with no address yet is refused before
//! anything is dialed.
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

/// One verb run, ready to be started, with the stubs ahead of
/// everything on `PATH`.
///
/// `HOME` and the working directory are moved into the scratch
/// directory so the run cannot read the operator's own `.env` or
/// caches, and `XDG_RUNTIME_DIR` so the ssh control sockets land there
/// too rather than in the operator's session directory.
///
/// Unstarted, because one test has to say where the CLI's stderr goes
/// before it runs (see `port_forward_builds_the_l_flags_…`).
fn verb_command(dir: &Path, args: &[&str], key: Option<&Path>) -> std::process::Command {
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
    command
}

/// That run, to completion, with both its streams captured.
fn verb(dir: &Path, args: &[&str], key: Option<&Path>) -> std::process::Output {
    verb_command(dir, args, key)
        .output()
        .expect("the CLI binary runs")
}

/// A stub `ssh` that does what a forward's wait is watching for: it
/// **binds the local port** the `-L` names and holds it.
///
/// Its own stub rather than a flag on `stub_transport`, which exits
/// immediately — a forward asks a running `ssh` a question the other
/// verbs never ask it, and an `ssh` that is not there to answer is a
/// different test.
///
/// `python3` is what holds the socket: it is on every GitHub
/// `ubuntu-latest` image and on any host with a working `lm-provision`
/// toolchain, and a shell has no way to listen on a TCP port by
/// itself. `exec` keeps the pid, so the `$$` recorded before it is the
/// pid the CLI is expected to report.
fn stub_forwarding_ssh(dir: &Path) {
    executable(
        &dir.join("ssh"),
        &format!(
            r#"#!/bin/sh
echo "$@" >> {argv}
port=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-L" ]; then
    port=$(echo "$arg" | cut -d: -f2)
  fi
  previous="$arg"
done
echo $$ > {pid}
exec python3 -c '
import socket, sys, time
listening = socket.socket()
listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listening.bind(("127.0.0.1", int(sys.argv[1])))
listening.listen(16)
while True:
    time.sleep(3600)
' "$port"
"#,
            argv = dir.join("ssh-argv").display(),
            pid = dir.join("ssh-pid").display(),
        ),
    );
}

/// A local port nothing is on: bound, read back, and let go.
///
/// Asking the kernel beats picking a number — a fixed one collides
/// with whatever else the host is running, and two of these tests on
/// one runner would collide with each other.
fn a_free_local_port() -> u16 {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port is available");
    let port = taken
        .local_addr()
        .expect("a bound socket has an address")
        .port();
    drop(taken);
    port
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
        stderr.contains("read from the platform: publicIp: empty; portMappings: []"),
        "{stderr}"
    );
    assert!(
        !dir.join("ssh-argv").exists(),
        "nothing was dialed: {}",
        recorded(&dir, "ssh-argv")
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// **A forward is the `ssh` flags the operator did not have to type,
/// and `--detach` answers with the pid carrying it.** The pairs become
/// `-L`s against the pod's own loopback, the address and port come
/// from the platform, and the run does not say the forward is up until
/// the local port actually accepts — which is the whole value of the
/// artifact, since a pid of an `ssh` that has not bound anything would
/// be a handle to nothing.
#[test]
fn port_forward_builds_the_l_flags_and_dials_where_the_platform_said() {
    let _guard = common::stage_and_run();
    let python = std::process::Command::new("python3")
        .arg("--version")
        .output();
    assert!(
        matches!(&python, Ok(it) if it.status.success()),
        "this test's stub `ssh` holds the forwarded port open with python3, \
         which is missing here: {python:?}"
    );

    let dir = unique_dir("port-forward");
    stub_platform_cli(&dir, running_pod());
    stub_forwarding_ssh(&dir);
    let key = key_file(&dir);
    let local = a_free_local_port();
    let pair = format!("{local}:8000");

    // The CLI's stderr goes to a file rather than a pipe: a detached
    // forward hands its stderr to the `ssh` it leaves behind, and a
    // pipe that process still holds open would never reach EOF — so
    // `output()` would wait for the forward instead of for the run.
    let mut command = verb_command(
        &dir,
        &[
            "port-forward",
            "--provider",
            "runpod",
            "--pod-id",
            "pod-1",
            "--detach",
            &pair,
        ],
        Some(&key),
    );
    let errors = dir.join("cli-stderr");
    command.stderr(std::process::Stdio::from(
        std::fs::File::create(&errors).expect("the temp directory is writable"),
    ));
    let output = command.output().expect("the CLI binary runs");
    let stderr = std::fs::read_to_string(&errors).unwrap_or_default();
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    let dialed = recorded(&dir, "ssh-argv");
    assert!(
        dialed.contains(" -N ") && dialed.contains("-o ExitOnForwardFailure=yes"),
        "no remote command, and a port it cannot bind is a failure: {dialed}"
    );
    assert!(
        dialed.contains(&format!("-L 127.0.0.1:{local}:127.0.0.1:8000")),
        "the pod side is reached from the pod's own loopback: {dialed}"
    );
    assert!(
        dialed.contains("-p 21001") && dialed.contains("root@203.0.113.9"),
        "the port and address the platform reported: {dialed}"
    );
    assert!(
        !dialed.contains(" -- "),
        "a forward closes no argv with the remote-command separator: {dialed}"
    );
    assert!(
        dialed.contains("-o ControlMaster=no") && dialed.contains("-o ControlPath=none"),
        "and it is not multiplexed: a master would take the forward and let this process \
         exit, leaving the pid below naming nothing [measured: 2026-09-20, a real pod]: \
         {dialed}"
    );

    let artifact: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("one JSON artifact on stdout: {err}: {:?}", output.stdout));
    let held = recorded(&dir, "ssh-pid");
    assert_eq!(
        artifact["pid"].as_u64(),
        held.trim().parse::<u64>().ok(),
        "the pid is the ssh still carrying the forward: {artifact} / {held:?}"
    );
    assert_eq!(artifact["address"], "127.0.0.1");
    assert_eq!(
        artifact["forwards"],
        serde_json::json!([{"local": local, "remote": 8000}])
    );

    let pid = artifact["pid"].as_u64().expect("a pid was reported");
    std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()
        .expect("kill runs");
    std::fs::remove_dir_all(&dir).ok();
}

/// **A pair that cannot be read is refused before any platform is
/// asked.** The same ordering `cp` keeps: a lookup costs a call to the
/// platform, and a command that could not have been carried out
/// whichever machine it named should not spend one.
#[test]
fn port_forward_refuses_a_bad_pair_before_asking_any_platform() {
    let _guard = common::stage_and_run();
    let dir = unique_dir("port-forward-pair");
    stub_platform_cli(&dir, running_pod());
    stub_transport(&dir, 0);
    let key = key_file(&dir);

    for spec in ["0:8000", "abc"] {
        let refused = verb(
            &dir,
            &[
                "port-forward",
                "--provider",
                "runpod",
                "--pod-id",
                "pod-1",
                spec,
            ],
            Some(&key),
        );
        let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert_eq!(refused.status.code(), Some(2), "{spec:?}: {stderr}");
        assert!(
            stderr.contains("18000:8000"),
            "the refusal shows a spelling that would have worked: {stderr}"
        );
        assert!(
            !dir.join("platform-argv").exists(),
            "no platform was asked about the pod: {}",
            recorded(&dir, "platform-argv")
        );
        assert!(
            !dir.join("ssh-argv").exists(),
            "and nothing was dialed: {}",
            recorded(&dir, "ssh-argv")
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}
