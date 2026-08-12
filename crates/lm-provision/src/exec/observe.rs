//! [`LocalObserve`]: the Assert model's observations against the
//! filesystem the provisioner itself runs on.
//!
//! The provisioner is a static binary that runs *on* the pod
//! (08-push-driver-protocol.md), so "the host an Assert asks about" and
//! "the filesystem this process sees" are the same thing, and these two
//! observations are plain local reads.
//!
//! **That does not make the async evaluator pointless.** The design
//! keeps observations on the far side of a driver precisely because a
//! read can fail to return — a `stat()` on a hard-mounted NFS path
//! enters D state, where not even SIGKILL helps and the only move left
//! is for the caller to stop waiting and answer `CheckFailed(Timeout)`.
//! This implementation is the near case; the shape it implements is
//! what lets a caller wrap it.
//!
//! ## What these two observations mean
//!
//! The model deliberately leaves the meaning to the observation
//! ([`crate::exec::assert::Observe`]), so it is settled here:
//!
//! - **`file_exists`** follows symlinks and answers `true` for a
//!   directory. It is `Path::try_exists`, which is the "is there
//!   something at this path" question, not "is there a regular file".
//!   The predicate's subject is a download destination, where a
//!   directory in the way is a real state of the host and reporting it
//!   as absent would be a lie.
//! - **`file_digest`** reads the content as a byte stream. An absent
//!   path answers [`DigestReading::Absent`]; a path that exists but is
//!   not a readable byte stream (a directory, a permission failure) is
//!   a [`CheckError`], not an absence — that distinction is the whole
//!   reason the failure is an *answer* (folding the read
//!   failure into "different" is what the driver's `ensure_binary` used
//!   to do).
//! - **`command_status`** spawns `argv` and waits for it, reporting the
//!   status it exited with. It does not judge that status: `0` is not
//!   "true" here, it is just what the process returned, and the
//!   predicate that composed the argv is what knows whether that means
//!   the condition holds. A binary that cannot be started is a
//!   [`CheckError`] — detected, therefore an answer — and a signal
//!   arrives as the `-1` the effect layer reports for one.
//!
//! - **`process_alive`** / **`process_argv`** read a launch's pid file
//!   and then look under [`PROC_ROOT`]. Both go through
//!   [`read_pid_file`], so there is exactly one implementation of "what
//!   does this pid file say" on the host — the readiness poll's
//!   `Liveness` probe projects from the same function
//!   ([`crate::exec::lifecycle`]). What differs between the callers is
//!   only how the reading is folded into an answer, which is where the
//!   two questions genuinely part company.
//!
//! `command_status` blocks the thread it is polled on, exactly as the
//! two file reads do: the effect layer's `sh_exec` is synchronous, and
//! this implementation is the near case, for the reason given above.
//! A `command_status` reaching a remote pod is
//! the one that would need the wrapper the async shape exists for.
//!
//! ## The procfs dependency
//!
//! The two process observations are Linux-only in substance: they ask
//! whether `/proc/<pid>` is there and read `/proc/<pid>/cmdline`. That
//! is not a portability oversight — the provisioner is a static binary
//! that runs on the pod, and the pod is Linux. On a host without a
//! procfs every pid reads as gone, which is why the functions that do
//! the looking take the root as a parameter and only
//! [`LocalObserve`]'s methods pin it to [`PROC_ROOT`]: the decision
//! stays testable on a developer machine, exactly as the poll's probe
//! has always been.

use std::path::Path;

use super::assert::{ArgvReading, CheckError, CheckErrorCategory, DigestReading, Observe};
use super::effects;

/// Linux procfs root. A running process has a `/proc/<pid>` directory,
/// and its command line is `/proc/<pid>/cmdline`.
///
/// Lives here rather than beside the readiness poll that first needed
/// it, because it is now what *observing* a process means and there are
/// two readers of it.
pub(crate) const PROC_ROOT: &str = "/proc";

/// Observes the filesystem this process is running on.
///
/// A unit struct: there is nothing to configure, and every call is a
/// fresh read. It is a type rather than free functions because
/// [`Observe`] is the seam a test replaces with a fixed-response host.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalObserve;

impl Observe for LocalObserve {
    async fn file_exists(&self, path: &Path) -> Result<bool, CheckError> {
        // `try_exists` is the three-way answer: yes / no / the question
        // could not be answered. `Path::exists` collapses the third
        // into "no", which is the fold this model exists to undo.
        path.try_exists().map_err(|err| unobservable(path, &err))
    }

    async fn file_digest(&self, path: &Path) -> Result<DigestReading, CheckError> {
        match crate::digest::of_file(path) {
            Ok(Some(hex)) => Ok(DigestReading::Present(hex)),
            Ok(None) => Ok(DigestReading::Absent),
            Err(err) => Err(unobservable(path, &err)),
        }
    }

    async fn command_status(&self, argv: &[String]) -> Result<i32, CheckError> {
        // The same spawn the effect layer uses, so a predicate and a
        // step see one implementation of "run this argv" — and one
        // answer to what an exit code, a signal or a missing binary
        // looks like. No env is injected: a predicate's command is
        // composed by the crate and carries no secrets, and handing it
        // the phase's resolved map would put them in reach of something
        // that only ever needs to read.
        match effects::sh_exec(argv, &effects::ShOpts::default()) {
            // `exit_code` is `-1` for a signal or an unknown status,
            // which is a code no predicate treats as an answer — it
            // falls into whatever "anything else" bucket the predicate
            // has, i.e. a failed observation.
            Ok(outcome) => Ok(outcome.exit_code),
            // Reached only when the process could not be started at all
            // (a missing binary). That is detected, so it is an answer
            // rather than an error.
            Err(err) => Err(CheckError::new(
                CheckErrorCategory::Unobservable,
                err.to_string(),
            )),
        }
    }

    async fn process_alive(&self, pid_file: &Path) -> Result<bool, CheckError> {
        match read_pid_file(pid_file) {
            // Nothing has recorded a launch here. A determinate answer,
            // and the state of a fresh pod.
            PidFile::Absent => Ok(false),
            PidFile::Unusable(error) => Err(error),
            PidFile::Pid(pid) => Ok(process_exists(pid, Path::new(PROC_ROOT))),
        }
    }

    async fn process_argv(&self, pid_file: &Path) -> Result<ArgvReading, CheckError> {
        match read_pid_file(pid_file) {
            PidFile::Absent => Ok(ArgvReading::NoProcess),
            PidFile::Unusable(error) => Err(error),
            PidFile::Pid(pid) => match process_argv(pid, Path::new(PROC_ROOT))? {
                None => Ok(ArgvReading::NoProcess),
                Some(argv) => Ok(ArgvReading::Argv(argv)),
            },
        }
    }
}

/// What a launch's pid file says, before anything is concluded from it.
///
/// The three cases are kept apart here so that each caller can fold
/// them its own way. The readiness poll fuses the last two into
/// `Liveness::Unknown` because it only needs "not a death"; the Assert
/// predicates split them, because an absent file is a determinate
/// observation and an unusable one is a failed one
/// ([`crate::exec::assert::Assert::ProcessAlive`]). Folding here would
/// force one of those two to be wrong.
#[derive(Debug)]
pub(crate) enum PidFile {
    /// There is no pid file at that path.
    Absent,
    /// The file holds this pid.
    Pid(u32),
    /// There is a file, and it yields no pid: it could not be read, or
    /// its contents are not a number — which includes the launch race,
    /// where the file exists a moment before `$!` has been written into
    /// it.
    Unusable(CheckError),
}

/// Read `path` as a launch's pid file.
///
/// The **one** implementation of that read in the crate. Distinguishing
/// "not there" from "there and unusable" is the whole reason it is not
/// simply `fs::read_to_string(..).ok()`.
pub(crate) fn read_pid_file(path: &Path) -> PidFile {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return PidFile::Absent,
        Err(err) => return PidFile::Unusable(unobservable(path, &err)),
    };
    match text.trim().parse::<u32>() {
        Ok(pid) => PidFile::Pid(pid),
        // The file is there but holds no pid — empty because a launch
        // has not written it yet, or garbage. Read successfully,
        // concluded nothing.
        Err(_) => PidFile::Unusable(CheckError::new(
            CheckErrorCategory::Unobservable,
            format!("no pid in {}", path.display()),
        )),
    }
}

/// Whether `pid` has an entry under `proc_root`.
///
/// `proc_root` is a parameter so the decision can be exercised without
/// a procfs; production passes [`PROC_ROOT`].
pub(crate) fn process_exists(pid: u32, proc_root: &Path) -> bool {
    proc_root.join(pid.to_string()).exists()
}

/// The argv `pid` was started with, read from `proc_root`.
///
/// `Ok(None)` is "that process is not there" — the same answer an
/// absent pid file gives, and not a failure. `Ok(Some(vec![]))` is a
/// process that exists and exposes no command line, which is what a
/// zombie looks like.
///
/// The contents are NUL-separated with a trailing NUL, so exactly one
/// trailing separator is stripped before splitting rather than every
/// empty field being dropped — an argument that is genuinely the empty
/// string is a position in the argv and has to survive the read, or two
/// different launches would compare equal.
pub(crate) fn process_argv(pid: u32, proc_root: &Path) -> Result<Option<Vec<String>>, CheckError> {
    let path = proc_root.join(pid.to_string()).join("cmdline");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(unobservable(&path, &err)),
    };
    let body = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
    if body.is_empty() {
        return Ok(Some(Vec::new()));
    }
    Ok(Some(
        body.split(|byte| *byte == 0)
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect(),
    ))
}

/// Turn a failed read into the answer it is.
///
/// The detail is `<ErrorKind>: <path>` — both halves are functions of
/// the observation alone, which [`CheckError`] requires: equality
/// includes the detail, so a clock, an attempt counter or an OS error
/// number that varies by platform would make "the same host state gives
/// the same answer" untestable. `ErrorKind`'s `Debug` spelling
/// (`PermissionDenied`) is the stable rendering; `io::Error`'s own
/// `Display` embeds the raw errno.
fn unobservable(path: &Path, err: &std::io::Error) -> CheckError {
    CheckError::new(
        CheckErrorCategory::Unobservable,
        format!("{:?}: {}", err.kind(), path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::assert::{eval, ArgvReading, Assert, AssertOutcome};
    use crate::exec::ExecMode;
    use std::path::PathBuf;

    // The command channel meeting a real repository is
    // `lifecycle`'s `a_second_apply_skips_the_clone_instead_of_failing_on_it`,
    // which drives the whole step. Here it is exercised on its own, with
    // commands that need nothing installed.

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lm-observe-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// The two predicates against a real file, both answers, plus the
    /// mismatch — the whole point being that `Unsatisfied` for "wrong
    /// content" and `Unsatisfied` for "nothing there" are reached
    /// through different observations.
    #[tokio::test]
    async fn the_two_predicates_answer_from_the_real_filesystem() {
        let dir = scratch_dir("real");
        let present = dir.join("present.bin");
        std::fs::write(&present, b"payload").expect("write payload");
        let absent = dir.join("absent.bin");

        let digest = crate::digest::hex_sha256(b"payload");

        let cases: Vec<(&str, Assert, AssertOutcome)> = vec![
            (
                "existing file",
                Assert::FileExists {
                    path: present.clone(),
                },
                AssertOutcome::Satisfied,
            ),
            (
                "absent file",
                Assert::FileExists {
                    path: absent.clone(),
                },
                AssertOutcome::Unsatisfied,
            ),
            (
                "matching digest",
                Assert::FileDigest {
                    path: present.clone(),
                    expected_sha256: digest,
                },
                AssertOutcome::Satisfied,
            ),
            (
                "differing digest",
                Assert::FileDigest {
                    path: present.clone(),
                    expected_sha256: crate::digest::hex_sha256(b"something else"),
                },
                AssertOutcome::Unsatisfied,
            ),
            (
                "digest of an absent file",
                Assert::FileDigest {
                    path: absent,
                    expected_sha256: crate::digest::hex_sha256(b"payload"),
                },
                AssertOutcome::Unsatisfied,
            ),
        ];

        for (label, assert, want) in cases {
            let node = eval(&assert, ExecMode::Real, &LocalObserve).await;
            assert_eq!(node.outcome(), &want, "{label}");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A path that exists but cannot be read as a byte stream answers
    /// `CheckFailed`, not `Unsatisfied`: the caller does the work
    /// either way, but the report has to be able to say which happened.
    /// A directory is the portable way to produce that state.
    #[tokio::test]
    async fn an_unreadable_path_answers_check_failed_rather_than_unsatisfied() {
        let dir = scratch_dir("unreadable");

        let exists = eval(
            &Assert::FileExists { path: dir.clone() },
            ExecMode::Real,
            &LocalObserve,
        )
        .await;
        assert_eq!(
            exists.outcome(),
            &AssertOutcome::Satisfied,
            "something is at that path, and existence says so",
        );

        let digest = eval(
            &Assert::FileDigest {
                path: dir.clone(),
                expected_sha256: crate::digest::hex_sha256(b""),
            },
            ExecMode::Real,
            &LocalObserve,
        )
        .await;
        assert!(
            matches!(digest.outcome(), AssertOutcome::CheckFailed(_)),
            "an unreadable path is a failed observation, not a content mismatch: {:?}",
            digest.outcome(),
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The command channel returns the status a process exited with,
    /// **without judging it**: `1` is not an error here, it is what the
    /// process said, and the predicate that composed the argv is what
    /// knows whether that means the condition holds.
    #[tokio::test]
    async fn a_command_that_runs_reports_the_status_it_exited_with() {
        for want in [0, 1, 7] {
            let argv = vec!["sh".to_string(), "-c".to_string(), format!("exit {want}")];
            assert_eq!(
                LocalObserve.command_status(&argv).await,
                Ok(want),
                "exit {want} is reported as-is",
            );
        }
    }

    /// A binary that is not there is **detected**, so it is an answer
    /// (`CheckFailed`) rather than a host-process error — the same
    /// boundary the two file reads sit on.
    #[tokio::test]
    async fn a_command_that_cannot_be_started_answers_check_failed() {
        let argv = vec!["lm-provision-no-such-binary-8f3a".to_string()];
        let err = LocalObserve
            .command_status(&argv)
            .await
            .expect_err("a missing binary cannot be run");
        assert_eq!(err.category(), CheckErrorCategory::Unobservable);
        assert!(
            err.detail().contains("lm-provision-no-such-binary-8f3a"),
            "the detail names what could not be started: {}",
            err.detail(),
        );
    }

    // -----------------------------------------------------------------
    // The pid file, and the process it names
    // -----------------------------------------------------------------

    /// A fake procfs plus a pid file, which is how the process
    /// observations are exercised on a host that has no `/proc`.
    ///
    /// `argv` is written the way procfs writes one: NUL-separated, with
    /// a trailing NUL.
    fn fake_launch(dir: &std::path::Path, pid: u32, argv: Option<&[&str]>) -> PathBuf {
        let entry = dir.join("proc").join(pid.to_string());
        if let Some(argv) = argv {
            std::fs::create_dir_all(&entry).expect("create procfs entry");
            let mut bytes = Vec::new();
            for arg in argv {
                bytes.extend_from_slice(arg.as_bytes());
                bytes.push(0);
            }
            std::fs::write(entry.join("cmdline"), &bytes).expect("write cmdline");
        }
        let pid_file = dir.join("svc.pid");
        std::fs::write(&pid_file, pid.to_string()).expect("write pid file");
        pid_file
    }

    /// The three readings a pid file can give, kept apart because two
    /// different callers fold them differently.
    #[test]
    fn a_pid_file_reads_as_absent_a_pid_or_unusable() {
        let dir = scratch_dir("pid-file");

        assert!(
            matches!(read_pid_file(&dir.join("nothing.pid")), PidFile::Absent),
            "a path with no file is an absence, not a failed read",
        );

        let ok = dir.join("ok.pid");
        std::fs::write(&ok, "4242\n").expect("write pid file");
        assert!(matches!(read_pid_file(&ok), PidFile::Pid(4242)));

        // Empty is the launch race: the file exists a moment before
        // `$!` has been written into it.
        for content in ["", "   ", "not-a-pid", "-1"] {
            let path = dir.join("unusable.pid");
            std::fs::write(&path, content).expect("write pid file");
            match read_pid_file(&path) {
                PidFile::Unusable(error) => assert!(
                    error.detail().contains("unusable.pid"),
                    "the detail names the file: {}",
                    error.detail(),
                ),
                other => panic!("content {content:?} must not yield a pid: {other:?}"),
            }
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Existence and the command line, against a procfs the test owns.
    #[test]
    fn a_live_process_reports_its_command_line_and_a_dead_one_reports_nothing() {
        let dir = scratch_dir("proc-argv");
        let proc_root = dir.join("proc");
        let argv = ["srv", "--port", "8188"];
        fake_launch(&dir, 4242, Some(&argv));

        assert!(process_exists(4242, &proc_root));
        assert_eq!(
            process_argv(4242, &proc_root).expect("a live process answers"),
            Some(argv.iter().map(|a| (*a).to_string()).collect::<Vec<_>>()),
        );

        assert!(!process_exists(4243, &proc_root));
        assert_eq!(
            process_argv(4243, &proc_root).expect("an absent process is an answer, not an error"),
            None,
            "a pid with no entry has no argv to compare, which is not a failed observation",
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A process that exists and exposes no command line — what a
    /// zombie looks like — is `Some(vec![])`, not `None` and not an
    /// error. It compares unequal to every declared launch, which is
    /// the answer a zombie deserves.
    #[test]
    fn a_process_with_an_empty_command_line_is_not_the_same_as_no_process() {
        let dir = scratch_dir("proc-zombie");
        let proc_root = dir.join("proc");
        fake_launch(&dir, 4242, Some(&[]));

        assert!(process_exists(4242, &proc_root));
        assert_eq!(
            process_argv(4242, &proc_root).expect("the entry is there"),
            Some(Vec::new()),
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An argument that is the empty string is a *position* in the
    /// argv, so it has to survive the read: dropping empty fields would
    /// make `srv "" --port` and `srv --port` compare equal, and two
    /// different launches would then read as the same server.
    #[test]
    fn an_empty_argument_survives_the_split() {
        let dir = scratch_dir("proc-empty-arg");
        let proc_root = dir.join("proc");
        fake_launch(&dir, 4242, Some(&["srv", "", "--port"]));

        assert_eq!(
            process_argv(4242, &proc_root).expect("the entry is there"),
            Some(vec!["srv".to_string(), String::new(), "--port".to_string()]),
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The two `Observe` methods against the real host. Only the arms
    /// that need no procfs can be driven here — a developer machine has
    /// none, so every pid reads as gone — and the rest are covered
    /// against an injected root above.
    #[tokio::test]
    async fn the_process_observations_answer_from_the_real_filesystem() {
        let dir = scratch_dir("proc-real");

        let absent = dir.join("nothing.pid");
        assert_eq!(
            LocalObserve.process_alive(&absent).await,
            Ok(false),
            "no pid file is an answer: nothing has recorded a launch",
        );
        assert_eq!(
            LocalObserve.process_argv(&absent).await,
            Ok(ArgvReading::NoProcess),
        );

        let unusable = dir.join("empty.pid");
        std::fs::write(&unusable, "").expect("write pid file");
        assert!(
            LocalObserve.process_alive(&unusable).await.is_err(),
            "a pid file that yields no pid is a failed observation, not an absence",
        );
        assert!(LocalObserve.process_argv(&unusable).await.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A whole [`crate::exec::assert::Service`] condition answered
    /// against the **real** procfs, with this test process standing in
    /// for the launched server.
    ///
    /// **Both platforms assert something; neither is skipped.** The
    /// provisioner runs on the pod and the pod is Linux, so that is
    /// where the interesting branch lives — but a host without a procfs
    /// also has a correct answer, and it is one worth pinning: every
    /// launch reads as not running, which is the safe direction. Which
    /// branch this host takes is read off the observation rather than
    /// off a `cfg`, so the whole test compiles and runs everywhere.
    #[tokio::test]
    async fn a_service_condition_answers_against_the_real_procfs() {
        use crate::exec::assert::{Done as _, Service};

        let dir = scratch_dir("service-real");
        let pid_file = dir.join("svc.pid");
        let pid = std::process::id();
        std::fs::write(&pid_file, pid.to_string()).expect("write pid file");

        // Whatever this test binary was started with, read the same way
        // a launched server's argv is read.
        let own_argv = process_argv(pid, Path::new(PROC_ROOT)).expect("this process is observable");

        let Some(own_argv) = own_argv else {
            // No procfs: this process cannot be found, so no condition
            // naming it can hold.
            assert!(
                !LocalObserve
                    .process_alive(&pid_file)
                    .await
                    .expect("the pid file is readable"),
                "without a procfs every launch reads as not running",
            );
            let any = Service::new(&pid_file, vec!["srv".to_string()]).done();
            assert_eq!(
                eval(&any, ExecMode::Real, &LocalObserve).await.outcome(),
                &AssertOutcome::Unsatisfied,
                "and a condition that cannot be confirmed never skips a launch",
            );
            std::fs::remove_dir_all(&dir).ok();
            return;
        };

        assert!(
            !own_argv.is_empty(),
            "a live process exposes its command line",
        );
        let matching = Service::new(&pid_file, own_argv.clone()).done();
        assert_eq!(
            eval(&matching, ExecMode::Real, &LocalObserve)
                .await
                .outcome(),
            &AssertOutcome::Satisfied,
            "the recorded process is running, with exactly this argv",
        );

        let mut edited = own_argv;
        edited.push("--a-flag-this-process-was-not-given".to_string());
        let differing = Service::new(&pid_file, edited).done();
        assert_eq!(
            eval(&differing, ExecMode::Real, &LocalObserve)
                .await
                .outcome(),
            &AssertOutcome::Unsatisfied,
            "one extra argument is a different launch",
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The detail is a function of the observation alone, so the same
    /// host state answers identically twice — the property `CheckError`
    /// being a value type exists to make testable.
    #[tokio::test]
    async fn the_same_host_state_gives_the_same_failure_detail() {
        let dir = scratch_dir("stable-detail");
        let assert = Assert::FileDigest {
            path: dir.clone(),
            expected_sha256: crate::digest::hex_sha256(b""),
        };

        let first = eval(&assert, ExecMode::Real, &LocalObserve).await;
        let second = eval(&assert, ExecMode::Real, &LocalObserve).await;
        assert_eq!(first.outcome(), second.outcome());

        std::fs::remove_dir_all(&dir).ok();
    }
}
