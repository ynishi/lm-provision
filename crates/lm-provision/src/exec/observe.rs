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
//! is for the caller to stop waiting and answer `CheckFailed(Timeout)`
//! (design §3.2d). This implementation is the near case; the shape it
//! implements is what lets a caller wrap it.
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
//!   reason the failure is an *answer* (design §4.1: folding the read
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
//! `command_status` blocks the thread it is polled on, exactly as the
//! two file reads do: the effect layer's `sh_exec` is synchronous, and
//! this implementation is the near case (§Why the async evaluator is
//! not pointless, above). A `command_status` reaching a remote pod is
//! the one that would need the wrapper the async shape exists for.

use std::path::Path;

use super::assert::{CheckError, CheckErrorCategory, DigestReading, Observe};
use super::effects;

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
            // rather than an error (design §3.2b).
            Err(err) => Err(CheckError::new(
                CheckErrorCategory::Unobservable,
                err.to_string(),
            )),
        }
    }
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
    use crate::exec::assert::{eval, Assert, AssertOutcome};
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
    /// boundary the two file reads sit on (design §3.2b).
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
