//! [`LocalExecTransport`]: the [`crate::transport::Transport`] that
//! reaches no further than the driver's own host — the other shipped
//! implementation is [`crate::ssh`], and a `docker exec` transport is
//! a documented extension point (08-push-driver-protocol.md
//! §Stability: "SSH, provider exec API, `docker exec` all satisfy
//! it"). Runs
//! the provisioner binary on the same host the driver itself runs on,
//! staging the uploaded artifacts under a directory of the caller's
//! choosing (08 §Driver steps step 1: "any byte-transport; paths are
//! the driver's choice").

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::transport::{ExecOutput, PodPaths, Transport, TransportError};

/// Copies the binary and profile into a staging directory, then runs
/// the staged binary directly via [`std::process::Command`] — "upload"
/// is a same-host filesystem copy, and "exec" is a direct child-process
/// invocation, the simplest transport that still satisfies 08's
/// three-step shape end to end. Used by this crate's own end-to-end
/// tests against the real Phase F binary; a production driver talking
/// to a remote pod needs an SSH- or exec-API-backed [`Transport`]
/// instead (08 §Stability).
pub struct LocalExecTransport {
    staging_dir: PathBuf,
}

impl LocalExecTransport {
    /// Stage every upload under `staging_dir` (created on the first
    /// [`Transport::upload`] call if it does not already exist).
    pub fn new(staging_dir: impl Into<PathBuf>) -> Self {
        Self {
            staging_dir: staging_dir.into(),
        }
    }
}

impl Transport for LocalExecTransport {
    fn dest_binary(&self, local_binary: &Path) -> Result<PathBuf, TransportError> {
        Ok(self.staging_dir.join(file_name(local_binary)?))
    }

    fn dest_profile(&self, local_profile: &Path) -> Result<PathBuf, TransportError> {
        Ok(self.staging_dir.join(file_name(local_profile)?))
    }

    fn ensure_binary(&self, local_binary: &Path) -> Result<PathBuf, TransportError> {
        std::fs::create_dir_all(&self.staging_dir)?;
        let staged_binary = self.dest_binary(local_binary)?;
        // Idempotent by content (08 §Session steps "ensure-binary"):
        // an already-identical destination skips the copy, so a
        // re-run converges without re-transfer.
        //
        // Compared by digest through `lm_provision::digest`, the same
        // implementation the SSH transport's `sha256sum` comparison and
        // the provisioner's own content predicate use. The two reasons
        // this is not a `Vec<u8>` equality any more:
        //
        // - it read both whole files into memory, on the same artifact
        //   the SSH path streams;
        // - **it folded a failed read into "not identical"**. A staged
        //   file that cannot be read is not a mismatch; it is a
        //   question that did not get answered, and answering it "no"
        //   makes a permission problem look like an ordinary re-copy.
        //   `NotFound` — nothing staged yet — is a real answer and
        //   still means copy.
        let already_identical = match lm_provision::digest::of_file(&staged_binary)? {
            Some(staged) => staged == crate::local_digest(local_binary)?,
            None => false,
        };
        if !already_identical {
            std::fs::copy(local_binary, &staged_binary)?;
        }
        mark_executable(&staged_binary)?;
        Ok(staged_binary)
    }

    fn place_profile(&self, local_profile: &Path) -> Result<PathBuf, TransportError> {
        std::fs::create_dir_all(&self.staging_dir)?;
        let staged_profile = self.dest_profile(local_profile)?;
        std::fs::copy(local_profile, &staged_profile)?;
        Ok(staged_profile)
    }

    fn exec(
        &self,
        paths: &PodPaths,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<ExecOutput, TransportError> {
        let output = run_waiting_out_a_busy_file(&paths.binary, args, env)?;
        Ok(ExecOutput {
            stdout: String::from_utf8(output.stdout)?,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
        })
    }

    fn download(&self, remote: &Path, local: &Path) -> Result<(), TransportError> {
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)?;
        }
        copy_recursively(remote, local)?;
        Ok(())
    }
}

/// A file copies as a file; a directory copies entry by entry — the
/// same-host reading of the SSH transport's `scp -r`.
fn copy_recursively(from: &Path, to: &Path) -> std::io::Result<()> {
    if std::fs::metadata(from)?.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_recursively(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else {
        std::fs::copy(from, to)?;
    }
    Ok(())
}

fn file_name(path: &Path) -> Result<&OsStr, TransportError> {
    path.file_name()
        .ok_or_else(|| TransportError::InvalidPath(path.to_path_buf()))
}

#[cfg(unix)]
fn mark_executable(path: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o111);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

/// How long to keep trying a binary the kernel calls busy, and how
/// often: about a tenth of a second, in 5 ms steps.
///
/// The window being waited out is the microseconds between another
/// thread's `fork` and its `exec`, so the first retry almost always
/// wins; a file something genuinely holds open for writing still fails,
/// and fails quickly enough that nobody is left wondering.
const BUSY_STEP: std::time::Duration = std::time::Duration::from_millis(5);

/// How many times [`BUSY_STEP`] is waited before the busy file is
/// reported as the error it is.
const BUSY_ATTEMPTS: u32 = 20;

/// Run `binary`, waiting out an `ETXTBSY` that says nothing about this
/// file.
///
/// **The kernel refuses to exec a file some process has open for
/// writing, and a forked child holds its parent's descriptors until it
/// execs.** This transport stages a binary and then runs it; anything
/// else in the process that spawns in the window between that write and
/// this exec leaves its child holding the descriptor, and the exec
/// fails with `Text file busy` for exactly as long as that child takes
/// to exec its own program. Nothing about the staged file is wrong, and
/// a run that reports it as a failure is reporting somebody else's
/// fork.
///
/// A long-lived `lm-provision mcp` serving two applies at once is the
/// shape that meets this in production: one call stages its binary
/// while the other spawns. The end-to-end suites meet it too, and hold
/// it off with a lock instead ([documented at length:
/// `lm-provision-cli/tests/common/mod.rs`]) — a lock works there
/// because those know every spawner in the process, and nothing here
/// does [measured: 2026-09-23, this crate's own unit suite lost 4 of
/// 120 parallel runs to it and none of 40 serial ones].
fn run_waiting_out_a_busy_file(
    binary: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> std::io::Result<std::process::Output> {
    for _ in 0..BUSY_ATTEMPTS {
        match Command::new(binary).args(args).envs(env).output() {
            Err(busy) if busy.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(BUSY_STEP);
            }
            other => return other,
        }
    }
    // One last attempt, so what a caller is told about a file that is
    // busy for good is the kernel's own error rather than this
    // function's account of having given up.
    Command::new(binary).args(args).envs(env).output()
}

#[cfg(not(unix))]
fn mark_executable(_path: &Path) -> Result<(), TransportError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-driver-local-exec-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn upload_copies_both_files_and_marks_the_binary_executable() {
        let source_dir = tmp_dir("upload-source");
        std::fs::create_dir_all(&source_dir).expect("create source dir");
        let binary_src = source_dir.join("fake-bin");
        std::fs::write(&binary_src, b"#!/bin/sh\necho hi\n").expect("write fake binary");
        let profile_src = source_dir.join("profile.lua");
        std::fs::write(&profile_src, b"return {}").expect("write profile");

        let staging = tmp_dir("upload-staging");
        let transport = LocalExecTransport::new(&staging);
        let paths = transport
            .upload(&binary_src, &profile_src)
            .expect("upload should succeed");

        assert_eq!(paths.binary, staging.join("fake-bin"));
        assert_eq!(paths.profile, staging.join("profile.lua"));
        assert!(paths.binary.exists());
        assert!(paths.profile.exists());

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&paths.binary)
            .expect("staged binary metadata")
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "staged binary should be executable");

        std::fs::remove_dir_all(&source_dir).ok();
        std::fs::remove_dir_all(&staging).ok();
    }

    #[test]
    fn upload_rejects_a_path_with_no_file_name() {
        let staging = tmp_dir("upload-invalid-path");
        let transport = LocalExecTransport::new(&staging);
        let err = transport
            .upload(Path::new("/"), Path::new("/also-root/"))
            .expect_err("a root path has no file_name()");
        assert!(matches!(err, TransportError::InvalidPath(_)));

        std::fs::remove_dir_all(&staging).ok();
    }

    /// [`Transport::download`] brings back a file as a file and a
    /// directory recursively — the same-host reading of `scp -r` the
    /// SSH transport ships (08 §Session steps pull-artifacts).
    #[test]
    fn download_copies_a_file_and_a_directory_recursively() {
        let pod = tmp_dir("download-pod");
        std::fs::create_dir_all(pod.join("out/nested")).expect("create pod dirs");
        std::fs::write(pod.join("run.log"), b"log line").expect("write file");
        std::fs::write(pod.join("out/a.png"), b"a").expect("write a");
        std::fs::write(pod.join("out/nested/b.png"), b"b").expect("write b");

        let local = tmp_dir("download-local");
        let transport = LocalExecTransport::new(tmp_dir("download-staging"));

        transport
            .download(&pod.join("run.log"), &local.join("pod/run.log"))
            .expect("a file downloads");
        assert_eq!(
            std::fs::read(local.join("pod/run.log")).expect("downloaded file readable"),
            b"log line"
        );

        transport
            .download(&pod.join("out"), &local.join("pod/out"))
            .expect("a directory downloads");
        assert_eq!(
            std::fs::read(local.join("pod/out/nested/b.png")).expect("nested entry survives"),
            b"b"
        );

        let err = transport
            .download(&pod.join("absent"), &local.join("pod/absent"))
            .expect_err("a missing remote is a transport error");
        assert!(matches!(err, TransportError::Io(_)));

        std::fs::remove_dir_all(&pod).ok();
        std::fs::remove_dir_all(&local).ok();
    }

    #[cfg(unix)]
    #[test]
    fn exec_captures_stdout_stderr_exit_code_and_exported_env() {
        let staging = tmp_dir("exec");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        let script = staging.join("script.sh");
        std::fs::write(
            &script,
            b"#!/bin/sh\necho \"out:$1\"\necho \"err:$MY_ENV_VAR\" 1>&2\nexit 7\n",
        )
        .expect("write script");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(perms.mode() | 0o111);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let transport = LocalExecTransport::new(&staging);
        let paths = PodPaths {
            binary: script.clone(),
            profile: staging.join("unused-profile.lua"),
        };
        let mut env = BTreeMap::new();
        env.insert("MY_ENV_VAR".to_string(), "secret-value".to_string());

        let output = transport
            .exec(&paths, &["hello".to_string()], &env)
            .expect("exec should run the staged script");

        assert_eq!(output.stdout, "out:hello\n");
        assert_eq!(output.stderr, "err:secret-value\n");
        assert_eq!(output.exit_code, Some(7));

        std::fs::remove_dir_all(&staging).ok();
    }

    /// **A binary something else still holds open for writing is waited
    /// out, not reported as a failure.** The hold here is deliberate and
    /// in this process; the one this guards against is another thread's
    /// forked child holding a descriptor it never asked for, which is
    /// the same refusal from the kernel and cannot be staged on purpose.
    #[cfg(unix)]
    #[test]
    fn exec_waits_out_a_binary_something_else_holds_open_for_writing() {
        let staging = tmp_dir("busy");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        let script = staging.join("script.sh");
        std::fs::write(&script, b"#!/bin/sh\necho ran\n").expect("write script");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(perms.mode() | 0o111);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        // Held open for writing for a fraction of the retry budget, then
        // closed: an exec that does not wait fails outright here.
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&script)
            .expect("hold the script open for writing");
        let holder = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            drop(held);
        });

        let transport = LocalExecTransport::new(&staging);
        let paths = PodPaths {
            binary: script.clone(),
            profile: staging.join("unused-profile.lua"),
        };
        let output = transport
            .exec(&paths, &[], &BTreeMap::new())
            .expect("a file held open for writing is waited out, not failed on");

        holder.join().expect("the holder thread");
        assert_eq!(output.stdout, "ran\n");
        assert_eq!(output.exit_code, Some(0));

        std::fs::remove_dir_all(&staging).ok();
    }
}
