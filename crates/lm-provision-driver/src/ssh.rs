//! [`SshTransport`]: the SSH realization of the session contract's
//! transport seam (08-push-driver-protocol.md §Session steps /
//! §Secret delivery). Wraps the operator host's `ssh` / `scp`
//! binaries — no in-process SSH library, matching the crate's
//! dependency posture; the two commands are operator-host
//! prerequisites the way `apt-get` / `pip` are pod prerequisites of a
//! profile (08 §Inputs).
//!
//! Two contract points this module is load-bearing for:
//!
//! - **Key material is explicit.** The identity file is a required
//!   constructor argument and is always passed as `-i`; there is no
//!   fallback to the user's default key. (First real-pod usage lost a
//!   round trip to a default-key mismatch — an explicit key turns
//!   that silent wrong-guess into a visible input.)
//! - **Secrets travel on stdin** (08 §Secret delivery). When `exec`
//!   receives a non-empty env map, the whole remote invocation —
//!   `export` lines and the final `exec` — is written to a remote
//!   `sh -s` over the ssh channel's stdin. Embedding `NAME=value` in
//!   the remote command string would land the value in the driver
//!   host's process list and shell history; that spelling is
//!   non-conforming and deliberately not implemented.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest as _, Sha256};

use crate::transport::{ExecOutput, PodPaths, Transport, TransportError};

/// SSH connection spec (08 §Session contract `ConnectionSpec`).
#[derive(Debug, Clone)]
pub struct SshTransport {
    /// Target host (name or address).
    pub host: String,
    /// TCP port the pod's sshd listens on (RunPod exposes a
    /// per-pod external port mapped to container port 22).
    pub port: u16,
    /// Remote user (RunPod pods run as `root`).
    pub user: String,
    /// Identity file, explicit and mandatory — never a default-key
    /// guess.
    pub key_path: PathBuf,
    /// Remote directory the binary and profile land in.
    pub remote_dir: PathBuf,
}

impl SshTransport {
    /// Build a transport for `user@host:port` with the mandatory
    /// identity file, staging uploads under `remote_dir`.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        key_path: impl Into<PathBuf>,
        remote_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            key_path: key_path.into(),
            remote_dir: remote_dir.into(),
        }
    }

    fn target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Shared non-interactive options. `BatchMode=yes` forbids any
    /// prompt (a wrong key fails loudly instead of hanging on a
    /// password prompt); host-key learning is accept-new so a fresh
    /// pod's first contact succeeds while a changed key still fails.
    fn base_ssh_args(&self) -> Vec<String> {
        vec![
            "-p".into(),
            self.port.to_string(),
            "-i".into(),
            self.key_path.display().to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
        ]
    }

    fn run_ssh(
        &self,
        remote_command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, TransportError> {
        let mut cmd = Command::new("ssh");
        cmd.args(self.base_ssh_args())
            .arg(self.target())
            .arg("--")
            .arg(remote_command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = cmd.spawn()?;
        if let Some(bytes) = stdin {
            child
                .stdin
                .take()
                .expect("stdin was requested piped above")
                .write_all(bytes)?;
            // Drop closes the pipe so the remote `sh -s` sees EOF.
        }
        let output = child.wait_with_output()?;
        Ok(ExecOutput {
            stdout: String::from_utf8(output.stdout)?,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
        })
    }

    fn scp(&self, local: &Path, remote: &Path) -> Result<(), TransportError> {
        let output = Command::new("scp")
            .args([
                "-P",
                &self.port.to_string(),
                "-i",
                &self.key_path.display().to_string(),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ])
            .arg(local)
            .arg(format!("{}:{}", self.target(), remote.display()))
            .output()?;
        if !output.status.success() {
            return Err(TransportError::Io(std::io::Error::other(format!(
                "scp {} -> {} exited with {:?}: {}",
                local.display(),
                remote.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ))));
        }
        Ok(())
    }

    fn file_name(path: &Path) -> Result<&std::ffi::OsStr, TransportError> {
        path.file_name()
            .ok_or_else(|| TransportError::InvalidPath(path.to_path_buf()))
    }
}

impl Transport for SshTransport {
    fn dest_binary(&self, local_binary: &Path) -> Result<PathBuf, TransportError> {
        Ok(self.remote_dir.join(Self::file_name(local_binary)?))
    }

    fn dest_profile(&self, local_profile: &Path) -> Result<PathBuf, TransportError> {
        Ok(self.remote_dir.join(Self::file_name(local_profile)?))
    }

    fn ensure_binary(&self, local_binary: &Path) -> Result<PathBuf, TransportError> {
        let dest = self.dest_binary(local_binary)?;
        let local_sha = hex_sha256(&std::fs::read(local_binary)?);
        // `sha256sum` prints `<hex>  <path>`; a missing file exits
        // non-zero, which reads as "not identical" — exactly the
        // trigger for a push. Idempotency rule: 08 §Session steps
        // "the pod-side sha256 is compared to the local artifact's;
        // identical → no-op".
        let probe = self.run_ssh(
            &format!(
                "sha256sum {} 2>/dev/null",
                shell_quote(&dest.display().to_string())
            ),
            None,
        )?;
        let remote_sha = probe
            .stdout
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        if probe.exit_code != Some(0) || remote_sha != local_sha {
            self.run_ssh(
                &format!(
                    "mkdir -p {}",
                    shell_quote(&self.remote_dir.display().to_string())
                ),
                None,
            )?;
            self.scp(local_binary, &dest)?;
        }
        let chmod = self.run_ssh(
            &format!("chmod +x {}", shell_quote(&dest.display().to_string())),
            None,
        )?;
        if chmod.exit_code != Some(0) {
            return Err(TransportError::Io(std::io::Error::other(format!(
                "chmod +x {} failed: {}",
                dest.display(),
                chmod.stderr
            ))));
        }
        Ok(dest)
    }

    fn place_profile(&self, local_profile: &Path) -> Result<PathBuf, TransportError> {
        let dest = self.dest_profile(local_profile)?;
        self.run_ssh(
            &format!(
                "mkdir -p {}",
                shell_quote(&self.remote_dir.display().to_string())
            ),
            None,
        )?;
        self.scp(local_profile, &dest)?;
        Ok(dest)
    }

    fn exec(
        &self,
        paths: &PodPaths,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<ExecOutput, TransportError> {
        if env.is_empty() {
            // No secrets: a plain remote command, every word quoted.
            let mut words = vec![shell_quote(&paths.binary.display().to_string())];
            words.extend(args.iter().map(|a| shell_quote(a)));
            self.run_ssh(&words.join(" "), None)
        } else {
            // Secrets present: the whole invocation travels on stdin
            // to a remote `sh -s` (08 §Secret delivery — values never
            // enter any argv, local or remote).
            let script = stdin_script(paths, args, env);
            self.run_ssh("sh -s", Some(script.as_bytes()))
        }
    }
}

/// POSIX single-quote escaping: wraps in `'...'`, spelling an embedded
/// `'` as `'\''`. Total for any byte string without NUL.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The remote `sh -s` script: one `export` per env entry, then `exec`
/// of the binary — values appear only inside this stdin payload.
fn stdin_script(paths: &PodPaths, args: &[String], env: &BTreeMap<String, String>) -> String {
    let mut script = String::new();
    for (name, value) in env {
        script.push_str(&format!("export {}={}\n", name, shell_quote(value)));
    }
    let mut words = vec![shell_quote(&paths.binary.display().to_string())];
    words.extend(args.iter().map(|a| shell_quote(a)));
    script.push_str(&format!("exec {}\n", words.join(" ")));
    script
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_wraps_and_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$HOME `x` \"y\""), "'$HOME `x` \"y\"'");
    }

    #[test]
    fn stdin_script_exports_then_execs_and_never_puts_values_in_argv_form() {
        let paths = PodPaths {
            binary: PathBuf::from("/root/lm-provision"),
            profile: PathBuf::from("/root/profile.json"),
        };
        let mut env = BTreeMap::new();
        env.insert("HF_TOKEN".to_string(), "sec'ret".to_string());
        let script = stdin_script(
            &paths,
            &["apply".to_string(), "/root/profile.json".to_string()],
            &env,
        );
        assert_eq!(
            script,
            "export HF_TOKEN='sec'\\''ret'\nexec '/root/lm-provision' 'apply' '/root/profile.json'\n"
        );
    }

    #[test]
    fn dest_paths_join_the_remote_dir_with_the_local_file_name() {
        let t = SshTransport::new("h", 22, "root", "/k", "/root");
        assert_eq!(
            t.dest_binary(Path::new("/local/target/lm-provision"))
                .unwrap(),
            PathBuf::from("/root/lm-provision")
        );
        assert_eq!(
            t.dest_profile(Path::new("p.json")).unwrap(),
            PathBuf::from("/root/p.json")
        );
    }
}
