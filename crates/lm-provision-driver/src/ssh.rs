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

use crate::transport::{ExecOutput, PodPaths, Transport, TransportError};

/// Remote user assumed when a caller does not name one (08 §Session
/// contract `ConnectionSpec`: "user (default root)" — RunPod pods run
/// as `root`).
///
/// The literal lives next to the transport it configures so the
/// driver CLI's `--ssh` fallback and any other caller that fills the
/// same hole (the MCP server's pod target registry) read one value
/// rather than repeating the string.
pub const DEFAULT_SSH_USER: &str = "root";

/// Remote directory uploads land in when a caller does not name one
/// (the driver CLI's `--remote-dir` default). Same single-source
/// rationale as [`DEFAULT_SSH_USER`].
pub const DEFAULT_REMOTE_DIR: &str = "/root";

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
    /// Where the connection-sharing control sockets live, when a
    /// directory for them could be made — see
    /// [`SshTransport::shared_options`]. `None` means every step
    /// dials its own connection, which is what this did before and
    /// still does wherever the directory cannot be created.
    ///
    /// Private because it is not part of the connection spec 08
    /// §Session contract names: it is where this host keeps a socket,
    /// not anything about the pod.
    control_dir: Option<PathBuf>,
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
            control_dir: prepared_control_dir(&default_control_dir()),
        }
    }

    /// Keep the control sockets in `dir` instead of the default one.
    ///
    /// The seam this module is tested through: a directory that cannot
    /// be made yields a transport with no multiplexing, and that is the
    /// fallback path a test has to be able to reach on purpose.
    pub fn with_control_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.control_dir = prepared_control_dir(dir.as_ref());
        self
    }

    fn target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Shared non-interactive options, in the one spelling both `ssh`
    /// and `scp` are given them. `BatchMode=yes` forbids any prompt (a
    /// wrong key fails loudly instead of hanging on a password
    /// prompt); host-key learning is accept-new so a fresh pod's first
    /// contact succeeds while a changed key still fails.
    ///
    /// The three `Control*` options share **one** TCP connection and
    /// one authentication across a session's steps: `ControlMaster=auto`
    /// reuses a live master if there is one and becomes the master
    /// otherwise, and `ControlPersist=60` keeps that master up for 60
    /// seconds after the last client exits, so the steps of one apply
    /// — and a command an operator runs straight after it — travel on
    /// the connection the first step opened [documented: OpenSSH
    /// `ssh_config(5)`, `ControlMaster` / `ControlPath` /
    /// `ControlPersist`].
    ///
    /// `%C` is the socket name rather than `%r@%h:%p`: it is a hash of
    /// exactly those fields, and a unix socket path has to fit in a
    /// `sockaddr_un`, which is around 104 bytes — a spelled-out host
    /// under a temporary directory can exceed that, and the failure
    /// mode is a connection that cannot be shared rather than a
    /// message about a path.
    ///
    /// Omitted entirely when no control directory could be made: this
    /// is an optimisation, and a transport that refused to run because
    /// it had nowhere to keep a socket would have traded the contract
    /// for the optimisation.
    fn shared_options(&self) -> Vec<String> {
        let mut options = vec![
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(),
        ];
        if let Some(dir) = &self.control_dir {
            options.extend([
                "-o".to_string(),
                "ControlMaster=auto".to_string(),
                "-o".to_string(),
                format!("ControlPath={}/%C", dir.display()),
                "-o".to_string(),
                "ControlPersist=60".to_string(),
            ]);
        }
        options
    }

    /// The `ssh` argv prefix: the port flag this program spells `-p`,
    /// the identity file, and [`shared_options`](Self::shared_options).
    fn base_ssh_args(&self) -> Vec<String> {
        let mut args = vec![
            "-p".to_string(),
            self.port.to_string(),
            "-i".to_string(),
            self.key_path.display().to_string(),
        ];
        args.extend(self.shared_options());
        args
    }

    /// The same, for `scp` — whose only difference is that it spells
    /// the port `-P`. Built from one source with the above so an option
    /// added for the session's `ssh` steps cannot go missing from its
    /// two file transfers, which is how the three multiplexing options
    /// would otherwise have been spelled three times.
    fn base_scp_args(&self) -> Vec<String> {
        let mut args = vec![
            "-P".to_string(),
            self.port.to_string(),
            "-i".to_string(),
            self.key_path.display().to_string(),
        ];
        args.extend(self.shared_options());
        args
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

    /// Send a local file or directory to `remote` — the push half of
    /// the pair whose pull half is [`Transport::download`].
    ///
    /// Public because it is also `lm-provision cp`'s local-to-pod
    /// direction; the session's own steps 0 and 1 reach it through
    /// [`Transport::ensure_binary`] / [`Transport::place_profile`],
    /// which is where the idempotency and the remote directory are
    /// decided.
    pub fn upload(&self, local: &Path, remote: &Path) -> Result<(), TransportError> {
        let output = Command::new("scp")
            .args(self.base_scp_args())
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

    /// Run `remote_command` on the pod with this process's own stdin,
    /// stdout and stderr, and give back the exit code it ended with
    /// (`None` when a signal ended it).
    ///
    /// The operator-verb surface, and deliberately **not** a
    /// [`Transport`] method: that trait is the session contract's seam
    /// (08 §Session steps), and `logs` / `exec` are not session steps
    /// — nothing here is collected, recorded or compared. What they
    /// need is the opposite of what a step needs: the pod's output is
    /// the operator's terminal as it is produced, not a string to
    /// capture and re-print afterwards, which is what makes `tail -f`
    /// and an interactive command work at all. Inherited stdin is the
    /// same decision from the other side — `… -- sh -s < script`
    /// feeds the pod from the operator's shell.
    ///
    /// The exit code is the remote command's, with one overload that
    /// is not ours to remove: **255 is `ssh`'s own failure** (it could
    /// not connect, or authenticate), and a remote command exiting 255
    /// is indistinguishable from it [documented: OpenSSH `ssh(1)`,
    /// EXIT STATUS]. It rides through unchanged rather than being
    /// remapped, so a caller reads the same number `ssh` itself would
    /// have handed them.
    ///
    /// [`base_ssh_args`](Self::base_ssh_args) is shared with the
    /// session's steps, so a verb run just after an apply travels on
    /// the connection that apply opened, and `BatchMode=yes` still
    /// forbids a password prompt.
    pub fn attach(&self, remote_command: &str) -> Result<Option<i32>, TransportError> {
        let status = Command::new("ssh")
            .args(self.base_ssh_args())
            .arg(self.target())
            .arg("--")
            .arg(remote_command)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        Ok(status.code())
    }

    /// `argv` as one remote command string: every word quoted for the
    /// remote shell, joined with spaces.
    ///
    /// `ssh` concatenates the words it is given and hands the result
    /// to the remote login shell [documented: OpenSSH `ssh(1)`], so a
    /// word carrying a space, a quote or a `$` has to be quoted
    /// before it goes on the wire — there is no argv-preserving form
    /// to fall back on. Every caller that builds one goes through
    /// here: the session's own `exec`, and the operator verbs, which
    /// quote what the operator typed after `--`.
    pub fn remote_command(argv: &[String]) -> String {
        argv.iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ")
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
        // `lm_provision::digest` is the workspace's one content-digest
        // implementation, shared with the profile hash and the Assert
        // model's content predicate. This module used to carry its own
        // `format!("{:x}")` spelling of the same thing — the same
        // judgement written twice, which is what 08's "compare the
        // pod-side sha256 to the local artifact's" needs exactly one
        // of. It also streams, so the artifact is not read into memory
        // whole.
        let local_sha = crate::local_digest(local_binary)?;
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
            self.upload(local_binary, &dest)?;
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
        self.upload(local_profile, &dest)?;
        Ok(dest)
    }

    fn download(&self, remote: &Path, local: &Path) -> Result<(), TransportError> {
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // `-r` unconditionally: a remote directory needs it, and scp
        // copies a plain file identically with or without it — so the
        // driver does not have to ask the pod what the path is first.
        let output = Command::new("scp")
            .arg("-r")
            .args(self.base_scp_args())
            .arg(format!("{}:{}", self.target(), remote.display()))
            .arg(local)
            .output()?;
        if !output.status.success() {
            return Err(TransportError::Io(std::io::Error::other(format!(
                "scp {} -> {} exited with {:?}: {}",
                remote.display(),
                local.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ))));
        }
        Ok(())
    }

    fn exec(
        &self,
        paths: &PodPaths,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<ExecOutput, TransportError> {
        if env.is_empty() {
            // No secrets: a plain remote command, every word quoted.
            self.run_ssh(&Self::remote_command(&invocation(paths, args)), None)
        } else {
            // Secrets present: the whole invocation travels on stdin
            // to a remote `sh -s` (08 §Secret delivery — values never
            // enter any argv, local or remote).
            let script = stdin_script(paths, args, env);
            self.run_ssh("sh -s", Some(script.as_bytes()))
        }
    }
}

/// Where the control sockets go when nothing names a directory:
/// `$XDG_RUNTIME_DIR/lm-provision` when the session has a runtime
/// directory, else a per-user directory under the system temporary
/// one.
///
/// The runtime directory first because that is what it is for — a
/// per-user, per-session directory the system owns and cleans up
/// [documented: freedesktop.org Base Directory Specification,
/// `XDG_RUNTIME_DIR`]. The fallback carries the user in its name
/// rather than sharing one path: a socket in a world-writable
/// directory that another account could have created first is not one
/// to dial a pod over.
fn default_control_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime) if !runtime.is_empty() => PathBuf::from(runtime).join("lm-provision"),
        _ => std::env::temp_dir().join(format!("lm-provision-ssh-{}", user_tag())),
    }
}

/// The current user's name, reduced to characters that are safe in a
/// path component, or `anon` when the environment does not say.
///
/// Only a name for a directory: nothing is authorized by it, so an
/// environment that lies about it costs a shared control socket and
/// nothing else.
fn user_tag() -> String {
    let named = std::env::var("USER").unwrap_or_default();
    let tag: String = named
        .chars()
        .filter(|it| it.is_ascii_alphanumeric() || *it == '-' || *it == '_')
        .take(32)
        .collect();
    if tag.is_empty() {
        "anon".to_string()
    } else {
        tag
    }
}

/// `dir`, made if it is not there and restricted to its owner, or
/// `None` if either could not be done.
///
/// `0700` because a control socket is a live, already-authenticated
/// connection to the pod: anything that can open it can run commands
/// there without holding the key. OpenSSH itself refuses a
/// `ControlPath` directory it considers too open, so this is the
/// permission the option was going to require anyway.
///
/// `None` rather than an error, at every step: the caller falls back
/// to one connection per step, which is what this did before
/// multiplexing existed.
fn prepared_control_dir(dir: &Path) -> Option<PathBuf> {
    // Fails when the path is an existing non-directory, which is how a
    // test reaches the fallback without needing a read-only filesystem.
    std::fs::create_dir_all(dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    Some(dir.to_path_buf())
}

/// POSIX single-quote escaping: wraps in `'...'`, spelling an embedded
/// `'` as `'\''`. Total for any byte string without NUL.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The provisioner invocation as unquoted words: the pod-side binary
/// path, then the subcommand's arguments. Quoting is
/// [`SshTransport::remote_command`]'s, in both spellings of the
/// invocation (plain remote command and `sh -s` script), so the two
/// cannot come to disagree about a word with a quote in it.
fn invocation(paths: &PodPaths, args: &[String]) -> Vec<String> {
    let mut words = vec![paths.binary.display().to_string()];
    words.extend(args.iter().cloned());
    words
}

/// The remote `sh -s` script: one `export` per env entry, then `exec`
/// of the binary — values appear only inside this stdin payload.
fn stdin_script(paths: &PodPaths, args: &[String], env: &BTreeMap<String, String>) -> String {
    let mut script = String::new();
    for (name, value) in env {
        script.push_str(&format!("export {}={}\n", name, shell_quote(value)));
    }
    script.push_str(&format!(
        "exec {}\n",
        SshTransport::remote_command(&invocation(paths, args))
    ));
    script
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

    /// **What the operator typed reaches the pod as they typed it.**
    /// `ssh` hands the words it is given to a remote shell, so a word
    /// with a space, a quote or a `$` in it is the difference between
    /// one argument and three — or between a literal and whatever the
    /// pod's environment happens to hold.
    #[test]
    fn remote_command_quotes_every_word_for_the_remote_shell() {
        let words = |it: &[&str]| it.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        assert_eq!(
            SshTransport::remote_command(&words(&["echo", "it's", "a b"])),
            "'echo' 'it'\\''s' 'a b'"
        );
        assert_eq!(
            SshTransport::remote_command(&words(&["echo", "$HOME"])),
            "'echo' '$HOME'",
            "the pod's shell must not expand a word the operator quoted"
        );
        assert_eq!(SshTransport::remote_command(&[]), "");
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

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-ssh-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("the temp directory is writable");
        dir
    }

    /// **One connection, and both programs asked for the same one.**
    /// The session's steps alternate between `ssh` and `scp`, so a
    /// control path spelled only on the first would leave the file
    /// transfers dialing and authenticating on their own — which is
    /// most of the handshakes an apply pays for.
    #[test]
    fn ssh_and_scp_are_given_the_same_shared_connection() {
        let dir = scratch("shared");
        let control = dir.join("control");
        let t = SshTransport::new("h", 2222, "root", "/k", "/root").with_control_dir(&control);

        let ssh = t.base_ssh_args();
        let scp = t.base_scp_args();
        let expected_path = format!("ControlPath={}/%C", control.display());
        for args in [&ssh, &scp] {
            assert!(args.contains(&"ControlMaster=auto".to_string()), "{args:?}");
            assert!(args.contains(&expected_path), "{args:?}");
            assert!(args.contains(&"ControlPersist=60".to_string()), "{args:?}");
        }
        assert_eq!(
            ssh[..2],
            ["-p".to_string(), "2222".to_string()],
            "ssh spells the port -p: {ssh:?}"
        );
        assert_eq!(
            scp[..2],
            ["-P".to_string(), "2222".to_string()],
            "scp spells the same port -P: {scp:?}"
        );
        assert_eq!(
            ssh[2..],
            scp[2..],
            "the port flag is the only difference between them"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The directory holding the sockets is the owner's alone: anything
    /// that can open one runs commands on the pod without holding the
    /// key.
    #[test]
    fn the_control_directory_is_created_for_its_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch("mode");
        let control = dir.join("nested/control");
        let t = SshTransport::new("h", 22, "root", "/k", "/root").with_control_dir(&control);

        assert!(
            t.base_ssh_args()
                .iter()
                .any(|it| it.starts_with("ControlPath=")),
            "a directory that could be made is one to share over"
        );
        let mode = std::fs::metadata(&control)
            .expect("the directory was created")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "mode {mode:o}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// **Nowhere to keep a socket is not a reason to refuse the pod.**
    /// Multiplexing is an optimisation; the transport falls back to one
    /// connection per step and says nothing about it, which is what it
    /// did before the options existed.
    #[test]
    fn a_control_directory_that_cannot_be_made_costs_the_sharing_and_nothing_else() {
        let dir = scratch("fallback");
        // A plain file where the directory would go: `create_dir_all`
        // cannot make this one.
        let occupied = dir.join("not-a-directory");
        std::fs::write(&occupied, b"").expect("the temp directory is writable");

        let t = SshTransport::new("h", 22, "root", "/k", "/root").with_control_dir(&occupied);
        let ssh = t.base_ssh_args();
        let scp = t.base_scp_args();
        for args in [&ssh, &scp] {
            assert!(
                !args.iter().any(|it| it.starts_with("ControlMaster")),
                "{args:?}"
            );
            assert!(
                !args.iter().any(|it| it.starts_with("ControlPath")),
                "{args:?}"
            );
            assert!(
                args.contains(&"BatchMode=yes".to_string()),
                "the non-interactive options are not the optional part: {args:?}"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
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
