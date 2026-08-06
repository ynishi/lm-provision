//! Pod target registry: the server-side table that binds a `pod_id` to
//! the place an apply actually runs.
//!
//! `lm_apply`'s `pod_id` is 09 §Ledger's provisioning context — a
//! caller-supplied string the ledger stamps verbatim. Until this module
//! existed it selected nothing: every apply ran against the same local
//! staging directory, so a ledger row saying "pod-abc123" recorded an
//! unchecked claim rather than an observed destination. The registry
//! turns that string into a lookup: a `pod_id` with no entry resolves
//! to nothing and the apply never starts.
//!
//! Two types, deliberately not one:
//!
//! ```text
//! TargetSpec (decode) --into_resolved(default_staging_dir)--> PodTarget
//! ```
//!
//! `TargetSpec` (private to this module) is what the registry file
//! spells; [`PodTarget`] is
//! what the registry hands out. Folding them together would keep
//! "not yet resolved" (absent `user`, absent `staging_dir`) expressible
//! after resolution, which is the state this module exists to remove.
//!
//! The registry file is read once at startup ([`crate::config`]); the
//! connection fields mirror 08 §Session contract's `ConnectionSpec`
//! (`host` / `port` / `user` / `key_path`) so an entry is exactly the
//! input [`SshTransport`] needs. Connection details stay out of the
//! tool arguments: those are written by the MCP client, and a
//! hallucinated host there would be the same unchecked destination in a
//! new place.

use std::fmt;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use lm_provision_driver::local_exec::LocalExecTransport;
use lm_provision_driver::ssh::{SshTransport, DEFAULT_REMOTE_DIR, DEFAULT_SSH_USER};
use lm_provision_driver::transport::Transport;
use serde::Deserialize;
use serde_json::value::RawValue;

/// Where a [`TargetRegistry`]'s contents came from, carried so an error
/// can name the file an operator has to edit.
///
/// [`RegistrySource::Unset`] has no path to name, so its message names
/// the environment variable instead rather than filling the hole with
/// an empty string or a `<unset>` placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrySource {
    /// Loaded from the file [`crate::config::TARGETS_PATH_ENV`] points
    /// at.
    FromFile(PathBuf),
    /// [`crate::config::TARGETS_PATH_ENV`] was not set: the registry is
    /// empty and every `pod_id` is unknown.
    Unset,
}

impl fmt::Display for RegistrySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FromFile(path) => write!(f, "registry file {}", path.display()),
            Self::Unset => write!(
                f,
                "{} is not set, so no pod targets are registered",
                crate::config::TARGETS_PATH_ENV
            ),
        }
    }
}

/// The registry file's top level: `{ "targets": [ ... ] }`.
///
/// An array, not a `pod_id`-keyed object: a duplicate key in an object
/// is silently resolved last-wins by any JSON decoder, which would put
/// an unchecked destination *inside* the registry.
///
/// The same hole exists one level in, and is closed the same way.
/// Entries are held as [`RawValue`] — the entry's JSON text, undecoded —
/// rather than [`serde_json::Value`], because building a `Value` means
/// building a map, and a map collapses a repeated `"host"` within one
/// entry last-wins before `TargetSpec` ever sees it. Keeping the text
/// lets [`serde_json::from_str`] drive the derived `Deserialize`
/// directly, which rejects a repeated field as `duplicate field`. The
/// text is also still readable for the `pod_id` an error has to name
/// (see [`declared_pod_id`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    targets: Vec<Box<RawValue>>,
}

/// One registry entry as written in the file — decode only.
///
/// `#[serde(deny_unknown_fields)]` is load-bearing: a misspelled
/// `keypath` / `remoteDir` that decoded silently would leave the
/// documented default in force while the operator believes the written
/// value applies.
///
/// ```json
/// { "pod_id": "dev-local", "kind": "local-exec", "staging_dir": "/tmp/lm-staging" }
/// { "pod_id": "pod-abc123", "kind": "ssh", "host": "pod.example.com",
///   "port": 21001, "user": "root", "key_path": "/path/to/key",
///   "remote_dir": "/root" }
/// ```
///
/// Path values are literal: neither `~` nor environment variables are
/// expanded. Kept private so no caller outside this module can hold an
/// unresolved target.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum TargetSpec {
    /// Runs on the MCP server's own host (`LocalExecTransport`).
    LocalExec {
        /// Registry key, matched against `lm_apply`'s `pod_id`.
        pod_id: String,
        /// Staging directory; defaults to the server's
        /// [`crate::config::Config::staging_dir`].
        #[serde(default)]
        staging_dir: Option<PathBuf>,
    },
    /// Runs on a remote pod over SSH (08 §Session contract
    /// `ConnectionSpec`).
    Ssh {
        /// Registry key, matched against `lm_apply`'s `pod_id`.
        pod_id: String,
        /// Target host (name or address).
        host: String,
        /// TCP port of the pod's sshd. Mandatory and non-zero: RunPod
        /// maps a per-pod external port, so there is no useful default
        /// (`driver/src/main.rs` says the same for `--ssh`), and
        /// [`NonZeroU16`] makes both "absent" and `0` decode failures
        /// instead of runtime checks.
        port: NonZeroU16,
        /// Remote user; defaults to [`DEFAULT_SSH_USER`].
        #[serde(default)]
        user: Option<String>,
        /// Identity file. Mandatory — `driver/src/ssh.rs` refuses to
        /// fall back to the operator's default key, and the registry
        /// does not reintroduce that guess.
        key_path: PathBuf,
        /// Remote directory uploads land in; defaults to
        /// [`DEFAULT_REMOTE_DIR`].
        #[serde(default)]
        remote_dir: Option<PathBuf>,
    },
}

impl TargetSpec {
    /// Apply the documented defaults, producing a [`PodTarget`] plus
    /// the `pod_id` it is registered under. The one place defaults are
    /// filled in — after this call nothing about a target is implicit.
    fn into_resolved(
        self,
        default_staging_dir: &Path,
    ) -> Result<(String, PodTarget), TargetLoadError> {
        match self {
            TargetSpec::LocalExec {
                pod_id,
                staging_dir,
            } => Ok((
                pod_id,
                PodTarget::LocalExec {
                    staging_dir: staging_dir.unwrap_or_else(|| default_staging_dir.to_path_buf()),
                },
            )),
            TargetSpec::Ssh {
                pod_id,
                host,
                port,
                user,
                key_path,
                remote_dir,
            } => {
                // serde types cannot express "non-empty"; an empty host
                // would otherwise reach `ssh` as `user@` and fail at
                // connect time, far from the file that caused it.
                if host.trim().is_empty() {
                    return Err(TargetLoadError::Invalid {
                        pod_id,
                        reason: "host is empty".to_string(),
                    });
                }
                Ok((
                    pod_id,
                    PodTarget::Ssh(SshTransport::new(
                        host,
                        port.get(),
                        user.unwrap_or_else(|| DEFAULT_SSH_USER.to_string()),
                        key_path,
                        remote_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_REMOTE_DIR)),
                    )),
                ))
            }
        }
    }
}

/// A resolved execution target: every default already applied.
///
/// The two variants are deliberately asymmetric.
/// [`SshTransport`] is `Clone` with public fields, so the SSH variant
/// holds the driver's own type — writing a parallel struct here would
/// put its field list in two places. [`LocalExecTransport`] keeps its
/// staging directory private and is neither `Debug` nor `Clone`, so the
/// local variant holds what its constructor needs instead. Neither
/// shape is worth changing the driver crate for.
#[derive(Debug, Clone)]
pub enum PodTarget {
    /// A remote pod reached over SSH.
    Ssh(SshTransport),
    /// The MCP server's own host, staging under this directory.
    LocalExec {
        /// Where uploads are staged (already defaulted at load time).
        staging_dir: PathBuf,
    },
}

impl PodTarget {
    /// Build the [`Transport`] this target denotes.
    ///
    /// Infallible: a resolved target is a 1:1 image of a transport
    /// constructor's arguments, so the only thing that can fail is the
    /// lookup ([`TargetRegistry::resolve`]) that produced it. Named
    /// `to_` rather than `into_` because it borrows —
    /// `clippy::wrong_self_convention` (warn by default) rejects an
    /// `into_*` taking `&self`.
    pub fn to_transport(&self) -> Box<dyn Transport> {
        match self {
            Self::Ssh(transport) => Box::new(transport.clone()),
            Self::LocalExec { staging_dir } => {
                Box::new(LocalExecTransport::new(staging_dir.clone()))
            }
        }
    }
}

/// Errors raised while loading a registry — startup only, wrapped by
/// [`crate::config::ConfigError`].
///
/// Separate from [`TargetResolveError`] on purpose: a load failure can
/// only be observed by the code that reads the file, and a resolve
/// failure only by the code serving a tool call. One shared type would
/// force each site to handle variants it cannot produce.
///
/// No message *this module* raises carries a connection detail (`host`
/// / `user` / `key_path`): these strings travel to an MCP client, and
/// naming the offending entry is all the client needs to be told.
///
/// The guarantee stops at this module's own boundary. Once a resolved
/// [`PodTarget`] is handed to the driver, a transport-level failure
/// relays the underlying `ssh` / `scp` stderr verbatim
/// ([`lm_provision_driver::ssh`]), and those tools name the host, the
/// user, and the identity file in their own diagnostics — so an
/// `lm_apply` that fails *while connecting* does surface connection
/// details to the caller. Redacting there would have to happen in the
/// driver crate, which this unit deliberately does not touch; it is
/// recorded as a known limitation rather than papered over here.
#[derive(Debug, thiserror::Error)]
pub enum TargetLoadError {
    /// The file, or one entry in it, did not decode: unknown `kind`,
    /// unknown field, missing `port` / `key_path`, `port: 0`, wrong
    /// type. `pod_id` is `None` only when the top level itself is
    /// malformed — entries are decoded one at a time precisely so the
    /// rest can be named.
    ///
    /// The field is `registry`, not `source`: `thiserror` treats a
    /// field named `source` as the error's `source()` and would require
    /// [`RegistrySource`] to implement `std::error::Error`.
    #[error("{registry}: {} failed to decode: {error}", entry_label(.pod_id.as_deref()))]
    Decode {
        /// The entry's `pod_id`, when the file was structured enough to
        /// read one.
        pod_id: Option<String>,
        /// Where the registry came from.
        registry: RegistrySource,
        /// The underlying decode failure.
        #[source]
        error: serde_json::Error,
    },

    /// An entry decoded but is not usable as written.
    #[error("target entry '{pod_id}' is invalid: {reason}")]
    Invalid {
        /// The offending entry's `pod_id`.
        pod_id: String,
        /// What is wrong with it.
        reason: String,
    },

    /// The same `pod_id` appears twice. Rejected rather than resolved
    /// last-wins: silently picking one of two declared destinations is
    /// the unchecked-target hole reappearing inside the registry.
    #[error("pod_id '{0}' is registered more than once")]
    DuplicatePodId(String),
}

/// The only way a `pod_id` fails at request time (10 §Error surface's
/// precondition class).
#[derive(Debug, thiserror::Error)]
pub enum TargetResolveError {
    /// No entry matches. The message names the `pod_id`, where the
    /// registry came from, and which ids *are* registered — enough to
    /// fix the call or the file, and nothing about how to reach a pod.
    #[error(
        "unknown pod_id '{pod_id}' ({registry}); registered pod_ids: {}",
        registered_label(.registered)
    )]
    UnknownPod {
        /// The `pod_id` the tool call asked for.
        pod_id: String,
        /// Where the registry came from (see [`TargetLoadError::Decode`]
        /// for why the field is not named `source`).
        registry: RegistrySource,
        /// Every registered `pod_id`, in file order.
        registered: Vec<String>,
    },
}

/// Startup-loaded `pod_id` → [`PodTarget`] table.
///
/// Immutable once built: there is no reload path, so adding a pod means
/// editing the file and restarting the server (documented in the
/// README). Held in declaration order — the table is a handful of
/// entries, and order makes the "registered pod_ids" list in an error
/// match the file an operator is reading.
#[derive(Debug, Clone)]
pub struct TargetRegistry {
    source: RegistrySource,
    targets: Vec<(String, PodTarget)>,
}

impl TargetRegistry {
    /// Decode `json` and apply every default, or fail.
    ///
    /// `default_staging_dir` is the server's
    /// [`crate::config::Config::staging_dir`], used for `local-exec`
    /// entries that do not name one. Decoding stops at the first bad
    /// entry rather than collecting all of them: this runs at startup,
    /// where the operator's loop is "fix one, restart".
    pub fn load(
        source: RegistrySource,
        json: &str,
        default_staging_dir: &Path,
    ) -> Result<Self, TargetLoadError> {
        let file: RegistryFile =
            serde_json::from_str(json).map_err(|error| TargetLoadError::Decode {
                pod_id: None,
                registry: source.clone(),
                error,
            })?;

        let mut targets: Vec<(String, PodTarget)> = Vec::with_capacity(file.targets.len());
        for entry in file.targets {
            // Read the id before decoding the entry, so a decode
            // failure can still say which entry failed.
            let label_pod_id = declared_pod_id(entry.get());
            let spec: TargetSpec =
                serde_json::from_str(entry.get()).map_err(|error| TargetLoadError::Decode {
                    pod_id: label_pod_id,
                    registry: source.clone(),
                    error,
                })?;
            let (pod_id, target) = spec.into_resolved(default_staging_dir)?;
            if targets.iter().any(|(known, _)| known == &pod_id) {
                return Err(TargetLoadError::DuplicatePodId(pod_id));
            }
            targets.push((pod_id, target));
        }

        Ok(Self { source, targets })
    }

    /// A registry with no entries — every `pod_id` is unknown. Used when
    /// [`crate::config::TARGETS_PATH_ENV`] is unset (there is no
    /// fallback to the pre-registry behaviour of running everything
    /// locally).
    pub fn empty(source: RegistrySource) -> Self {
        Self {
            source,
            targets: Vec::new(),
        }
    }

    /// Look up the target a `pod_id` denotes.
    pub fn resolve(&self, pod_id: &str) -> Result<&PodTarget, TargetResolveError> {
        self.targets
            .iter()
            .find(|(known, _)| known == pod_id)
            .map(|(_, target)| target)
            .ok_or_else(|| TargetResolveError::UnknownPod {
                pod_id: pod_id.to_string(),
                registry: self.source.clone(),
                registered: self.targets.iter().map(|(id, _)| id.clone()).collect(),
            })
    }
}

/// Read an entry's `pod_id` out of its raw JSON text, for labelling an
/// error only.
///
/// Deliberately best-effort and deliberately not the decode path: it
/// goes through [`serde_json::Value`], so a repeated `"pod_id"` is read
/// last-wins here. That is harmless because the entry is decoded
/// separately in [`TargetRegistry::load`], where the repetition is a
/// `duplicate field` failure — this function only picks the name that
/// failure is reported under. Returns `None` when the entry is not an
/// object, or has no string `pod_id`, in which case
/// [`entry_label`] names the file instead of inventing an id.
fn declared_pod_id(raw_entry: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(raw_entry)
        .ok()?
        .get("pod_id")?
        .as_str()
        .map(str::to_string)
}

/// Name what failed in a [`TargetLoadError::Decode`] message: the
/// entry, when the file was structured enough to read its `pod_id`, or
/// the file itself.
fn entry_label(pod_id: Option<&str>) -> String {
    match pod_id {
        Some(pod_id) => format!("target entry '{pod_id}'"),
        None => "the file itself".to_string(),
    }
}

/// Render the registered-id list of a [`TargetResolveError::UnknownPod`]
/// message.
fn registered_label(registered: &[String]) -> String {
    if registered.is_empty() {
        "none".to_string()
    } else {
        registered.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY_PATH: &str = "/etc/lm-provision/targets.json";
    const DEFAULT_STAGING: &str = "/var/tmp/lm-provision-default-staging";

    fn from_file() -> RegistrySource {
        RegistrySource::FromFile(PathBuf::from(REGISTRY_PATH))
    }

    fn load(json: &str) -> Result<TargetRegistry, TargetLoadError> {
        TargetRegistry::load(from_file(), json, Path::new(DEFAULT_STAGING))
    }

    fn ssh_of(target: &PodTarget) -> &SshTransport {
        match target {
            PodTarget::Ssh(transport) => transport,
            PodTarget::LocalExec { .. } => panic!("expected an ssh target"),
        }
    }

    /// Done criterion 1: both kinds decode, and an ssh entry that omits
    /// `user` / `remote_dir` picks up the driver's own constants.
    #[test]
    fn both_kinds_decode_and_ssh_defaults_come_from_the_driver_constants() {
        let registry = load(
            r#"{
                "targets": [
                    { "pod_id": "dev-local", "kind": "local-exec",
                      "staging_dir": "/tmp/lm-staging" },
                    { "pod_id": "pod-abc123", "kind": "ssh", "host": "pod.example.com",
                      "port": 21001, "key_path": "/path/to/key" }
                ]
            }"#,
        )
        .expect("both entries are well-formed");

        assert!(matches!(
            registry.resolve("dev-local").expect("registered"),
            PodTarget::LocalExec { staging_dir } if staging_dir == Path::new("/tmp/lm-staging")
        ));

        let ssh = ssh_of(registry.resolve("pod-abc123").expect("registered"));
        assert_eq!(ssh.user, DEFAULT_SSH_USER);
        assert_eq!(ssh.remote_dir, PathBuf::from(DEFAULT_REMOTE_DIR));
    }

    /// Done criterion 2: every "the file says something the schema does
    /// not accept" case is a `Decode`, and each one names the entry it
    /// came from.
    #[test]
    fn schema_violations_are_decode_errors_that_name_the_entry() {
        let cases = [
            // unknown kind
            r#"{ "pod_id": "pod-1", "kind": "docker-exec", "host": "h" }"#,
            // unknown field (a misspelled key_path)
            r#"{ "pod_id": "pod-1", "kind": "ssh", "host": "h", "port": 22,
                 "keypath": "/path/to/key" }"#,
            // unknown field on an entry that is otherwise complete: the
            // misspelling must not be dropped in favour of the default
            r#"{ "pod_id": "pod-1", "kind": "local-exec", "stagingDir": "/tmp/lm-staging" }"#,
            // missing port
            r#"{ "pod_id": "pod-1", "kind": "ssh", "host": "h", "key_path": "/path/to/key" }"#,
            // port 0
            r#"{ "pod_id": "pod-1", "kind": "ssh", "host": "h", "port": 0,
                 "key_path": "/path/to/key" }"#,
            // missing key_path
            r#"{ "pod_id": "pod-1", "kind": "ssh", "host": "h", "port": 22 }"#,
        ];

        for entry in cases {
            let err =
                load(&format!(r#"{{ "targets": [{entry}] }}"#)).expect_err("entry must not decode");
            let message = err.to_string();
            assert!(
                matches!(err, TargetLoadError::Decode { pod_id: Some(ref id), .. } if id == "pod-1"),
                "expected a Decode naming pod-1, got: {err:?}"
            );
            assert!(
                message.contains("pod-1") && message.contains(REGISTRY_PATH),
                "message should name the entry and the file: {message}"
            );
        }
    }

    /// A key written twice inside one entry declares two values for one
    /// field. Decoding the entry from its raw text (rather than from a
    /// `Value`, whose map would keep only the last one) makes serde
    /// reject it, so neither of the two declarations is silently
    /// preferred.
    #[test]
    fn a_repeated_key_within_one_entry_is_a_decode_error_that_names_the_entry() {
        let err = load(
            r#"{ "targets": [
                { "pod_id": "pod-1", "kind": "ssh", "host": "a.example.com",
                  "host": "b.example.com", "port": 22, "key_path": "/path/to/key" }
            ] }"#,
        )
        .expect_err("two hosts for one entry is not one destination");

        assert!(
            matches!(err, TargetLoadError::Decode { pod_id: Some(ref id), .. } if id == "pod-1"),
            "expected a Decode naming pod-1, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("duplicate field") && message.contains("host"),
            "the message should say which field was declared twice: {message}"
        );
        assert!(
            message.contains("pod-1") && message.contains(REGISTRY_PATH),
            "message should name the entry and the file: {message}"
        );
    }

    /// The registry key itself is not exempt: a repeated `pod_id` is
    /// the same `duplicate field` failure. The label the error is
    /// reported under is read last-wins, since that read is only there
    /// to name the entry and takes no part in accepting it.
    #[test]
    fn a_repeated_pod_id_within_one_entry_is_a_decode_error_labelled_last_wins() {
        let err = load(
            r#"{ "targets": [
                { "pod_id": "pod-1", "kind": "local-exec", "pod_id": "pod-2" }
            ] }"#,
        )
        .expect_err("two ids for one entry is not one registration");

        assert!(
            matches!(err, TargetLoadError::Decode { pod_id: Some(ref id), .. } if id == "pod-2"),
            "expected a Decode labelled with the last-wins id, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("duplicate field") && message.contains("pod_id"),
            "the message should say which field was declared twice: {message}"
        );
    }

    /// A malformed top level has no entry to name, and says so instead
    /// of inventing one.
    #[test]
    fn a_malformed_top_level_is_a_decode_error_without_a_pod_id() {
        let err = load(r#"{ "target": [] }"#).expect_err("`target` is not `targets`");
        assert!(matches!(err, TargetLoadError::Decode { pod_id: None, .. }));
        assert!(err.to_string().contains(REGISTRY_PATH));
    }

    /// Done criterion 3: the two post-decode rejections.
    #[test]
    fn an_empty_host_is_invalid_and_a_repeated_pod_id_is_a_duplicate() {
        let err = load(
            r#"{ "targets": [
                { "pod_id": "pod-1", "kind": "ssh", "host": "", "port": 22,
                  "key_path": "/path/to/key" }
            ] }"#,
        )
        .expect_err("an empty host is not a destination");
        assert!(matches!(
            err,
            TargetLoadError::Invalid { ref pod_id, .. } if pod_id == "pod-1"
        ));

        let err = load(
            r#"{ "targets": [
                { "pod_id": "pod-1", "kind": "local-exec" },
                { "pod_id": "pod-1", "kind": "ssh", "host": "h", "port": 22,
                  "key_path": "/path/to/key" }
            ] }"#,
        )
        .expect_err("a repeated pod_id must not resolve last-wins");
        assert!(matches!(
            err,
            TargetLoadError::DuplicatePodId(ref pod_id) if pod_id == "pod-1"
        ));
    }

    /// Done criterion 4: the `staging_dir` default is applied at load
    /// time, and an explicit value survives it.
    #[test]
    fn local_exec_staging_dir_defaults_at_load_time_and_keeps_an_explicit_value() {
        let registry = load(
            r#"{ "targets": [
                { "pod_id": "implicit", "kind": "local-exec" },
                { "pod_id": "explicit", "kind": "local-exec", "staging_dir": "/srv/staging" }
            ] }"#,
        )
        .expect("both entries are well-formed");

        assert!(matches!(
            registry.resolve("implicit").expect("registered"),
            PodTarget::LocalExec { staging_dir } if staging_dir == Path::new(DEFAULT_STAGING)
        ));
        assert!(matches!(
            registry.resolve("explicit").expect("registered"),
            PodTarget::LocalExec { staging_dir } if staging_dir == Path::new("/srv/staging")
        ));
    }

    /// Done criterion 5: an unknown `pod_id` says which file to edit and
    /// what is in it — and nothing about how to reach a pod.
    #[test]
    fn an_unknown_pod_id_names_the_file_and_the_registered_ids_only() {
        let registry = load(
            r#"{ "targets": [
                { "pod_id": "dev-local", "kind": "local-exec" },
                { "pod_id": "pod-abc123", "kind": "ssh", "host": "pod.example.com",
                  "port": 21001, "user": "operator", "key_path": "/path/to/key" }
            ] }"#,
        )
        .expect("registry loads");

        let err = registry
            .resolve("unregistered")
            .expect_err("an unregistered pod_id must not resolve");
        assert!(matches!(err, TargetResolveError::UnknownPod { .. }));

        let message = err.to_string();
        assert!(message.contains("unregistered"), "{message}");
        assert!(message.contains(REGISTRY_PATH), "{message}");
        assert!(message.contains("dev-local"), "{message}");
        assert!(message.contains("pod-abc123"), "{message}");
        for secret_ish in ["pod.example.com", "operator", "/path/to/key", "21001"] {
            assert!(
                !message.contains(secret_ish),
                "connection details must not travel to the client: {message}"
            );
        }
    }

    /// Done criterion 6: with no registry configured the same call names
    /// the environment variable, since there is no path to name.
    #[test]
    fn an_unset_registry_names_the_env_var_instead_of_a_path() {
        let registry = TargetRegistry::empty(RegistrySource::Unset);

        let err = registry
            .resolve("unregistered")
            .expect_err("an empty registry resolves nothing");
        let message = err.to_string();
        assert!(
            message.contains(crate::config::TARGETS_PATH_ENV),
            "{message}"
        );
        assert!(message.contains("none"), "{message}");
        assert!(!message.contains('/'), "no path to name: {message}");
    }

    /// Done criterion 8: an ssh entry becomes exactly the transport it
    /// declares (no connection is attempted).
    #[test]
    fn an_ssh_entry_becomes_the_transport_it_declares() {
        let registry = load(
            r#"{ "targets": [
                { "pod_id": "pod-abc123", "kind": "ssh", "host": "pod.example.com",
                  "port": 21001, "user": "operator", "key_path": "/path/to/key",
                  "remote_dir": "/workspace" }
            ] }"#,
        )
        .expect("registry loads");

        let ssh = ssh_of(registry.resolve("pod-abc123").expect("registered"));
        assert_eq!(ssh.host, "pod.example.com");
        assert_eq!(ssh.port, 21001);
        assert_eq!(ssh.user, "operator");
        assert_eq!(ssh.key_path, PathBuf::from("/path/to/key"));
        assert_eq!(ssh.remote_dir, PathBuf::from("/workspace"));
    }

    /// A resolved target builds a transport whose destination paths are
    /// the ones the entry declared — the only observable difference
    /// between the two variants without touching a pod.
    #[test]
    fn to_transport_builds_the_kind_the_entry_declared() {
        let registry = load(
            r#"{ "targets": [
                { "pod_id": "dev-local", "kind": "local-exec", "staging_dir": "/tmp/lm-staging" },
                { "pod_id": "pod-abc123", "kind": "ssh", "host": "pod.example.com",
                  "port": 21001, "key_path": "/path/to/key", "remote_dir": "/workspace" }
            ] }"#,
        )
        .expect("registry loads");

        let local = registry
            .resolve("dev-local")
            .expect("registered")
            .to_transport();
        assert_eq!(
            local
                .dest_binary(Path::new("/local/lm-provision"))
                .expect("a named file has a destination"),
            PathBuf::from("/tmp/lm-staging/lm-provision")
        );

        let remote = registry
            .resolve("pod-abc123")
            .expect("registered")
            .to_transport();
        assert_eq!(
            remote
                .dest_binary(Path::new("/local/lm-provision"))
                .expect("a named file has a destination"),
            PathBuf::from("/workspace/lm-provision")
        );
    }
}
