//! Server deployment configuration: how this server reaches pods, and
//! which pods it may reach at all.
//!
//! Three of the four knobs are single values the driver protocol needs
//! (the provisioner binary, the default staging directory, the ledger
//! file). The fourth, [`Config::targets`], is the pod target registry
//! ([`crate::targets`]): the table `lm_apply`'s `pod_id` is resolved
//! against, loaded once here at startup. Pod connection details live in
//! that file rather than in tool arguments — an MCP client writes tool
//! arguments, and a destination it made up would be exactly the
//! unchecked target the registry exists to remove.

use std::path::PathBuf;

use crate::targets::{RegistrySource, TargetLoadError, TargetRegistry};

/// `LM_PROVISION_BINARY` — path to the `lm-provision` provisioner
/// binary [`lm_provision_driver::driver::run`] uploads and invokes (08
/// §Inputs "provisioner binary artifact"). Required: the MVP
/// [`lm_provision_driver::local_exec::LocalExecTransport`] has no
/// other way to locate it.
pub const BINARY_PATH_ENV: &str = "LM_PROVISION_BINARY";

/// `LM_PROVISION_STAGING_DIR` — the directory
/// [`lm_provision_driver::local_exec::LocalExecTransport`] stages
/// uploaded artifacts under. Optional; defaults to a fixed
/// subdirectory of the OS temp dir.
///
/// Since the pod target registry landed this is the *default* for
/// `local-exec` registry entries that do not name their own
/// `staging_dir`, not the one staging directory every apply uses.
pub const STAGING_DIR_ENV: &str = "LM_PROVISION_STAGING_DIR";

/// `LM_PROVISION_TARGETS` — path to the pod target registry JSON file
/// ([`crate::targets`]). Optional, but a server started without it
/// resolves no `pod_id` at all: `lm_apply` then fails with
/// [`crate::targets::TargetResolveError::UnknownPod`] for every call.
/// There is deliberately no fallback to the pre-registry behaviour of
/// running every apply on the server's own host — that fallback is the
/// unchecked destination the registry exists to remove.
pub const TARGETS_PATH_ENV: &str = "LM_PROVISION_TARGETS";

/// `LM_PROVISION_LEDGER_PATH` — the append-only ledger file
/// [`lm_provision_driver::ledger`] reads and writes (09 §Ledger).
/// Optional; defaults to a fixed path under the OS temp dir.
pub const LEDGER_PATH_ENV: &str = "LM_PROVISION_LEDGER_PATH";

/// Errors raised while resolving [`Config`] from the process
/// environment.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// [`BINARY_PATH_ENV`] was not set. Every other knob has a usable
    /// default; the binary path does not, because guessing at one
    /// would silently point the driver at the wrong artifact.
    #[error(
        "{BINARY_PATH_ENV} is not set: the MCP server needs the path to the \
         lm-provision provisioner binary to drive lm_apply (08-push-driver-protocol.md \
         §Inputs)"
    )]
    MissingBinaryPath,

    /// [`TARGETS_PATH_ENV`] named a file that could not be read.
    /// Startup fails rather than continuing with an empty registry:
    /// an empty registry would report every configured pod as
    /// unregistered, hiding the real cause (a typo'd path, a missing
    /// file) behind a per-call error.
    #[error("failed to read the pod target registry at {}: {source}", .path.display())]
    ReadTargets {
        /// The path [`TARGETS_PATH_ENV`] pointed at.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The registry file was read but did not load (see
    /// [`TargetLoadError`]). Same fail-at-startup rationale as
    /// [`ConfigError::ReadTargets`].
    #[error("invalid pod target registry: {0}")]
    Targets(#[from] TargetLoadError),
}

/// Server deployment configuration, resolved once at startup from the
/// MCP server's own process environment (10 §Inputs: "the MCP server
/// process environment is the secret source" — the same environment
/// this config is read from, per that same input boundary).
#[derive(Debug, Clone)]
pub struct Config {
    /// See [`BINARY_PATH_ENV`].
    pub binary_path: PathBuf,
    /// See [`STAGING_DIR_ENV`].
    pub staging_dir: PathBuf,
    /// See [`LEDGER_PATH_ENV`].
    pub ledger_path: PathBuf,
    /// The pod target registry [`TARGETS_PATH_ENV`] names, loaded once
    /// at startup and immutable thereafter: adding a pod means editing
    /// the file and restarting the server.
    pub targets: TargetRegistry,
}

impl Config {
    /// Resolve every knob from the process environment, applying the
    /// defaults documented on [`STAGING_DIR_ENV`] / [`LEDGER_PATH_ENV`],
    /// and read the registry file [`TARGETS_PATH_ENV`] points at.
    ///
    /// Reading that file is the one impure step: [`Config::from_vars`]
    /// receives its already-read contents so it stays a pure function
    /// of its arguments.
    pub fn from_env() -> Result<Self, ConfigError> {
        let targets_path = std::env::var(TARGETS_PATH_ENV).ok().map(PathBuf::from);
        let targets_json =
            match &targets_path {
                Some(path) => Some(std::fs::read_to_string(path).map_err(|source| {
                    ConfigError::ReadTargets {
                        path: path.clone(),
                        source,
                    }
                })?),
                None => None,
            };

        Self::from_vars(
            std::env::var(BINARY_PATH_ENV).ok(),
            std::env::var(STAGING_DIR_ENV).ok(),
            std::env::var(LEDGER_PATH_ENV).ok(),
            targets_json,
            targets_path,
        )
    }

    /// The pure resolution [`Config::from_env`] wraps — takes already-read
    /// environment-variable values directly so tests can exercise every
    /// default/override combination without mutating the real process
    /// environment (the same pattern `cli::resolve_log_filter_from`
    /// in the `lm-provision` crate uses for `RUST_LOG`).
    ///
    /// `targets_json` is the registry file's contents and
    /// `targets_path` the path it was read from — both together, or
    /// neither. Either half alone cannot describe a loaded registry
    /// (the path is what an error message names), so a lone half is
    /// treated as "no registry configured", which is what
    /// [`Config::from_env`] produces when [`TARGETS_PATH_ENV`] is unset.
    pub fn from_vars(
        binary_path: Option<String>,
        staging_dir: Option<String>,
        ledger_path: Option<String>,
        targets_json: Option<String>,
        targets_path: Option<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let binary_path = binary_path
            .map(PathBuf::from)
            .ok_or(ConfigError::MissingBinaryPath)?;
        let staging_dir = staging_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("lm-provision-mcp-staging"));
        let ledger_path = ledger_path
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("lm-provision-mcp-ledger.jsonl"));
        let targets = match (targets_path, targets_json) {
            (Some(path), Some(json)) => {
                TargetRegistry::load(RegistrySource::FromFile(path), &json, &staging_dir)?
            }
            _ => TargetRegistry::empty(RegistrySource::Unset),
        };
        Ok(Config {
            binary_path,
            staging_dir,
            ledger_path,
            targets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_path_is_a_config_error() {
        let err = Config::from_vars(None, None, None, None, None)
            .expect_err("missing binary path must error");
        assert!(matches!(err, ConfigError::MissingBinaryPath));
    }

    #[test]
    fn staging_dir_and_ledger_path_default_when_unset() {
        let config = Config::from_vars(
            Some("/usr/local/bin/lm-provision".to_string()),
            None,
            None,
            None,
            None,
        )
        .expect("binary path is set");
        assert_eq!(
            config.binary_path,
            PathBuf::from("/usr/local/bin/lm-provision")
        );
        assert!(config.staging_dir.ends_with("lm-provision-mcp-staging"));
        assert!(config
            .ledger_path
            .ends_with("lm-provision-mcp-ledger.jsonl"));
    }

    #[test]
    fn explicit_staging_dir_and_ledger_path_override_the_default() {
        let config = Config::from_vars(
            Some("/bin/lm-provision".to_string()),
            Some("/tmp/custom-staging".to_string()),
            Some("/tmp/custom-ledger.jsonl".to_string()),
            None,
            None,
        )
        .expect("all knobs set");
        assert_eq!(config.staging_dir, PathBuf::from("/tmp/custom-staging"));
        assert_eq!(
            config.ledger_path,
            PathBuf::from("/tmp/custom-ledger.jsonl")
        );
    }

    /// The staging directory a `local-exec` entry inherits is the
    /// server's own, resolved first so the registry sees the effective
    /// value rather than the raw environment variable.
    #[test]
    fn a_local_exec_entry_without_a_staging_dir_inherits_the_servers_default() {
        let config = Config::from_vars(
            Some("/bin/lm-provision".to_string()),
            Some("/tmp/custom-staging".to_string()),
            None,
            Some(
                r#"{ "targets": [ { "pod_id": "dev-local", "kind": "local-exec" } ] }"#.to_string(),
            ),
            Some(PathBuf::from("/etc/lm-provision/targets.json")),
        )
        .expect("the registry loads");

        let target = config.targets.resolve("dev-local").expect("registered");
        assert!(matches!(
            target,
            crate::targets::PodTarget::LocalExec { staging_dir }
                if staging_dir == &PathBuf::from("/tmp/custom-staging")
        ));
    }

    /// Both startup branches of [`TARGETS_PATH_ENV`], observed in one
    /// place: unset is a valid (if unusable) deployment, while a path
    /// that cannot be read or does not parse stops the server with the
    /// path named — the alternative, starting with an empty registry,
    /// would report every configured pod as unregistered and hide the
    /// real cause.
    #[test]
    fn an_unreadable_or_invalid_registry_path_fails_startup_while_unset_is_an_empty_registry() {
        std::env::set_var(BINARY_PATH_ENV, "/usr/local/bin/lm-provision");

        std::env::remove_var(TARGETS_PATH_ENV);
        let config = Config::from_env().expect("no registry configured is still a valid startup");
        let err = config
            .targets
            .resolve("dev-local")
            .expect_err("an empty registry resolves nothing");
        assert!(
            err.to_string().contains(TARGETS_PATH_ENV),
            "the per-call error must point at the missing configuration: {err}"
        );

        let missing = std::env::temp_dir().join(format!(
            "lm-provision-mcp-config-test-missing-{}.json",
            std::process::id()
        ));
        std::fs::remove_file(&missing).ok();
        std::env::set_var(TARGETS_PATH_ENV, &missing);
        let err = Config::from_env().expect_err("an unreadable registry must not start");
        assert!(matches!(err, ConfigError::ReadTargets { .. }));
        assert!(
            err.to_string().contains(&missing.display().to_string()),
            "the error must name the file to fix: {err}"
        );

        let broken = std::env::temp_dir().join(format!(
            "lm-provision-mcp-config-test-broken-{}.json",
            std::process::id()
        ));
        std::fs::write(&broken, r#"{ "targets": [ { "pod_id": "dev-local" "#)
            .expect("write a truncated registry");
        std::env::set_var(TARGETS_PATH_ENV, &broken);
        let err = Config::from_env().expect_err("a malformed registry must not start");
        assert!(matches!(err, ConfigError::Targets(_)));
        assert!(
            err.to_string().contains(&broken.display().to_string()),
            "the error must name the file to fix: {err}"
        );

        std::env::remove_var(TARGETS_PATH_ENV);
        std::fs::remove_file(&broken).ok();
    }
}
