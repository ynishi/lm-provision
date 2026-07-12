//! Server deployment configuration (10-mcp.md §Inputs: "Pod transport
//! configuration (how the server reaches pods) is server deployment
//! configuration, not tool arguments").
//!
//! MVP scope (plan.md §M6; task instruction): the only [`Transport`]
//! this server wires is
//! [`lm_provision_driver::local_exec::LocalExecTransport`], so the
//! three knobs below are exactly what that transport plus the ledger
//! need. A production deployment fronting a real pod-manager transport
//! (SSH / exec-API) would replace [`Config::binary_path`] /
//! [`Config::staging_dir`] with whatever that transport's own
//! constructor needs instead — this struct is deliberately the
//! smallest config shape the MVP transport requires, not a general
//! transport-selection mechanism.
//!
//! [`Transport`]: lm_provision_driver::transport::Transport

use std::path::PathBuf;

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
pub const STAGING_DIR_ENV: &str = "LM_PROVISION_STAGING_DIR";

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
}

/// Server deployment configuration, resolved once at startup from the
/// MCP server's own process environment (10 §Inputs: "the MCP server
/// process environment is the secret source" — the same environment
/// this config is read from, per that same input boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// See [`BINARY_PATH_ENV`].
    pub binary_path: PathBuf,
    /// See [`STAGING_DIR_ENV`].
    pub staging_dir: PathBuf,
    /// See [`LEDGER_PATH_ENV`].
    pub ledger_path: PathBuf,
}

impl Config {
    /// Resolve every knob from the process environment, applying the
    /// defaults documented on [`STAGING_DIR_ENV`] / [`LEDGER_PATH_ENV`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(
            std::env::var(BINARY_PATH_ENV).ok(),
            std::env::var(STAGING_DIR_ENV).ok(),
            std::env::var(LEDGER_PATH_ENV).ok(),
        )
    }

    /// The pure resolution [`Config::from_env`] wraps — takes already-read
    /// environment-variable values directly so tests can exercise every
    /// default/override combination without mutating the real process
    /// environment (the same pattern [`crate::cli::resolve_log_filter_from`]
    /// in the `lm-provision` crate uses for `RUST_LOG`).
    pub fn from_vars(
        binary_path: Option<String>,
        staging_dir: Option<String>,
        ledger_path: Option<String>,
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
        Ok(Config {
            binary_path,
            staging_dir,
            ledger_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_path_is_a_config_error() {
        let err = Config::from_vars(None, None, None).expect_err("missing binary path must error");
        assert!(matches!(err, ConfigError::MissingBinaryPath));
    }

    #[test]
    fn staging_dir_and_ledger_path_default_when_unset() {
        let config = Config::from_vars(Some("/usr/local/bin/lm-provision".to_string()), None, None)
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
        )
        .expect("all knobs set");
        assert_eq!(config.staging_dir, PathBuf::from("/tmp/custom-staging"));
        assert_eq!(
            config.ledger_path,
            PathBuf::from("/tmp/custom-ledger.jsonl")
        );
    }
}
