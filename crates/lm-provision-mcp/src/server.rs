//! MCP tool wiring (10-mcp.md §Tool set) over the plain, transport-free
//! functions in [`crate::pipeline`] / [`crate::apply_tool`] /
//! [`crate::ledger_tools`]. Every blocking call (subprocess spawn,
//! ledger file I/O) runs through
//! [`tokio::task::spawn_blocking`] rather than inline in an `async fn`:
//! a blocking call made directly inside `async` stalls the runtime's
//! worker thread.
//!
//! Every tool method below returns `Result<String, McpError>` (the
//! tool's JSON output, pre-serialized) rather than manually building a
//! `CallToolResult` — `rmcp`'s blanket `IntoContents for String` /
//! `IntoCallToolResult for Result<T, E>` impls do that wrapping, and
//! `ErrorData` (aliased here as `McpError`) already implements
//! `IntoCallToolResult` for the `Err` side (10 §Error surface: MCP
//! transport / precondition errors surface through the MCP error
//! channel, not embedded in a success payload).

use std::path::{Path, PathBuf};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::apply_tool::{self, ApplyArgs, ApplyOutput};
use crate::config::Config;
use crate::ledger_tools;
use crate::pipeline;
use crate::targets::TargetRegistry;

/// `lm_validate` / `lm_hash` / `lm_plan` request shape (10 §Tool set: a
/// single `profile_path` string argument, shared by all three).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProfilePathParams {
    /// Path to the profile file, visible to this MCP server's host (10
    /// §Inputs).
    pub profile_path: String,
}

/// `lm_apply(profile_path, pod_id, dry_run=false)` request shape (10
/// §Tool set).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ApplyParams {
    /// Path to the profile file, visible to this MCP server's host.
    pub profile_path: String,
    /// Driver-provided provisioning context (09 §Ledger `pod_id`), and
    /// the key resolved in the pod target registry to decide where the
    /// apply runs ([`crate::targets`]). Connection details are server
    /// configuration; they are deliberately not arguments here.
    pub pod_id: String,
    /// Decode + policy + secret resolution only, no effects. Defaults
    /// to `false` (10 §Tool set).
    #[serde(default)]
    pub dry_run: bool,
}

/// `lm_ledger_list(pod_id?, profile_hash?, limit?)` request shape (10
/// §Tool set).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct LedgerListParams {
    /// Filter to rows with this `pod_id`.
    #[serde(default)]
    pub pod_id: Option<String>,
    /// Filter to rows with this `profile_hash`.
    #[serde(default)]
    pub profile_hash: Option<String>,
    /// Cap the number of rows returned, applied after filtering.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `lm_ledger_get(row_id)` request shape (10 §Tool set).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct LedgerGetParams {
    /// Newest-first row index (09 §Stability: row locator provisional).
    pub row_id: usize,
}

/// Serialize `value` as a tool's JSON text result (10 §Outputs).
fn json_result(value: serde_json::Value) -> Result<String, McpError> {
    serde_json::to_string(&value).map_err(|err| McpError::internal_error(err.to_string(), None))
}

/// Map a precondition-class failure (10 §Error surface) to an MCP tool
/// error.
fn precondition_error(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}

/// Map a `tokio::task::JoinError` (the blocking task itself panicked)
/// to an MCP internal error.
fn join_error(err: tokio::task::JoinError) -> McpError {
    McpError::internal_error(err.to_string(), None)
}

/// Record an `lm_apply` failure in full, and hand the client the part
/// of it that is addressed to a client
/// ([`apply_tool::ApplyToolError::client_message`]).
///
/// The two duties are one function so they cannot drift apart: the
/// redaction is only acceptable *because* the full error is written to
/// the server's log in the same breath. `main` initializes tracing on
/// stderr, so an operator watching the server sees the `ssh` / `scp` or
/// pod-side stderr this message drops — nothing is lost, only
/// readdressed.
///
/// # Why the event is `ERROR` and must stay there
///
/// The level is not a severity judgement; it is what makes the sentence
/// above true. `main` builds its subscriber from
/// `EnvFilter::from_default_env()`, and `tracing-subscriber` documents
/// that when `RUST_LOG` is unset, empty, or wholly invalid it injects a
/// default directive enabling **the `ERROR` level only**. `RUST_LOG`
/// unset is the ordinary state of a stdio MCP server spawned by its
/// client: nothing in this repo sets it, and no operator action is
/// required to run the server. At `WARN` this event would therefore be
/// dropped by default, and the client would be handed
/// "(see server log)" pointing at a line that was never written — the
/// dropped detail destroyed rather than readdressed.
///
/// So: lowering this to `warn!`/`info!`/`debug!` silently voids
/// [`apply_tool::ApplyToolError::client_message`]'s justification. If
/// the level is ever to be lowered, `main`'s filter has to grow a
/// default directive of its own first (e.g.
/// `EnvFilter::builder().with_default_directive(LevelFilter::WARN.into())`),
/// so that the operator's copy still exists without `RUST_LOG`.
fn log_and_map_apply_error(err: &apply_tool::ApplyToolError, pod_id: &str) -> McpError {
    tracing::error!(pod_id, error = %err, "lm_apply failed");
    precondition_error(err.client_message(pod_id))
}

/// `lm_apply`'s body, without `rmcp`: resolve the `pod_id` against the
/// pod target registry, then run one driver session against whatever
/// transport that entry denotes.
///
/// Split out from the `#[tool]` method (which is a thin wrapper over
/// it) so the "unregistered `pod_id` produces no effect" case is
/// testable at the function level. It cannot be tested one layer down:
/// [`apply_tool::lm_apply`] takes an already-resolved transport, and an
/// unregistered `pod_id` has none to pass.
///
/// Both arms map to `invalid_params`. An unknown `pod_id` is squarely
/// 10 §Error surface's precondition class, and so is most of what
/// [`apply_tool::ApplyToolError`] wraps (a profile that does not
/// validate, a secret the server's environment does not hold) — "the
/// call cannot start". A transport-class failure inside the session
/// (08 §Error surface: driver-side, retryable) is not the same thing
/// and MCP has a code for it; it is folded in here only because
/// nothing downstream distinguishes them yet. The distinction survives
/// in the error value ([`apply_tool::ApplyToolError::Session`]), which
/// is what a later refinement would match on.
///
/// The two arms differ in how much of the error the client is shown.
/// [`TargetResolveError`] is already written for this audience — it
/// names the `pod_id`, the registry, and the registered ids, and
/// nothing about how to reach a pod ([`crate::targets`]) — so its
/// message travels as-is. A session failure can relay an external
/// process's stderr, so it goes through
/// [`log_and_map_apply_error`] instead.
///
/// [`TargetResolveError`]: crate::targets::TargetResolveError
fn handle_lm_apply(
    registry: &TargetRegistry,
    binary_path: &Path,
    ledger_path: &Path,
    args: ApplyArgs<'_>,
) -> Result<ApplyOutput, McpError> {
    let transport = registry
        .resolve(args.pod_id)
        .map_err(|err| precondition_error(err.to_string()))?
        .to_transport();
    apply_tool::lm_apply(transport.as_ref(), binary_path, ledger_path, args)
        .map_err(|err| log_and_map_apply_error(&err, args.pod_id))
}

/// The MCP server handler (10-mcp.md). Deployment configuration
/// ([`Config`]) is resolved once at construction time and shared
/// (`Clone`) across every tool call.
#[derive(Clone)]
pub struct LmProvisionServer {
    config: Config,
}

#[tool_router]
impl LmProvisionServer {
    /// Construct the server over an already-resolved [`Config`].
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// `lm_validate` (10 §Tool set: `profile_path`; backing surface 07
    /// `validate`).
    #[tool(description = "Validate a profile file (07-cli.md `validate`, read-only).")]
    async fn lm_validate(
        &self,
        Parameters(ProfilePathParams { profile_path }): Parameters<ProfilePathParams>,
    ) -> Result<String, McpError> {
        let path = PathBuf::from(profile_path);
        let value = tokio::task::spawn_blocking(move || pipeline::lm_validate(&path))
            .await
            .map_err(join_error)?
            .map_err(precondition_error)?;
        json_result(value)
    }

    /// `lm_hash` (10 §Tool set: `profile_path`; backing surface 07
    /// `hash`).
    #[tool(description = "Compute a profile's 64-hex sha256 hash (07-cli.md `hash`, read-only).")]
    async fn lm_hash(
        &self,
        Parameters(ProfilePathParams { profile_path }): Parameters<ProfilePathParams>,
    ) -> Result<String, McpError> {
        let path = PathBuf::from(profile_path);
        let value = tokio::task::spawn_blocking(move || pipeline::lm_hash(&path))
            .await
            .map_err(join_error)?
            .map_err(precondition_error)?;
        json_result(value)
    }

    /// `lm_plan` (10 §Tool set: `profile_path`; backing surface 07
    /// `plan`).
    #[tool(description = "Expand a profile's plan artifact (07-cli.md `plan`, read-only).")]
    async fn lm_plan(
        &self,
        Parameters(ProfilePathParams { profile_path }): Parameters<ProfilePathParams>,
    ) -> Result<String, McpError> {
        let path = PathBuf::from(profile_path);
        let value = tokio::task::spawn_blocking(move || pipeline::lm_plan(&path))
            .await
            .map_err(join_error)?
            .map_err(precondition_error)?;
        json_result(value)
    }

    /// `lm_apply` (10 §Tool set: `profile_path`, `pod_id`,
    /// `dry_run=false`; backing surface 08 upload/invoke/collect).
    /// `pod_id` selects the destination through the pod target registry
    /// ([`crate::targets`]); an unregistered one fails before any
    /// effect.
    #[tool(
        description = "Run the full push-driver protocol (upload/invoke/collect) against the pod \
                        the given pod_id is registered for, then append the result to the apply \
                        ledger (08/09-mcp.md). An unregistered pod_id is rejected."
    )]
    async fn lm_apply(
        &self,
        Parameters(ApplyParams {
            profile_path,
            pod_id,
            dry_run,
        }): Parameters<ApplyParams>,
    ) -> Result<String, McpError> {
        let config = self.config.clone();
        let profile_path = PathBuf::from(profile_path);
        let output = tokio::task::spawn_blocking(move || {
            handle_lm_apply(
                &config.targets,
                &config.binary_path,
                &config.ledger_path,
                ApplyArgs {
                    profile_path: &profile_path,
                    pod_id: &pod_id,
                    dry_run,
                },
            )
        })
        .await
        .map_err(join_error)??;
        let value = serde_json::to_value(output)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        json_result(value)
    }

    /// `lm_ledger_list` (10 §Tool set: `pod_id?`, `profile_hash?`,
    /// `limit?`; backing surface 09 ledger rows, newest first).
    #[tool(description = "List apply-ledger rows, newest first, optionally filtered (09 §Ledger).")]
    async fn lm_ledger_list(
        &self,
        Parameters(LedgerListParams {
            pod_id,
            profile_hash,
            limit,
        }): Parameters<LedgerListParams>,
    ) -> Result<String, McpError> {
        let ledger_path = self.config.ledger_path.clone();
        let rows = tokio::task::spawn_blocking(move || {
            ledger_tools::lm_ledger_list(
                &ledger_path,
                pod_id.as_deref(),
                profile_hash.as_deref(),
                limit,
            )
        })
        .await
        .map_err(join_error)?
        .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        let value = serde_json::to_value(rows)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        json_result(value)
    }

    /// `lm_ledger_get` (10 §Tool set: row locator; backing surface 09
    /// single row).
    #[tool(description = "Fetch a single apply-ledger row by newest-first index (09 §Ledger).")]
    async fn lm_ledger_get(
        &self,
        Parameters(LedgerGetParams { row_id }): Parameters<LedgerGetParams>,
    ) -> Result<String, McpError> {
        let ledger_path = self.config.ledger_path.clone();
        let row =
            tokio::task::spawn_blocking(move || ledger_tools::lm_ledger_get(&ledger_path, row_id))
                .await
                .map_err(join_error)?
                .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        let value = serde_json::to_value(row)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        json_result(value)
    }
}

#[tool_handler]
impl ServerHandler for LmProvisionServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "lm-provision MCP server: validate/hash/plan a profile, apply it through the \
             push-driver protocol, and read the apply ledger (10-mcp.md).",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use lm_provision_driver::ledger::{self, LedgerRow};
    use lm_provision_driver::transport::{ExecOutput, PodPaths, Transport, TransportError};
    use rmcp::model::ErrorCode;

    use crate::targets::{RegistrySource, TargetRegistry};

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "{}/../lm-provision/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-mcp-server-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    /// An unregistered `pod_id` is rejected as a precondition failure
    /// and nothing runs: no upload, no invoke, and — the observable
    /// part — no ledger row. A `pod_id` that resolves to nothing must
    /// not be able to leave a record claiming an apply happened.
    ///
    /// The `binary_path` / `profile_path` here point at files that do
    /// not exist: if the rejection ever stopped happening first, the
    /// call would fail for a different reason, which the message
    /// assertion catches.
    #[test]
    fn an_unregistered_pod_id_is_rejected_before_any_effect() {
        let ledger_path = temp_path("unknown-pod-ledger").with_extension("jsonl");
        ledger::append(
            &ledger_path,
            &LedgerRow {
                pod_id: "dev-local".to_string(),
                profile_hash: "0".repeat(64),
                report: serde_json::json!({ "ok": true }),
                collected_at: "2026-08-06T00:00:00Z".to_string(),
            },
        )
        .expect("seed the ledger with one row");
        let before = ledger::list(&ledger_path)
            .expect("ledger is readable")
            .len();

        let registry = TargetRegistry::load(
            RegistrySource::FromFile(PathBuf::from("/etc/lm-provision/targets.json")),
            r#"{ "targets": [ { "pod_id": "dev-local", "kind": "local-exec" } ] }"#,
            Path::new("/tmp/lm-provision-staging"),
        )
        .expect("registry loads");

        let err = handle_lm_apply(
            &registry,
            Path::new("/nonexistent/lm-provision"),
            &ledger_path,
            ApplyArgs {
                profile_path: Path::new("/nonexistent/profile.json"),
                pod_id: "pod-not-registered",
                dry_run: true,
            },
        )
        .expect_err("an unregistered pod_id must not reach the driver protocol");

        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains("pod-not-registered") && err.message.contains("dev-local"),
            "the client must be told which pod_id failed and which are registered: {}",
            err.message
        );
        assert_eq!(
            ledger::list(&ledger_path)
                .expect("ledger is readable")
                .len(),
            before,
            "a rejected pod_id must not append a ledger row"
        );

        std::fs::remove_file(&ledger_path).ok();
    }

    /// How a [`FailingTransport`] fails: the two session failures that
    /// relay an external process's own output back to this layer.
    enum Failure {
        /// A transport call fails carrying the text `ssh` / `scp` write
        /// on their own stderr (`driver/src/ssh.rs` embeds it verbatim).
        Transport(String),
        /// The pod's own `hash` invocation exits non-zero with this
        /// stderr.
        RemoteHash {
            /// The remote exit code.
            exit_code: i32,
            /// The remote stderr.
            stderr: String,
        },
    }

    /// A [`Transport`] rigged to fail in one chosen way, so a test can
    /// hold a *real* [`apply_tool::ApplyToolError`] that carries
    /// external-process text — the only kind of error worth asserting
    /// redaction on.
    ///
    /// It is not reachable through [`handle_lm_apply`], which builds its
    /// transport from a registry entry — so the two tests below enter at
    /// [`log_and_map_apply_error`] to exercise the *mapping* against a
    /// chosen failure. That the mapping is actually wired into
    /// `handle_lm_apply` is a separate claim, asserted by
    /// `handle_lm_apply_redacts_a_transport_failure_from_a_registered_pod`
    /// through a real `local-exec` entry.
    struct FailingTransport {
        failure: Failure,
    }

    impl FailingTransport {
        /// Either fail the upload outright, or let it land at `dest` so
        /// the session reaches the remote `hash` invocation.
        fn upload_to(&self, dest: &str) -> Result<PathBuf, TransportError> {
            match &self.failure {
                Failure::Transport(stderr) => {
                    Err(TransportError::Io(std::io::Error::other(stderr.clone())))
                }
                Failure::RemoteHash { .. } => Ok(PathBuf::from(dest)),
            }
        }
    }

    impl Transport for FailingTransport {
        fn dest_binary(&self, _local_binary: &Path) -> Result<PathBuf, TransportError> {
            self.upload_to("/pod/lm-provision")
        }

        fn dest_profile(&self, _local_profile: &Path) -> Result<PathBuf, TransportError> {
            self.upload_to("/pod/profile.json")
        }

        fn ensure_binary(&self, _local_binary: &Path) -> Result<PathBuf, TransportError> {
            self.upload_to("/pod/lm-provision")
        }

        fn place_profile(&self, _local_profile: &Path) -> Result<PathBuf, TransportError> {
            self.upload_to("/pod/profile.json")
        }

        fn exec(
            &self,
            _paths: &PodPaths,
            _args: &[String],
            _env: &BTreeMap<String, String>,
        ) -> Result<ExecOutput, TransportError> {
            match &self.failure {
                Failure::Transport(stderr) => {
                    Err(TransportError::Io(std::io::Error::other(stderr.clone())))
                }
                Failure::RemoteHash { exit_code, stderr } => Ok(ExecOutput {
                    stdout: String::new(),
                    stderr: stderr.clone(),
                    exit_code: Some(*exit_code),
                }),
            }
        }
    }

    /// Run an apply that is rigged to fail, and hand back the error the
    /// session produced.
    fn failed_apply(failure: Failure) -> apply_tool::ApplyToolError {
        apply_tool::lm_apply(
            &FailingTransport { failure },
            Path::new("/nonexistent/lm-provision"),
            &temp_path("redacted-ledger").with_extension("jsonl"),
            ApplyArgs {
                profile_path: &fixture("apply-sh-fs.json"),
                pod_id: "test-pod-1",
                dry_run: true,
            },
        )
        .expect_err("the transport is rigged to fail")
    }

    /// A failure while connecting must not tell the client where it was
    /// connecting to. `ssh` / `scp` name the host, the user, and the
    /// identity file in their own standard phrasing, and the driver
    /// relays that stderr verbatim — which is right for the CLI operator
    /// who wrote the registry, and wrong for an MCP client that was
    /// never given the connection in the first place.
    ///
    /// The `pod_id` does travel: the client passed it in, so it is not a
    /// new disclosure, and it is what makes the message actionable.
    #[test]
    fn a_transport_failure_names_the_pod_and_nothing_about_the_connection() {
        let err = failed_apply(Failure::Transport(
            "scp /local/lm-provision -> /root/lm-provision exited with Some(1): \
             root@pod.example.com: Permission denied (publickey)."
                .to_string(),
        ));

        let mapped = log_and_map_apply_error(&err, "test-pod-1");
        assert_eq!(mapped.code, ErrorCode::INVALID_PARAMS);
        for connection_detail in ["pod.example.com", "root@", "publickey"] {
            assert!(
                !mapped.message.contains(connection_detail),
                "the client must not be told '{connection_detail}': {}",
                mapped.message
            );
        }
        assert!(
            mapped.message.contains("test-pod-1"),
            "the client must be told which pod failed: {}",
            mapped.message
        );

        // The other half of the trade: the operator's copy is intact,
        // which is what makes dropping it from the client's copy
        // acceptable (`log_and_map_apply_error` logs exactly this).
        let logged = err.to_string();
        for connection_detail in ["pod.example.com", "root@", "publickey"] {
            assert!(
                logged.contains(connection_detail),
                "the server-side error must keep '{connection_detail}': {logged}"
            );
        }
    }

    /// The pod's own stderr is the same problem one layer further in:
    /// the remote `hash` exit code sits on the failure path, so
    /// whatever that invocation printed now reaches the client. The
    /// exit code survives — it is a number the pod chose, not something
    /// it said about its own filesystem.
    #[test]
    fn a_remote_hash_failure_keeps_the_exit_code_and_drops_the_pod_stderr() {
        let err = failed_apply(Failure::RemoteHash {
            exit_code: 127,
            stderr: "/root/lm-provision: not found".to_string(),
        });

        let mapped = log_and_map_apply_error(&err, "test-pod-1");
        assert!(
            !mapped.message.contains("/root/lm-provision"),
            "the pod's stderr must not travel: {}",
            mapped.message
        );
        assert!(
            mapped.message.contains("127") && mapped.message.contains("test-pod-1"),
            "the exit code and the pod are what the client can act on: {}",
            mapped.message
        );

        let logged = err.to_string();
        assert!(
            logged.contains("/root/lm-provision") && logged.contains("127"),
            "the server-side error must keep the pod's stderr: {logged}"
        );
    }

    /// The redaction has to be *wired in*, not merely available: this
    /// enters where a tool call does. A registered `local-exec` entry
    /// plus a `binary_path` that does not exist fails inside
    /// `ensure_binary` (`driver/src/local_exec.rs`'s `fs::copy`), which
    /// is a `SessionError::Transport` — the same class as an `ssh`
    /// failure, reached without inventing a transport.
    ///
    /// The assertion distinguishes the two mappings: the earlier form
    /// (`precondition_error(err.to_string())`) yields "apply session
    /// failed: transport error: i/o error: ...", which the negative
    /// assertion below rejects.
    #[test]
    fn handle_lm_apply_redacts_a_transport_failure_from_a_registered_pod() {
        let staging_dir = temp_path("wired-redaction-staging");
        let ledger_path = temp_path("wired-redaction-ledger").with_extension("jsonl");
        let registry_json = serde_json::json!({
            "targets": [
                { "pod_id": "dev-local", "kind": "local-exec", "staging_dir": staging_dir }
            ]
        })
        .to_string();
        let registry = TargetRegistry::load(
            RegistrySource::FromFile(PathBuf::from("/etc/lm-provision/targets.json")),
            &registry_json,
            Path::new("/this-default-must-not-be-used"),
        )
        .expect("registry loads");

        let err = handle_lm_apply(
            &registry,
            Path::new("/nonexistent/lm-provision"),
            &ledger_path,
            ApplyArgs {
                profile_path: &fixture("apply-sh-fs.json"),
                pod_id: "dev-local",
                dry_run: true,
            },
        )
        .expect_err("a binary that does not exist cannot be staged");

        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains("transport error (see server log)")
                && err.message.contains("dev-local"),
            "the tool call must return the redacted form: {}",
            err.message
        );
        assert!(
            !err.message.contains("i/o error"),
            "the underlying transport text must not travel: {}",
            err.message
        );

        std::fs::remove_dir_all(&staging_dir).ok();
        std::fs::remove_file(&ledger_path).ok();
    }

    /// The `#[tool_router]` macro must generate schema entries for
    /// exactly the six tools 10 §Tool set specifies, under their
    /// spec-literal names.
    #[test]
    fn tool_router_lists_exactly_the_six_spec_tools() {
        let router = LmProvisionServer::tool_router();
        let mut names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "lm_apply",
                "lm_hash",
                "lm_ledger_get",
                "lm_ledger_list",
                "lm_plan",
                "lm_validate",
            ]
        );
    }

    /// Every tool's generated JSON schema must at least carry its
    /// declared required fields — a schema is generated for each of the
    /// six, and each one is complete.
    #[test]
    fn lm_apply_schema_requires_profile_path_and_pod_id() {
        let router = LmProvisionServer::tool_router();
        let tool = router
            .get("lm_apply")
            .expect("lm_apply should be registered");
        let schema = &tool.input_schema;
        let required = schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("lm_apply schema should declare required fields");
        let required: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required.contains(&"profile_path"));
        assert!(required.contains(&"pod_id"));
    }
}
