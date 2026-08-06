//! MCP tool wiring (10-mcp.md §Tool set) over the plain, transport-free
//! functions in [`crate::pipeline`] / [`crate::apply_tool`] /
//! [`crate::ledger_tools`]. Every blocking call (Lua VM evaluation,
//! subprocess spawn, ledger file I/O) runs through
//! [`tokio::task::spawn_blocking`] rather than inline in an `async fn`
//! (`rust-architecture-baseline.md` §Async/Concurrency: "blocking call
//! を async 内で直叩き禁止").
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

/// `lm_apply`'s body, without `rmcp`: resolve the `pod_id` against the
/// pod target registry, then run the driver protocol against whatever
/// transport that entry denotes.
///
/// Split out from the `#[tool]` method (which is a thin wrapper over
/// it) so the "unregistered `pod_id` produces no effect" case is
/// testable at the function level. It cannot be tested one layer down:
/// [`apply_tool::lm_apply`] takes an already-resolved transport, and an
/// unregistered `pod_id` has none to pass.
///
/// Both failure modes are 10 §Error surface's precondition class — an
/// unknown `pod_id` and a missing secret are equally "the call cannot
/// start" — so both map to `invalid_params`.
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
        .map_err(|err| precondition_error(err.to_string()))
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

    use lm_provision_driver::ledger::{self, LedgerRow};
    use rmcp::model::ErrorCode;

    use crate::targets::{RegistrySource, TargetRegistry};

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

    /// Smoke test (task instruction): the `#[tool_router]` macro must
    /// generate schema entries for exactly the six tools 10 §Tool set
    /// specifies, under their spec-literal names.
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
    /// declared required fields (task instruction: "schema が 6 tool
    /// 分生成されることの smoke").
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
