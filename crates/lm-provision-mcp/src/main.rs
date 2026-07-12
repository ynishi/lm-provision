//! `lm-provision-mcp` binary entry point: resolve [`Config`] from the
//! process environment, then serve [`LmProvisionServer`] over stdio
//! (the standard MCP transport for a locally-spawned server).

use lm_provision_mcp::config::Config;
use lm_provision_mcp::server::LmProvisionServer;
use rmcp::transport::io::stdio;
use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let config = Config::from_env()?;
    let server = LmProvisionServer::new(config);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
