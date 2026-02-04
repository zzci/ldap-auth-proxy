mod api_client;
mod config;
mod ldap_handler;

use api_client::ApiClient;
use config::Config;
use ldap_handler::LdapHandler;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, Level};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(Level::INFO.into()),
        )
        .init();

    info!("Starting LDAP Authentication Proxy");

    // Load configuration
    let config = match Config::load() {
        Ok(cfg) => {
            info!("Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            info!("Could not load config file ({}), using defaults", e);
            Config::default_config()
        }
    };

    info!("Server config: {}:{}", config.server.bind_address, config.server.port);
    info!("API endpoint: {}", config.api.url);
    info!("Base DN: {}", config.server.base_dn);

    // Create API client
    let api_client = Arc::new(ApiClient::new(config.api.clone())?);

    // Create LDAP handler
    let ldap_handler = Arc::new(LdapHandler::new(
        api_client,
        config.server.base_dn.clone(),
    ));

    // Bind to address
    let bind_addr = format!("{}:{}", config.server.bind_address, config.server.port);
    let listener = TcpListener::bind(&bind_addr).await?;

    info!("LDAP server listening on {}", bind_addr);

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let handler = ldap_handler.clone();

                tokio::spawn(async move {
                    handler.handle_connection(stream, addr).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
