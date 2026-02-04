mod api_client;
mod config;
mod ldap_handler;

use api_client::ApiClient;
use config::Config;
use ldap_handler::LdapHandler;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
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
    let ldap_handler = Arc::new(LdapHandler::new(api_client));

    // Bind to address
    let bind_addr = format!("{}:{}", config.server.bind_address, config.server.port);
    let listener = TcpListener::bind(&bind_addr).await?;

    info!("LDAP server listening on {}", bind_addr);

    // Accept connections with graceful shutdown
    loop {
        tokio::select! {
            // Handle shutdown signals
            _ = shutdown_signal() => {
                info!("Received shutdown signal, exiting...");
                break;
            }
            // Accept new connections
            result = listener.accept() => {
                match result {
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
    }

    info!("LDAP server stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
