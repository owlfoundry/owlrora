#![forbid(unsafe_code)]

use std::{env, error::Error, net::SocketAddr};

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .try_init()?;

    let address = env::var("OWLRORA_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse::<SocketAddr>()?;
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "server listening");

    owlrora_server::run(listener).await?;
    Ok(())
}
