//! VoidB Sync Server entry point.
//!
//! Author: Limmy

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

use voidb_sync_server::{Config, serve};

#[derive(Debug, Parser)]
#[command(name = "voidb-sync-server", version, about = "VoidB Sync Server")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone()));
    fmt().with_env_filter(filter).with_target(true).init();

    tracing::info!(
        bind = %config.bind,
        data_dir = %config.data_dir.display(),
        registration = ?config.registration,
        "starting voidb-sync-server"
    );

    serve(config).await
}
