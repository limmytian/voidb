//! VoidB Sync Server — end-to-end encrypted config/data sync backend.
//!
//! The server is intentionally dumb: it stores opaque ciphertext blobs and
//! password verifiers. Encryption keys never leave the client.
//!
//! Crate layout:
//!   - [`config`]  — TOML config loader
//!   - [`db`]      — rusqlite pool + schema bootstrap
//!   - [`storage`] — filesystem blob storage
//!   - [`auth`]    — password hashing + bearer token utilities
//!   - [`routes`]  — HTTP handlers under `/v1/...`
//!   - [`state`]   — shared application state
//!
//! Author: Limmy

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod routes;
pub mod state;
pub mod storage;

use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};

pub use config::{Config, RegistrationPolicy};
pub use state::AppState;

/// Build the public router without binding a socket. Handy for tests.
pub fn router(state: AppState) -> Router {
    let max_bytes = state.config.max_blob_bytes;

    Router::new()
        .merge(routes::auth::router())
        .merge(routes::devices::router())
        .merge(routes::blobs::router())
        .merge(routes::objects::router())
        .merge(routes::misc::router())
        .layer(RequestBodyLimitLayer::new(max_bytes))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start the HTTP server and block until it exits.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let state = AppState::bootstrap(config.clone()).await?;
    let app = router(state);

    let addr: SocketAddr = config
        .bind
        .parse()
        .with_context(|| format!("invalid bind address: {}", config.bind))?;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {}", addr))?;

    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .await
        .context("axum server exited with error")?;

    Ok(())
}
