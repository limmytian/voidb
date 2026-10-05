//! Shared application state injected into Axum handlers.
//!
//! Author: Limmy

use std::sync::Arc;

use anyhow::Context;

use crate::{
    config::Config,
    db::{DbPool, open as open_db},
    storage::BlobStore,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: DbPool,
    pub blobs: BlobStore,
}

impl AppState {
    pub async fn bootstrap(config: Config) -> anyhow::Result<Self> {
        let data_dir = config.data_dir.clone();
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("create data_dir {}", data_dir.display()))?;

        let db_path = data_dir.join("metadata.db");
        let blobs_root = data_dir.join("blobs");

        let db = open_db(&db_path).context("open sqlite")?;
        let blobs = BlobStore::new(blobs_root)?;

        Ok(Self {
            config: Arc::new(config),
            db,
            blobs,
        })
    }
}
