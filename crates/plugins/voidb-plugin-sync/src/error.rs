//! Plugin-level error type.
//!
//! Author: Limmy

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ObjectConflictDetails {
    pub attempted_base_server_revision: u64,
    pub current_server_revision: u64,
    pub attempted_object_version: u64,
    pub current_object_version: u64,
    pub server_updated_at: Option<String>,
    pub redaction: String,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("config error: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("bundle error: {0}")]
    Bundle(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("server error [{status}]: {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
        current_revision: Option<i64>,
    },

    #[error("unauthorized")]
    Unauthorized,

    #[error("revision conflict (server at {current})")]
    Conflict { current: i64 },

    #[error("object revision conflict for {object_kind} {object_id}")]
    ObjectConflict {
        object_id: String,
        object_kind: String,
        details: Box<ObjectConflictDetails>,
    },

    #[error("not logged in")]
    NotLoggedIn,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<toml::de::Error> for SyncError {
    fn from(e: toml::de::Error) -> Self {
        SyncError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for SyncError {
    fn from(e: toml::ser::Error) -> Self {
        SyncError::Config(e.to_string())
    }
}

impl From<reqwest::Error> for SyncError {
    fn from(e: reqwest::Error) -> Self {
        SyncError::Network(e.to_string())
    }
}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        SyncError::Bundle(e.to_string())
    }
}
