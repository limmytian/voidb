//! TOML configuration loader.
//!
//! Author: Limmy

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Runtime configuration for the sync server.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: String,

    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    #[serde(default = "default_max_blob_bytes")]
    pub max_blob_bytes: usize,

    #[serde(default = "default_history_keep")]
    pub history_keep: u32,

    #[serde(default)]
    pub registration: RegistrationPolicy,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// Policy controlling who may register a new account.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    #[default]
    Open,
    InviteOnly,
    Closed,
}

fn default_bind() -> String {
    "0.0.0.0:7781".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

fn default_max_blob_bytes() -> usize {
    32 * 1024 * 1024
}

fn default_history_keep() -> u32 {
    20
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// Load from TOML file, then apply env var overrides.
    ///
    /// Env vars (all optional):
    ///   VOIDB_BIND             e.g. "0.0.0.0:7781"
    ///   VOIDB_DATA_DIR         e.g. "/app/data"
    ///   VOIDB_MAX_BLOB_BYTES   e.g. "33554432"
    ///   VOIDB_HISTORY_KEEP     e.g. "20"
    ///   VOIDB_REGISTRATION     "open" | "invite_only" | "closed"
    ///   VOIDB_LOG_LEVEL        "info" | "debug" | ...
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&contents)?;
        cfg.apply_env();
        Ok(cfg)
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("VOIDB_BIND") {
            self.bind = v;
        }
        if let Ok(v) = std::env::var("VOIDB_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("VOIDB_MAX_BLOB_BYTES")
            && let Ok(n) = v.parse()
        {
            self.max_blob_bytes = n;
        }
        if let Ok(v) = std::env::var("VOIDB_HISTORY_KEEP")
            && let Ok(n) = v.parse()
        {
            self.history_keep = n;
        }
        if let Ok(v) = std::env::var("VOIDB_REGISTRATION") {
            self.registration = match v.as_str() {
                "invite_only" => RegistrationPolicy::InviteOnly,
                "closed" => RegistrationPolicy::Closed,
                _ => RegistrationPolicy::Open,
            };
        }
        if let Ok(v) = std::env::var("VOIDB_LOG_LEVEL") {
            self.log_level = v;
        }
    }
}
