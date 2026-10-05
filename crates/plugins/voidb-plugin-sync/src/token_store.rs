//! Local storage for sync bearer tokens.
//!
//! The preferred backend is the OS keyring. A private-file fallback is kept for
//! headless or unsupported environments and is surfaced explicitly in status.

use sha2::{Digest, Sha256};

use crate::config::SyncConfig;
use crate::error::SyncError;

const SERVICE: &str = "voidb-sync";
const TOKEN_STORE_ENV: &str = "VOIDB_SYNC_TOKEN_STORE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStoreBackend {
    Keyring,
    FileFallback,
    None,
}

impl TokenStoreBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::FileFallback => "file_fallback",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenStoreStatus {
    pub present: bool,
    pub backend: TokenStoreBackend,
    pub mode: &'static str,
    pub keyring_error: Option<String>,
}

impl TokenStoreStatus {
    pub fn not_set(mode: &'static str, keyring_error: Option<String>) -> Self {
        Self {
            present: false,
            backend: TokenStoreBackend::None,
            mode,
            keyring_error,
        }
    }

    pub fn present(backend: TokenStoreBackend, mode: &'static str) -> Self {
        Self {
            present: true,
            backend,
            mode,
            keyring_error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenStoreMode {
    Auto,
    Keyring,
    File,
}

impl TokenStoreMode {
    fn current() -> Result<Self, SyncError> {
        match std::env::var(TOKEN_STORE_ENV) {
            Ok(value) if value.eq_ignore_ascii_case("auto") => Ok(Self::Auto),
            Ok(value) if value.eq_ignore_ascii_case("keyring") => Ok(Self::Keyring),
            Ok(value) if value.eq_ignore_ascii_case("file") => Ok(Self::File),
            Ok(value) => Err(SyncError::Config(format!(
                "{TOKEN_STORE_ENV} must be auto, keyring, or file (got {value})"
            ))),
            Err(_) => Ok(Self::Auto),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Keyring => "keyring",
            Self::File => "file",
        }
    }
}

pub fn save_token(config: &mut SyncConfig, token: &str) -> Result<TokenStoreStatus, SyncError> {
    let mode = TokenStoreMode::current()?;
    let mut keyring_error = None;

    if mode != TokenStoreMode::File {
        match save_keyring_token(config, token) {
            Ok(()) => {
                config.token = None;
                config.save()?;
                return Ok(TokenStoreStatus::present(
                    TokenStoreBackend::Keyring,
                    mode.as_str(),
                ));
            }
            Err(err) if mode == TokenStoreMode::Keyring => return Err(err),
            Err(err) => keyring_error = Some(redacted_error(&err)),
        }
    }

    config.token = Some(token.to_string());
    config.save()?;
    Ok(TokenStoreStatus {
        present: true,
        backend: TokenStoreBackend::FileFallback,
        mode: mode.as_str(),
        keyring_error,
    })
}

pub fn load_token(config: &SyncConfig) -> Result<Option<String>, SyncError> {
    let (token, _) = load_token_with_status(config)?;
    Ok(token)
}

pub fn load_token_with_status(
    config: &SyncConfig,
) -> Result<(Option<String>, TokenStoreStatus), SyncError> {
    let mode = TokenStoreMode::current()?;
    let mut keyring_error = None;

    if mode != TokenStoreMode::File {
        match load_keyring_token(config) {
            Ok(Some(token)) => {
                return Ok((
                    Some(token),
                    TokenStoreStatus::present(TokenStoreBackend::Keyring, mode.as_str()),
                ));
            }
            Ok(None) => {}
            Err(err) if mode == TokenStoreMode::Keyring => return Err(err),
            Err(err) => keyring_error = Some(redacted_error(&err)),
        }
    }

    if let Some(result) = file_fallback_token(config, mode.as_str(), keyring_error.clone()) {
        return Ok(result);
    }

    Ok((
        None,
        TokenStoreStatus::not_set(mode.as_str(), keyring_error),
    ))
}

pub fn clear_token(config: &mut SyncConfig) -> Result<TokenStoreStatus, SyncError> {
    let mode = TokenStoreMode::current()?;
    if mode != TokenStoreMode::File {
        match delete_keyring_token(config) {
            Ok(()) => {}
            Err(err) if mode == TokenStoreMode::Keyring => return Err(err),
            Err(_) => {}
        }
    }
    config.token = None;
    config.save()?;
    Ok(TokenStoreStatus::not_set(mode.as_str(), None))
}

pub fn status(config: &SyncConfig) -> Result<TokenStoreStatus, SyncError> {
    let (_, status) = load_token_with_status(config)?;
    Ok(status)
}

fn account(config: &SyncConfig) -> Result<String, SyncError> {
    let server = config
        .server_url
        .as_deref()
        .ok_or_else(|| SyncError::Config("sync token key needs server_url".into()))?;
    let email = config
        .email
        .as_deref()
        .ok_or_else(|| SyncError::Config("sync token key needs email".into()))?;
    let device = config
        .device_id
        .as_deref()
        .ok_or_else(|| SyncError::Config("sync token key needs device_id".into()))?;

    let mut hasher = Sha256::new();
    hasher.update(server.as_bytes());
    hasher.update(b"\n");
    hasher.update(email.as_bytes());
    hasher.update(b"\n");
    hasher.update(device.as_bytes());
    let digest = hex::encode(hasher.finalize());
    Ok(format!("{email}:{}", &digest[..16]))
}

fn redacted_error(error: &SyncError) -> String {
    match error {
        SyncError::Config(_) => "keyring_unavailable".into(),
        _ => "token_store_error".into(),
    }
}

fn file_fallback_token(
    config: &SyncConfig,
    mode: &'static str,
    keyring_error: Option<String>,
) -> Option<(Option<String>, TokenStoreStatus)> {
    config.token.clone().map(|token| {
        (
            Some(token),
            TokenStoreStatus {
                present: true,
                backend: TokenStoreBackend::FileFallback,
                mode,
                keyring_error,
            },
        )
    })
}

#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
))]
fn keyring_entry(config: &SyncConfig) -> Result<keyring::Entry, SyncError> {
    let account = account(config)?;
    keyring::Entry::new(SERVICE, &account)
        .map_err(|e| SyncError::Config(format!("open keyring token entry: {e}")))
}

#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
))]
fn save_keyring_token(config: &SyncConfig, token: &str) -> Result<(), SyncError> {
    keyring_entry(config)?
        .set_password(token)
        .map_err(|e| SyncError::Config(format!("write keyring token: {e}")))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
)))]
fn save_keyring_token(_config: &SyncConfig, _token: &str) -> Result<(), SyncError> {
    Err(SyncError::Config(
        "OS keyring token storage is unavailable on this platform".into(),
    ))
}

#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
))]
fn load_keyring_token(config: &SyncConfig) -> Result<Option<String>, SyncError> {
    match keyring_entry(config)?.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(SyncError::Config(format!("read keyring token: {e}"))),
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
)))]
fn load_keyring_token(_config: &SyncConfig) -> Result<Option<String>, SyncError> {
    Err(SyncError::Config(
        "OS keyring token storage is unavailable on this platform".into(),
    ))
}

#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
))]
fn delete_keyring_token(config: &SyncConfig) -> Result<(), SyncError> {
    match keyring_entry(config)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SyncError::Config(format!("delete keyring token: {e}"))),
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "macos"))
    )
)))]
fn delete_keyring_token(_config: &SyncConfig) -> Result<(), SyncError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> SyncConfig {
        SyncConfig {
            server_url: Some("https://sync.example.test".into()),
            email: Some("alice@example.test".into()),
            device_id: Some("device-1".into()),
            ..Default::default()
        }
    }

    #[test]
    fn file_fallback_status_is_explicit_and_redacted() {
        let mut cfg = configured();
        cfg.token = Some("secret-token".into());

        let (token, status) = file_fallback_token(&cfg, "file", Some("keyring_unavailable".into()))
            .expect("fallback token");
        assert_eq!(token.as_deref(), Some("secret-token"));
        assert_eq!(status.backend, TokenStoreBackend::FileFallback);
        assert_eq!(status.mode, "file");
        assert_eq!(status.keyring_error.as_deref(), Some("keyring_unavailable"));
    }
}
