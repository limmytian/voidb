//! Cryptographic utilities for encrypting sensitive configuration fields.
//!
//! Uses AES-256-GCM for authenticated encryption and Argon2id for key derivation.
//!
//! # Envelope format
//!
//! Encrypted values are stored as base64-encoded strings with the prefix `$VOIDB$`:
//!
//! ```text
//! $VOIDB$<base64(salt ‖ nonce ‖ ciphertext)>
//! ```
//!
//! - Salt: 16 bytes (for Argon2 key derivation)
//! - Nonce: 12 bytes (AES-GCM IV)
//! - Ciphertext: variable length (includes 16-byte auth tag)
//!
//! # Key sources
//!
//! - `Some(password)`: the user master password is the sole key source.
//! - `None`: a per-installation random secret generated on first use and
//!   stored in the OS keyring (with a 0600 file fallback next to the config
//!   when no usable keyring backend exists). Configs encrypted by very old
//!   VoidB versions with the retired compiled-in default passphrase remain
//!   readable through a decrypt-only migration fallback.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::Argon2;
use base64::prelude::*;
use zeroize::Zeroizing;

use crate::error::VoidbError;

/// V1 prefix (original, expensive Argon2 defaults — kept for backward compat).
const ENCRYPTED_PREFIX_V1: &str = "$VOIDB$";

/// V2 prefix (lighter Argon2 params — used for all new encryptions).
const ENCRYPTED_PREFIX_V2: &str = "$VOIDB2$";

/// Salt length for Argon2.
const SALT_LEN: usize = 16;

/// Nonce length for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// AES-256 key length.
const KEY_LEN: usize = 32;

/// Retired compiled-in default passphrase. New encryptions never use it; it
/// remains a decrypt-only migration fallback for envelopes created by old
/// versions before per-installation keys existed.
const LEGACY_DEFAULT_PASSPHRASE: &str = "voidb-default-config-key-v1";

/// OS keyring service name for VoidB-managed secrets.
const KEYRING_SERVICE: &str = "voidb";

/// OS keyring account holding the per-installation config secret.
const KEYRING_INSTALL_KEY_ACCOUNT: &str = "config-install-key";

/// File name of the per-installation key fallback, stored under the config
/// directory with owner-only permissions.
const INSTALL_KEY_FILE: &str = "install-key";

/// Derive key with original expensive Argon2 defaults (V1 — for decrypting legacy configs).
fn derive_key_v1(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VoidbError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| VoidbError::Crypto(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

/// Derive key with lighter Argon2 params (V2 — used for all new encryptions).
///
/// Parameters: m_cost=4096 KiB (4 MB), t_cost=3, p=1.
/// Sufficient for config-file encryption; completes in milliseconds instead of seconds.
fn derive_key_v2(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VoidbError> {
    use argon2::{Algorithm, Params, Version};
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let params = Params::new(4096, 3, 1, Some(KEY_LEN))
        .map_err(|e| VoidbError::Crypto(format!("Argon2 params error: {}", e)))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| VoidbError::Crypto(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

/// Generate a fresh random installation secret (256-bit, URL-safe base64).
fn generate_install_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Resolve the per-installation fallback passphrase.
///
/// Prefers the OS keyring and falls back to a 0600 file next to the config
/// when no usable keyring backend exists (headless machines, CI). The same
/// source is used deterministically on a given machine: keyring-backed
/// machines never consult the file and vice versa.
///
/// Creation is serialized process-wide so concurrent threads (and parallel
/// tests) cannot each mint a different secret on first use. The file fallback
/// is additionally created atomically with `O_EXCL` so the winner of a
/// cross-process race is re-read instead of overwritten.
fn installation_passphrase() -> Result<Zeroizing<String>, VoidbError> {
    static INSTALL_KEY_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = INSTALL_KEY_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(passphrase) = install_passphrase_from_keyring()? {
        return Ok(passphrase);
    }
    install_passphrase_from_file()
}

/// Read (or create) the per-installation secret in the OS keyring.
///
/// Returns `Ok(None)` when no keyring backend is available so the caller can
/// fall back to the file-based secret.
fn install_passphrase_from_keyring() -> Result<Option<Zeroizing<String>>, VoidbError> {
    let entry = match keyring::Entry::new(KEYRING_SERVICE, KEYRING_INSTALL_KEY_ACCOUNT) {
        Ok(entry) => entry,
        Err(_) => return Ok(None),
    };
    match entry.get_password() {
        Ok(existing) => Ok(Some(Zeroizing::new(existing))),
        Err(keyring::Error::NoEntry) => {
            let generated = generate_install_secret();
            entry
                .set_password(&generated)
                .map_err(|e| VoidbError::Crypto(format!("Keyring write failed: {}", e)))?;
            Ok(Some(Zeroizing::new(generated)))
        }
        Err(_) => Ok(None),
    }
}

/// Read (or create) the per-installation secret file under the config
/// directory with owner-only permissions (0600 on Unix, applied at creation).
fn install_passphrase_from_file() -> Result<Zeroizing<String>, VoidbError> {
    let dir = dirs::config_dir()
        .ok_or_else(|| VoidbError::Crypto("Cannot determine config directory".to_string()))?;
    let path = dir.join(INSTALL_KEY_FILE);

    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed.to_string()));
        }
    }

    let generated = generate_install_secret();
    std::fs::create_dir_all(&dir)
        .map_err(|e| VoidbError::Crypto(format!("Config dir create failed: {}", e)))?;

    let open_result = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
        }
    };

    match open_result {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(generated.as_bytes())
                .map_err(|e| VoidbError::Crypto(format!("Install key write failed: {}", e)))?;
            Ok(Zeroizing::new(generated))
        }
        // Another creator (process or thread) won the race; use its secret.
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read_to_string(&path)
                .map_err(|e| VoidbError::Crypto(format!("Install key read failed: {}", e)))?;
            let trimmed = existing.trim();
            if trimmed.is_empty() {
                return Err(VoidbError::Crypto("Install key file is empty".to_string()));
            }
            Ok(Zeroizing::new(trimmed.to_string()))
        }
        Err(err) => Err(VoidbError::Crypto(format!("Install key create failed: {}", err))),
    }
}

/// Resolve the passphrase for encryption: the user master password when set,
/// otherwise the per-installation secret.
fn encryption_passphrase(master_password: Option<&str>) -> Result<Zeroizing<String>, VoidbError> {
    match master_password {
        Some(password) => Ok(Zeroizing::new(password.to_string())),
        None => installation_passphrase(),
    }
}

/// Encrypt a plaintext string.
///
/// Returns the encrypted envelope string (`$VOIDB2$<base64>`).
/// If `master_password` is `None`, the per-installation secret is used.
pub fn encrypt(plaintext: &str, master_password: Option<&str>) -> Result<String, VoidbError> {
    let passphrase = encryption_passphrase(master_password)?;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

    // Derive key (V2 — light params)
    let key_bytes = derive_key_v2(passphrase.as_bytes(), &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);

    // Encrypt
    let ciphertext = cipher
        .encrypt(&nonce_bytes, plaintext.as_bytes())
        .map_err(|e| VoidbError::Crypto(format!("Encryption failed: {}", e)))?;

    // Pack: salt ‖ nonce ‖ ciphertext
    let mut envelope = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(format!("{}{}", ENCRYPTED_PREFIX_V2, BASE64_STANDARD.encode(&envelope)))
}

/// Decrypt an encrypted envelope string.
///
/// Errors on values that are not `$VOIDB$`/`$VOIDB2$` envelopes — plaintext
/// inputs no longer pass through silently. Callers that must tolerate legacy
/// plaintext configs opt in explicitly via [`decrypt_allow_plaintext`].
///
/// When `master_password` is `Some`, it is the sole key source. When `None`,
/// the per-installation secret is tried first, then the retired default
/// passphrase as a decrypt-only migration fallback for very old envelopes.
pub fn decrypt(value: &str, master_password: Option<&str>) -> Result<String, VoidbError> {
    if !is_encrypted(value) {
        return Err(VoidbError::Crypto(
            "value is not an encrypted envelope; call decrypt_allow_plaintext for legacy plaintext configs"
                .to_string(),
        ));
    }

    if let Some(password) = master_password {
        return decrypt_envelope(value, password.as_bytes());
    }

    let install_key = installation_passphrase()?;
    if let Ok(plaintext) = decrypt_envelope(value, install_key.as_bytes()) {
        return Ok(plaintext);
    }
    // Migration-only fallback: envelopes created by versions that still used
    // the retired compiled-in default passphrase.
    decrypt_envelope(value, LEGACY_DEFAULT_PASSPHRASE.as_bytes())
}

/// Like [`decrypt`], but returns non-encrypted values unchanged for
/// backwards compatibility with plaintext configs. Use only at explicit
/// legacy-config loading boundaries.
pub fn decrypt_allow_plaintext(
    value: &str,
    master_password: Option<&str>,
) -> Result<String, VoidbError> {
    if !is_encrypted(value) {
        return Ok(value.to_string());
    }
    decrypt(value, master_password)
}

/// Decrypt a `$VOIDB$`/`$VOIDB2$` envelope with a single passphrase.
fn decrypt_envelope(value: &str, passphrase: &[u8]) -> Result<String, VoidbError> {
    // Determine version and strip prefix (check V2 first — V1 is a prefix of V2)
    type DeriveFn = fn(&[u8], &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VoidbError>;
    let (encoded, derive_fn): (&str, DeriveFn) =
        if let Some(stripped) = value.strip_prefix(ENCRYPTED_PREFIX_V2) {
            (stripped, derive_key_v2)
        } else {
            (&value[ENCRYPTED_PREFIX_V1.len()..], derive_key_v1)
        };

    let envelope = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| VoidbError::Crypto(format!("Invalid base64: {}", e)))?;

    let min_len = SALT_LEN + NONCE_LEN + 16; // 16 = AES-GCM auth tag
    if envelope.len() < min_len {
        return Err(VoidbError::Crypto("Encrypted data too short".to_string()));
    }

    let salt = &envelope[..SALT_LEN];
    let nonce_bytes = &envelope[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &envelope[SALT_LEN + NONCE_LEN..];

    // Derive key using the appropriate version
    let key_bytes = derive_fn(passphrase, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VoidbError::Crypto("Decryption failed (wrong password?)".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| VoidbError::Crypto(format!("Decrypted data is not valid UTF-8: {}", e)))
}

/// Check whether a string value is encrypted (has the `$VOIDB$` or `$VOIDB2$` prefix).
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX_V1) || value.starts_with(ENCRYPTED_PREFIX_V2)
}

/// Encrypt a `serde_json::Value` in place, encrypting all string values
/// whose keys are in `sensitive_keys`.
pub fn encrypt_json_fields(
    value: &mut serde_json::Value,
    sensitive_keys: &[&str],
    master_password: Option<&str>,
) -> Result<(), VoidbError> {
    if let serde_json::Value::Object(map) = value {
        for (key, val) in map.iter_mut() {
            if sensitive_keys.contains(&key.as_str())
                && let serde_json::Value::String(s) = val
                    && !s.is_empty() && !is_encrypted(s) {
                        *s = encrypt(s, master_password)?;
                    }
        }
    }
    Ok(())
}

/// Decrypt a `serde_json::Value` in place, decrypting all string values
/// whose keys are in `sensitive_keys`.
pub fn decrypt_json_fields(
    value: &mut serde_json::Value,
    sensitive_keys: &[&str],
    master_password: Option<&str>,
) -> Result<(), VoidbError> {
    if let serde_json::Value::Object(map) = value {
        for (key, val) in map.iter_mut() {
            if sensitive_keys.contains(&key.as_str())
                && let serde_json::Value::String(s) = val
                    && is_encrypted(s) {
                        *s = decrypt(s, master_password)?;
                    }
        }
    }
    Ok(())
}

// ============================================================================
// Known sensitive field names
// ============================================================================

/// Standard sensitive field names that should always be encrypted.
pub const SENSITIVE_FIELDS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "access_key",
    "secret_key",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = "my-secret-password-123";
        let encrypted = encrypt(plaintext, None).unwrap();
        assert!(is_encrypted(&encrypted));
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX_V2));

        let decrypted = decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_master_password() {
        let plaintext = "database-password";
        let master = "my-master-key";

        let encrypted = encrypt(plaintext, Some(master)).unwrap();
        assert!(is_encrypted(&encrypted));

        // Correct password
        let decrypted = decrypt(&encrypted, Some(master)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Wrong password
        let result = decrypt(&encrypted, Some("wrong-password"));
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_rejects_plaintext_by_default() {
        // decrypt() is strict: plaintext input is an error, not a silent
        // passthrough. Legacy plaintext configs must opt in explicitly.
        let plain = "just-a-plain-string";
        assert!(decrypt(plain, None).is_err());
        assert!(decrypt(plain, Some("pw")).is_err());

        let result = decrypt_allow_plaintext(plain, None).unwrap();
        assert_eq!(result, plain);
    }

    #[test]
    fn test_new_encryptions_do_not_use_legacy_default_passphrase() {
        let encrypted = encrypt("install-key-protected", None).unwrap();
        // The retired compiled-in passphrase must not decrypt fresh envelopes;
        // they are protected by the per-installation secret instead.
        assert!(decrypt_envelope(&encrypted, LEGACY_DEFAULT_PASSPHRASE.as_bytes()).is_err());
        assert_eq!(decrypt(&encrypted, None).unwrap(), "install-key-protected");
    }

    #[test]
    fn test_is_encrypted() {
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted(""));
        assert!(is_encrypted("$VOIDB$abc123"));
        assert!(is_encrypted("$VOIDB2$abc123"));
    }

    #[test]
    fn test_encrypt_empty_string() {
        let encrypted = encrypt("", None).unwrap();
        let decrypted = decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_encrypt_unicode() {
        let plaintext = "密码测试 パスワード 🔐";
        let encrypted = encrypt(plaintext, None).unwrap();
        let decrypted = decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let plaintext = "same-password";
        let e1 = encrypt(plaintext, None).unwrap();
        let e2 = encrypt(plaintext, None).unwrap();
        // Due to random salt and nonce, outputs should differ
        assert_ne!(e1, e2);
        // But both should decrypt to same value
        assert_eq!(decrypt(&e1, None).unwrap(), plaintext);
        assert_eq!(decrypt(&e2, None).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_json_fields() {
        let mut config = serde_json::json!({
            "host": "localhost",
            "port": 3306,
            "username": "root",
            "password": "secret123",
            "token": "abc-token",
            "database": "mydb"
        });

        let keys = &["password", "token"];
        encrypt_json_fields(&mut config, keys, None).unwrap();

        // password and token should be encrypted
        let pw = config["password"].as_str().unwrap();
        assert!(is_encrypted(pw));
        let tk = config["token"].as_str().unwrap();
        assert!(is_encrypted(tk));

        // other fields unchanged
        assert_eq!(config["host"], "localhost");
        assert_eq!(config["username"], "root");

        // Decrypt back
        decrypt_json_fields(&mut config, keys, None).unwrap();
        assert_eq!(config["password"], "secret123");
        assert_eq!(config["token"], "abc-token");
    }

    #[test]
    fn test_invalid_encrypted_data() {
        let result = decrypt("$VOIDB$not-valid-base64!!!", None);
        assert!(result.is_err());

        // Too short (valid base64 but not enough data)
        let result = decrypt("$VOIDB$AAAA", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_v1_backward_compat() {
        // Manually create a V1-encrypted value using old derive_key_v1
        let plaintext = "legacy-secret";
        let passphrase = LEGACY_DEFAULT_PASSPHRASE;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let key_bytes = derive_key_v1(passphrase.as_bytes(), &salt).unwrap();
        let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
        let cipher = Aes256Gcm::new(key);
        let ciphertext = cipher.encrypt(&nonce_bytes, plaintext.as_bytes()).unwrap();
        let mut envelope = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        let v1_encrypted = format!("{}{}", ENCRYPTED_PREFIX_V1, BASE64_STANDARD.encode(&envelope));

        // V1 value should be recognized as encrypted
        assert!(is_encrypted(&v1_encrypted));
        assert!(v1_encrypted.starts_with("$VOIDB$"));
        assert!(!v1_encrypted.starts_with("$VOIDB2$"));

        // decrypt() should handle V1 values correctly
        let decrypted = decrypt(&v1_encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_new_encryptions_use_v2() {
        let encrypted = encrypt("test", None).unwrap();
        assert!(encrypted.starts_with("$VOIDB2$"));
    }
}
