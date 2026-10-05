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

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::Argon2;
use base64::prelude::*;

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

/// Default passphrase used when no master password is configured.
/// This provides basic obfuscation — not strong security — but prevents
/// casual reading of plaintext credentials in config files.
const DEFAULT_PASSPHRASE: &str = "voidb-default-config-key-v1";

/// Derive key with original expensive Argon2 defaults (V1 — for decrypting legacy configs).
fn derive_key_v1(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], VoidbError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| VoidbError::Crypto(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

/// Derive key with lighter Argon2 params (V2 — used for all new encryptions).
///
/// Parameters: m_cost=4096 KiB (4 MB), t_cost=3, p=1.
/// Sufficient for config-file encryption; completes in milliseconds instead of seconds.
fn derive_key_v2(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], VoidbError> {
    use argon2::{Algorithm, Params, Version};
    let mut key = [0u8; KEY_LEN];
    let params = Params::new(4096, 3, 1, Some(KEY_LEN))
        .map_err(|e| VoidbError::Crypto(format!("Argon2 params error: {}", e)))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| VoidbError::Crypto(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

/// Encrypt a plaintext string.
///
/// Returns the encrypted envelope string (`$VOIDB$<base64>`).
/// If `master_password` is `None`, uses the default passphrase.
pub fn encrypt(plaintext: &str, master_password: Option<&str>) -> Result<String, VoidbError> {
    let passphrase = master_password.unwrap_or(DEFAULT_PASSPHRASE);

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

    // Derive key (V2 — light params)
    let key_bytes = derive_key_v2(passphrase.as_bytes(), &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
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
/// Returns the plaintext. If the value is not encrypted (no `$VOIDB$` prefix),
/// returns it as-is for backwards compatibility with plaintext configs.
pub fn decrypt(value: &str, master_password: Option<&str>) -> Result<String, VoidbError> {
    // Not encrypted — return as-is (backwards compat)
    if !is_encrypted(value) {
        return Ok(value.to_string());
    }

    let passphrase = master_password.unwrap_or(DEFAULT_PASSPHRASE);

    // Determine version and strip prefix (check V2 first — V1 is a prefix of V2)
    type DeriveFn = fn(&[u8], &[u8]) -> Result<[u8; KEY_LEN], VoidbError>;
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
    let key_bytes = derive_fn(passphrase.as_bytes(), salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
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
    fn test_decrypt_plaintext_passthrough() {
        // Unencrypted values should pass through unchanged
        let plain = "just-a-plain-string";
        let result = decrypt(plain, None).unwrap();
        assert_eq!(result, plain);
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
        let passphrase = DEFAULT_PASSPHRASE;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let key_bytes = derive_key_v1(passphrase.as_bytes(), &salt).unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
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
